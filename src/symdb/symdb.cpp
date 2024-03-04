#include "symdb.h"
#include <fstream>
#include <map>
#include <memory>
#include <regex>
#include <spdlog/spdlog.h>

#include "bpf-common.h"

typedef struct {
    std::string func_name;
    std::string mod_name;
    int skb_pos;
} skb_func_t;

typedef struct {
    bpfhelper::ksyms *ksyms;
    std::map<std::string, libbpf::btf *> btf_list;
    std::map<std::string, skb_func_t> skb_func_list;
} symdb_mgr_priv_t;

SymdbMgr::SymdbMgr()
{
    auto p = new symdb_mgr_priv_t();
    p->ksyms = nullptr;
    p->btf_list = {};
    p->skb_func_list = {};
    priv = static_cast<void *>(p);
}

SymdbMgr::~SymdbMgr()
{
    auto p = static_cast<symdb_mgr_priv_t *>(priv);
    if (p == nullptr) {
        return;
    }

    for (auto &it : p->btf_list) {
        libbpf::btf__free(it.second);
    }

    if (p->ksyms) {
        bpfhelper::ksyms__free(p->ksyms);
    }

    delete p;
}

static int get_func_param_pos(libbpf::btf *btf, const char *func, const char *param)
{
    const libbpf::btf_type *t_func, *t_func_proto, *t;
    const libbpf::btf_param *p;
    int id, i;

    // Find the BTF ID of the function
    id = libbpf::btf__find_by_name_kind(btf, func, BTF_KIND_FUNC);
    if (id < 0) {
        return -ENOENT;
    }

    t_func = libbpf::btf__type_by_id(btf, id);
    if (!t_func || !libbpf::btf_is_func(t_func)) {
        spdlog::error("Error looking up function type: {}", func);
        return -ENOENT;
    }
    t_func_proto = libbpf::btf__type_by_id(btf, t_func->type);
    if (!t_func_proto || !libbpf::btf_is_func_proto(t_func_proto)) {
        spdlog::error("Error looking up function proto type: {}", func);
        return -ENOENT;
    }

    // Print the function parameters
    for (i = 0; i < btf_vlen(t_func_proto); i++) {
        p = btf_params(t_func_proto) + i;
        t = libbpf::btf__type_by_id(btf, p->type);
        if (!t || !btf_is_ptr(t)) {
            continue;
        }
        t = libbpf::btf__type_by_id(btf, t->type);
        if (!t || !btf_is_struct(t)) {
            continue;
        }
        if (!strcmp(libbpf::btf__name_by_offset(btf, t->name_off), param)) {
            return i;
        }
    }

    return -ENOENT;
}

static int iterate_kernel_module(symdb_mgr_priv_t *priv)
{
    auto process_module = [&](const char *module) {
        if (!bpfhelper::module_btf_exists(module)) {
            spdlog::warn("Module {} BTF not found", module);
            return -ENOENT;
        }

        libbpf::btf *btf = libbpf::btf__load_module_btf(module, priv->btf_list["vmlinux"]);
        int err = libbpf::libbpf_get_error(btf);
        if (err) {
            spdlog::error("Failed to load BTF for module {}: {}", module, strerror(err));
            return -err;
        }

        priv->btf_list[module] = btf;
        return 0;
    };

    std::ifstream file("/proc/modules");
    if (!file.is_open()) {
        return -errno;
    }

    std::string line;
    std::regex regex(R"((\S+)\s+\S+)");
    while (std::getline(file, line)) {
        std::smatch match;
        if (!std::regex_match(line, match, regex)) {
            spdlog::debug("Skip line: {}", line);
            continue;
        }
        std::string name = match[1].str();
        process_module(name.c_str());
    }

    file.close();
    return 0;
}

static int iterate_available_functions(symdb_mgr_priv_t *priv)
{
    auto process_function = [&](const std::string module, const std::string func) {
        const std::string param = "sk_buff";
        skb_func_t s = {};
        s.func_name = func;
        s.mod_name = module;
        s.skb_pos = get_func_param_pos(priv->btf_list[module], func.c_str(), param.c_str());
        if (s.skb_pos < 0) {
            return;
        }
        priv->skb_func_list[func] = s;
        spdlog::debug("Found param '{}' in {} at postion {}", param, func, s.skb_pos);
    };

    const std::string availfuncs = "/sys/kernel/debug/tracing/available_filter_functions";
    std::ifstream file(availfuncs);
    if (!file.is_open()) {
        spdlog::error("Failed to open {}", availfuncs);
        return -errno;
    }

    std::string line;
    std::regex regex(R"(\[([^\]]+)\])");
    while (std::getline(file, line)) {
        std::smatch match;
        std::string func = line;
        std::string mod = "vmlinux";
        if (std::regex_search(line, match, regex)) {
            func = match.prefix().str();
            func.pop_back();
            mod = match[1].str();
        }
        process_function(mod, func);
    }

    file.close();
    return 0;
}

int SymdbMgr::init()
{
    auto p = static_cast<symdb_mgr_priv_t *>(priv);

    auto vmlinux_btf = libbpf::btf__load_vmlinux_btf();
    auto err = libbpf::libbpf_get_error(vmlinux_btf);
    if (err) {
        spdlog::error("Failed to load vmlinux BTF: {}", strerror(err));
        return -err;
    }
    p->btf_list["vmlinux"] = vmlinux_btf;

    p->ksyms = bpfhelper::ksyms__load();
    if (p->ksyms == NULL) {
        spdlog::error("Failed to load ksyms\n");
        return -EFAULT;
    }

    iterate_kernel_module(p);
    iterate_available_functions(p);
    return 0;
}

std::pair<int, std::string> SymdbMgr::get_func_by_addr(const unsigned long addr) const
{
    auto p = static_cast<symdb_mgr_priv_t *>(priv);
    auto sym = bpfhelper::ksyms__map_addr(p->ksyms, addr);
    if (sym == NULL) {
        return { -ENOENT, "" };
    }

    return { 0, std::string(sym->name) };
}

std::pair<int, unsigned long> SymdbMgr::get_addr_by_func(const std::string &func) const
{
    auto p = static_cast<symdb_mgr_priv_t *>(priv);
    auto sym = bpfhelper::ksyms__get_symbol(p->ksyms, func.c_str());
    if (sym == NULL) {
        return { -ENOENT, 0 };
    }

    return { 0, sym->addr };
}

std::pair<int, std::vector<std::string>> SymdbMgr::get_skb_func_list(const std::string &filter) const
{
    auto p = static_cast<symdb_mgr_priv_t *>(priv);
    std::vector<std::string> list = {};
    for (auto &it : p->skb_func_list) {
        list.push_back(it.first);
    }

    return { 0, list };
}

std::pair<int, int> SymdbMgr::get_skb_func_param_pos(const std::string &func) const
{
    auto p = static_cast<symdb_mgr_priv_t *>(priv);
    auto it = p->skb_func_list.find(func);
    if (it == p->skb_func_list.end()) {
        return { -ENOENT, 0 };
    }

    return { 0, it->second.skb_pos };
}