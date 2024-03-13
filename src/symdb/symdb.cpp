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

static int load_all_kmod_btfs(symdb_mgr_priv_t *priv)
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

static std::map<std::string, bool> get_avail_funcs()
{
    std::map<std::string, bool> kprobe_funcs;
    std::ifstream file("/sys/kernel/debug/tracing/available_filter_functions");
    if (!file.is_open()) {
        return kprobe_funcs;
    }

    std::string line;
    std::regex regex(R"(\[([^\]]+)\])");
    while (std::getline(file, line)) {
        std::smatch match;
        std::string func = line;
        if (std::regex_search(line, match, regex)) {
            func = match.prefix().str();
            func.pop_back();
        }

        kprobe_funcs[func] = true;
    }

    file.close();
    return kprobe_funcs;
}

static int get_func_param_pos(libbpf::btf *btf, const int btf_id, const char *param)
{
    const libbpf::btf_type *t_func_proto, *t;
    const libbpf::btf_param *p;

    t_func_proto = libbpf::btf__type_by_id(btf, btf_id);
    if (!t_func_proto || !libbpf::btf_is_func_proto(t_func_proto)) {
        return -ENOENT;
    }

    for (size_t i = 0; i < libbpf::btf_vlen(t_func_proto); i++) {
        p = libbpf::btf_params(t_func_proto) + i;
        t = libbpf::btf__type_by_id(btf, p->type);
        if (!t || !btf_is_ptr(t)) {
            continue;
        }
        t = libbpf::btf__type_by_id(btf, t->type);
        if (!t || !btf_is_struct(t)) {
            continue;
        }
        if (!std::strcmp(libbpf::btf__name_by_offset(btf, t->name_off), param)) {
            return i;
        }
    }

    return -ENOENT;
}

static int get_skb_func_from_btfs(symdb_mgr_priv_t *priv)
{
    auto funcs = get_avail_funcs();
    for (auto &it : priv->btf_list) {
        const auto mod_name = it.first;
        const auto btf = it.second;
        for (size_t id = 1; id < libbpf::btf__type_cnt(btf); id++) {
            const libbpf::btf_type *t = libbpf::btf__type_by_id(btf, id);
            if (!t || !libbpf::btf_is_func(t)) {
                continue;
            }

            const auto func_name = libbpf::btf__name_by_offset(btf, t->name_off);
            if (funcs.find(func_name) == funcs.end()) {
                continue;
            }

            int skb_pos = get_func_param_pos(btf, t->type, "sk_buff");
            if (skb_pos < 0) {
                continue;
            }

            skb_func_t skb_func = { func_name, mod_name, skb_pos };
            priv->skb_func_list[func_name] = skb_func;
            spdlog::debug("Found skb func {} with {} in mod {}", func_name, skb_pos, mod_name);
        }
    }

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

    load_all_kmod_btfs(p);
    get_skb_func_from_btfs(p);
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
        if (!filter.empty() && !std::regex_match(it.first, std::regex(filter))) {
            continue;
        }
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