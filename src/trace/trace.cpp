#include "trace.h"

#include <elf.h>
#include <poll.h>

#include <fstream>
#include <map>
#include <regex>
#include <spdlog/spdlog.h>

#include "pcap2bpf.h"
#include "skbtracer.h"

extern "C" {
namespace libbpf {
#include "skbtracer.skel.h"
} // namespace libbpf
}

typedef struct {
    std::string filter_pcap;
    std::map<int, libbpf::bpf_program *> prog_mapping_list;
    std::map<std::string, libbpf::bpf_link *> link_mapping_list;
    libbpf::skbtracer_bpf *skel;
    int libbpf_sec_handler;

    TraceMgr::output_callback_t output_cb;
    void *ctx;
} trace_mgr_priv_t;

static int custom_prepare_load_skbtracer_prog(libbpf::bpf_program *prog, libbpf::bpf_prog_load_opts *opts, long cookie)
{
    const char *func_prefix = "filter_pcap_ebpf_l";
    auto p = reinterpret_cast<trace_mgr_priv_t*>(cookie);
    auto obj = p->skel->obj;
    auto btf = libbpf::bpf_object__btf(obj);
    auto func_info = static_cast<const libbpf::bpf_func_info*>(opts->func_info);
    size_t offset = 0;

    for (size_t i = 0; i < opts->func_info_cnt; i++) {
        const libbpf::btf_type *t = libbpf::btf__type_by_id(btf, func_info[i].type_id);
        if (!t || !libbpf::btf_is_func(t)) {
            continue;
        }

        const auto func_name = libbpf::btf__name_by_offset(btf, t->name_off);
        if (func_name == NULL || std::string(func_name).find(func_prefix) != 0) {
            continue;
        }
        spdlog::info("Injecting eBPF filter into {} for {}", func_name, libbpf::bpf_program__name(prog));

        bool is_l3 = func_name[std::strlen(func_prefix)] == '3' ? true : false;
        auto [ret, insn, len] = pcap2bpf::compile_ebpf_filter(p->filter_pcap, is_l3);
        if (ret) {
            spdlog::error("Failed to compile eBPF filter");
            return ret;
        }
        pcap2bpf::inject_ebpf_filter(prog, func_info[i].insn_off + offset, insn, len);

        delete[] insn;
        offset += len;
    }

    // drop func_info and line_info to avoid verification failure
    opts->func_info = NULL;
    opts->func_info_cnt = 0;
    opts->line_info = NULL;
    opts->line_info_cnt = 0;
    return 0;
}

TraceMgr::TraceMgr()
{
    auto p = new trace_mgr_priv_t();

    auto libbpf_print_fn = [](
        libbpf::libbpf_print_level level,
        const char *format, va_list args) {
            return vfprintf(stderr, format, args);
        };

    libbpf::libbpf_set_print(libbpf_print_fn);
    libbpf::libbpf_set_strict_mode(libbpf::LIBBPF_STRICT_ALL);

    LIBBPF_OPTS(libbpf::libbpf_prog_handler_opts, handler_opts,
        .prog_prepare_load_fn = custom_prepare_load_skbtracer_prog,
    );
    handler_opts.cookie = reinterpret_cast<long>(p);
    int handler = libbpf::libbpf_register_prog_handler("skbtracer/", libbpf::BPF_PROG_TYPE_KPROBE, static_cast<libbpf::bpf_attach_type>(0), &handler_opts);
    if (handler < 0) {
        throw std::runtime_error("Failed to register prog handler");
    }
    p->libbpf_sec_handler = handler;

    auto skel = libbpf::skbtracer_bpf__open();
    if (libbpf::libbpf_get_error(skel)) {
        throw std::runtime_error("Failed to open BPF skeleton");
    }
    p->skel = skel;


    p->prog_mapping_list.emplace(0, skel->progs.kprobe_skb_1);
    p->prog_mapping_list.emplace(1, skel->progs.kprobe_skb_2);
    p->prog_mapping_list.emplace(2, skel->progs.kprobe_skb_3);
    p->prog_mapping_list.emplace(3, skel->progs.kprobe_skb_4);
    p->prog_mapping_list.emplace(4, skel->progs.kprobe_skb_5);

    priv = static_cast<void *>(p);
}

TraceMgr::~TraceMgr()
{
    auto p = static_cast<trace_mgr_priv_t *>(priv);
    if (p->libbpf_sec_handler >= 0) {
        libbpf::libbpf_unregister_prog_handler(p->libbpf_sec_handler);
    }
    if (p->skel) {
        libbpf::skbtracer_bpf__destroy(p->skel);
    }
    delete p;
}

int TraceMgr::init(const Options::args &args)
{
    auto p = static_cast<trace_mgr_priv_t *>(priv);
    p->filter_pcap = args.filter_pcap;

    /* pass cfg */
    p->skel->rodata->cfg.output_skb = args.output_skb;
    p->skel->rodata->cfg.output_stack = args.output_stack;
    libbpf::skbtracer_bpf__load(p->skel);

    for (const auto &prog : p->prog_mapping_list) {
        libbpf::bpf_program__set_autoattach(prog.second, false);
    }

    int err = libbpf::skbtracer_bpf__attach(p->skel);
    if (err) {
        spdlog::error("Failed to attach BPF skeleton");
        return err;
    }

    return 0;
}

int TraceMgr::attach_skb_func(const std::string &skb_func, int skb_param_pos)
{
    auto p = static_cast<trace_mgr_priv_t *>(priv);
    auto iter = p->prog_mapping_list.find(skb_param_pos);
    if (iter == p->prog_mapping_list.end()) {
        return -EINVAL;
    }

    auto link = libbpf::bpf_program__attach_kprobe(iter->second, false, skb_func.c_str());
    auto err = libbpf::libbpf_get_error(link);
    if (err) {
        return err;
    }
    p->link_mapping_list.emplace(skb_func, link);
    return 0;
}

int TraceMgr::detach_skb_func(const std::string &skb_func)
{
    auto p = static_cast<trace_mgr_priv_t *>(priv);
    auto iter = p->link_mapping_list.find(skb_func);
    if (iter == p->link_mapping_list.end()) {
        return -EINVAL;
    }

    auto err = libbpf::bpf_link__detach(iter->second);
    if (err) {
        return err;
    }
    p->link_mapping_list.erase(iter);
    return 0;
}

int TraceMgr::register_output_callback(TraceMgr::output_callback_t cb, void *ctx)
{
    auto p = static_cast<trace_mgr_priv_t *>(priv);
    p->output_cb = cb;
    p->ctx = ctx;
    return 0;
}

int TraceMgr::run()
{
    auto p = static_cast<trace_mgr_priv_t *>(priv);
    int map_fd = bpf_map__fd(p->skel->maps.events);
    if (map_fd < 0) {
        spdlog::error("Failed to get events map fd");
        return -EFAULT;
    }

    while (1) {
        struct pollfd fd = {
            .fd = map_fd,
            .events = POLLIN,
        };
        int ret = poll(&fd, 1, -1);
        if (ret < 0) {
            spdlog::error("Failed to poll events: %d", errno);
            break;
        }

        skb_event event = {};
        int err = bpf_map__lookup_and_delete_elem(p->skel->maps.events, NULL, 0, &event, sizeof(event), 0);
        if (err) {
            if (errno == ENOENT)
                continue;
            spdlog::error("Failed to lookup elem: %d", errno);
            break;
        }

        if (p->output_cb) {
            p->output_cb(p->ctx, &event, sizeof(event));
        }
    }

    return 0;
}