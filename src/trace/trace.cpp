#include "trace.h"
#include <map>
#include <regex>
#include <spdlog/spdlog.h>

namespace libbpf {
extern "C" {
#include "skbtracer.skel.h"
}
} /* namespace libbpf */

typedef struct {
    std::map<int, libbpf::bpf_program *> prog_mapping_list;
    std::map<std::string, libbpf::bpf_link *> link_mapping_list;
    libbpf::skbtracer_bpf *skel;
} trace_mgr_priv_t;

TraceMgr::TraceMgr()
{
    auto libbpf_print_fn = [](libbpf::libbpf_print_level level, const char *format, va_list args) { return vfprintf(stderr, format, args); };

    libbpf::libbpf_set_print(libbpf_print_fn);
    libbpf::libbpf_set_strict_mode(libbpf::LIBBPF_STRICT_ALL);

    auto skel = libbpf::skbtracer_bpf__open_and_load();
    if (libbpf::libbpf_get_error(skel)) {
        spdlog::error("Failed to open and load BPF skeleton");
        return;
    }

    auto p = new trace_mgr_priv_t();
    p->prog_mapping_list.emplace(0, skel->progs.kprobe_skb_1);
    p->prog_mapping_list.emplace(1, skel->progs.kprobe_skb_2);
    p->prog_mapping_list.emplace(2, skel->progs.kprobe_skb_3);
    p->prog_mapping_list.emplace(3, skel->progs.kprobe_skb_4);
    p->prog_mapping_list.emplace(4, skel->progs.kprobe_skb_5);
    p->skel = skel;
    priv = static_cast<void *>(p);
}

TraceMgr::~TraceMgr()
{
    auto p = static_cast<trace_mgr_priv_t *>(priv);
    if (p->skel) {
        libbpf::skbtracer_bpf__destroy(p->skel);
    }
    delete p;
}

int TraceMgr::init()
{
    auto p = static_cast<trace_mgr_priv_t *>(priv);
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