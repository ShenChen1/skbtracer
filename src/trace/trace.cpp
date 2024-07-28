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
    std::map<int, libbpf::bpf_program *> prog_mapping_list;
    std::map<std::string, libbpf::bpf_link *> link_mapping_list;
    libbpf::skbtracer_bpf *skel;
    TraceMgr::output_callback_t output_cb;
    void *ctx;
} trace_mgr_priv_t;

TraceMgr::TraceMgr()
{
    auto libbpf_print_fn = [](
        libbpf::libbpf_print_level level,
        const char *format, va_list args) {
            return vfprintf(stderr, format, args);
        };

    libbpf::libbpf_set_print(libbpf_print_fn);
    libbpf::libbpf_set_strict_mode(libbpf::LIBBPF_STRICT_ALL);

    auto p = new trace_mgr_priv_t();
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

int TraceMgr::init(const Options::args &args)
{
    const std::string object_name = "skbtracer.bpf.o";
    auto p = static_cast<trace_mgr_priv_t *>(priv);

    size_t size = 0;
    const void *data = libbpf::skbtracer_bpf__elf_bytes(&size);
    std::ofstream outfile(object_name, std::ios::binary);
    outfile.write(reinterpret_cast<const char*>(data), size);
    outfile.close();


    if (0) {
        /* modify ebpf code */
        auto [ret_l3, insn_l3, len_l3] = pcap2bpf::compile_ebpf_filter(args.filter_pcap, true);
        pcap2bpf::inject_ebpf_filter(object_name, "filter_pcap_ebpf_l3", insn_l3, len_l3);
        auto [ret_l2, insn_l2, len_l2] = pcap2bpf::compile_ebpf_filter(args.filter_pcap, false);
        pcap2bpf::inject_ebpf_filter(object_name, "filter_pcap_ebpf_l2", insn_l2, len_l2);
    } else {
        libbpf::bpf_insn filter_pcap_ebpf_insns = {};
        filter_pcap_ebpf_insns.code = BPF_ALU64 | BPF_MOV | BPF_X;
        filter_pcap_ebpf_insns.dst_reg = libbpf::BPF_REG_4;
        filter_pcap_ebpf_insns.src_reg = libbpf::BPF_REG_5;
        filter_pcap_ebpf_insns.off = 0;
        filter_pcap_ebpf_insns.imm = 0;
        pcap2bpf::inject_ebpf_filter(object_name, "filter_pcap_ebpf_l3", &filter_pcap_ebpf_insns, 1);
        pcap2bpf::inject_ebpf_filter(object_name, "filter_pcap_ebpf_l2", &filter_pcap_ebpf_insns, 1);
    }

    std::ifstream infile(object_name, std::ios::binary);
    std::vector<char> new_data((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
    infile.close();

    libbpf::skbtracer_bpf *skel = new libbpf::skbtracer_bpf();
    libbpf::skbtracer_bpf__create_skeleton(skel);
    skel->skeleton->data = new_data.data();
    skel->skeleton->data_sz = new_data.size();
    bpf_object__open_skeleton(skel->skeleton, NULL);

    p->prog_mapping_list.emplace(0, skel->progs.kprobe_skb_1);
    p->prog_mapping_list.emplace(1, skel->progs.kprobe_skb_2);
    p->prog_mapping_list.emplace(2, skel->progs.kprobe_skb_3);
    p->prog_mapping_list.emplace(3, skel->progs.kprobe_skb_4);
    p->prog_mapping_list.emplace(4, skel->progs.kprobe_skb_5);
    p->skel = skel;

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