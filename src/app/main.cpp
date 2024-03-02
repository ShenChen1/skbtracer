#include <limits>
#include <map>

#include <getopt.h>
#include <poll.h>
#include <spdlog/spdlog.h>

#include "skbtracer.skel.h"
#include "skbtracer.h"
#include "symdb.h"
#include "trace.h"
#include "utils.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main()
{
    int err;

    /* Set up libbpf errors and debug stacks callback */
    libbpf_set_print(libbpf_print_fn);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    utils::enforce_infinite_rlimit();
    spdlog::set_level(spdlog::level::debug);

    SymdbMgr symdb;
    err = symdb.init();
    if (err) {
        spdlog::error("Failed to initialize SymdbMgr");
        return err;
    }

    TraceMgr trace;
    err = trace.init();
    if (err) {
        spdlog::error("Failed to initialize TraceMgr");
        return err;
    }

    struct skbtracer_bpf *skel = skbtracer_bpf::open_and_load();
    if (!skel) {
        spdlog::error("Failed to open and load BPF skeleton");
        return -EFAULT;
    }

    const std::map<int, struct bpf_program *> prog_mapping_list = {
        { 0, skel->progs.kprobe_skb_1 }, { 1, skel->progs.kprobe_skb_2 }, { 2, skel->progs.kprobe_skb_3 }, { 3, skel->progs.kprobe_skb_4 }, { 4, skel->progs.kprobe_skb_5 },
    };

    for (const auto &prog : prog_mapping_list) {
        bpf_program__set_autoattach(prog.second, false);
    }

    err = skbtracer_bpf::attach(skel);
    if (err) {
        spdlog::error("Failed to attach BPF skeleton");
        return err;
    }

    const auto [ret_get_skb_func_list, skb_func_list] = symdb.get_skb_func_list();
    if (ret_get_skb_func_list) {
        spdlog::error("Failed to get skb function list");
        return ret_get_skb_func_list;
    }

    for (const auto &func : skb_func_list) {
        const auto [ret_get_skb_func_param_pos, skb_param_pos] = symdb.get_skb_func_param_pos(func);
        if (ret_get_skb_func_param_pos) {
            spdlog::warn("Failed to get skb function param pos");
            continue;
        }

        if (prog_mapping_list.find(skb_param_pos) == prog_mapping_list.end()) {
            spdlog::debug("Invalid skb_param_pos on {} : {}", func, skb_param_pos);
            continue;
        }
        bpf_program__attach_kprobe(prog_mapping_list.at(skb_param_pos), false, func.c_str());
    }

    int map_fd = bpf_map__fd(skel->maps.events);
    if (map_fd < 0) {
        spdlog::error("Failed to get events map fd");
        return -EFAULT;
    }

    struct event_t event;
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

        err = bpf_map__lookup_and_delete_elem(skel->maps.events, NULL, 0, &event, sizeof(event), 0);
        if (err) {
            if (errno == ENOENT)
                continue;
            spdlog::error("Failed to lookup elem: %d", errno);
            break;
        }
    }

    return 0;
}