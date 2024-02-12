// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "skbtracer.h"
#include "skbtracer.skel.h"
#include "symdb.h"
#include "tracer.h"
#include "utils.h"
#include "valuemap.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void handle_events(struct skbtracer_bpf *skel, symdb_mgr_t *symdb)
{
    int err;
    int map_fd = bpf_map__fd(skel->maps.events);
    if (map_fd < 0) {
        log_error("Failed to get events map fd");
        return;
    }

    struct event_t event;
    while (1) {
        // put map_fd into poll, and wait for events
        struct pollfd fds[] = {{
            .fd = map_fd,
            .events = POLLIN,
        }};
        int ret = poll(fds, ARRAY_SIZE(fds), -1);
        if (ret < 0) {
            log_error("Failed to poll events: %d", errno);
            break;
        }

        // read events from map
        err = bpf_map__lookup_and_delete_elem(skel->maps.events, NULL, 0, &event, sizeof(event), 0);
        if (err) {
            if (errno == ENOENT)
                continue;
            log_error("Failed to lookup elem: %d", errno);
            break;
        }

        const char *func = symdb->get_func_by_addr(symdb, event.addr);
        printf("[%8u][%16llx]: %32s(%16llx)\n", event.pid, event.skb_addr, func, event.addr);
    }
}

int main(int argc, char **argv)
{
    int err;
    set_max_rlimit();

    symdb_mgr_t *symdb = createSymdbMgr();
    if (symdb == NULL) {
        log_error("Failed to create symdb mgr");
        return -EINVAL;
    }

    tracer_t *tracer = createTracer();
    log_info("tracer:%p", tracer);

    /* Set up libbpf errors and debug stacks callback */
    libbpf_set_print(libbpf_print_fn);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct skbtracer_bpf *skel = skbtracer_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = skbtracer_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    const char **skb_func_list = NULL;
    size_t skb_func_list_size = 0;
    err = symdb->get_skb_func_list(symdb, &skb_func_list, &skb_func_list_size);
    if (err) {
        log_error("Failed to get skb func list");
        goto cleanup;
    }

    for (size_t i = 0; i < skb_func_list_size; i++) {
        int postion;
        err = symdb->get_skb_func_param_pos(symdb, skb_func_list[i], &postion);
        if (err) {
            log_error("Failed to get skb func param pos: %s", skb_func_list[i]);
            continue;
        }

        struct bpf_program *prog = NULL;
        const VALUEMAP_STRUCT(int, struct bpf_program *) prog_mapping_list[] = {
            {0, skel->progs.kprobe_skb_1},
            {1, skel->progs.kprobe_skb_2},
            {2, skel->progs.kprobe_skb_3},
            {3, skel->progs.kprobe_skb_4},
            {4, skel->progs.kprobe_skb_5},
        };
        if (VALUEMAP_TRY_FIND(prog_mapping_list, postion, &prog)) {
            bpf_program__attach_kprobe(prog, false, skb_func_list[i]);
        }
    }
    bpf_program__attach_kprobe(skel->progs.skb_clone, true, "skb_clone");
    bpf_program__attach_kprobe(skel->progs.skb_copy, true, "skb_copy");
    bpf_program__attach_kprobe(skel->progs.kfree_skbmem, false, "kfree_skbmem");

    handle_events(skel, symdb);

cleanup:
    if (symdb)
        symdb->destroy(symdb);
    if (tracer)
        tracer->destroy(tracer);
    if (skel)
        skbtracer_bpf__destroy(skel);
    return -err;
}