// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"
#include "skbtracer.skel.h"
#include "symdb.h"
#include "tracer.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void read_trace_pipe(void)
{
    int trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
    if (trace_fd < 0)
        return;

    while (1) {
        static char buf[4096];
        ssize_t sz;

        sz = read(trace_fd, buf, sizeof(buf) - 1);
        if (sz > 0) {
            printf("%.*s", (int)sz, buf);
        }
    }
}

int main(int argc, char **argv)
{
    int err;
    const symdb_mgr_t *symdb = createSymdbMgr();
    log_info("symdb:%p", symdb);

    const tracer_t *tracer = createTracer();
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

    /* Let libbpf perform auto-attach for uprobe/uretprobe
     * NOTICE: we provide path and symbol stacks in SEC for BPF programs
     */
    struct bpf_program *prog = skel->progs.kprobe_skb_1;
    bpf_program__attach_kprobe(prog, false, "kfree_skb_reason");

    read_trace_pipe();

cleanup:
    if (skel)
        skbtracer_bpf__destroy(skel);
    return -err;
}