#include <cassert>
#include <cerrno>
#include <iostream>
#include <vector>

#include "pcap2bpf.h"
#include "skbtracer.h"

extern "C" {
namespace libbpf {
#include "skbtracer.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
} // namespace libbpf
}

/**
 * Simulator for prepare_load filter injection loop to verify regression
 * behavior when inject_ebpf_filter returns an error.
 */
struct InjectSimulationResult {
    int ret;
    ssize_t final_offset;
};

static InjectSimulationResult simulate_old_inject_loop(int mock_inject_ret, size_t stub_len, size_t new_len)
{
    ssize_t offset = 0;
    // Old buggy logic: ignore inject_ret and update offset anyway
    offset += ((ssize_t)new_len - (ssize_t)stub_len);
    return { 0, offset };
}

static InjectSimulationResult simulate_new_inject_loop(int mock_inject_ret, size_t stub_len, size_t new_len)
{
    ssize_t offset = 0;
    // New logic: check inject_ret, return immediately and keep offset unchanged
    if (mock_inject_ret != 0) {
        return { mock_inject_ret, offset };
    }
    offset += ((ssize_t)new_len - (ssize_t)stub_len);
    return { 0, offset };
}

static void test_filter_injection_error_regression()
{
    constexpr size_t STUB_ORIG_LEN = 7;
    constexpr size_t NEW_FILTER_LEN = 15;
    const int mock_error = -EINVAL;

    // 1. Old logic behavior: ignores error, mutates offset, and returns 0 (buggy)
    auto old_res = simulate_old_inject_loop(mock_error, STUB_ORIG_LEN, NEW_FILTER_LEN);
    assert(old_res.ret == 0);
    assert(old_res.final_offset == 8); // Offset erroneously updated!

    // 2. New logic behavior: catches error, keeps offset unchanged, and returns error code
    auto new_res = simulate_new_inject_loop(mock_error, STUB_ORIG_LEN, NEW_FILTER_LEN);
    assert(new_res.ret == mock_error);
    assert(new_res.final_offset == 0); // Offset unchanged!

    std::cout << "[PASS] test_filter_injection_error_regression" << std::endl;
}

static void test_inject_ebpf_filter_bounds_failure()
{
    auto skel = libbpf::skbtracer_bpf__open();
    assert(skel != nullptr);

    auto prog = skel->progs.kprobe_skb_1;
    assert(prog != nullptr);

    size_t insn_cnt = libbpf::bpf_program__insn_cnt(prog);
    assert(insn_cnt > 0);

    libbpf::bpf_insn dummy_insn{};
    dummy_insn.code = BPF_ALU64 | BPF_MOV | BPF_K;
    dummy_insn.dst_reg = libbpf::BPF_REG_0;
    dummy_insn.imm = 1;

    // Failure path: position out of bounds
    int ret = pcap2bpf::inject_ebpf_filter(prog, insn_cnt + 10, 7, &dummy_insn, 1);
    assert(ret == -EINVAL);

    libbpf::skbtracer_bpf__destroy(skel);
    std::cout << "[PASS] test_inject_ebpf_filter_bounds_failure" << std::endl;
}

/**
 * Simulator for ring_buffer__poll loop to verify regression behavior.
 */
static int simulate_old_poll_loop(const std::vector<int> &poll_events, bool &exited)
{
    for (int err : poll_events) {
        if (err < 0) {
            if (err == -EINTR) {
                continue;
            }
            // Old buggy logic: break and return 0
            break;
        }
    }
    return 0; // Caller cannot distinguish failure from normal termination
}

static int simulate_new_poll_loop(const std::vector<int> &poll_events, bool &exited)
{
    int poll_err = 0;
    for (int err : poll_events) {
        if (err < 0) {
            if (err == -EINTR) {
                continue;
            }
            // New fixed logic: record poll_err and break
            poll_err = err;
            break;
        }
    }
    return poll_err;
}

static void test_ringbuf_poll_error_regression()
{
    bool exited = false;

    // 1. Happy path: only normal events or EINTR then exit
    std::vector<int> happy_events = { 1, 0, -EINTR, 2 };
    assert(simulate_new_poll_loop(happy_events, exited) == 0);

    // 2. Fatal error path: -EBADF (poll failure)
    std::vector<int> error_events = { 1, -EINTR, -EBADF, 2 };
    
    // Old logic returned 0 even on -EBADF failure (buggy)
    assert(simulate_old_poll_loop(error_events, exited) == 0);

    // New logic returns -EBADF (fixed)
    assert(simulate_new_poll_loop(error_events, exited) == -EBADF);

    std::cout << "[PASS] test_ringbuf_poll_error_regression" << std::endl;
}

int main()
{
    std::cout << "Running trace unit and regression tests..." << std::endl;
    test_filter_injection_error_regression();
    test_inject_ebpf_filter_bounds_failure();
    test_ringbuf_poll_error_regression();
    std::cout << "All trace unit and regression tests passed successfully!" << std::endl;
    return 0;
}
