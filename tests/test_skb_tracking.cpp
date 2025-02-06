#include <cassert>
#include <cstdint>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include "skbtracer.h"

extern "C" {
namespace libbpf {
#include "skbtracer.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
} // namespace libbpf
}

/**
 * Regression simulation of the old vs fexit-based clone tracking logic.
 */
class FexitSkbTrackingSimulator {
  public:
    std::set<uint64_t> tracked_skbs;
    bool track_skb_enabled = true;

    void add_tracked_skb(uint64_t skb)
    {
        tracked_skbs.insert(skb);
    }

    bool is_skb_tracked(uint64_t skb) const
    {
        return tracked_skbs.find(skb) != tracked_skbs.end();
    }

    // --- Old buggy logic ---
    // In old code, kretprobe directly read PT_REGS_PARM1, which is clobbered upon function exit.
    bool old_track_skb_clone_exit(uint64_t clobbered_parm1, uint64_t ret_new_skb)
    {
        if (!clobbered_parm1 || !ret_new_skb) {
            return false;
        }
        if (is_skb_tracked(clobbered_parm1)) {
            tracked_skbs.insert(ret_new_skb);
            return true;
        }
        return false;
    }

    // --- New fexit logic (pwru-style) ---
    // In fexit probe, both original input `old` and return value `new` are directly available.
    bool fexit_track_skb_clone(uint64_t old_skb, uint64_t new_skb)
    {
        if (!track_skb_enabled || old_skb == 0 || new_skb == 0) {
            return false;
        }
        if (is_skb_tracked(old_skb)) {
            tracked_skbs.insert(new_skb);
            return true;
        }
        return false;
    }
};

static void test_old_bug_reproduction()
{
    FexitSkbTrackingSimulator sim;
    const uint64_t old_skb = 0xdeadbeef1000ULL;
    const uint64_t new_skb = 0xdeadbeef2000ULL;
    sim.add_tracked_skb(old_skb);

    // In a real function return, PARM1 is clobbered with garbage or RAX (e.g. 0x0 or return value)
    uint64_t clobbered_reg = 0x12345678; // Clobbered register value
    bool success = sim.old_track_skb_clone_exit(clobbered_reg, new_skb);

    // Old logic FAILS to track the cloned skb
    assert(!success);
    assert(!sim.is_skb_tracked(new_skb));
    std::cout << "[PASS] test_old_bug_reproduction (verified failure with clobbered register)" << std::endl;
}

static void test_fexit_tracking_happy_path()
{
    FexitSkbTrackingSimulator sim;
    const uint64_t old_skb = 0xffff888100100000ULL;
    const uint64_t new_skb = 0xffff888100200000ULL;
    sim.add_tracked_skb(old_skb);

    // fexit hook invocation with original old_skb and return new_skb
    bool ok = sim.fexit_track_skb_clone(old_skb, new_skb);
    assert(ok);
    assert(sim.is_skb_tracked(new_skb));

    // Subsequent clone of the new skb
    const uint64_t third_skb = 0xffff888100300000ULL;
    ok = sim.fexit_track_skb_clone(new_skb, third_skb);
    assert(ok);
    assert(sim.is_skb_tracked(third_skb));

    std::cout << "[PASS] test_fexit_tracking_happy_path" << std::endl;
}

static void test_fexit_tracking_untracked_skb()
{
    FexitSkbTrackingSimulator sim;
    const uint64_t untracked_skb = 0xffff888100999000ULL;
    const uint64_t new_skb = 0xffff888100888000ULL;

    // fexit with untracked skb should NOT track new_skb
    bool ok = sim.fexit_track_skb_clone(untracked_skb, new_skb);
    assert(!ok);
    assert(!sim.is_skb_tracked(new_skb));

    std::cout << "[PASS] test_fexit_tracking_untracked_skb" << std::endl;
}

static void test_fexit_tracking_null_allocation()
{
    FexitSkbTrackingSimulator sim;
    const uint64_t old_skb = 0xffff888100111000ULL;
    sim.add_tracked_skb(old_skb);

    // Allocation failure returns NULL (0)
    bool ok = sim.fexit_track_skb_clone(old_skb, 0);
    assert(!ok);
    assert(!sim.is_skb_tracked(0));

    std::cout << "[PASS] test_fexit_tracking_null_allocation" << std::endl;
}

static void test_fexit_tracking_disabled()
{
    FexitSkbTrackingSimulator sim;
    sim.track_skb_enabled = false;
    const uint64_t old_skb = 0xffff888100111000ULL;
    const uint64_t new_skb = 0xffff888100222000ULL;
    sim.add_tracked_skb(old_skb);

    bool ok = sim.fexit_track_skb_clone(old_skb, new_skb);
    assert(!ok);
    assert(!sim.is_skb_tracked(new_skb));

    std::cout << "[PASS] test_fexit_tracking_disabled" << std::endl;
}

static void test_bpf_skeleton_fexit_progs()
{
    auto skel = libbpf::skbtracer_bpf__open();
    assert(skel != nullptr);

    // 1. Verify clone_entries map is removed (zero-map fexit design)
    auto clone_map = libbpf::bpf_object__find_map_by_name(skel->obj, "clone_entries");
    assert(clone_map == nullptr);

    // 2. Verify trace_skb_clone_exit is fexit
    auto prog_clone_exit = libbpf::bpf_object__find_program_by_name(skel->obj, "trace_skb_clone_exit");
    assert(prog_clone_exit != nullptr);
    assert(std::string(libbpf::bpf_program__section_name(prog_clone_exit)) == "fexit/skb_clone");

    // 3. Verify trace_skb_copy_exit is fexit
    auto prog_copy_exit = libbpf::bpf_object__find_program_by_name(skel->obj, "trace_skb_copy_exit");
    assert(prog_copy_exit != nullptr);
    assert(std::string(libbpf::bpf_program__section_name(prog_copy_exit)) == "fexit/skb_copy");

    // 4. Verify no entry probes remain
    assert(libbpf::bpf_object__find_program_by_name(skel->obj, "trace_skb_clone_entry") == nullptr);
    assert(libbpf::bpf_object__find_program_by_name(skel->obj, "trace_skb_copy_entry") == nullptr);

    libbpf::skbtracer_bpf__destroy(skel);
    std::cout << "[PASS] test_bpf_skeleton_fexit_progs" << std::endl;
}

int main()
{
    std::cout << "Running skb tracking fexit unit and regression tests..." << std::endl;
    test_old_bug_reproduction();
    test_fexit_tracking_happy_path();
    test_fexit_tracking_untracked_skb();
    test_fexit_tracking_null_allocation();
    test_fexit_tracking_disabled();
    test_bpf_skeleton_fexit_progs();
    std::cout << "All skb tracking fexit unit and regression tests passed successfully!" << std::endl;
    return 0;
}
