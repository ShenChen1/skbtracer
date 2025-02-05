#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

#include "pcap2bpf.h"

extern "C" {
int get_insns_for_filter_empty(libbpf::bpf_insn *data, int *len);
}

static void test_empty_filter()
{
    auto [err, insns, len] = pcap2bpf::compile_ebpf_filter("", false);
    assert(err == 0);
    assert(insns != nullptr);
    assert(len == 2);
    // Verify default pass instructions:
    // 1: r0 = 1
    // 2: exit
    assert(insns[0].code == (BPF_ALU64 | BPF_MOV | BPF_K));
    assert(insns[0].dst_reg == libbpf::BPF_REG_0);
    assert(insns[0].imm == 1);
    assert(insns[1].code == (BPF_JMP | BPF_EXIT));
    delete[] insns;
    std::cout << "[PASS] test_empty_filter" << std::endl;
}

static void test_get_insns_for_filter_empty_boundaries()
{
    // Test null len pointer
    assert(get_insns_for_filter_empty(nullptr, nullptr) == -EINVAL);

    // Test query len with null data
    int len = 0;
    assert(get_insns_for_filter_empty(nullptr, &len) == 0);
    assert(len == 2);

    // Test buffer too small
    len = 1;
    libbpf::bpf_insn small_buf[1];
    assert(get_insns_for_filter_empty(small_buf, &len) == -EINVAL);

    // Test normal fill
    len = 2;
    libbpf::bpf_insn valid_buf[2];
    assert(get_insns_for_filter_empty(valid_buf, &len) == 0);
    assert(len == 2);
    std::cout << "[PASS] test_get_insns_for_filter_empty_boundaries" << std::endl;
}

static void test_valid_filters()
{
    const std::vector<std::string> valid_cases = {
        "icmp",        "tcp and port 80", "udp and src port 53",         "host 192.168.1.1",     "ip proto 6 and dst port 443", "ip6", "icmp6",
        "tcp and ip6", "udp and ip6",     "ip6 proto 6 and dst port 80", "ip6 host 2001:db8::1",
    };

    for (const auto &filter : valid_cases) {
        auto [err, insns, len] = pcap2bpf::compile_ebpf_filter(filter, false);
        assert(err == 0);
        assert(insns != nullptr);
        assert(len > 0);
        delete[] insns;
        std::cout << "[PASS] test_valid_filter: " << filter << " (len=" << len << ")" << std::endl;
    }
}

static void test_l3_filter()
{
    const std::vector<std::string> l3_cases = {
        "ip and tcp port 80", "ip6", "icmp6", "tcp and ip6", "ip6 proto 6 and dst port 80",
    };

    for (const auto &filter : l3_cases) {
        auto [err, insns, len] = pcap2bpf::compile_ebpf_filter(filter, true);
        assert(err == 0);
        assert(insns != nullptr);
        assert(len > 0);
        delete[] insns;
        std::cout << "[PASS] test_l3_filter: " << filter << " (len=" << len << ")" << std::endl;
    }
}

static void test_invalid_filter_syntax()
{
    auto [err, insns, len] = pcap2bpf::compile_ebpf_filter("invalid syntax &&& @@@", false);
    assert(err != 0);
    assert(insns == nullptr);
    assert(len == 0);
    std::cout << "[PASS] test_invalid_filter_syntax (expected error=" << err << ")" << std::endl;
}

static uint64_t get_src_val(const uint64_t *regs, const libbpf::bpf_insn &insn, bool is64)
{
    if (BPF_SRC(insn.code) == BPF_X) {
        return is64 ? regs[insn.src_reg] : (uint32_t)regs[insn.src_reg];
    }
    return is64 ? (uint64_t)(int64_t)insn.imm : (uint32_t)insn.imm;
}

static void exec_alu(uint64_t *regs, const libbpf::bpf_insn &insn)
{
    bool is64 = (BPF_CLASS(insn.code) == BPF_ALU64);
    uint64_t src = get_src_val(regs, insn, is64);
    uint64_t dst = is64 ? regs[insn.dst_reg] : (uint32_t)regs[insn.dst_reg];
    uint64_t res = 0;

    switch (BPF_OP(insn.code)) {
    case BPF_MOV: res = src; break;
    case BPF_ADD: res = dst + src; break;
    case BPF_SUB: res = dst - src; break;
    case BPF_AND: res = dst & src; break;
    case BPF_OR:  res = dst | src; break;
    case BPF_XOR: res = dst ^ src; break;
    case BPF_LSH: res = dst << (src & (is64 ? 63 : 31)); break;
    case BPF_RSH: res = dst >> (src & (is64 ? 63 : 31)); break;
    case BPF_END:
        if (insn.imm == 16) {
            res = __builtin_bswap16((uint16_t)dst);
        } else if (insn.imm == 32) {
            res = __builtin_bswap32((uint32_t)dst);
        }
        break;
    default: break;
    }
    regs[insn.dst_reg] = is64 ? res : (uint32_t)res;
}

static bool eval_jmp_cond(uint64_t dst, uint64_t src, uint8_t op)
{
    switch (op) {
    case BPF_JA:   return true;
    case BPF_JEQ:  return dst == src;
    case BPF_JNE:  return dst != src;
    case BPF_JGT:  return dst > src;
    case BPF_JGE:  return dst >= src;
    case BPF_JLT:  return dst < src;
    case BPF_JLE:  return dst <= src;
    case BPF_JSET: return (dst & src) != 0;
    case BPF_JSLT: return (int64_t)dst < (int64_t)src;
    default: return false;
    }
}

static bool exec_jmp(uint64_t *regs, const libbpf::bpf_insn &insn, size_t &pc, bool &exited)
{
    uint8_t op = BPF_OP(insn.code);
    if (op == BPF_EXIT) {
        exited = true;
        return true;
    }
    if (op == BPF_CALL) {
        if (insn.imm == (libbpf::BPF_FUNC_probe_read_kernel - libbpf::BPF_FUNC_unspec)) {
            std::memcpy(reinterpret_cast<void *>(regs[libbpf::BPF_REG_1]),
                        reinterpret_cast<const void *>(regs[libbpf::BPF_REG_3]),
                        regs[libbpf::BPF_REG_2]);
            regs[libbpf::BPF_REG_0] = 0;
        }
        return true;
    }

    bool is32 = (BPF_CLASS(insn.code) == BPF_JMP32);
    uint64_t dst = is32 ? (uint32_t)regs[insn.dst_reg] : regs[insn.dst_reg];
    uint64_t src = (BPF_SRC(insn.code) == BPF_X) ?
                   (is32 ? (uint32_t)regs[insn.src_reg] : regs[insn.src_reg]) :
                   (is32 ? (uint32_t)insn.imm : (uint64_t)(int64_t)insn.imm);

    if (eval_jmp_cond(dst, src, op)) {
        pc += (int16_t)insn.off;
    }
    return true;
}

static uint64_t run_bpf_prog(const libbpf::bpf_insn *insns, size_t count, void *data, void *data_end)
{
    uint64_t regs[11] = {0};
    uint8_t stack[512] = {0};
    regs[libbpf::BPF_REG_1] = 0x1234;
    regs[libbpf::BPF_REG_4] = reinterpret_cast<uint64_t>(data);
    regs[libbpf::BPF_REG_5] = reinterpret_cast<uint64_t>(data_end);
    regs[libbpf::BPF_REG_10] = reinterpret_cast<uint64_t>(&stack[512]);

    size_t pc = 0;
    bool exited = false;
    while (pc < count && !exited) {
        const auto &insn = insns[pc];
        uint8_t cls = BPF_CLASS(insn.code);
        if (cls == BPF_ALU || cls == BPF_ALU64) {
            exec_alu(regs, insn);
        } else if (cls == BPF_JMP || cls == BPF_JMP32) {
            exec_jmp(regs, insn, pc, exited);
        } else if (cls == BPF_LDX && BPF_MODE(insn.code) == BPF_MEM) {
            uint64_t addr = regs[insn.src_reg] + insn.off;
            if (BPF_SIZE(insn.code) == BPF_B) {
                regs[insn.dst_reg] = *reinterpret_cast<const uint8_t *>(addr);
            } else if (BPF_SIZE(insn.code) == BPF_H) {
                regs[insn.dst_reg] = *reinterpret_cast<const uint16_t *>(addr);
            } else if (BPF_SIZE(insn.code) == BPF_W) {
                regs[insn.dst_reg] = *reinterpret_cast<const uint32_t *>(addr);
            } else if (BPF_SIZE(insn.code) == BPF_DW) {
                regs[insn.dst_reg] = *reinterpret_cast<const uint64_t *>(addr);
            }
        } else if (cls == BPF_STX && BPF_MODE(insn.code) == BPF_MEM) {
            uint64_t addr = regs[insn.dst_reg] + insn.off;
            if (BPF_SIZE(insn.code) == BPF_W) {
                *reinterpret_cast<uint32_t *>(addr) = (uint32_t)regs[insn.src_reg];
            } else if (BPF_SIZE(insn.code) == BPF_DW) {
                *reinterpret_cast<uint64_t *>(addr) = regs[insn.src_reg];
            }
        }
        pc++;
    }
    return regs[libbpf::BPF_REG_0];
}

static void test_packet_truncation_boundary()
{
    // Ethernet + IPv4 + TCP packet (dest port 80 = 0x0050)
    uint8_t pkt[54] = {
        // Ethernet: dst(6), src(6), type(0x0800)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        // IPv4: ihl=5(20 bytes), proto=6(TCP), src, dst
        0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
        192, 168, 1, 1, 192, 168, 1, 2,
        // TCP: sport=12345 (0x3039), dport=80 (0x0050), offset=5
        0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    auto [err, insns, len] = pcap2bpf::compile_ebpf_filter("tcp and dst port 80", false);
    assert(err == 0);
    assert(insns != nullptr);
    assert(len > 0);

    // Happy path: Full packet, must match (returns 1)
    uint64_t res_full = run_bpf_prog(insns, len, pkt, pkt + sizeof(pkt));
    assert(res_full == 1);

    // Truncated packet: Only 14 bytes (Ethernet only, TCP header is outside data_end).
    // Must NOT match and must return 0 (drop/mismatch) due to data_end bounds check!
    uint64_t res_truncated = run_bpf_prog(insns, len, pkt, pkt + 14);
    assert(res_truncated == 0);

    // Inverted/corrupted bounds: data_end < data. Must return 0.
    uint64_t res_inverted = run_bpf_prog(insns, len, pkt + 20, pkt + 10);
    assert(res_inverted == 0);

    delete[] insns;
    std::cout << "[PASS] test_packet_truncation_boundary" << std::endl;
}

extern "C" {
int bpf_convert_filter(libbpf::sock_filter *prog, int len,
                       libbpf::bpf_insn *new_prog, int *new_len);
}

static void test_ind_and_overflow_boundaries()
{
    uint8_t buffer[64] = {0};
    buffer[14] = 0x08;
    buffer[15] = 0x00;

    // cBPF prog:
    // 0: X = imm (set dynamically in tests)
    // 1: A = *(data + X + 4) (IND H)
    // 2: if (A == 0x0800) return 1
    // 3: return 0
    libbpf::sock_filter prog[] = {
        { BPF_LDX | BPF_IMM, 0, 0, 10 },
        { BPF_LD | BPF_IND | BPF_H, 0, 0, 4 },
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0x0800 },
        { BPF_RET | BPF_K, 0, 0, 1 },
        { BPF_RET | BPF_K, 0, 0, 0 },
    };

    int ebpf_len = 0;
    int ret = bpf_convert_filter(prog, 5, nullptr, &ebpf_len);
    assert(ret == 0 && ebpf_len > 0);
    auto ebpf = new libbpf::bpf_insn[ebpf_len];
    ret = bpf_convert_filter(prog, 5, ebpf, &ebpf_len);
    assert(ret == 0);

    // Exact boundary test: X=10, imm=4, size=2 -> end_offset = 16.
    // 1. Packet len == 16: exactly reaches end, succeeds and matches 0x0800 (ret 1)
    uint64_t res = run_bpf_prog(ebpf, ebpf_len, buffer, buffer + 16);
    assert(res == 1);

    // 2. Packet len == 15: one byte short (truncated), must drop (ret 0)
    res = run_bpf_prog(ebpf, ebpf_len, buffer, buffer + 15);
    assert(res == 0);
    delete[] ebpf;

    // 3. Overflow test: X = 0xFFFFFFFC, imm = 8 -> X + imm overflows u32 (wraps to 4)
    prog[0].k = 0xFFFFFFFC;
    ret = bpf_convert_filter(prog, 5, nullptr, &ebpf_len);
    assert(ret == 0);
    ebpf = new libbpf::bpf_insn[ebpf_len];
    ret = bpf_convert_filter(prog, 5, ebpf, &ebpf_len);
    assert(ret == 0);
    res = run_bpf_prog(ebpf, ebpf_len, buffer, buffer + 64);
    assert(res == 0); // must fail due to addition overflow
    delete[] ebpf;

    // 4. Negative offset test: imm = -4 (or 0xFFFFFFFC)
    libbpf::sock_filter neg_prog[] = {
        { BPF_LD | BPF_ABS | BPF_W, 0, 0, static_cast<uint32_t>(-4) },
        { BPF_RET | BPF_K, 0, 0, 1 },
    };
    ret = bpf_convert_filter(neg_prog, 2, nullptr, &ebpf_len);
    assert(ret == 0);
    ebpf = new libbpf::bpf_insn[ebpf_len];
    ret = bpf_convert_filter(neg_prog, 2, ebpf, &ebpf_len);
    assert(ret == 0);
    res = run_bpf_prog(ebpf, ebpf_len, buffer, buffer + 64);
    assert(res == 0); // must fail due to negative/overflow offset
    delete[] ebpf;

    std::cout << "[PASS] test_ind_and_overflow_boundaries" << std::endl;
}

int main()
{
    std::cout << "Running pcap2bpf unit tests..." << std::endl;
    test_empty_filter();
    test_get_insns_for_filter_empty_boundaries();
    test_valid_filters();
    test_l3_filter();
    test_invalid_filter_syntax();
    test_packet_truncation_boundary();
    test_ind_and_overflow_boundaries();
    std::cout << "All pcap2bpf unit tests passed successfully!" << std::endl;
    return 0;
}
