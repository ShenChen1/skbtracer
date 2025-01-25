#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#undef __LINUX_FILTER_H
#include "filter.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define BPF_REG_ARG1    BPF_REG_1
#define BPF_REG_ARG2    BPF_REG_2
#define BPF_REG_ARG3    BPF_REG_3
#define BPF_REG_ARG4    BPF_REG_4
#define BPF_REG_ARG5    BPF_REG_5
#define BPF_REG_CTX     BPF_REG_6
#define BPF_REG_FP      BPF_REG_10

#define BPF_REG_A       BPF_REG_0
#define BPF_REG_X       BPF_REG_7
#define BPF_REG_TMP     BPF_REG_2

#define BPF_ALU32_REG(OP, DST, SRC)                             \
    ((struct bpf_insn) {                                        \
        .code  = BPF_ALU | BPF_OP(OP) | BPF_X,                  \
        .dst_reg = DST,                                         \
        .src_reg = SRC,                                         \
        .off   = 0,                                             \
        .imm   = 0 })

#define BPF_ALU64_REG(OP, DST, SRC)                             \
    ((struct bpf_insn) {                                        \
        .code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,                \
        .dst_reg = DST,                                         \
        .src_reg = SRC,                                         \
        .off   = 0,                                             \
        .imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)                                 \
    ((struct bpf_insn) {                                        \
        .code  = BPF_ALU | BPF_MOV | BPF_X,                     \
        .dst_reg = DST,                                         \
        .src_reg = SRC,                                         \
        .off   = 0,                                             \
        .imm   = 0 })

#define BPF_MOV32_RAW(TYPE, DST, SRC, IMM)                      \
    ((struct bpf_insn) {                                        \
        .code  = BPF_ALU | BPF_MOV | BPF_SRC(TYPE),             \
        .dst_reg = DST,                                         \
        .src_reg = SRC,                                         \
        .off   = 0,                                             \
        .imm   = IMM })

#define BPF_ENDIAN(TYPE, DST, LEN)                              \
    ((struct bpf_insn) {                                        \
        .code  = BPF_ALU | BPF_END | BPF_SRC(TYPE),             \
        .dst_reg = DST,                                         \
        .src_reg = 0,                                           \
        .off   = 0,                                             \
        .imm   = LEN })

int get_insns_for_filter_empty(struct bpf_insn *data, int *len)
{
    const struct bpf_insn insns[] = {
        BPF_MOV64_IMM(BPF_REG_0, 1),
        BPF_EXIT_INSN(),
    };

    if (!len) {
        return -EINVAL;
    }

    if (!data) {
        *len = (int)ARRAY_SIZE(insns);
        return 0;
    }

    if (*len < (int)ARRAY_SIZE(insns)) {
        return -EINVAL;
    }

    *len = (int)ARRAY_SIZE(insns);
    memcpy(data, insns, sizeof(insns));
    return 0;
}

static void emit_epilogue_fail(struct bpf_insn **insn)
{
    *(*insn)++ = BPF_MOV64_IMM(BPF_REG_0, 0);
    *(*insn)++ = BPF_EXIT_INSN();
}

static void emit_packet_load(struct bpf_insn **insn, uint8_t code, int32_t imm)
{
    int size = (BPF_SIZE(code) == BPF_B) ? 1 : ((BPF_SIZE(code) == BPF_H) ? 2 : 4);

    // R1 = FP - 56 (read buffer)
    *(*insn)++ = BPF_MOV64_REG(BPF_REG_1, BPF_REG_FP);
    *(*insn)++ = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -56);

    // R2 = size
    *(*insn)++ = BPF_MOV64_IMM(BPF_REG_2, size);

    // R3 = *(FP - 40) (packet data pointer)
    *(*insn)++ = BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_FP, -40);
    if (BPF_MODE(code) == BPF_IND) {
        *(*insn)++ = BPF_ALU64_REG(BPF_ADD, BPF_REG_3, BPF_REG_X);
    }
    *(*insn)++ = BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, imm);

    // call bpf_probe_read_kernel
    *(*insn)++ = BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel);

    // If read succeeded (R0 == 0), skip failure epilogue (2 instructions)
    *(*insn)++ = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2);

    // Failure: return 0
    emit_epilogue_fail(insn);

    // Load value into accumulator A (R0)
    *(*insn)++ = BPF_LDX_MEM(BPF_SIZE(code), BPF_REG_A, BPF_REG_FP, -56);

    // Convert network byte order to host byte order
    if (BPF_SIZE(code) == BPF_H) {
        *(*insn)++ = BPF_ENDIAN(BPF_FROM_BE, BPF_REG_A, 16);
    } else if (BPF_SIZE(code) == BPF_W) {
        *(*insn)++ = BPF_ENDIAN(BPF_FROM_BE, BPF_REG_A, 32);
    }
}

int bpf_convert_filter(struct sock_filter *prog, int len,
                       struct bpf_insn *new_prog, int *new_len)
{
    int new_flen = 0, pass = 0, target, i, stack_off;
    struct bpf_insn *new_insn, *first_insn = NULL;
    struct sock_filter *fp;
    int *addrs = NULL;
    uint8_t bpf_src;

    if (len <= 0 || len > BPF_MAXINSNS) {
        return -EINVAL;
    }

    if (new_prog) {
        first_insn = new_prog;
        addrs = calloc(len, sizeof(*addrs));
        if (!addrs) {
            return -ENOMEM;
        }
    }

do_pass:
    new_insn = first_insn;
    fp = prog;

    if (new_prog) {
        // Save data (R4) and data_end (R5)
        *new_insn++ = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_4, -40);
        *new_insn++ = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_5, -48);
        // CTX = skb (R1)
        *new_insn++ = BPF_MOV64_REG(BPF_REG_CTX, BPF_REG_ARG1);
        // Reset A and X using MOV to avoid R0 !read_ok verifier error
        *new_insn++ = BPF_MOV64_IMM(BPF_REG_A, 0);
        *new_insn++ = BPF_MOV64_IMM(BPF_REG_X, 0);
    } else {
        new_insn += 5;
    }

    for (i = 0; i < len; fp++, i++) {
        struct bpf_insn tmp_insns[64] = { };
        struct bpf_insn *insn = tmp_insns;

        if (addrs) {
            addrs[i] = new_insn - first_insn;
        }

        switch (fp->code) {
        case BPF_ALU | BPF_ADD | BPF_X:
        case BPF_ALU | BPF_ADD | BPF_K:
        case BPF_ALU | BPF_SUB | BPF_X:
        case BPF_ALU | BPF_SUB | BPF_K:
        case BPF_ALU | BPF_AND | BPF_X:
        case BPF_ALU | BPF_AND | BPF_K:
        case BPF_ALU | BPF_OR | BPF_X:
        case BPF_ALU | BPF_OR | BPF_K:
        case BPF_ALU | BPF_LSH | BPF_X:
        case BPF_ALU | BPF_LSH | BPF_K:
        case BPF_ALU | BPF_RSH | BPF_X:
        case BPF_ALU | BPF_RSH | BPF_K:
        case BPF_ALU | BPF_XOR | BPF_X:
        case BPF_ALU | BPF_XOR | BPF_K:
        case BPF_ALU | BPF_MUL | BPF_X:
        case BPF_ALU | BPF_MUL | BPF_K:
        case BPF_ALU | BPF_DIV | BPF_X:
        case BPF_ALU | BPF_DIV | BPF_K:
        case BPF_ALU | BPF_MOD | BPF_X:
        case BPF_ALU | BPF_MOD | BPF_K:
        case BPF_ALU | BPF_NEG:
            if (fp->code == (BPF_ALU | BPF_DIV | BPF_X) ||
                fp->code == (BPF_ALU | BPF_MOD | BPF_X)) {
                *insn++ = BPF_MOV32_REG(BPF_REG_X, BPF_REG_X);
                *insn++ = BPF_JMP_IMM(BPF_JNE, BPF_REG_X, 0, 2);
                emit_epilogue_fail(&insn);
            }
            *insn = BPF_RAW_INSN(fp->code, BPF_REG_A, (BPF_SRC(fp->code) == BPF_X) ? BPF_REG_X : 0, 0, fp->k);
            break;

        case BPF_LD | BPF_ABS | BPF_W:
        case BPF_LD | BPF_ABS | BPF_H:
        case BPF_LD | BPF_ABS | BPF_B:
        case BPF_LD | BPF_IND | BPF_W:
        case BPF_LD | BPF_IND | BPF_H:
        case BPF_LD | BPF_IND | BPF_B:
            emit_packet_load(&insn, fp->code, fp->k);
            insn--;
            break;

#define BPF_EMIT_JMP                                                    \
    do {                                                                \
        const int32_t off_min = SHRT_MIN, off_max = SHRT_MAX;           \
        int32_t off;                                                    \
        if (target >= len || target < 0)                                \
            goto err;                                                   \
        off = addrs ? addrs[target] - addrs[i] - 1 : 0;                 \
        off -= insn - tmp_insns;                                        \
        if (off < off_min || off > off_max)                             \
            goto err;                                                   \
        insn->off = off;                                                \
    } while (0)

        case BPF_JMP | BPF_JA:
            target = i + fp->k + 1;
            insn->code = fp->code;
            BPF_EMIT_JMP;
            break;

        case BPF_JMP | BPF_JEQ | BPF_K:
        case BPF_JMP | BPF_JEQ | BPF_X:
        case BPF_JMP | BPF_JSET | BPF_K:
        case BPF_JMP | BPF_JSET | BPF_X:
        case BPF_JMP | BPF_JGT | BPF_K:
        case BPF_JMP | BPF_JGT | BPF_X:
        case BPF_JMP | BPF_JGE | BPF_K:
        case BPF_JMP | BPF_JGE | BPF_X:
            if (BPF_SRC(fp->code) == BPF_K && (int)fp->k < 0) {
                *insn++ = BPF_MOV32_IMM(BPF_REG_TMP, fp->k);
                insn->dst_reg = BPF_REG_A;
                insn->src_reg = BPF_REG_TMP;
                bpf_src = BPF_X;
            } else {
                insn->dst_reg = BPF_REG_A;
                insn->imm = fp->k;
                bpf_src = BPF_SRC(fp->code);
                insn->src_reg = (bpf_src == BPF_X) ? BPF_REG_X : 0;
            }

            if (fp->jf == 0) {
                insn->code = BPF_JMP | BPF_OP(fp->code) | bpf_src;
                target = i + fp->jt + 1;
                BPF_EMIT_JMP;
                break;
            }

            if (fp->jt == 0) {
                switch (BPF_OP(fp->code)) {
                case BPF_JEQ:
                    insn->code = BPF_JMP | BPF_JNE | bpf_src;
                    break;
                case BPF_JGT:
                    insn->code = BPF_JMP | BPF_JLE | bpf_src;
                    break;
                case BPF_JGE:
                    insn->code = BPF_JMP | BPF_JLT | bpf_src;
                    break;
                default:
                    goto jmp_rest;
                }
                target = i + fp->jf + 1;
                BPF_EMIT_JMP;
                break;
            }
jmp_rest:
            target = i + fp->jt + 1;
            insn->code = BPF_JMP | BPF_OP(fp->code) | bpf_src;
            BPF_EMIT_JMP;
            insn++;

            insn->code = BPF_JMP | BPF_JA;
            target = i + fp->jf + 1;
            BPF_EMIT_JMP;
            break;

        case BPF_LDX | BPF_MSH | BPF_B: {
            *insn++ = BPF_MOV64_REG(BPF_REG_X, BPF_REG_A);
            emit_packet_load(&insn, BPF_LD | BPF_ABS | BPF_B, fp->k);
            *insn++ = BPF_ALU32_IMM(BPF_AND, BPF_REG_A, 0xf);
            *insn++ = BPF_ALU32_IMM(BPF_LSH, BPF_REG_A, 2);
            *insn++ = BPF_MOV64_REG(BPF_REG_TMP, BPF_REG_X);
            *insn++ = BPF_MOV64_REG(BPF_REG_X, BPF_REG_A);
            *insn = BPF_MOV64_REG(BPF_REG_A, BPF_REG_TMP);
            break;
        }

        case BPF_RET | BPF_A:
        case BPF_RET | BPF_K:
            if (BPF_RVAL(fp->code) == BPF_K) {
                *insn++ = BPF_MOV32_IMM(BPF_REG_0, fp->k ? 1 : 0);
            } else {
                *insn++ = BPF_JMP_IMM(BPF_JEQ, BPF_REG_A, 0, 2);
                *insn++ = BPF_MOV32_IMM(BPF_REG_0, 1);
                *insn++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
                *insn++ = BPF_MOV32_IMM(BPF_REG_0, 0);
            }
            *insn = BPF_EXIT_INSN();
            break;

        case BPF_ST:
        case BPF_STX:
            stack_off = fp->k * 4 + 64; // past saved frame
            *insn = BPF_STX_MEM(BPF_W, BPF_REG_FP,
                                (BPF_CLASS(fp->code) == BPF_ST) ? BPF_REG_A : BPF_REG_X,
                                -stack_off);
            break;

        case BPF_LD | BPF_MEM:
        case BPF_LDX | BPF_MEM:
            stack_off = fp->k * 4 + 64;
            *insn = BPF_LDX_MEM(BPF_W,
                                (BPF_CLASS(fp->code) == BPF_LD) ? BPF_REG_A : BPF_REG_X,
                                BPF_REG_FP,
                                -stack_off);
            break;

        case BPF_LD | BPF_IMM:
        case BPF_LDX | BPF_IMM:
            *insn = BPF_MOV32_IMM((BPF_CLASS(fp->code) == BPF_LD) ? BPF_REG_A : BPF_REG_X, fp->k);
            break;

        case BPF_MISC | BPF_TAX:
            *insn = BPF_MOV64_REG(BPF_REG_X, BPF_REG_A);
            break;

        case BPF_MISC | BPF_TXA:
            *insn = BPF_MOV64_REG(BPF_REG_A, BPF_REG_X);
            break;

        default:
            goto err;
        }

        insn++;
        if (new_prog) {
            memcpy(new_insn, tmp_insns, sizeof(*insn) * (insn - tmp_insns));
        }
        new_insn += insn - tmp_insns;
    }

    if (!new_prog) {
        *new_len = new_insn - first_insn;
        return 0;
    }

    pass++;
    if (new_flen != new_insn - first_insn) {
        new_flen = new_insn - first_insn;
        if (pass > 2) {
            goto err;
        }
        goto do_pass;
    }

    free(addrs);
    assert(*new_len == new_flen);
    return 0;

err:
    free(addrs);
    return -EINVAL;
}