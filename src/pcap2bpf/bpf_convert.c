#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/filter.h>

#include "filter.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

/* ArgX, context and stack frame pointer register positions. Note,
 * Arg1, Arg2, Arg3, etc are used as argument mappings of function
 * calls in BPF_CALL instruction.
 */
#define BPF_REG_ARG1	BPF_REG_1
#define BPF_REG_ARG2	BPF_REG_2
#define BPF_REG_ARG3	BPF_REG_3
#define BPF_REG_ARG4	BPF_REG_4
#define BPF_REG_ARG5	BPF_REG_5
#define BPF_REG_CTX	BPF_REG_6
#define BPF_REG_FP	BPF_REG_10

/* Additional register mappings for converted user programs. */
#define BPF_REG_A	BPF_REG_0
#define BPF_REG_X	BPF_REG_7
#define BPF_REG_TMP	BPF_REG_2	/* scratch reg */
#define BPF_REG_D	BPF_REG_8	/* data, callee-saved */
#define BPF_REG_H	BPF_REG_9	/* hlen, callee-saved */

#define BPF_ALU32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_MOV32_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

static bool convert_bpf_extensions(struct sock_filter *fp,
				   struct bpf_insn **insnp)
{
	switch (fp->k) {
	case SKF_AD_OFF + SKF_AD_PROTOCOL:
	case SKF_AD_OFF + SKF_AD_PKTTYPE:
	case SKF_AD_OFF + SKF_AD_IFINDEX:
	case SKF_AD_OFF + SKF_AD_HATYPE:
	case SKF_AD_OFF + SKF_AD_MARK:
	case SKF_AD_OFF + SKF_AD_RXHASH:
	case SKF_AD_OFF + SKF_AD_QUEUE:
	case SKF_AD_OFF + SKF_AD_VLAN_TAG:
	case SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT:
	case SKF_AD_OFF + SKF_AD_VLAN_TPID:
	case SKF_AD_OFF + SKF_AD_PAY_OFFSET:
	case SKF_AD_OFF + SKF_AD_NLATTR:
	case SKF_AD_OFF + SKF_AD_NLATTR_NEST:
	case SKF_AD_OFF + SKF_AD_CPU:
	case SKF_AD_OFF + SKF_AD_RANDOM:
	case SKF_AD_OFF + SKF_AD_ALU_XOR_X:
		return true;

	default:
		return false;
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

	if (len <= 0 || len > BPF_MAXINSNS)
		return -EINVAL;

	if (new_prog) {
		first_insn = new_prog;
		addrs = calloc(len, sizeof(*addrs));
		if (!addrs)
			return -ENOMEM;
	}

do_pass:
	new_insn = first_insn;
	fp = prog;

	/* Classic BPF related prologue emission. */
	if (new_prog) {
		/* Classic BPF expects A and X to be reset first. These need
		 * to be guaranteed to be the first two instructions.
		 */
		*new_insn++ = BPF_ALU32_REG(BPF_XOR, BPF_REG_A, BPF_REG_A);
		*new_insn++ = BPF_ALU32_REG(BPF_XOR, BPF_REG_X, BPF_REG_X);

		/* All programs must keep CTX in callee saved BPF_REG_CTX.
		 * In eBPF case it's done by the compiler, here we need to
		 * do this ourself. Initial CTX is present in BPF_REG_ARG1.
		 */
		*new_insn++ = BPF_MOV64_REG(BPF_REG_CTX, BPF_REG_ARG1);
	} else {
		new_insn += 3;
	}

	for (i = 0; i < len; fp++, i++) {
		struct bpf_insn tmp_insns[32] = { };
		struct bpf_insn *insn = tmp_insns;

		if (addrs)
			addrs[i] = new_insn - first_insn;

		switch (fp->code) {
		/* All arithmetic insns and skb loads map as-is. */
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
		case BPF_LD | BPF_ABS | BPF_W:
		case BPF_LD | BPF_ABS | BPF_H:
		case BPF_LD | BPF_ABS | BPF_B:
		case BPF_LD | BPF_IND | BPF_W:
		case BPF_LD | BPF_IND | BPF_H:
		case BPF_LD | BPF_IND | BPF_B:
			/* Check for overloaded BPF extension and
			 * directly convert it if found, otherwise
			 * just move on with mapping.
			 */
			if (BPF_CLASS(fp->code) == BPF_LD &&
			    BPF_MODE(fp->code) == BPF_ABS &&
			    convert_bpf_extensions(fp, &insn))
				break;

			if (fp->code == (BPF_ALU | BPF_DIV | BPF_X) ||
			    fp->code == (BPF_ALU | BPF_MOD | BPF_X)) {
				*insn++ = BPF_MOV32_REG(BPF_REG_X, BPF_REG_X);
				/* Error with exception code on div/mod by 0.
				 * For cBPF programs, this was always return 0.
				 */
				*insn++ = BPF_JMP_IMM(BPF_JNE, BPF_REG_X, 0, 2);
				*insn++ = BPF_ALU32_REG(BPF_XOR, BPF_REG_A, BPF_REG_A);
				*insn++ = BPF_EXIT_INSN();
			}

			*insn = BPF_RAW_INSN(fp->code, BPF_REG_A, BPF_REG_X, 0, fp->k);
			break;

		/* Jump transformation cannot use BPF block macros
		 * everywhere as offset calculation and target updates
		 * require a bit more work than the rest, i.e. jump
		 * opcodes map as-is, but offsets need adjustment.
		 */

#define BPF_EMIT_JMP							\
	do {								\
		const int32_t off_min = SHRT_MIN, off_max = SHRT_MAX;	\
		int32_t off;						\
									\
		if (target >= len || target < 0)			\
			goto err;					\
		off = addrs ? addrs[target] - addrs[i] - 1 : 0;		\
		/* Adjust pc relative offset for 2nd or 3rd insn. */	\
		off -= insn - tmp_insns;				\
		/* Reject anything not fitting into insn->off. */	\
		if (off < off_min || off > off_max)			\
			goto err;					\
		insn->off = off;					\
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
			if (BPF_SRC(fp->code) == BPF_K && (int) fp->k < 0) {
				/* BPF immediates are signed, zero extend
				 * immediate into tmp register and use it
				 * in compare insn.
				 */
				*insn++ = BPF_MOV32_IMM(BPF_REG_TMP, fp->k);

				insn->dst_reg = BPF_REG_A;
				insn->src_reg = BPF_REG_TMP;
				bpf_src = BPF_X;
			} else {
				insn->dst_reg = BPF_REG_A;
				insn->imm = fp->k;
				bpf_src = BPF_SRC(fp->code);
				insn->src_reg = bpf_src == BPF_X ? BPF_REG_X : 0;
			}

			/* Common case where 'jump_false' is next insn. */
			if (fp->jf == 0) {
				insn->code = BPF_JMP | BPF_OP(fp->code) | bpf_src;
				target = i + fp->jt + 1;
				BPF_EMIT_JMP;
				break;
			}

			/* Convert some jumps when 'jump_true' is next insn. */
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
			/* Other jumps are mapped into two insns: Jxx and JA. */
			target = i + fp->jt + 1;
			insn->code = BPF_JMP | BPF_OP(fp->code) | bpf_src;
			BPF_EMIT_JMP;
			insn++;

			insn->code = BPF_JMP | BPF_JA;
			target = i + fp->jf + 1;
			BPF_EMIT_JMP;
			break;

		/* ldxb 4 * ([14] & 0xf) is remaped into 6 insns. */
		case BPF_LDX | BPF_MSH | BPF_B: {
			/* X = A */
			*insn++ = BPF_MOV64_REG(BPF_REG_X, BPF_REG_A);
			/* A = BPF_R0 = *(uint8_t *) (skb->data + K) */
			*insn++ = BPF_LD_ABS(BPF_B, fp->k);
			/* A &= 0xf */
			*insn++ = BPF_ALU32_IMM(BPF_AND, BPF_REG_A, 0xf);
			/* A <<= 2 */
			*insn++ = BPF_ALU32_IMM(BPF_LSH, BPF_REG_A, 2);
			/* tmp = X */
			*insn++ = BPF_MOV64_REG(BPF_REG_TMP, BPF_REG_X);
			/* X = A */
			*insn++ = BPF_MOV64_REG(BPF_REG_X, BPF_REG_A);
			/* A = tmp */
			*insn = BPF_MOV64_REG(BPF_REG_A, BPF_REG_TMP);
			break;
		}
		/* RET_K is remaped into 2 insns. RET_A case doesn't need an
		 * extra mov as BPF_REG_0 is already mapped into BPF_REG_A.
		 */
		case BPF_RET | BPF_A:
		case BPF_RET | BPF_K:
			if (BPF_RVAL(fp->code) == BPF_K)
				*insn++ = BPF_MOV32_RAW(BPF_K, BPF_REG_0,
							0, fp->k);
			*insn = BPF_EXIT_INSN();
			break;

		/* Store to stack. */
		case BPF_ST:
		case BPF_STX:
			stack_off = fp->k * 4  + 4;
			*insn = BPF_STX_MEM(BPF_W, BPF_REG_FP, BPF_CLASS(fp->code) ==
					    BPF_ST ? BPF_REG_A : BPF_REG_X,
					    -stack_off);
			break;

		/* Load from stack. */
		case BPF_LD | BPF_MEM:
		case BPF_LDX | BPF_MEM:
			stack_off = fp->k * 4  + 4;
			*insn = BPF_LDX_MEM(BPF_W, BPF_CLASS(fp->code) == BPF_LD  ?
					    BPF_REG_A : BPF_REG_X, BPF_REG_FP,
					    -stack_off);
			break;

		/* A = K or X = K */
		case BPF_LD | BPF_IMM:
		case BPF_LDX | BPF_IMM:
			*insn = BPF_MOV32_IMM(BPF_CLASS(fp->code) == BPF_LD ?
					      BPF_REG_A : BPF_REG_X, fp->k);
			break;

		/* X = A */
		case BPF_MISC | BPF_TAX:
			*insn = BPF_MOV64_REG(BPF_REG_X, BPF_REG_A);
			break;

		/* A = X */
		case BPF_MISC | BPF_TXA:
			*insn = BPF_MOV64_REG(BPF_REG_A, BPF_REG_X);
			break;

		/* Access seccomp_data fields. */
		case BPF_LDX | BPF_ABS | BPF_W:
			/* A = *(uint32_t *) (ctx + K) */
			*insn = BPF_LDX_MEM(BPF_W, BPF_REG_A, BPF_REG_CTX, fp->k);
			break;

		/* Unknown instruction. */
		default:
			goto err;
		}

		insn++;
		if (new_prog)
			memcpy(new_insn, tmp_insns,
			       sizeof(*insn) * (insn - tmp_insns));
		new_insn += insn - tmp_insns;
	}

	if (!new_prog) {
		/* Only calculating new length. */
		*new_len = new_insn - first_insn;
		return 0;
	}

	pass++;
	if (new_flen != new_insn - first_insn) {
		new_flen = new_insn - first_insn;
		if (pass > 2)
			goto err;
		goto do_pass;
	}

	free(addrs);
	assert(*new_len == new_flen);
	return 0;
err:
	free(addrs);
	return -EINVAL;
}

int get_insns_for_filter_empty(struct bpf_insn **data, int *len)
{
	const struct bpf_insn insns[] = {
		BPF_MOV64_REG(BPF_REG_4, BPF_REG_5),
	};

	*len = ARRAY_SIZE(insns);
	*data = malloc(*len * sizeof(struct bpf_insn));
	if (*data == NULL) {
		return -ENOMEM;
	}
	memcpy(*data, insns, *len * sizeof(struct bpf_insn));
	return 0;
}

enum {
	BpfReadKernelOffset	= -8*(0+1) - 80,
	R1Offset 		= -8*(1+1) - 80,
	R2Offset		= -8*(2+1) - 80,
	R3Offset		= -8*(3+1) - 80,
	R4Offset		= -8*(4+1) - 80,
	R5Offset		= -8*(5+1) - 80,
	AvailableOffset 	= -8*(6+1) - 80,
};

int get_insns_for_prepare_replace_insns(struct bpf_insn **data, int *len)
{
	const struct bpf_insn insns[] = {
		// Store R4, R5 on stack.
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_4, R4Offset),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_5, R5Offset),
	};

	*len = ARRAY_SIZE(insns);
	*data = malloc(*len * sizeof(struct bpf_insn));
	if (*data == NULL) {
		return -ENOMEM;
	}
	memcpy(*data, insns, *len * sizeof(struct bpf_insn));
	return 0;
}

int get_insns_for_post_replace_insns(struct bpf_insn **data, int *len)
{
	const struct bpf_insn insns[] = {
		BPF_MOV64_IMM(BPF_REG_1, 0),
		BPF_MOV64_IMM(BPF_REG_2, 0),
		BPF_MOV64_IMM(BPF_REG_3, 0),
		BPF_MOV64_REG(BPF_REG_4, BPF_REG_0),
		BPF_MOV64_IMM(BPF_REG_5, 0),
	};

	*len = ARRAY_SIZE(insns);
	*data = malloc(*len * sizeof(struct bpf_insn));
	if (*data == NULL) {
		return -ENOMEM;
	}
	memcpy(*data, insns, *len * sizeof(struct bpf_insn));
	return 0;
}

int get_insns_for_replace_insns(struct bpf_insn *origin, struct bpf_insn **data, int *len)
{
	int size = 0;
	switch(BPF_SIZE(origin->code)) {
		case BPF_B:
			size = 1;
			break;
		case BPF_H:
			size = 2;
			break;
		case BPF_W:
			size = 4;
			break;
		case BPF_DW:
			size = 8;
			break;
	}

	const struct bpf_insn insns[] = {
		// Store R1, R2, R3 on stack.
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_1, R1Offset),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_2, R2Offset),
		BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_3, R3Offset),

		// bpf_probe_read_kernel(RFP-8, size, inst.Src)
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_FP),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, BpfReadKernelOffset),
		BPF_MOV64_IMM(BPF_REG_2, size),
		BPF_MOV64_REG(BPF_REG_3, origin->src_reg),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, origin->off),
		BPF_EMIT_CALL(BPF_FUNC_probe_read_kernel),

		// inst.Dst = *(RFP-8)
		BPF_LDX_MEM(BPF_SIZE(origin->code), origin->dst_reg, BPF_REG_FP, BpfReadKernelOffset),

		// Restore R4, R5 from stack.
		BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_FP, R4Offset),
		BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_FP, R5Offset),

		// Restore R1, R2, R3 from stack.
		BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_FP, R1Offset),
		BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_FP, R2Offset),
		BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_FP, R3Offset),
	};

	*len = ARRAY_SIZE(insns);
	*data = malloc(*len * sizeof(struct bpf_insn));
	if (*data == NULL) {
		return -ENOMEM;
	}
	memcpy(*data, insns, *len * sizeof(struct bpf_insn));

	if (origin->dst_reg == BPF_REG_1 || origin->dst_reg == BPF_REG_2 || origin->dst_reg == BPF_REG_3) {
		memmove(*data + *len - (4 - origin->dst_reg), insns + *len - (4 - origin->dst_reg) + 1, (3 - origin->dst_reg) * sizeof(struct bpf_insn));
		*len -= 1;
	}

	return 0;
}

int free_insns(struct bpf_insn *data)
{
	free(data);
	return 0;
}