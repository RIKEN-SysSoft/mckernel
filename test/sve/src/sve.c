/* sve.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <errno.h>
#include "sve.h"

static unsigned long sve_magic[] = {
	0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444,
	0x5555555555555555, 0x6666666666666666, 0x7777777777777777, 0x8888888888888888,
	0x9999999999999999, 0xaaaaaaaaaaaaaaaa, 0xbbbbbbbbbbbbbbbb, 0xcccccccccccccccc,
	0xdddddddddddddddd, 0xeeeeeeeeeeeeeeee, 0xffffffffffffffff, 0x1111111122222222,
	0x2222222233333333, 0x3333333344444444, 0x4444444455555555, 0x5555555566666666,
	0x6666666677777777, 0x7777777788888888, 0x99999999aaaaaaaa, 0xaaaaaaaabbbbbbbb,
	0xbbbbbbbbcccccccc, 0xccccccccdddddddd, 0xddddddddeeeeeeee, 0xeeeeeeeeffffffff,
	0xffffffff11111111, 0x1111222233334444, 0x5555666677778888, 0x9999aaaabbbbcccc,
	0xddddeeeeffff1111, 0xffffeeeeddddcccc, 0xbbbbaaaa99998888, 0x7777666655554444,
	0x333322221111ffff, 0x1122334455667788, 0x99aabbccddeeff11, 0xffeeddccbbaa9988,
	0x77665544332211ff, 0x123456789abcdef1, 0xfedcba987654321f, 0xcafecafecafecafe
};

unsigned int gen_set_vl(const unsigned int vl)
{
	switch(vl) {
	case VL_128_BIT:
		return VL_256_BIT;
	case VL_256_BIT:
		return VL_512_BIT;
	case VL_512_BIT:
		return VL_128_BIT;
	default:
		break;
	}
	return -1;
}

static int compare_vl_flags(const unsigned int exp, const unsigned int target,
			    const unsigned int onexec_vl)
{
	int ret = 0;
	const unsigned int exp_vl = PR_SVE_GET_VL_LEN(exp);
	unsigned int exp_flags = PR_SVE_GET_VL_FLAGS(exp);
	const unsigned int target_vl = PR_SVE_GET_VL_LEN(target);
	const unsigned int target_flags = PR_SVE_GET_VL_FLAGS(target);
	const unsigned int rd_vl = sve_get_vl();
	unsigned int exp_rdvl = 0;

	/* PR_SVE_SET_VL_ONEXEC flag is set only. */
	exp_flags &= ~PR_SVE_SET_VL_ONEXEC;

	if (onexec_vl == 0) {
		exp_rdvl = exp_vl;
	}
	else {
		exp_rdvl = onexec_vl;
	}

	if (exp_vl != target_vl) {
		printf("Expected VL(0x%x) != Target VL(0x%x).\n",
				exp_vl, target_vl);
		ret = -1;
	}

	if (exp_flags != target_flags) {
		printf("Expected FLAGS(0x%x) != Target FLAGS(0x%x).\n",
				exp_flags, target_flags);
		ret = -1;
	}

	if (exp_rdvl != rd_vl) {
		printf("Expected VL(0x%x) != VL on Register(0x%x).\n",
				exp_rdvl, rd_vl);
		ret = -1;
	}

	if (ret == -1) {
		printf("Expected VALUE (0x%x), Target VALUE (0x%x).\n",
				(exp & ~PR_SVE_SET_VL_ONEXEC), target);
	}
	return ret;
}

int get_and_compare_vl(const unsigned long exp_arg)
{
	int ret = -1;
	int vl_flags = 0;

	vl_flags = prctl(PR_SVE_GET_VL);
	if (vl_flags == -1) {
		perror("prctl(PR_SVE_GET_VL)");
		ret = errno;
	}
	else {
		printf("Get VL(0x%x), FLAGS(0x%x)\n",
			PR_SVE_GET_VL_LEN(vl_flags), PR_SVE_GET_VL_FLAGS(vl_flags));
		ret = compare_vl_flags(exp_arg, vl_flags, 0);
	}
	return ret;
}

int set_and_compare_vl(const unsigned long set_arg)
{
	int ret = 0;
	int vl_flags = 0;
	const int onexec = ((set_arg & PR_SVE_SET_VL_ONEXEC) ? 1 : 0);
	unsigned long exp_vl = PR_SVE_GET_VL_LEN(set_arg);
	unsigned long exp_flags = PR_SVE_GET_VL_FLAGS(set_arg);
	unsigned int onexec_vl = 0;

	printf("Set VL(0x%lx), FLAGS(0x%lx)\n",
		PR_SVE_GET_VL_LEN(set_arg),
		PR_SVE_GET_VL_FLAGS(set_arg));

	if (onexec) {
		int exp_arg = 0;

		exp_arg = prctl(PR_SVE_GET_VL);
		if (exp_arg == -1) {
			perror("prctl(PR_SVE_GET_VL)");
			ret = errno;
			goto out;
		}
		else {
			onexec_vl = PR_SVE_GET_VL_LEN(exp_arg);
		}
	}

	vl_flags = prctl(PR_SVE_SET_VL, set_arg);
	if (vl_flags == -1) {
		perror("prctl(PR_SVE_SET_VL)");
		ret = errno;
	}
	else {
		ret = compare_vl_flags(exp_vl | exp_flags, vl_flags, onexec_vl);
	}
out:
	return ret;
}

void gen_test_sve(void *buf, unsigned int vq)
{
	struct fpsimd_sve_state(vq) *svereg = buf;
	unsigned long *pzreg = (unsigned long *)svereg->zregs;
	unsigned int sve_magic_num = sizeof(sve_magic) / sizeof(sve_magic[0]);
	int i = 0, j = 0;

	/* zregs */
	for (i = 0; i < 32; i++) {
		for (j = 0; j < vq * 2; j++) {
			int k = i * vq * 2;
			pzreg[k + j] = sve_magic[(k + j) % sve_magic_num];
		}
	}

	/* pregs */
	for (i = 0; i < 16; i++) {
		for (j = 0; j < vq; j++) {
			int k = i * vq;
			svereg->pregs[i][j] = (unsigned short)(sve_magic[(k + j) % sve_magic_num]);
		}
	}

	/* ffr */
	for (i = 0; i < vq; i++) {
		svereg->ffr[i] = (unsigned short)(sve_magic[i % sve_magic_num]);
	}
}

void gen_test_sve_low_128(void *buf, unsigned int bf_vq, unsigned int af_vq)
{
	struct fpsimd_sve_state(bf_vq) tmp_buf;
	struct fpsimd_sve_state(af_vq) *svereg = buf;
	int i = 0;

	memset(&tmp_buf, 0, sizeof(tmp_buf));
	gen_test_sve(&tmp_buf, bf_vq);

	/* zregs */
	for (i = 0; i < 32; i++) {
		svereg->zregs[i][0] = tmp_buf.zregs[i][0];
	}
}

void gen_test_fpsimd(struct user_fpsimd_state *buf, unsigned int vq)
{
	int i = 0;
	struct fpsimd_sve_state(vq) svereg;

	gen_test_sve(&svereg, vq);
	for (i = 0; i < 32; i++) {
		buf->vregs[i] = svereg.zregs[i][0];
	}
}

void gen_test_sve_dirty(void *buf, unsigned int vq)
{
	struct fpsimd_sve_state(vq) *svereg = buf;
	memset(svereg, 0xda, sizeof(*svereg));
}

void write_sve(void *buf, unsigned int vq, unsigned int *fpscr)
{
	struct fpsimd_sve_state(vq) *svereg = buf;
	sve_load_state(svereg->ffr, fpscr);
	return;
}

void read_sve(void *buf, unsigned int vq, unsigned int *fpscr)
{
	struct fpsimd_sve_state(vq) *svereg = buf;
	sve_save_state(svereg->ffr, fpscr);
	return;
}

void show_sve(const void *buf, unsigned int vq, unsigned int *fpscr)
{
	const struct fpsimd_sve_state(vq) *svereg = buf;
	int i = 0, j = 0;
	unsigned long *pzreg = (unsigned long *)svereg->zregs;

	/* zregs */
	for (i = 0; i < 32; i++) {
		printf("z%2d: ", i);
		for (j = 0; j < vq * 2; j++) {
			int k = i * vq * 2;

			if ((j != 0) && (j % 4 == 0)) {
				printf("\n");
				printf("     ");
			}
			printf("0x%016lx ", pzreg[k + j]);
		}
		printf("\n");
	}

	/* pregs */
	for (i = 0; i < 16; i++) {
		printf("p%2d: ", i);
		for (j = 0; j < vq; j++) {
			printf("0x%04x ", svereg->pregs[i][j]);
		}
		printf("\n");
	}

	/* ffr */
	for (i = 0; i < vq; i++) {
		printf("ffr%2d: 0x%04x\n", i, svereg->ffr[i]);
	}
	printf("fpsr: 0x%08x\n", fpscr[0]);
	printf("fpcr: 0x%08x\n", fpscr[1]);

	return;
}

void read_and_show_sve(void *buf, unsigned int vq, unsigned int *fpscr)
{
	read_sve(buf, vq, fpscr);
	show_sve(buf, vq, fpscr);

	return;
}

int header_compare(const struct user_sve_header *target)
{
	int ret = -1;
	unsigned int vq, max_vq;

	if (!sve_vl_valid(target->vl)) {
		printf("VL invalid.\n");
		goto out;
	}
	vq = sve_vq_from_vl(target->vl);

	if (!sve_vl_valid(target->max_vl)) {
		printf("MAX-VL invalid.\n");
		goto out;
	}
	max_vq = sve_vq_from_vl(target->max_vl);

	if (!(target->flags & SVE_PT_REGS_SVE)) {
		printf("FLAGS invalid.\n");
		goto out;
	}

	if (target->size != SVE_PT_SIZE(vq, target->flags)) {
		printf("SIZE invalid.\n");
		goto out;
	}

	if (target->max_size != SVE_PT_SIZE(max_vq, SVE_PT_REGS_SVE)) {
		printf("MAX-SIZE invalid.\n");
		goto out;
	}
	ret = 0;
out:
	return ret;
}

int sve_compare(const void *expect, const void *target, unsigned int vq)
{
	int i = 0, ret = 0;
	typedef struct fpsimd_sve_state(vq) sve_regs_t;
	sve_regs_t *exp = (sve_regs_t *)expect;
	sve_regs_t *tgt = (sve_regs_t *)target;

	/* compare low 64 bits of z8-z15 */
	for (i = 8; i <= 15; i++) {
		unsigned long e = (unsigned long)exp->zregs[i][0];
		unsigned long t = (unsigned long)tgt->zregs[i][0];

		if (e != t) {
			printf("Compare Failed, z%2d exp 0x%016lx val 0x%016lx\n",
				i, e, t);
			ret = -1;
		}
	}
	return ret;
}

int fpsimd_compare(const struct user_fpsimd_state *expect,
			const struct user_fpsimd_state *target, size_t n)
{
	int i = 0;

	if (memcmp(expect, target, n)) {
		const unsigned long *exp = (const unsigned long *)expect;
		const unsigned long *tgt = (const unsigned long *)target;

		printf("Compare Failed !!\n");
		printf("[show expect values]\n");
		for (i = 0; i < 64; i += 2) {
			printf("q%2d: 0x%016lx 0x%016lx\n", i / 2, exp[i], exp[i + 1]);
		}
		printf("fpsr: 0x%08x\n", expect->fpsr);
		printf("fpcr: 0x%08x\n", expect->fpcr);

		printf("[show target values]\n");
		for (i = 0; i < 64; i += 2) {
			printf("q%2d: 0x%016lx 0x%016lx\n", i / 2, tgt[i], tgt[i + 1]);
		}
		printf("fpsr: 0x%08x\n", target->fpsr);
		printf("fpcr: 0x%08x\n", target->fpcr);

		return -1;
	}
	return 0;
}

void read_fpsimd(struct user_fpsimd_state *regs)
{
	asm volatile(
		"stp q0, q1, [%0, #16 * 0]\n"
		"stp q2, q3, [%0, #16 * 2]\n"
		"stp q4, q5, [%0, #16 * 4]\n"
		"stp q6, q7, [%0, #16 * 6]\n"
		"stp q8, q9, [%0, #16 * 8]\n"
		"stp q10, q11, [%0, #16 * 10]\n"
		"stp q12, q13, [%0, #16 * 12]\n"
		"stp q14, q15, [%0, #16 * 14]\n"
		"stp q16, q17, [%0, #16 * 16]\n"
		"stp q18, q19, [%0, #16 * 18]\n"
		"stp q20, q21, [%0, #16 * 20]\n"
		"stp q22, q23, [%0, #16 * 22]\n"
		"stp q24, q25, [%0, #16 * 24]\n"
		"stp q26, q27, [%0, #16 * 26]\n"
		"stp q28, q29, [%0, #16 * 28]\n"
		"stp q30, q31, [%0, #16 * 30]\n"
		"mrs x8, fpsr\n"
		"str w8, [%0, #512]\n"
		"mrs x8, fpcr\n"
		"str w8, [%0, #516]\n"
		: : "r" (regs)
		: "x8", "memory"
	);
}
