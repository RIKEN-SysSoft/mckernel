/* main.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include "common.h"

/* usage messages */
char *usage_messages[] = {
/* TP# 0 */	"", /* TP#0 is none */
/* TP# 1 */	"Process starts immediately after registers check.",
/* TP# 2 */	"Use fork() takeover registers check.",
/* TP# 3 */	"Use pthread_create() takeover registers check.",
/* TP# 4 */	"Use execve() takeover registers check. "
		"(execve target is #1 testcase)",
/* TP# 5 */	"Preservation register check signalhsndler before and after.",
/* TP# 6 */	"Preservation register check migrate cpus before and after.",
/* TP# 7 */	"ptrace(GETREGSET + NT_ARM_SVE) check.",
/* TP# 8 */	"ptrace(SETREGSET + NT_ARM_SVE) check.",
/* TP# 9 */	"ptrace(GETREGSET + NT_ARM_SVE) parameters pattern check.",
/* TP#10 */	"ptrace(SETREGSET + NT_ARM_SVE) parameters pattern check.",
/* TP#11 */	"Preservation check signalhsndler(use sigaltstack) "
		"before and after.",
/* TP#12 */	"When SVE is enable, ptrace(GETREGSET + NT_PRFPREG) check.",
/* TP#13 */	"When SVE is enable, ptrace(SETREGSET + NT_PRFPREG) check.",
/* TP#14 */	"ptrace(SETREGSET + NT_ARM_SVE) check, use brk instruction.",
/* TP#15 */	"Context switch in the same core check and SIGSTOP -> SIGCONT "
		"restart check.(need run on background '&')",
/* TP#16 */	"prctl(PR_SVE_GET_VL) check.",
/* TP#17 */	"prctl(PR_SVE_SET_VL) check.",
/* TP#18 */	"prctl(PR_SVE_SET_VL, PR_SVE_SET_VL_THREAD) on multi thread.",
/* TP#19 */	"prctl(PR_SVE_SET_VL) parameters pattern check.",
/* TP#20 */	"Use fork() VL check if setting INHERIT flags.",
/* TP#21 */	"Use pthread_create() VL check if setting INHERIT flags.",
/* TP#22 */	"Use execve() VL check if setting INHERIT flags. "
		"(execve target is #1 testcase)",
/* TP#23 */	"Preservation VL check signalhsndler before and after.",
/* TP#24 */	"Preservation VL check migrate cpus before and after.",
/* TP#25 */	"ptrace(GETREGSET + NT_ARM_SVE) VL check.",
/* TP#26 */	"ptrace(SETREGSET + NT_ARM_SVE) VL check.",
/* TP#27 */	"Use fork() VL check if not setting INHERIT flags.",
/* TP#28 */	"Use pthread_create() VL check if not setting INHERIT flags.",
/* TP#29 */	"Use execve() VL check if not setting INHERIT flags. "
		"(execve target is #1 testcase)",
/* TP#30 */	"When SVE is enable, ptrace(SETREGSET + NT_ARM_SVE + "
		"SVE_PT_REGS_FPSIMD), regs fpsimd struct check.",
/* TP#31 */	"When SVE is enable, ptrace(SETREGSET + NT_ARM_SVE + "
		"SVE_PT_REGS_FPSIMD), regs sve struct check.",
/* TP#32 */	"Use fork() VL check if setting ONEXEC flags.",
/* TP#33 */	"Use pthread_create() VL check if setting ONEXEC flags.",
/* TP#34 */	"Use execve() VL check if setting ONEXEC flags.",
/* TP#35 */	"Confirmation when SETREGSET + FPSIMD is set while using SVE.",
/* TP#36 */	"It becomes SIGSEGV when changing and using SVE-VL "
		"during signalhandler execution.",
/* TP#37 */	"Confirmation of execve() operation when VL is set in "
		"INHERIT->ONEXEC order.",
/* TP#38 */	"Confirmation of execve() operation when VL is set in "
		"ONEXEC->INHERIT order.",
/* TP#39 */	"Confirmation of execve() operation when ONEXEC and "
		"INHERIT are set at the same time.",
/* TP#40 */	"Coredump SVE register output check.",
};

struct test_case {
	int (*func)(int arg0, unsigned int arg1,
		unsigned int arg2, int arg3, char **arg4);
};

#define TEST_CASE_DEF(number)	\
	extern int test_##number(int, unsigned int, unsigned int, int, char **);
#include "test_case.list"
#undef TEST_CASE_DEF

#define TEST_CASE_DEF(number) { .func = test_##number },
const struct test_case test_cases[] = {
	{ .func = NULL },	/* TP#0 is none */
#include "test_case.list"
};
#undef TEST_CASE_DEF

static void usage(char *string)
{
	int i = 0;
	int tp_count = ARRAY_SIZE(usage_messages) - 1;

	printf("%s N\n", string);
	printf("   N    : tp number. (1-%d)\n", tp_count);

	for (i = 1; i < tp_count + 1; i++) {
		printf("%6d : %s\n", i, usage_messages[i]);
	}
}

int main(int argc, char *argv[])
{
	int tp_num = 0, ret = -1;
	unsigned int vl, vl_tmp, vq;
	int usage_count = ARRAY_SIZE(usage_messages);
	int tp_count = ARRAY_SIZE(test_cases);

	if (usage_count != tp_count) {
		printf("BUG: Usage strings and TP count are different.\n");
		goto out;
	}

	if ((argc != 2) && (argc != 4)) {
		usage(argv[0]);
		goto out;
	}

	tp_num = atoi(argv[1]);
	if (tp_num == 0 || tp_count <= tp_num) {
		printf("TP number invalid.\n");
		usage(argv[0]);
		goto out;
	}

	/* get VL */
	vl = sve_get_vl();
	vl_tmp =  PR_SVE_GET_VL_LEN(prctl(PR_SVE_GET_VL));

	if (vl != vl_tmp) {
		printf("Running on QEMU (Bug in RDVL instruction)\n");
		vl = vl_tmp;
	}

	/* calc VQ */
	vq = sve_vq_from_vl(vl);

	printf("Vector Length = %d bytes (128 bit register * %d)\n",
		vl * 8, vq);
	if (test_cases[tp_num].func) {
		ret = test_cases[tp_num].func(tp_num, vl, vq, argc, argv);
	} else {
		printf("BUG: TP function pointer is NULL.\n");
	}
out:
	return ret;
}
