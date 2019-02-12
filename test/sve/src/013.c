/* 013.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
/* When SVE is enable, ptrace(SETREGSET + NT_PRFPREG) check. */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/types.h> 
#include <unistd.h>
#include <linux/elf.h>
#include "common.h"

static unsigned long inst_addr = 0;

static int child_func(unsigned int vq)
{
	int ret = -1;
	struct user_fpsimd_state rd_fregs;
	struct user_fpsimd_state cmp_fregs;

	memset(&rd_fregs, 0, sizeof(rd_fregs));
	memset(&cmp_fregs, 0, sizeof(cmp_fregs));

	/* send PTRACE_TRACEME */
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
		perror("ptrace(PTRACE_TRACEME)");
		goto out;
	}

	/* gen register */
	gen_test_fpsimd(&cmp_fregs, vq);

	/* enable SVE */
	sve_get_vl();

	/* stop mine, brk instruction */
	asm volatile(
		"adr x10, 1f\n"
		"str x10, [%0]\n"
		"nop\n"
		"nop\n"
		"1:\n"
		"brk #0\n"
		"nop\n"
		: /* nothing */
		: "r"(&inst_addr)
		: "x10"
	);

	/* read register */
	read_fpsimd(&rd_fregs);

	/* compare */
	if (fpsimd_compare(&cmp_fregs, &rd_fregs, sizeof(cmp_fregs))) {
		printf("child-process compare failed.\n");
		goto out;
	}

	/* success */
	ret = 0;
out:
	return ret;
}

static int parent_func(pid_t cpid, unsigned int vq)
{
	int ret = -1;
	struct user_fpsimd_state wr_fregs;
	struct iovec iov;

	memset(&wr_fregs, 0, sizeof(wr_fregs));
	memset(&iov, 0, sizeof(iov));

	/* wait child stop */
	if (wait_child_stop(cpid)) {
		goto out;
	}

	/* gen register */
	gen_test_fpsimd(&wr_fregs, vq);

	/* PTRACE_SETREGSET */
	iov.iov_len = sizeof(wr_fregs);
	iov.iov_base = &wr_fregs;
	if (ptrace(PTRACE_SETREGSET, cpid, NT_PRFPREG, &iov)) {
		perror("ptrace(PTRACE_SETREGSET)");
		goto cont;
	}

	/* success */
	ret = 0;
cont:
	/* rewrite child brk instruction */
	if (rewrite_brk_inst(cpid, &inst_addr)) {
		/* Through */
	}

	/* child continue */
	if (ptrace(PTRACE_CONT, cpid, NULL, NULL)) {
		perror("ptrace(PTRACE_CONT)");
		ret = -1;
	}
out:
	return ret;
}

TEST_FUNC(TEST_NUMBER, unused1, vq, unused2, unused3)
{
	pid_t cpid = 0;
	int func_ret = 0;
	int ret = -1;

	print_test_overview(tp_num);

	/* create child process */
	cpid = fork();
	switch (cpid) {
	case -1:
		/* fork() error. */
		perror("fork()");
		goto out;
		break;
	case 0:
		/* child process */
		func_ret = child_func(vq);

		/* child exit */
		exit(func_ret);
		break;
	default:
		/* parent process */
		func_ret = parent_func(cpid, vq);

		/* wait child */
		if (wait_child_exit(cpid)) {
			goto out;
		}

		/* parent_func check */
		if (func_ret) {
			goto out;
		}
		break;
	}

	/* sccess. */
	ret = 0;
out:
	if (ret == 0) {
		printf("RESULT: OK.\n");
	} else {
		printf("RESULT: NG.\n");
	}
	return ret;
}
