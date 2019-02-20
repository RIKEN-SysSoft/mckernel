/* 008.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
/* ptrace(SETREGSET + NT_ARM_SVE) check. */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <unistd.h>
#include "common.h"

static unsigned long inst_addr;

static int child_func(unsigned int vq)
{
	int ret = -1;
	struct fpsimd_sve_state(vq) cmp_buf;
	struct fpsimd_sve_state(vq) rd_buf;
	unsigned int fpscr[2] = { 0, 0 };

	memset(&cmp_buf, 0, sizeof(struct fpsimd_sve_state(vq)));
	memset(&rd_buf, 0, sizeof(struct fpsimd_sve_state(vq)));

	/* send PTRACE_TRACEME */
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
		perror("ptrace(PTRACE_TRACEME)");
		goto out;
	}

	/* gen and read register */
	gen_test_sve(&cmp_buf, vq);
	read_sve(&rd_buf, vq, fpscr);

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
	read_sve(&rd_buf, vq, fpscr);

	/* compare */
	if (sve_compare(&cmp_buf, &rd_buf, vq)) {
		printf("child-process compare failed.\n");
	}

	/* success */
	ret = 0;
out:
	return ret;
}

static int parent_func(pid_t cpid, unsigned int vq)
{
	int ret = -1;
	struct user_fpsimd_sve_state(vq) wr_buf;
	struct iovec iov;

	memset(&wr_buf, 0, sizeof(wr_buf));
	memset(&iov, 0, sizeof(iov));

	/* wait child stop */
	if (wait_child_stop(cpid)) {
		goto out;
	}

	/* PTRACE_GETREGSET */
	iov.iov_len = sizeof(wr_buf);
	iov.iov_base = &wr_buf;
	if (ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_GETREGSET)");
		goto cont;
	}

	/* header compare */
	if (header_compare(&wr_buf.header)) {
		printf("ptrace(PTRACE_GETREGSET) header compare failed.\n");
		goto cont;
	}

	/* gen register */
	gen_test_sve(&wr_buf.regs, vq);

	/* PTRACE_SETREGSET */
	iov.iov_len = sizeof(wr_buf);
	iov.iov_base = &wr_buf;
	if (ptrace(PTRACE_SETREGSET, cpid, NT_ARM_SVE, &iov)) {
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
