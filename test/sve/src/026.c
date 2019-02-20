/* 026.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* ptrace(SETREGSET + NT_ARM_SVE) VL check. */
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

static int child_func(const unsigned int vl)
{
	int ret = -1;
	/* before SETREGS VQ */
	const unsigned int bf_vq = sve_vq_from_vl(vl);
	/* after  SETREGS VQ */
	const unsigned int af_vq = sve_vq_from_vl(gen_set_vl(vl));
	struct fpsimd_sve_state(bf_vq) bf_rd_buf;
	struct fpsimd_sve_state(af_vq) cmp_buf, af_rd_buf;
	unsigned int fpscr[2] = { 0, 0 };

	/* struct initialize */
	memset(&bf_rd_buf, 0, sizeof(bf_rd_buf));
	memset(&cmp_buf, 0, sizeof(cmp_buf));
	memset(&af_rd_buf, 0, sizeof(af_rd_buf));

	/* send PTRACE_TRACEME */
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
		perror("ptrace(PTRACE_TRACEME)");
		goto out;
	}

	/* gen and read register */
	gen_test_sve(&cmp_buf, af_vq);
	read_sve(&bf_rd_buf, bf_vq, fpscr);

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
	read_sve(&af_rd_buf, af_vq, fpscr);

	/* compare */
	if (sve_compare(&cmp_buf, &af_rd_buf, af_vq)) {
		printf("child-process compare failed.\n");
		goto out;
	}

	/* success */
	ret = 0;
out:
	return ret;
}

static int parent_func(pid_t cpid, const unsigned int vl)
{
	int ret = -1;
	/* after  SETREGS VQ */
	const unsigned int af_vq = sve_vq_from_vl(gen_set_vl(vl));
	struct user_fpsimd_sve_state(af_vq) wr_buf;
	struct iovec iov;

	/* struct initialize */
	memset(&wr_buf, 0, sizeof(wr_buf));
	memset(&iov, 0, sizeof(iov));

	/* wait child stop */
	if (wait_child_stop(cpid)) {
		goto out;
	}

	/* PTRACE_GETREGSET */
	iov.iov_len = sizeof(wr_buf.header);
	iov.iov_base = &wr_buf.header;
	if (ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_GETREGSET)");
		goto cont;
	}

	/* check Header */
	if (header_compare(&wr_buf.header)) {
		printf("header compare failed.\n");
		goto cont;
	}

	/* set VL & flags */
	wr_buf.header.vl = gen_set_vl(vl);
	wr_buf.header.flags |= PR_SVE_VL_INHERIT;

	/* gen register */
	gen_test_sve(&wr_buf.regs, af_vq);

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

TEST_FUNC(TEST_NUMBER, vl, unused1, unused2, unused3)
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
		func_ret = child_func(vl);

		/* child exit */
		exit(func_ret);
		break;
	default:
		/* parent process */
		func_ret = parent_func(cpid, vl);

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

	/* success. */
	ret = 0;
out:
	if (ret == 0) {
		printf("RESULT: OK.\n");
	} else {
		printf("RESULT: NG.\n");
	}
	return ret;
}
