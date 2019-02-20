/* 025.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* ptrace(GETREGSET + NT_ARM_SVE) VL check. */
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
	struct fpsimd_sve_state(vq) wr_buf;
	unsigned int fpscr[2] = { 0, 0 };

	/* clear work area */
	memset(&wr_buf, 0, sizeof(wr_buf));

	/* send PTRACE_TRACEME */
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
		perror("ptrace(PTRACE_TRACEME)");
		goto out;
	}

	/* pre write register */
	gen_test_sve(&wr_buf, vq);
	write_sve(&wr_buf, vq, fpscr);

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

	/* success */
	ret = 0;
out:
	return ret;
}

static int parent_func(pid_t cpid, unsigned int vq)
{
	int ret = -1;
	struct fpsimd_sve_state(vq) cmp_buf;
	struct user_fpsimd_sve_state(vq) rd_buf;
	struct iovec iov;

	memset(&cmp_buf, 0, sizeof(cmp_buf));
	memset(&rd_buf, 0, sizeof(rd_buf));
	memset(&iov, 0, sizeof(iov));

	/* wait child stop */
	if (wait_child_stop(cpid)) {
		goto out;
	}

	/* gen cmp value */
	gen_test_sve(&cmp_buf, vq);

	/* PTRACE_GETREGSET */
	iov.iov_len = sizeof(rd_buf);
	iov.iov_base = &rd_buf;
	if (ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_GETREGSET)");
		goto cont;
	}

	/* check Header */
	printf("size     = 0x%x\n", rd_buf.header.size);
	printf("max_size = 0x%x\n", rd_buf.header.max_size);
	printf("vl       = 0x%x\n", rd_buf.header.vl);
	printf("max_vl   = 0x%x\n", rd_buf.header.max_vl);
	printf("flags    = 0x%x\n", rd_buf.header.flags);

	if (header_compare(&rd_buf.header)) {
		printf("child-process header compare failed.\n");
		goto cont;
	}

	/* compare */
	if (sve_compare(&cmp_buf, &rd_buf.regs, vq)) {
		printf("child-process compare failed.\n");
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

TEST_FUNC(TEST_NUMBER, vl, vq, unused1, unused2)
{
	pid_t cpid = 0;
	int func_ret = 0;
	int ret = -1;

	print_test_overview(tp_num);

	if (set_and_compare_vl(gen_set_vl(vl) | PR_SVE_VL_INHERIT)) {
		printf("prctl: error.\n");
		goto out;
	}

	/* create child process */
	cpid = fork();
	switch (cpid) {
	case -1:
		/* fork() error. */
		perror("fork()");
		goto out;
	case 0:
		/* child process */
		func_ret = child_func(sve_vq_from_vl(gen_set_vl(vl)));

		/* child exit */
		exit(func_ret);
		break;
	default:

		/* parent process */
		func_ret = parent_func(cpid, sve_vq_from_vl(gen_set_vl(vl)));

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
