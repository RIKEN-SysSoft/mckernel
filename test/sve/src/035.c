/* 035.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* Confirmation when SETREGSET + FPSIMD is set while using SVE. */
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

static unsigned long inst_addr = 0;

static int child_func(unsigned int vq)
{
	int ret = -1;
	typedef struct fpsimd_sve_state(vq) sve_regs_t;
	sve_regs_t cmp_buf;
	sve_regs_t rd_buf;
	sve_regs_t wr_buf;
	unsigned int fpscr[2] = { 0, 0 };

	memset(&cmp_buf, 0, sizeof(sve_regs_t));
	memset(&rd_buf, 0, sizeof(sve_regs_t));
	memset(&wr_buf, 0, sizeof(sve_regs_t));

	/* send PTRACE_TRACEME */
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
		perror("ptrace(PTRACE_TRACEME)");
		goto out;
	}

	/* gen and read/write register */
	gen_test_sve(&cmp_buf, vq);
	gen_test_sve_low_128(&cmp_buf, VQ_128_BIT, vq);
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

	/* read register */
	read_sve(&rd_buf, vq, fpscr);

	/* compare */
	if (sve_compare(&cmp_buf, &rd_buf, vq)) {
		printf("child-process compare failed.\n");
		goto out;
	}

	/* success */
	ret = 0;
out:
	return ret;
}

static int parent_func(pid_t cpid)
{
	int ret = -1;
	struct user_sve_header *wr_buf = NULL;
	struct iovec iov;
	size_t buf_size = sizeof(struct user_sve_header) +
			  sizeof(struct user_fpsimd_state);

	wr_buf = calloc(1, buf_size);
	if (!wr_buf) {
		printf("calloc() failed.\n");
		goto out;
	}
	memset(&iov, 0, sizeof(iov));

	/* wait child stop */
	if (wait_child_stop(cpid)) {
		goto out;
	}

	/* PTRACE_GETREGSET */
	iov.iov_len = sizeof(struct user_sve_header);
	iov.iov_base = wr_buf;
	if (ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_GETREGSET)");
		goto cont;
	}

	/* header compare */
	if (header_compare(wr_buf)) {
		printf("ptrace(PTRACE_GETREGSET) header compare failed.\n");
		goto cont;
	}

	/* set flags FPSIMD set */
	wr_buf->flags &= ~SVE_PT_REGS_SVE;
	wr_buf->flags |= SVE_PT_REGS_FPSIMD;

	/* gen register */
	gen_test_fpsimd((struct user_fpsimd_state *)(wr_buf + 1), VQ_128_BIT);

	/* PTRACE_SETREGSET */
	iov.iov_len = buf_size;
	iov.iov_base = wr_buf;
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
	if (wr_buf) {
		free(wr_buf);
	}
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
		func_ret = parent_func(cpid);

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
	return 0;
}
