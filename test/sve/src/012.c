/* 012.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
/* When SVE is enable, ptrace(GETREGSET + NT_PRFPREG) check. */
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
	struct iovec iov;
	struct user_fpsimd_state rd_fregs;
	struct user_fpsimd_state cmp_fregs;
	struct user_sve_header header;

	memset(&header, 0, sizeof(header));
	memset(&cmp_fregs, 0, sizeof(cmp_fregs));
	memset(&rd_fregs, 0, sizeof(rd_fregs));
	memset(&iov, 0, sizeof(iov));

	/* wait child stop */
	if (wait_child_stop(cpid)) {
		goto out;
	}

	/* PTRACE_GETREGSET(get vl) */
	iov.iov_len = sizeof(header);
	iov.iov_base = &header;
	if (ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_GETREGSET)");
		goto cont;
	}

	/* gen cmp value */
	gen_test_fpsimd(&cmp_fregs, sve_vq_from_vl(header.vl));

	/* PTRACE_GETREGSET */
	iov.iov_len = sizeof(rd_fregs);
	iov.iov_base = &rd_fregs;
	if (ptrace(PTRACE_GETREGSET, cpid, NT_PRFPREG, &iov)) {
		perror("ptrace(PTRACE_GETREGSET)");
		goto cont;
	}

	/* compare */
	if (fpsimd_compare(&cmp_fregs, &rd_fregs, sizeof(cmp_fregs))) {
		printf("parent-process compare failed.\n");
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
