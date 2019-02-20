/* 009.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
/* ptrace(GETREGSET + NT_ARM_SVE) parameters pattern check. */
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
	struct fpsimd_sve_state(vq) rd_buf;
	unsigned int fpscr[2] = { 0, 0 };

	/* clear work area */
	memset(&wr_buf, 0, sizeof(wr_buf));
	memset(&rd_buf, 0, sizeof(rd_buf));

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
	char *l_rd_buf = NULL;
	struct fpsimd_sve_state(vq) cmp_buf;
	struct user_fpsimd_sve_state(vq) rd_buf;
	size_t align_half_regsz =
		(sizeof(cmp_buf) / 2 + 15) & ~15UL;

	memset(&cmp_buf, 0, sizeof(cmp_buf));
	memset(&rd_buf, 0, sizeof(rd_buf));
	memset(&iov, 0, sizeof(iov));

	/* wait child stop */
	if (wait_child_stop(cpid)) {
		goto out;
	}

	printf("PTRACE_GETREGSET parameter check\n");

	/* case 1: iov_base is NULL */
	printf("check 1: iov_base == NULL\n");
	iov.iov_len = sizeof(rd_buf);
	iov.iov_base = NULL;
	if (!ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		printf("why sccess ptrace(PTRACE_GETREGSET) ???\n");
		goto cont;
	}

	if (errno != EFAULT) {
		printf("errno(%d) is not expectation value\n", errno);
		printf("expectation value is EFAULT(%d)\n", EFAULT);
		goto cont;
	}
	errno = 0;

	/* case 2: iov_len is zero */
	printf("check 2: iov_len == 0\n");
	iov.iov_len = 0;
	iov.iov_base = &rd_buf;
	if (ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_GETREGSET)");
		goto cont;
	}

	if (rd_buf.header.vl != 0 ||
	    rd_buf.header.max_vl != 0 ||
	    rd_buf.header.flags != 0) {
		printf("why iov_len over area getting ???\n");
		goto cont;
	}

	/* case 3: iov_len is less than sizeof(struct user_sve_header) */
	printf("check 3: iov_len < sizeof(struct user_sve_header)\n");
	memset(&rd_buf, 0, sizeof(rd_buf));
	iov.iov_len = sizeof(rd_buf.header.vl);
	iov.iov_base = &rd_buf;
	if (!ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		printf("why sccess ptrace(PTRACE_GETREGSET) ???\n");
		goto cont;
	}

	if (errno != EINVAL) {
		printf("errno(%d) is not expectation value\n", errno);
		printf("expectation value is EINVAL(%d)\n", EINVAL);
		goto cont;
	}
	errno = 0;

	/* case 4: iov_len is just sizeof(struct user_sve_header) */
	printf("check 4: iov_len == sizeof(struct user_sve_header)\n");
	memset(&rd_buf, 0, sizeof(rd_buf));
	iov.iov_len = sizeof(struct user_sve_header);
	iov.iov_base = &rd_buf;
	if (ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_GETREGSET)");
		goto cont;
	}

	if ((vq * 16) != rd_buf.header.vl) {
		printf("mismatch vl (exp(%d), value(%d))\n",
			vq * 16, rd_buf.header.vl);
		goto cont;
	}

	if (rd_buf.header.max_vl == 0 || rd_buf.header.flags == 0) {
		printf("why iov_len over area not getting ???\n");
		goto cont;
	}

	/* compare */
	if (sve_compare(&cmp_buf, &rd_buf.regs, vq)) {
		printf("parent-process compare failed.\n");
		goto cont;
	}

	/* case 5:
	 * iov_len is sizeof(struct user_sve_header) +
	 * sizeof(struct fpsimd_sve_state(vq)) / 2
	 */
	printf("check 5: iov_len header + "
		"(registerarea size / 2) (16 byte align)\n");
	gen_test_sve(&cmp_buf, vq);
	memset((char *)&cmp_buf + align_half_regsz, 0,
		sizeof(cmp_buf) - align_half_regsz);

	memset(&rd_buf, 0, sizeof(rd_buf));
	iov.iov_len = sizeof(struct user_sve_header) + align_half_regsz;
	iov.iov_base = &rd_buf;
	if (ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_GETREGSET)");
		goto cont;
	}

	/* compare */
	if (sve_compare(&cmp_buf, &rd_buf.regs, vq)) {
		printf("parent-process compare failed.\n");
		goto cont;
	}

	/* case 6: iov_len larger than struct user_sve_regs */
	printf("check 6: iov_len larger than struct user_sve_regs\n");
	memset(&cmp_buf, 0, sizeof(cmp_buf));
	memset(&rd_buf, 0, sizeof(rd_buf));

	iov.iov_len = ((sizeof(rd_buf) * 2 + 15) & ~15UL);
	iov.iov_base = &rd_buf;
	if (ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_GETREGSET)");
		goto cont;
	}
	gen_test_sve(&cmp_buf, vq);

	/* compare */
	if (sve_compare(&cmp_buf, &rd_buf.regs, vq)) {
		printf("parent-process compare failed.\n");
		goto cont;
	}

	/* case 7: iov_len larger than MAX_SIZE */
	printf("check 7: iov_len larger than MAX_SIZE\n");
	memset(&cmp_buf, 0, sizeof(cmp_buf));
	gen_test_sve(&cmp_buf, vq);

	iov.iov_len = ((SVE_PT_SIZE(SVE_VQ_MAX,
			SVE_PT_REGS_SVE) + 15) / 16 * 16) + 16;
	l_rd_buf = calloc(1, iov.iov_len);
	if (!l_rd_buf) {
		printf("calloc() failed.\n");
		goto cont;
	}

	iov.iov_base = l_rd_buf;
	if (ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_GETREGSET)");
		free(iov.iov_base);
		goto free_cont;
	}

	/* compare */
	iov.iov_base = l_rd_buf;
	if (sve_compare(&cmp_buf,
		l_rd_buf + sizeof(struct user_sve_header), vq)) {
		printf("parent-process compare failed.\n");
		free(iov.iov_base);
		goto free_cont;
	}

	/* success */
	ret = 0;

free_cont:
	free(iov.iov_base);
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
