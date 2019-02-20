/* 010.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
/* ptrace(SETREGSET + NT_ARM_SVE) parameters pattern check. */
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
	struct fpsimd_sve_state(vq) zero_buf;
	struct fpsimd_sve_state(vq) rd_buf;
	unsigned int fpscr[2] = { 0, 0 };
	size_t align_half_regsz =
		(sizeof(cmp_buf) / 2 + 15) & ~15UL;

	memset(&cmp_buf, 0, sizeof(cmp_buf));
	memset(&zero_buf, 0, sizeof(cmp_buf));
	memset(&rd_buf, 0, sizeof(cmp_buf));

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

	/* case 7: read register */
	read_sve(&rd_buf, vq, fpscr);

	/* compare */
	if (sve_compare(&cmp_buf, &rd_buf, vq)) {
		printf("child-process compare failed.\n");
		goto out;
	}

	/* clear sve */
	fpscr[0] = 0;
	fpscr[1] = 0;
	write_sve(&zero_buf, vq, fpscr);

	/* stop mine, brk instruction */
	asm volatile(
		"adr x10, 2f\n"
		"str x10, [%0]\n"
		"nop\n"
		"nop\n"
		"2:\n"
		"brk #0\n"
		"nop\n"
		: /* nothing */
		: "r"(&inst_addr)
		: "x10"
	);

	/* case 8: read register */
	read_sve(&rd_buf, vq, fpscr);

	/* compare */
	if (sve_compare(&cmp_buf, &rd_buf, vq)) {
		printf("child-process compare failed.\n");
		goto out;
	}

	/* clear sve */
	fpscr[0] = 0;
	fpscr[1] = 0;
	write_sve(&zero_buf, vq, fpscr);

	/* stop mine, brk instruction */
	asm volatile(
		"adr x10, 3f\n"
		"str x10, [%0]\n"
		"nop\n"
		"nop\n"
		"3:\n"
		"brk #0\n"
		"nop\n"
		: /* nothing */
		: "r"(&inst_addr)
		: "x10"
	);

	/* case 9: read register */
	read_sve(&rd_buf, vq, fpscr);

	/* create expected value */
	memset((char *)&cmp_buf + align_half_regsz, 0,
		sizeof(cmp_buf) - align_half_regsz);

	/* compare */
	if (sve_compare(&cmp_buf, &rd_buf, vq)) {
		printf("child-process compare failed.\n");
		goto out;
	}

	/* clear sve */
	fpscr[0] = 0;
	fpscr[1] = 0;
	write_sve(&zero_buf, vq, fpscr);

	/* stop mine, brk instruction */
	asm volatile(
		"adr x10, 4f\n"
		"str x10, [%0]\n"
		"nop\n"
		"nop\n"
		"4:\n"
		"brk #0\n"
		"nop\n"
		: /* nothing */
		: "r"(&inst_addr)
		: "x10"
	);

	/* case 10: read register */
	read_sve(&rd_buf, vq, fpscr);

	/* compare */
	if (sve_compare(&zero_buf, &rd_buf, vq)) {
		printf("child-process compare failed.\n");
		goto out;
	}

	/* clear sve */
	fpscr[0] = 0;
	fpscr[1] = 0;
	write_sve(&zero_buf, vq, fpscr);

	/* stop mine, brk instruction */
	asm volatile(
		"adr x10, 5f\n"
		"str x10, [%0]\n"
		"nop\n"
		"nop\n"
		"5:\n"
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
	struct user_fpsimd_sve_state(vq) wr_buf;
	struct fpsimd_sve_state(vq) tmp_buf;
	char *l_wr_buf = NULL;
	struct iovec iov;
	struct user_sve_header header, work_header;
	size_t align_half_regsz =
		(sizeof(tmp_buf) / 2 + 15) & ~15UL;

	memset(&wr_buf, 0, sizeof(wr_buf));
	memset(&l_wr_buf, 0, sizeof(l_wr_buf));
	memset(&iov, 0, sizeof(iov));
	memset(&header, 0, sizeof(header));
	memset(&work_header, 0, sizeof(work_header));

	/* wait child stop */
	if (wait_child_stop(cpid)) {
		goto out;
	}

	/* get header value */
	iov.iov_len = sizeof(header);
	iov.iov_base = &header;
	if (ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_GETREGSET)");
		goto cont;
	}

	/* header compare */
	if (header_compare(&header)) {
		printf("header compare failed.\n");
		goto cont;
	}

	printf("PTRACE_SETREGSET parameter check\n");

	/* case 1: iov_base is NULL */
	printf("check  1: iov_base == NULL\n");
	iov.iov_len = sizeof(wr_buf);
	iov.iov_base = NULL;
	if (!ptrace(PTRACE_SETREGSET, cpid, NT_ARM_SVE, &iov)) {
		printf("why sccess ptrace(PTRACE_SETREGSET) ???\n");
		goto cont;
	}

	if (errno != EFAULT) {
		printf("errno(%d) is not expectation value\n", errno);
		printf("expectation value is EFAULT(%d)\n", EFAULT);
		goto cont;
	}
	errno = 0;

	/* case 2: iov_len is zero */
	printf("check  2: iov_len == 0\n");
	iov.iov_len = 0;
	iov.iov_base = &wr_buf;
	if (!ptrace(PTRACE_SETREGSET, cpid, NT_ARM_SVE, &iov)) {
		printf("why sccess ptrace(PTRACE_SETREGSET) ???\n");
		goto cont;
	}

	if (errno != EINVAL) {
		printf("errno(%d) is not expectation value\n", errno);
		printf("expectation value is EINVAL(%d)\n", EINVAL);
		goto cont;
	}
	errno = 0;

	/* case 3: header.vl invalid */
	printf("check  3: header.vl invalid\n");
	wr_buf.header = header;
	wr_buf.header.vl = 0xffff;	/* invalid */

	iov.iov_len = sizeof(wr_buf);
	iov.iov_base = &wr_buf;
	if (!ptrace(PTRACE_SETREGSET, cpid, NT_ARM_SVE, &iov)) {
		printf("why sccess ptrace(PTRACE_SETREGSET) ???\n");
		goto cont;
	}

	if (errno != EINVAL) {
		printf("errno(%d) is not expectation value\n", errno);
		printf("expectation value is EINVAL(%d)\n", EINVAL);
		goto cont;
	}
	errno = 0;

	/* case 4: header.max_vl invalid */
	printf("check  4: header.max_vl invalid\n");
	wr_buf.header = header;
	wr_buf.header.max_vl = 0xffff;	/* invalid */

	iov.iov_len = sizeof(wr_buf);
	iov.iov_base = &wr_buf;
	if (ptrace(PTRACE_SETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_SETREGSET)");
		goto cont;
	}

	/* get header value */
	iov.iov_len = sizeof(work_header);
	iov.iov_base = &work_header;
	if (ptrace(PTRACE_GETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_GETREGSET)");
		goto cont;
	}

	if (work_header.max_vl != header.max_vl) {
		printf("setting invalid max_vl\n");
		goto cont;
	}

	/* case 5: header.flags invalid part 1 */
	printf("check  5: header.flags invalid part 1\n");
	wr_buf.header = header;
	wr_buf.header.flags = 0xffff;	/* invalid */

	iov.iov_len = sizeof(wr_buf);
	iov.iov_base = &wr_buf;
	if (!ptrace(PTRACE_SETREGSET, cpid, NT_ARM_SVE, &iov)) {
		printf("why sccess ptrace(PTRACE_SETREGSET) ???\n");
		goto cont;
	}

	if (errno != EINVAL) {
		printf("errno(%d) is not expectation value\n", errno);
		printf("expectation value is EINVAL(%d)\n", EINVAL);
		goto cont;
	}
	errno = 0;

	/* case 6: header.flags invalid part 2 */
	printf("check  6: header.flags invalid part 2\n");
	wr_buf.header = header;
	wr_buf.header.flags = SVE_PT_INVALID_FLAGS;	/* invalid */

	iov.iov_len = sizeof(wr_buf);
	iov.iov_base = &wr_buf;
	if (!ptrace(PTRACE_SETREGSET, cpid, NT_ARM_SVE, &iov)) {
		printf("why sccess ptrace(PTRACE_SETREGSET) ???\n");
		goto cont;
	}

	if (errno != EINVAL) {
		printf("errno(%d) is not expectation value\n", errno);
		printf("expectation value is EINVAL(%d)\n", EINVAL);
		goto cont;
	}
	errno = 0;

	/* case 7: iov_len larger than struct user_sve_regs */
	printf("check  7: iov_len larger than struct user_sve_regs\n");
	wr_buf.header = header;

	/* gen register */
	gen_test_sve(&wr_buf.regs, vq);

	/* PTRACE_SETREGSET */
	iov.iov_len = ((sizeof(wr_buf) * 2 + 15) & ~15UL);
	iov.iov_base = &wr_buf;
	if (ptrace(PTRACE_SETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_SETREGSET)");
		goto cont;
	}

	/* rewrite child brk instruction */
	if (rewrite_brk_inst(cpid, &inst_addr)) {
		/* Through */
	}

	/* child continue */
	if (ptrace(PTRACE_CONT, cpid, NULL, NULL)) {
		perror("ptrace(PTRACE_CONT)");
		goto cont;
	}

	/* wait child stop */
	if (wait_child_stop(cpid)) {
		goto out;
	}

	/* case 8: iov_len larger than MAX_SIZE */
	printf("check  8: iov_len larger than MAX_SIZE\n");
	iov.iov_len = ((SVE_PT_SIZE(SVE_VQ_MAX,
			SVE_PT_REGS_SVE) + 15) / 16 * 16) + 16;
	l_wr_buf = calloc(1, iov.iov_len);
	if (!l_wr_buf) {
		printf("calloc() failed.\n");
		goto cont;
	}
	memcpy(l_wr_buf, &header, sizeof(header));
	gen_test_sve(l_wr_buf + sizeof(struct user_sve_header), vq);

	/* PTRACE_SETREGSET */
	iov.iov_base = l_wr_buf;
	if (ptrace(PTRACE_SETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_SETREGSET)");
		free(l_wr_buf);
		goto cont;
	}
	free(l_wr_buf);

	/* rewrite child brk instruction */
	if (rewrite_brk_inst(cpid, &inst_addr)) {
		/* Through */
	}

	/* child continue */
	if (ptrace(PTRACE_CONT, cpid, NULL, NULL)) {
		perror("ptrace(PTRACE_CONT)");
		goto cont;
	}

	/* wait child stop */
	if (wait_child_stop(cpid)) {
		goto out;
	}

	/* case 9:
	 * iov_len is sizeof(struct user_sve_header) +
	 * sizeof(struct fpsimd_sve_state(vq)) / 2
	 */
	printf("check  9: iov_len header + "
		"(registerarea size / 2) (16 byte align)\n");
	memset(&wr_buf, 0, sizeof(wr_buf));

	/* gen register */
	wr_buf.header = header;
	gen_test_sve(&wr_buf.regs, vq);

	/* PTRACE_SETREGSET */
	iov.iov_len = sizeof(struct user_sve_header) + align_half_regsz;
	iov.iov_base = &wr_buf;
	if (ptrace(PTRACE_SETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_SETREGSET)");
		goto cont;
	}

	/* rewrite child brk instruction */
	if (rewrite_brk_inst(cpid, &inst_addr)) {
		/* Through */
	}

	/* child continue */
	if (ptrace(PTRACE_CONT, cpid, NULL, NULL)) {
		perror("ptrace(PTRACE_CONT)");
		goto cont;
	}

	/* wait child stop */
	if (wait_child_stop(cpid)) {
		goto out;
	}

	/* case 10: iov_len is sizeof(struct user_sve_header) */
	printf("check 10: iov_len is sizeof(struct user_sve_header)\n");
	memset(&wr_buf, 0, sizeof(wr_buf));

	/* gen register */
	wr_buf.header = header;
	gen_test_sve(&wr_buf.regs, vq);

	/* PTRACE_SETREGSET */
	iov.iov_len = sizeof(struct user_sve_header);
	iov.iov_base = &wr_buf;
	if (ptrace(PTRACE_SETREGSET, cpid, NT_ARM_SVE, &iov)) {
		perror("ptrace(PTRACE_SETREGSET)");
		goto cont;
	}

	/* rewrite child brk instruction */
	if (rewrite_brk_inst(cpid, &inst_addr)) {
		/* Through */
	}

	/* child continue */
	if (ptrace(PTRACE_CONT, cpid, NULL, NULL)) {
		perror("ptrace(PTRACE_CONT)");
		goto cont;
	}

	/* wait child stop */
	if (wait_child_stop(cpid)) {
		goto out;
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
