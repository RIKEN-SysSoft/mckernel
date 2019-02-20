/* 011.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
/* Preservation check signalhsndler(use sigaltstack) before and after. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include "common.h"

static unsigned long used_stack_addr;

static void sig_handler(int sig)
{
	unsigned int vl = sve_get_vl();
	unsigned int vq = sve_vq_from_vl(vl);
	void *wr_buf = calloc(1, (vl * 35) + 15);
	void *align_wr_buf = (void *)(((unsigned long)(wr_buf + 15)) & ~15UL);
	unsigned int fpscr[2] = { 0, 0 };

	if (!wr_buf) {
		printf("calloc() failed.\n");
		return;
	}

	/* stack addr set */
	used_stack_addr = (unsigned long)&vl;

	/* set dirty */
	gen_test_sve_dirty(align_wr_buf, vq);
	write_sve(align_wr_buf, vq, fpscr);

	free(wr_buf);
}

#define ALTSTACK_SIZE 16384 /* recommendation size */

TEST_FUNC(TEST_NUMBER, unused1, vq, unused2, unused3)
{
	struct fpsimd_sve_state(vq) rd_buf;
	struct fpsimd_sve_state(vq) wr_buf;
	stack_t ss;
	unsigned int fpscr[2] = { 0, 0 };
	int ret = -1;
	void *sstack = calloc(1, ALTSTACK_SIZE);
	void *cmp_ss = calloc(1, ALTSTACK_SIZE);
	struct sigaction act;

	print_test_overview(tp_num);

	memset(&rd_buf, 0, sizeof(rd_buf));
	memset(&wr_buf, 0, sizeof(wr_buf));

	if (!sstack || !cmp_ss) {
		printf("calloc() failed.\n");
		goto end;
	}

	memset(&ss, 0, sizeof(ss));
	ss.ss_sp = sstack;
	ss.ss_size = ALTSTACK_SIZE;
	ss.ss_flags = 0;

	if (sigaltstack(&ss, NULL)) {
		perror("sigaltstack");
		goto out;
	}

	memset(&act, 0, sizeof(act));
	act.sa_flags = SA_ONSTACK | SA_RESETHAND;
	act.sa_handler = sig_handler;
	if (sigaction(SIGUSR1, &act, NULL)) {
		perror("sigaction()");
		goto out;
	}

	/* before sighandler */
	gen_test_sve(&wr_buf, vq);
	write_sve(&wr_buf, vq, fpscr);

	if (raise(SIGUSR1)) {
		perror("raise(SIGUSR1)");
		goto out;
	}

	if ((unsigned long)ss.ss_sp > used_stack_addr ||
		used_stack_addr >= (unsigned long)ss.ss_sp + ss.ss_size) {
		printf("altstack area unused.\n");
		goto out;
	}

	/* after sighandler */
	read_sve(&rd_buf, vq, fpscr);

	/* compare */
	if (sve_compare(&wr_buf, &rd_buf, vq)) {
		printf("compare failed.\n");
		goto out;
	}

	/* success. */
	ret = 0;
out:
	free(sstack);
	free(cmp_ss);
end:
	if (ret == 0) {
		printf("RESULT: OK.\n");
	} else {
		printf("RESULT: NG.\n");
	}
	return ret;
}
