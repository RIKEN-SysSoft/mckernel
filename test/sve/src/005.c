/* 005.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
/* Preservation register check signalhsndler before and after. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include "common.h"

static void sig_handler(int sig)
{
	unsigned int vl = sve_get_vl();
	unsigned int vq = sve_vq_from_vl(vl);
	void *wr_buf = calloc(1, (vl * 35) + 15);
	void *align_wr_buf = (void *)(((unsigned long)(wr_buf + 15)) & ~15UL);
	unsigned int fpscr[2] = { 0, 0 };

	if (!wr_buf) {
		printf("calloc() failed.\n");
		goto out;
	}

	/* set dirty */
	gen_test_sve_dirty(align_wr_buf, vq);
	write_sve(align_wr_buf, vq, fpscr);

	free(wr_buf);
out:
	return;
}

TEST_FUNC(TEST_NUMBER, unused1, vq, unused2, unused3)
{
	struct fpsimd_sve_state(vq) rd_buf;
	struct fpsimd_sve_state(vq) wr_buf;
	unsigned int fpscr[2] = { 0, 0 };
	int ret = -1;

	print_test_overview(tp_num);

	memset(&rd_buf, 0, sizeof(rd_buf));
	memset(&wr_buf, 0, sizeof(wr_buf));

	if (signal(SIGUSR1, sig_handler) == SIG_ERR) {
		printf("Set signal handler failed.\n");
		goto out;
	}

	/* before sighandler */
	gen_test_sve(&wr_buf, vq);
	write_sve(&wr_buf, vq, fpscr);

	if (raise(SIGUSR1)) {
		perror("raise(SIGUSR1)");
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
	if (ret == 0) {
		printf("RESULT: OK.\n");
	} else {
		printf("RESULT: NG.\n");
	}
	return ret;
}
