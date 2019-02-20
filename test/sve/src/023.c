/* 023.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* Preservation VL check signalhsndler before and after. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/prctl.h>
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

TEST_FUNC(TEST_NUMBER, vl, vq, unused1, unused2)
{
	const int use_vq = sve_vq_from_vl(gen_set_vl(vl));
	struct fpsimd_sve_state(use_vq) rd_buf;
	struct fpsimd_sve_state(use_vq) wr_buf;
	unsigned int fpscr[2] = { 0, 0 };
	int ret = -1;
	unsigned int before_vl;
	unsigned int after_vl;

	print_test_overview(tp_num);

	memset(&rd_buf, 0, sizeof(rd_buf));
	memset(&wr_buf, 0, sizeof(wr_buf));

	if (signal(SIGUSR1, sig_handler) == SIG_ERR) {
		printf("Set signal handler failed.\n");
		goto out;
	}

	if (set_and_compare_vl(gen_set_vl(vl) | PR_SVE_VL_INHERIT)) {
		printf("prctl: error.\n");
		goto out;
	}

	/* before sighandler */
	gen_test_sve(&wr_buf, sve_vq_from_vl(gen_set_vl(vl)));
	write_sve(&wr_buf, sve_vq_from_vl(gen_set_vl(vl)), fpscr);

	before_vl = sve_get_vl();
	if (raise(SIGUSR1)) {
		perror("raise(SIGUSR1)");
		goto out;
	}
	after_vl = sve_get_vl();

	if (before_vl != after_vl) {
		printf("before VL=%d, after VL=%d\n", before_vl, after_vl);
		printf("VL compare failed.\n");
		goto out;
	}

	/* after sighandler */
	read_sve(&rd_buf, sve_vq_from_vl(after_vl), fpscr);

	/* compare */
	if (sve_compare(&wr_buf, &rd_buf, sve_vq_from_vl(after_vl))) {
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
