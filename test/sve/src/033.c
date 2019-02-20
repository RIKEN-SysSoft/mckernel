/* 033.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* Use pthread_create() VL check if setting ONEXEC flags. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common.h"

static void *child_function(void *arg)
{
	void *ret = (void *)-1;
	unsigned int vl = sve_get_vl();
	unsigned int vq = sve_vq_from_vl(vl);
	unsigned int *exp_vl = (unsigned int *)arg;
	void *rd_buf = calloc(1, (vl * 35) + 15);
	void *cmp_buf = NULL, *align_cmp_buf = NULL;
	void *align_rd_buf = (void *)(((unsigned long)(rd_buf + 15)) & ~15UL);
	unsigned int fpscr[2] = { 0, 0 };

	if (!rd_buf) {
		printf("calloc() failed.\n");
		goto out;
	}

	if (get_and_compare_vl(*exp_vl)) {
		printf("prctl: error.\n");
		goto rd_free_out;
	}
	read_sve(align_rd_buf, vq, fpscr);

	cmp_buf = calloc(1, (vl * 35) + 15);
	if (!cmp_buf) {
		printf("calloc() failed.\n");
		goto rd_free_out;
	}
	align_cmp_buf = (void *)(((unsigned long)(rd_buf + 15)) & ~15UL);
	gen_test_sve_low_128(align_cmp_buf, vq, vq);

	if (sve_compare(align_cmp_buf, align_rd_buf, vq)) {
		printf("child-thread register compare failed.\n");
		goto cmp_free_out;
	}

	/* success */
	ret = NULL;

cmp_free_out:
	free(cmp_buf);
rd_free_out:
	free(rd_buf);
out:
	pthread_exit(ret);
	return NULL;
}

TEST_FUNC(TEST_NUMBER, vl, vq, unused1, unused2)
{
	void *pret = (void *)-1;
	struct fpsimd_sve_state(vq) rd_buf;
	struct fpsimd_sve_state(vq) wr_buf;
	unsigned int fpscr[2] = { 0, 0 };
	pthread_t thread;
	int ret = -1;

	print_test_overview(tp_num);

	memset(&rd_buf, 0, sizeof(rd_buf));
	memset(&wr_buf, 0, sizeof(wr_buf));

	gen_test_sve(&wr_buf, vq);
	write_sve(&wr_buf, vq, fpscr);
	read_sve(&rd_buf, vq, fpscr);

	if (sve_compare(&wr_buf, &rd_buf, vq)) {
		printf("parent-thread compare failed.\n");
		goto out;
	}

	if (set_and_compare_vl(gen_set_vl(vl) | PR_SVE_SET_VL_ONEXEC)) {
		printf("prctl: error.\n");
		goto out;
	}

	memset(&thread, 0, sizeof(thread));
	if (pthread_create(&thread, NULL, child_function, &vl)) {
		printf("pthread_create: error.\n");
		goto out;
	}

	if (pthread_join(thread, &pret)) {
		printf("pthread_join: error.\n");
		goto out;
	}

	if (pret != NULL) {
		printf("child thread error.\n");
		goto out;
	}
	ret = 0;
out:
	if (ret == 0) {
		printf("RESULT: OK.\n");
	} else {
		printf("RESULT: NG.\n");
	}
	return ret;
}
