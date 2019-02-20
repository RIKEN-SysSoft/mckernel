/* 018.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* prctl(PR_SVE_SET_VL, PR_SVE_SET_VL_THREAD) on multi thread. */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include "common.h"

static int sync;
static void *child_function(void *arg)
{
	while (!sync) {
		cpu_pause();
	}
	return NULL;
}

TEST_FUNC(TEST_NUMBER, vl, unused1, unused2, unused3)
{
	int ret = -1;
	pthread_t thread;

	print_test_overview(tp_num);

	if (pthread_create(&thread, NULL, child_function, NULL)) {
		printf("pthread_create: error.\n");
		goto out;
	}

	ret = set_and_compare_vl(vl);
	if (ret != EINVAL) {
		printf("SVE_SET_VL is not EINVAL error.\n");
		goto join_out;
	}

	/* success */
	ret = 0;

join_out:
	sync = 1;
	if (pthread_join(thread, NULL)) {
		printf("pthread_join: error.\n");
		ret = -1;
	}
out:
	if (ret == 0) {
		printf("RESULT: OK.\n");
	} else {
		printf("RESULT: NG.\n");
	}
	return ret;
}
