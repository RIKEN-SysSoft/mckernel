/* 001.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
/* Process starts immediately after registers check. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

TEST_FUNC(TEST_NUMBER, unused1, vq, unused2, unused3)
{
	int ret = 0;
	struct fpsimd_sve_state(vq) exp_buf;
	struct fpsimd_sve_state(vq) rd_buf;
	unsigned int fpscr[2] = { 0, 0 };

	print_test_overview(tp_num);

	read_sve(&rd_buf, vq, fpscr);

	memset(&exp_buf, 0, sizeof(exp_buf));

	if (sve_compare(&exp_buf, &rd_buf, vq)) {
		printf("RESULT: NG.\n");
		ret = -1;
	}
	else {
		printf("RESULT: OK.\n");
	}
	return ret;
}
