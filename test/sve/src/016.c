/* 016.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* prctl(PR_SVE_GET_VL) check. */
#include <stdio.h>
#include <stdlib.h>
#include "common.h"

TEST_FUNC(TEST_NUMBER, vl, unused1, unused2, unused3)
{
	int ret = -1;

	print_test_overview(tp_num);

	ret = get_and_compare_vl(vl);
	if (ret == 0) {
		printf("Expected VL (0x%x) == return VL (0x%x).\n", vl, vl);
		printf("RESULT: OK.\n");
	} else {
		printf("SVE_GET_VL compare failed.\n");
		printf("RESULT: NG.\n");
	}
	return ret;
}
