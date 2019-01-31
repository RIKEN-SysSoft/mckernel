/* 019.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* prctl(PR_SVE_SET_VL) parameters pattern check. */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include "common.h"

TEST_FUNC(TEST_NUMBER, vl, unused1, unused2, unused3)
{
	int ret = 0, func_ret = 0;
	int i, j;

	struct params {
		unsigned int vl;
		unsigned int flags;
	};
	struct params unsup_vl[] = { { UNSPPORT_VL, 0 } };
	struct params inval_vl[] = { { INVALID_VL_1, 0 }, { INVALID_VL_2, 0 }, { INVALID_VL_3, 0 } };
	struct params inval_fl[] = { { vl, PR_SVE_INVALID_FLAGS } };

	struct {
		char *pattern_string;
		struct params *param;
		int param_count;
	} testcases[] = {
		{ "unsupport VL" , unsup_vl, sizeof(unsup_vl) / sizeof(unsup_vl[0]) },
		{ "invalid VL",    inval_vl, sizeof(inval_vl) / sizeof(inval_vl[0]) },
		{ "invalid FLAGS", inval_fl, sizeof(inval_fl) / sizeof(inval_fl[0]) }
	};

	print_test_overview(tp_num);

	for (i = 0; i < sizeof(testcases) / sizeof(testcases[0]); i++) {
		printf("check %d : %s setting.\n", i, testcases[i].pattern_string);

		for (j = 0; j < testcases[i].param_count; j++) {
			func_ret = set_and_compare_vl(testcases[i].param[j].vl | testcases[i].param[j].flags);
			if (func_ret != EINVAL) {
				printf("%s (%d, %d) setting successed.\n",
					testcases[i].pattern_string, testcases[i].param[j].vl,
					testcases[i].param[j].flags);
				printf("RESULT: NG.\n");
				ret = -1;
				goto out;
			}
		}
	}
	printf("RESULT: OK.\n");
out:
	return ret;
}
