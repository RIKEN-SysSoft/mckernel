/* 038.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* Confirmation of execve() operation when VL is set
 * in ONEXEC->INHERIT order.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "common.h"

extern char **environ;
TEST_FUNC(TEST_NUMBER, vl, unused2, tp_argc, tp_argv)
{
	char *self = (char *)tp_argv[0];
	char arg0[FILENAME_MAX] = "";
	char arg1[8] = "";
	char arg2[8] = "";
	char arg3[8] = "";
	char *execve_args[5];
	int rest = 0, ret = -1;
	unsigned int exp_vl = 0;
	unsigned int dfl_vl = 0;

	/* First time */
	if (tp_argc == 2) {
		unsigned int set_vl_1 = 0;
		unsigned int set_vl_2 = 0;

		print_test_overview(tp_num);

		/* ONEXEC setting */
		set_vl_1 = gen_set_vl(vl);
		if (set_and_compare_vl(set_vl_1 | PR_SVE_SET_VL_ONEXEC)) {
			printf("prctl: error.\n");
			goto out;
		}

		/* INHERIT setting */
		set_vl_2 = gen_set_vl(set_vl_1);
		if (set_and_compare_vl(set_vl_2 | PR_SVE_VL_INHERIT)) {
			printf("prctl: error.\n");
			goto out;
		}
		rest = 2;
		dfl_vl = vl;
	/* After the execve() */
	} else {
		rest = atoi(tp_argv[2]);
		dfl_vl = atoi(tp_argv[3]);
		rest--;

		exp_vl = gen_set_vl(gen_set_vl(dfl_vl));
		if (get_and_compare_vl(exp_vl | PR_SVE_VL_INHERIT)) {
			printf("prctl: error.\n");
			goto out;
		}
	}

	if (rest != 0) {
		memcpy(arg0, self, strlen(self) + 1);
		memcpy(arg1, tp_argv[1], strlen(tp_argv[1]) + 1);
		sprintf(arg2, "%d", rest);
		sprintf(arg3, "%d", dfl_vl);

		execve_args[0] = arg0;
		execve_args[1] = arg1;
		execve_args[2] = arg2;
		execve_args[3] = arg3;
		execve_args[4] = NULL;

		ret = execve(self, execve_args, environ);
		if (ret == -1) {
			perror("execve()");
			goto out;
		}
	}

	ret = 0;
out:
	if (ret != 0) {
		printf("RESULT: NG.\n");
	} else {
		printf("RESULT: OK.\n");
	}
	return ret;
}
