/* 029.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* Use execve() VL check if not setting INHERIT flags. (execve target is #1 testcase) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "common.h"

extern char **environ;
TEST_FUNC(TEST_NUMBER, vl, vq, unused1, tp_argv)
{
	char *self = (char *)tp_argv[0];
	typedef struct fpsimd_sve_state(vq) sve_regs_t;
	sve_regs_t rd_buf;
	sve_regs_t wr_buf;
	unsigned int fpscr[2] = { 0, 0 };
	char *execve_args[] = {
		"", "1", NULL
	};
	int ret = -1;

	print_test_overview(tp_num);

	memset(&rd_buf, 0, sizeof(rd_buf));
	memset(&wr_buf, 0, sizeof(wr_buf));

	gen_test_sve(&wr_buf, vq);
	write_sve(&wr_buf, vq, fpscr);
	read_sve(&rd_buf, vq, fpscr);

	if (sve_compare(&wr_buf, &rd_buf, vq)) {
		printf("Dirty SVE-register before executing execve(), NG.\n");
		goto out;
	}
	printf("Dirty SVE-register before executing execve(), OK.\n");

	if (set_and_compare_vl(gen_set_vl(vl))) {
		printf("prctl: error.\n");
		goto out;
	}

	printf("=== look at the contents of the register since run execve. ===\n");

	ret = execve(self, execve_args, environ);
	if (ret == -1) {
		perror("execve()");
	} else {
		ret = -1;
		printf("Why return execve() ???\n");
	}
out:
	printf("RESULT: NG.\n");
	return ret;
}
