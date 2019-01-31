/* 040.c COPYRIGHT FUJITSU LIMITED 2019 */
/* coredump SVE register output check. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

TEST_FUNC(TEST_NUMBER, unused1, vq, unused2, unused3)
{
	typedef struct fpsimd_sve_state(vq) sve_regs_t;
	sve_regs_t wr_buf;
	unsigned int fpscr[2] = { 0, 0 };
	unsigned int *null_p = NULL;

	print_test_overview(tp_num);

	memset(&wr_buf, 0, sizeof(wr_buf));

	gen_test_sve(&wr_buf, vq);
	write_sve(&wr_buf, vq, fpscr);

	/* gen Segmentation fault. */
	*null_p = 1;

	return 0;
}
