/* 027.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* Use fork() VL check if not setting INHERIT flags. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h> 
#include "common.h"

TEST_FUNC(TEST_NUMBER, vl, vq, unused1, unused2)
{
	typedef struct fpsimd_sve_state(vq) sve_regs_t;
	typedef struct fpsimd_sve_state(sve_vq_from_vl(gen_set_vl(vl))) c_sve_regs_t;
	sve_regs_t rd_buf;
	sve_regs_t wr_buf;
	unsigned int fpscr[2] = { 0, 0 };
	pid_t cpid = 0;
	int ret = -1;

	print_test_overview(tp_num);

	memset(&rd_buf, 0, sizeof(rd_buf));
	memset(&wr_buf, 0, sizeof(wr_buf));

	gen_test_sve(&wr_buf, vq);
	write_sve(&wr_buf, vq, fpscr);
	read_sve(&rd_buf, vq, fpscr);

	if (sve_compare(&wr_buf, &rd_buf, vq)) {
		printf("parent-process Dirty SVE-register setting failed.\n");
		goto out;
	}

	if (set_and_compare_vl(gen_set_vl(vl))) {
		printf("prctl: error.\n");
		goto out;
	}

	cpid = fork();
	switch (cpid) {
	case -1:
		/* error */
		printf("ERROR: fork()=%d, errno=%d\n", cpid, errno);
		goto out;
		break;
	case 0: {
		/* child process */
		c_sve_regs_t c_rd_buf;
		c_sve_regs_t c_cmp_buf;

		memset(&c_rd_buf, 0, sizeof(c_rd_buf));
		if (get_and_compare_vl(gen_set_vl(vl))) {
			printf("prctl: error.\n");
			exit(-1);
		}
		read_sve(&c_rd_buf, sve_vq_from_vl(gen_set_vl(vl)), fpscr);

		memset(&c_cmp_buf, 0, sizeof(c_cmp_buf));
		gen_test_sve_low_128(&c_cmp_buf, vq, sve_vq_from_vl(gen_set_vl(vl)));

		if (sve_compare(&c_cmp_buf, &c_rd_buf, sve_vq_from_vl(gen_set_vl(vl)))) {
			printf("child-process compare failed.\n");
			exit(-1);
		}
		exit(0);
		break;
	}
	default:
		/* parent process */
		if (wait_child_exit(cpid)) {
			goto out;
		}
		break;
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
