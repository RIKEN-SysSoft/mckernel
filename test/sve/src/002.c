/* 002.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
/* Use fork() takeover registers check. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include "common.h"

TEST_FUNC(TEST_NUMBER, unused1, vq, unused2, unused3)
{
	struct fpsimd_sve_state(vq) rd_buf;
	struct fpsimd_sve_state(vq) wr_buf;
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
		printf("parent-process register compare failed.\n");
		goto out;
	}

	cpid = fork();
	switch (cpid) {
	case -1:
		/* error */
		printf("ERROR: fork()=%d, errno=%d\n", cpid, errno);
		goto out;
	case 0: {
		/* child process */
		struct fpsimd_sve_state(vq) c_rd_buf;
		struct fpsimd_sve_state(vq) c_cmp_buf;

		memset(&c_rd_buf, 0, sizeof(struct fpsimd_sve_state(vq)));
		read_sve(&c_rd_buf, vq, fpscr);

		memset(&c_cmp_buf, 0, sizeof(struct fpsimd_sve_state(vq)));
		gen_test_sve_low_128(&c_cmp_buf, vq, vq);

		if (sve_compare(&c_cmp_buf, &c_rd_buf, vq)) {
			printf("child-process register compare failed.\n");
			exit(-1);
		}
		exit(0);
		break;
	}
	default:
		/* parent process */
		/* wait child */
		if (wait_child_exit(cpid)) {
			goto out;
		}
		break;
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
