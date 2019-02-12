/* 017.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* prctl(PR_SVE_SET_VL) check. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"

TEST_FUNC(TEST_NUMBER, vl, vq, unused1, unused2)
{
	typedef struct fpsimd_sve_state(vq) sve_regs_t;
	sve_regs_t wr_buf;
	sve_regs_t rd_buf;
	unsigned int fpscr[2] = { 0, 0 };
	int i = 0, ret = -1;
	const unsigned int set_vl_1 = gen_set_vl(vl);
	const unsigned int set_vl_2 = gen_set_vl(set_vl_1);
	struct {
		unsigned int vl;
		unsigned int flags;
		void *compare;
	} setting[] = { 
		{ set_vl_1, 0, NULL },
		{ set_vl_2, 0, NULL }
	};
	struct fpsimd_sve_state(sve_vq_from_vl(setting[0].vl)) cmp_0;
	struct fpsimd_sve_state(sve_vq_from_vl(setting[1].vl)) cmp_1;

	print_test_overview(tp_num);

	/* buffer initialize */
	memset(&wr_buf, 0, sizeof(wr_buf));
	memset(&rd_buf, 0, sizeof(rd_buf));

	memset(&cmp_0, 0, sizeof(cmp_0));
	memset(&cmp_1, 0, sizeof(cmp_1));
	gen_test_sve_low_128(&cmp_0, vq, sve_vq_from_vl(setting[0].vl));
	gen_test_sve_low_128(&cmp_1, vq, sve_vq_from_vl(setting[1].vl));
	setting[0].compare = &cmp_0;
	setting[1].compare = &cmp_1;

	/* write SVE (default VL) */
	gen_test_sve(&wr_buf, vq);
	write_sve(&wr_buf, vq, fpscr);
	read_sve(&rd_buf, vq, fpscr);

	if (sve_compare(&wr_buf, &rd_buf, vq)) {
		printf("Dirty SVE-register for default-VL, failed.\n");
		goto out;
	}

	for (i = 0; i < sizeof(setting) / sizeof(setting[0]); i++) {
		struct fpsimd_sve_state(sve_vq_from_vl(setting[i].vl)) work_buf;
		unsigned int work_fpscr[2] = { 0, 0 };

		if (set_and_compare_vl(setting[i].vl | setting[i].flags)) {
			printf("SVE_SET_VL compare failed.\n");
			goto out;
		}
		memset(&work_buf, 0, sizeof(work_buf));
		read_sve(&work_buf, (sve_vq_from_vl(setting[i].vl)), work_fpscr);

		if (sve_compare(setting[i].compare, &work_buf, sve_vq_from_vl(setting[i].vl))) {
			printf("After SET_VL compare failed.\n");
			goto out;
		}
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
