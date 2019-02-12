/* 036.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* It becomes SIGSEGV when changing and using SVE-VL during signalhandler execution. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/prctl.h>
#include "common.h"

static int segv_flag = 0;
static unsigned int set_vl = 0;
static int sig_handler_ret = 0;

static void sig_handler(int sig)
{
	int ret = -1;
	unsigned int fpscr[2] = { 0, 0 };
	unsigned int hndlr_vl = gen_set_vl(set_vl);
	void *wr_buf = calloc(1, (hndlr_vl * 35) + 15);
	void *align_wr_buf = (void *)(((unsigned long)(wr_buf + 15)) & ~15UL);

	if (!wr_buf) {
		printf("[in sighandler] calloc failed.\n");
		return;
	}

	/* set dirty */
	if (set_and_compare_vl(hndlr_vl)) {
		printf("[in sighandler] prctl: error.\n");
		goto out;
	}
	gen_test_sve_dirty(align_wr_buf, sve_vq_from_vl(hndlr_vl));
	write_sve(align_wr_buf, sve_vq_from_vl(hndlr_vl), fpscr);

	ret = 0;
out:
	free(wr_buf);
	sig_handler_ret = ret;
	return;
}

static void segv_handler(int sig)
{
	segv_flag = 1;
}

TEST_FUNC(TEST_NUMBER, vl, vq, unused1, unused2)
{
	int ret = -1;
	typedef struct fpsimd_sve_state(sve_vq_from_vl(gen_set_vl(vl))) sve_regs_t;
	sve_regs_t wr_buf;
	unsigned int fpscr[2] = { 0, 0 };

	print_test_overview(tp_num);

	memset(&wr_buf, 0, sizeof(wr_buf));

	if (signal(SIGUSR1, sig_handler) == SIG_ERR) {
		printf("Set signal handler(SIGUSR1) failed.\n");
		goto out;
	}

	if (signal(SIGSEGV, segv_handler) == SIG_ERR) {
		printf("Set signal handler(SIGSEGV) failed.\n");
		goto out;
	}

	set_vl = gen_set_vl(vl);
	if (set_and_compare_vl(set_vl | PR_SVE_VL_INHERIT)) {
		printf("prctl: error.\n");
		goto out;
	}

	/* before sighandler */
	gen_test_sve(&wr_buf, sve_vq_from_vl(set_vl));
	write_sve(&wr_buf, sve_vq_from_vl(set_vl), fpscr);

	if (raise(SIGUSR1)) {
		perror("raise(SIGUSR1)");
		goto out;
	}

	if (segv_flag != 1) {
		printf("SIGSEGV not handling.\n");
		goto out;
	}

	if (sig_handler_ret == 0) {
		/* success. */
		ret = 0;
	}
out:
	if (ret == 0) {
		printf("RESULT: OK.\n");
	} else {
		printf("RESULT: NG.\n");
	}
	return ret;
}
