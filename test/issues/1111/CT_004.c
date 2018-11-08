#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "./test_chk.h"

#define TEST_NAME "CT_004"

int main(int argc, char **argv)
{
	int rc = 0;
	int status;
	int tmp_flag = 0;
	struct sigaction old_act;

	printf("*** %s start *******************************\n", TEST_NAME);

	rc = sigaction(SIGKILL, NULL, &old_act);
	OKNG(rc != 0, "sigaction to get SIGKILL action");

	if (old_act.sa_handler == SIG_DFL) {
		tmp_flag = 1;
	}
	OKNG(tmp_flag != 1, "check SIGKILL act");

	rc = sigaction(SIGSTOP, NULL, &old_act);
	OKNG(rc != 0, "sigaction to get SIGSTOP action");

	tmp_flag = 0;
	if (old_act.sa_handler == SIG_DFL) {
		tmp_flag = 1;
	}
	OKNG(tmp_flag != 1, "check SIGSTOP act");

	printf("*** %s PASSED\n\n", TEST_NAME);

	return 0;

fn_fail:
	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;
}
