#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "./test_chk.h"

#define TEST_NAME "CT_006"

int handled_cnt = 0;

void test_handler(int sig)
{
	handled_cnt++;
}

int main(int argc, char** argv)
{
	int rc = 0;
	int status;
	int tmp_flag = 0;
	struct sigaction sa, old_act;

	printf("*** %s start *******************************\n", TEST_NAME);

	sa.sa_handler = test_handler;
	sa.sa_flags = SA_RESETHAND;

	rc = sigaction(SIGUSR1, &sa, NULL);
	OKNG(rc != 0, "sigaction with SA_RESETHAND");

	rc = sigaction(SIGUSR1, NULL, &old_act);
	OKNG(rc != 0, "sigaction to get current action");

	if (old_act.sa_handler == test_handler &&
	    old_act.sa_flags & SA_RESETHAND) {
		tmp_flag = 1;
	}
	OKNG(tmp_flag != 1, "check current act");

	printf("*** %s PASSED\n\n", TEST_NAME);

	return 0;

fn_fail:
	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;
}
