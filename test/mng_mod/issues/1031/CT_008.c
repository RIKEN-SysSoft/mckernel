#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "./test_chk.h"

#define TEST_NAME "CT_008"

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

	rc = sigaction(0, &sa, NULL);
	OKNG(rc != -1, "sigaction 0 failed");

	rc = sigaction(_NSIG, &sa, NULL);
	OKNG(rc != -1, "sigaction _NSIG failed");

	rc = sigaction(SIGKILL, &sa, NULL);
	OKNG(rc != -1, "sigaction SIGKILL failed");

	rc = sigaction(SIGSTOP, &sa, NULL);
	OKNG(rc != -1, "sigaction SIGSTOP failed");

	printf("*** %s PASSED\n\n", TEST_NAME);

	return 0;

fn_fail:
	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;
}
