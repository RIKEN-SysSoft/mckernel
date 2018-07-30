#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "./test_chk.h"

#define TEST_NAME "CT_005"

int main(int argc, char **argv)
{
	int rc = 0;
	int status;

	printf("*** %s start *******************************\n", TEST_NAME);

	rc = sigaction(SIGUSR1, NULL, NULL);
	OKNG(rc != 0, "SIGUSR1 is valid");

	rc = sigaction(SIGKILL, NULL, NULL);
	OKNG(rc != 0, "SIGKILL is valid");

	rc = sigaction(SIGSTOP, NULL, NULL);
	OKNG(rc != 0, "SIGSTOP is valid");

	rc = sigaction(_NSIG, NULL, NULL);
	OKNG(rc != -1, "_NSIG is invalid");

	printf("*** %s PASSED\n\n", TEST_NAME);

	return 0;

fn_fail:
	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;
}
