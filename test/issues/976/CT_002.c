#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "./test_chk.h"

#include <fenv.h>

#define TEST_NAME "CT_002"

int main(int argc, char *argv[])
{
	fenv_t fenv;
	int rc = 0;
	int round = 0;
	double dummy = 0;
	char *exargv[3] = {argv[0], "stop", NULL};
	char *exenvp[1] = {NULL};

	printf("*** %s start ********************************\n", TEST_NAME);
	rc = fetestexcept(FE_ALL_EXCEPT);
	OKNG(rc != 0, "fetestexcept(FE_ALL_EXCEPT) returned %d"
		"\n      (expect return is 0)", rc);

	dummy = (double)0 / 0;
	rc = fetestexcept(FE_ALL_EXCEPT);
	OKNG(rc != FE_INVALID, "fetestexcept(FE_ALL_EXCEPT) returned %d"
		"\n      (expect return is FE_INVALID(%d))", rc, FE_INVALID);

	rc = feraiseexcept(FE_ALL_EXCEPT);
	OKNG(rc != 0, "feraiseexcept(FE_ALL_EXCEPT) returned %d"
		"\n      (expect return is 0)", rc);

	rc = fetestexcept(FE_ALL_EXCEPT);
	OKNG(rc != FE_ALL_EXCEPT, "fetestexcept(FE_ALL_EXCEPT) returned %d"
		"\n      (expect return is FE_ALL_EXCEPT(%d))",
		rc, FE_ALL_EXCEPT);

	if (argc < 2) {
		printf("** Re-run by execve\n");
		execve(exargv[0], exargv, exenvp);
	}

	printf("*** %s PASSED\n\n", TEST_NAME);

	return 0;

fn_fail:
	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;
}
