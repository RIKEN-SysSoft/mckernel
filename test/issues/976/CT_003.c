#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "./test_chk.h"

#include <fenv.h>

#define TEST_NAME "CT_003"

int main(int argc, char *argv[])
{
	fenv_t fenv;
	int rc = 0;
	int round = 0;
	char *exargv[3] = {argv[0], "stop", NULL};
	char *exenvp[1] = {NULL};

	printf("*** %s start ********************************\n", TEST_NAME);
	round = fegetround();
	OKNG(round != FE_TONEAREST, "fegetround  returned %d"
		"\n      (expect return is FE_TONEAREST(%d))",
		round, FE_TONEAREST);

	rc = fesetround(FE_TOWARDZERO);
	OKNG(rc != 0, "fesetround(FE_TOWARDZERO) returned %d"
		"\n      (expect return is 0)", rc);

	round = fegetround();
	OKNG(round != FE_TOWARDZERO, "fegetround  returned %d"
		"\n      (expect return is FE_TOWARDZERO(%d))",
		round, FE_TOWARDZERO);


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
