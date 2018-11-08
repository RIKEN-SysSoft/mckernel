#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "./test_chk.h"

#define TEST_NAME "CT_001"

int main(int argc, char *argv[])
{
	time_t now;
	long sys_ret;
	int ng_flag = 0;

	printf("*** %s start *******************************\n", TEST_NAME);

	/* get seconds since the Epoch by glibc time() */
	now = time(NULL);

	/* get seconds since the Epoch by syscall_time */
	sys_ret = syscall(__NR_time, NULL);

	if (now != sys_ret) {
		/* check again only once */
		now = time(NULL);
		if (now != sys_ret) {
			ng_flag = 1;
		}
	}
	printf("glibc time(): %ld seconds\n", now);
	printf("sys_time    : %ld seconds\n", sys_ret);

	OKNG(ng_flag != 0, "check seconds since the Epoch");
	printf("*** %s PASSED\n\n", TEST_NAME);

	return 0;

fn_fail:

	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;
}

