#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "./test_chk.h"

#define TEST_NAME "CT_002"

int main(int argc, char **argv)
{
	struct rlimit get_rlim, set_rlim;
	int rc, resource;
	int __errno;
	rlim_t set_max, set_cur;


	printf("*** %s start *******************************\n", TEST_NAME);
	CHKANDJUMP(geteuid() != 0, "Test needs to be run as root");

	resource = RLIMIT_NPROC;
	rc = getrlimit(resource, &get_rlim);

	OKNG(rc != 0, "getrlimit cur:%lx max:%lx",
		get_rlim.rlim_cur, get_rlim.rlim_max);

	set_max = get_rlim.rlim_max + 10;
	if (get_rlim.rlim_cur > set_max) {
		set_cur = set_max;
	}
	else {
		set_cur = get_rlim.rlim_cur;
	}

	set_rlim.rlim_cur = set_cur;
	set_rlim.rlim_max = set_max;

	errno = 0;
	rc = setrlimit(resource, &set_rlim);
	__errno = errno;

	OKNG(rc != 0, "setrlimit cur:%lx max:%lx  returned %d"
		" (expect return is 0)",
		set_rlim.rlim_cur, set_rlim.rlim_max, rc);

	OKNG(__errno != 0, "errno after setrlimit :%d"
		" (expect error is 0)", __errno);

	rc = getrlimit(resource, &get_rlim);
	OKNG(get_rlim.rlim_max != set_max, "getrlimit cur:%lx max:%lx"
		" (expect max is %lx)",
		get_rlim.rlim_cur, get_rlim.rlim_max, set_max);

	printf("*** %s PASSED\n\n", TEST_NAME);

	return 0;

fn_fail:
	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;
}
