#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "ihklib.h"
#include "util.h"

#define DELAY0 (100UL * 1000 * 1000)
#define DELAY1 (200UL * 1000 * 1000)
#define SCALE 1.5
#define WITHIN_RANGE(x, y, s) (x >= y && x <= y * s)

int main(int argc, char **argv)
{
	int ret = 0;
	struct ihk_os_rusage rusage;

	if ((ret = ihk_os_getrusage(0, &rusage))) {
		fprintf(stderr, "%s: ihk_os_getrusage failed\n", __func__);
		ret = -EINVAL;
		goto fn_fail;
	}

	OKNG(WITHIN_RANGE(rusage.cpuacct_usage_percpu[1], DELAY0, SCALE),
	     "cpu 0: user time: expected: %ld nsec, reported: %ld nsec\n",
	     DELAY0, rusage.cpuacct_usage_percpu[1]);
	OKNG(WITHIN_RANGE(rusage.cpuacct_usage_percpu[2], DELAY1, SCALE),
	     "cpu 1: user time: expected: %ld nsec, reported: %ld nsec\n",
	     DELAY1, rusage.cpuacct_usage_percpu[2]);

	printf("All tests finished\n");

 fn_fail:
	return ret;
}

