#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include "fwq.h"

static double nspw; /* nsec per work */

void fwq_init(void)
{
	struct timespec start, end;
	unsigned long nsec;
	int i;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
#define N_INIT 10000000
	bulk_fsw(N_INIT);
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	nsec = DIFFNSEC(end, start);
	nspw = nsec / (double)N_INIT;
}

void fwq(long delay_nsec)
{
	if (delay_nsec < 0) {
		return;
		//printf("%s: delay_nsec < 0\n", __func__);
	}
	bulk_fsw(delay_nsec / nspw);
}
