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
#include "delay.h"

#define N_INIT 10000000
double nspw; /* nsec per work */

void ndelay_init(int verbose)
{
	struct timeval start, end;

	//clock_gettime(TIMER_KIND, &start);
	gettimeofday(&start, NULL);

#pragma omp parallel
	{
		asmloop(N_INIT);
	}

	//clock_gettime(TIMER_KIND, &end);
	gettimeofday(&end, NULL);

	nspw = DIFFUSEC(end, start) * 1000 / (double)N_INIT;
	if (verbose) {
		pr_debug("nspw=%f\n", nspw);
	}
}

void ndelay(long delay_nsec)
{
	if (delay_nsec < 0) {
		printf("delay_nsec < 0\n");
		return;
	}
#pragma omp parallel
	{
		asmloop(delay_nsec / nspw);
	}
}

static double cycpw; /* cyc per work */

void cdlay_init(void)
{
	unsigned long start, end;

	start = rdtsc_light();
#define N_INIT 10000000
	asmloop(N_INIT);
	end = rdtsc_light();
	cycpw = (end - start) / (double)N_INIT;
}

void cdelay(long delay_cyc)
{
	if (delay_cyc < 0) {
		return;
	}
	asmloop(delay_cyc / cycpw);
}
