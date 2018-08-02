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
#include "util.h"

/* Messaging */
enum test_loglevel test_loglevel = TEST_LOGLEVEL_DEBUG;

/* Calculation */
static inline void asmloop(unsigned long n) {
	int j;

	for (j = 0; j < n; j++) {
	asm volatile(
	    "movq $0, %%rcx\n\t"
		"1:\t"
		"addq $1, %%rcx\n\t"
		"cmpq $99, %%rcx\n\t"
		"jle 1b\n\t"
		:
		: 
		: "rcx", "cc");
	} 
}

#define N_INIT 10000000
double nspw; /* nsec per work */

void ndelay_init() {
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
	pr_debug("nspw=%f\n", nspw);
}

#if 1
void ndelay(long delay_nsec) {
	if (delay_nsec < 0) { 
		printf("delay_nsec < 0\n");
		return;
	}
#pragma omp parallel
	{
		asmloop(delay_nsec / nspw);
	}
}
#else /* For machines with large core-to-core performance variation (e.g. OFP) */
void ndelay(long delay_nsec) {
	struct timespec start, end;
	
	if (delay_nsec < 0) { return; }
	clock_gettime(TIMER_KIND, &start);

	while (1) {
		clock_gettime(TIMER_KIND, &end);
		if (DIFFNSEC(end, start) >= delay_nsec) {
			break;
		}
		asmloop(2); /* ~150 ns per iteration on FOP */
	}
}
#endif


double cycpw; /* cyc per work */

void cdlay_init() {
	unsigned long start, end;

	start = rdtsc_light();
#define N_INIT 10000000
	asmloop(N_INIT);
	end = rdtsc_light();
	cycpw = (end - start) / (double)N_INIT;
}

#if 0
void cdelay(long delay_cyc) {
	if (delay_cyc < 0) { 
		return;
	}
	asmloop(delay_cyc / cycpw);
}
#else /* For machines with large core-to-core performance variation (e.g. OFP) */
void cdelay(long delay_cyc) {
	unsigned long start, end;
	
	if (delay_cyc < 0) { return; }
	start = rdtsc_light();

	while (1) {
		end = rdtsc_light();
		if (end - start >= delay_cyc) {
			break;
		}
		asmloop(2);
	}
}
#endif
