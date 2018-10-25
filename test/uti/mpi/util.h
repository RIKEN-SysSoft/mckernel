#ifndef __UTIL_H_INCLUDED__
#define __UTIL_H_INCLUDED__

#include <stdint.h>
#include <mpi.h>

/* Calculation */

static inline void asmloop(unsigned long n)
{
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

/* Messaging */

enum test_loglevel {
	TEST_LOGLEVEL_ERR = 0,
	TEST_LOGLEVEL_WARN,
	TEST_LOGLEVEL_DEBUG
};

extern enum test_loglevel test_loglevel;
static inline void test_set_loglevel(enum test_loglevel level)
{
	test_loglevel = level;
}

#define pr_level(level, fmt, args...) do {	\
	if (test_loglevel >= level) {	\
		fprintf(stdout, fmt, ##args);	\
	}					\
} while (0)

#define pr_err(fmt, args...) pr_level(TEST_LOGLEVEL_ERR, fmt, ##args)
#define pr_warn(fmt, args...) pr_level(TEST_LOGLEVEL_WARN, fmt, ##args)
#define pr_debug(fmt, args...) pr_level(TEST_LOGLEVEL_DEBUG, fmt, ##args)

#define _OKNG(verb, jump, cond, fmt, args...) do {	\
	if (cond) {					\
		if (verb)				\
			printf("[ OK ] " fmt, ##args);	\
	} else {					\
		printf("[ NG ] " fmt, ##args);		\
		if (jump) {				\
			ret = -1;			\
			goto out;			\
		}					\
	}						\
} while (0)

#define OKNG(args...) _OKNG(1, 1, ##args)
#define NG(args...) _OKNG(0, 1, ##args)
#define OKNGNOJUMP(args...) _OKNG(1, 0, ##args)


/* Time */

#define MYTIME_TOUSEC 1000000
#define MYTIME_TONSEC 1000000000
#define N_INIT 10000000 /* 100 loop takes 500 ns on KNL */
#define MAX2(x, y) ((x) > (y) ? (x) : (y))

inline uint64_t rdtsc_light(void)
{
    uint64_t x;
    __asm__ __volatile__("rdtscp;" /* rdtscp don't jump over earlier instructions */
                         "shl $32, %%rdx;"
                         "or %%rdx, %%rax" :
                         "=a"(x) :
                         :    
                         "%rcx", "%rdx", "memory");
    return x;
}

inline double mytime(void)
{
	return /*rdtsc_light()*/MPI_Wtime();
}

#define DIFFUSEC(end, start) ((end.tv_sec - start.tv_sec) * 1000000UL + (end.tv_usec - start.tv_usec))
#define DIFFNSEC(end, start) ((end.tv_sec - start.tv_sec) * 1000000000UL + (end.tv_nsec - start.tv_nsec))
#define TIMER_KIND CLOCK_MONOTONIC_RAW /* CLOCK_THREAD_CPUTIME_ID */


/* Calculation emulation */

void ndelay_init(void);
void ndelay(long delay_nsec);
void cdelay_init(void);
void cdelay(long delay_cyc);

/* CPU location */

int print_cpu_last_executed_on();

#endif
