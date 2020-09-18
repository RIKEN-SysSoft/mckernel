#ifndef __UTIL_H_INCLUDED__
#define __UTIL_H_INCLUDED__

#include <stdint.h>

#define isb()       asm volatile("isb" : : : "memory")

#define DEBUG

#ifdef DEBUG
#define dprintf(...) do {			 \
	char msg[1024];			 \
	sprintf(msg, __VA_ARGS__);		 \
	fprintf(stderr, "%s,%s", __func__, msg); \
} while (0)
#else
#define dprintf(...) do {  } while (0)
#endif

#define eprintf(...) do {			 \
	char msg[1024];			 \
	sprintf(msg, __VA_ARGS__);		 \
	fprintf(stderr, "%s,%s", __func__, msg); \
} while (0)

#define CHKANDJUMP(cond, err, ...) do { \
	if (cond) {			\
		eprintf(__VA_ARGS__);   \
		ret = err;		\
		goto fn_fail;		\
	}				\
} while (0)

#define _OKNG(verb, jump, cond, fmt, args...) do {	\
	if (cond) {					\
		if (verb)				\
			printf("[ OK ] " fmt, ##args);	\
	} else {					\
		printf("[ NG ] " fmt, ##args);		\
		if (jump)				\
			goto fn_fail;			\
	}						\
} while (0)

#define OKNG(args...) _OKNG(1, 1, ##args)
#define NG(args...) _OKNG(0, 1, ##args)
#define OKNGNOJUMP(args...) _OKNG(1, 0, ##args)

#define DIFFNSEC(end, start) ((end.tv_sec - start.tv_sec) * 1000000000UL + (end.tv_nsec - start.tv_nsec))
#define TIMER_KIND CLOCK_MONOTONIC_RAW /* CLOCK_THREAD_CPUTIME_ID */

static inline uint64_t rdtsc_light(void )
{
	unsigned long cval;

	isb();
	asm volatile("mrs %0, cntvct_el0" : "=r" (cval));

	return cval;
}

extern double nspw; /* nsec per work */
extern unsigned long nsec;

void fwq_init(unsigned long *mem);
void fwq(long delay_nsec, unsigned long *mem);
int print_cpu_last_executed_on(const char *name);

#endif

