/**
 * \file vsyscall.c
 *  License details are found in the file LICENSE.
 * \brief
 *  implements x86's vsyscall
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2014  Hitachi, Ltd.
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY:
 */

/*
 * .vsyscall.* section's LMAs are different from their VMA.
 * make sure that these are position-independent codes.
 */

#include <cls.h>
#include <syscall.h>
#include <ihk/atomic.h>
#include <arch/cpu.h>

extern int vsyscall_gettimeofday(struct timeval *tv, void *tz)
	__attribute__ ((section (".vsyscall.gettimeofday")));

struct tod_data_s tod_data
		__attribute__ ((section(".vsyscall.gettimeofday.data"))) = {
	.do_local =	0,
	.version =	IHK_ATOMIC64_INIT(0),
};

static inline void cpu_pause_for_vsyscall(void)
{
	asm volatile ("pause" ::: "memory");
	return;
} /* cpu_pause_for_vsyscall() */

static inline void calculate_time_from_tsc(struct timespec *ts)
{
	long ver;
	unsigned long current_tsc;
	__time_t sec_delta;
	long ns_delta;

	for (;;) {
		while ((ver = ihk_atomic64_read(&tod_data.version)) & 1) {
			/* settimeofday() is in progress */
			cpu_pause_for_vsyscall();
		}
		rmb();
		*ts = tod_data.origin;
		rmb();
		if (ver == ihk_atomic64_read(&tod_data.version)) {
			break;
		}

		/* settimeofday() has intervened */
		cpu_pause_for_vsyscall();
	}

	current_tsc = rdtsc();
	sec_delta = current_tsc / tod_data.clocks_per_sec;
	ns_delta = NS_PER_SEC * (current_tsc % tod_data.clocks_per_sec)
		/ tod_data.clocks_per_sec;
	/* calc. of ns_delta overflows if clocks_per_sec exceeds 18.44 GHz */

	ts->tv_sec += sec_delta;
	ts->tv_nsec += ns_delta;
	if (ts->tv_nsec >= NS_PER_SEC) {
		ts->tv_nsec -= NS_PER_SEC;
		++ts->tv_sec;
	}

	return;
} /* calculate_time_from_tsc() */

int vsyscall_gettimeofday(struct timeval *tv, void *tz)
{
	int error;
	struct timespec ats;

	if (!tv && !tz) {
		/* nothing to do */
		return 0;
	}

	/* Do it locally if supported */
	if (!tz && tod_data.do_local) {
		calculate_time_from_tsc(&ats);

		tv->tv_sec = ats.tv_sec;
		tv->tv_usec = ats.tv_nsec / 1000;

		return 0;
	}

	/* Otherwise syscall */
	asm ("syscall" : "=a" (error)
			: "a" (__NR_gettimeofday), "D" (tv), "S" (tz)
			: "%rcx", "%r11", "memory");

	if (error) {
		*(int *)0 = 0;	/* i.e. raise(SIGSEGV) */
	}
	return error;
} /* vsyscall_gettimeofday() */

extern long vsyscall_time(void *tp)
	__attribute__ ((section (".vsyscall.time")));

long vsyscall_time(void *tp)
{
	long t;

	asm (		"syscall	;"
			/*
			 * This vsyscall_time() cannot fail, because glibc's
			 * vsyscall_time() does not set the errno.
			 *
			 * Because a possible error is only a memory access error,
			 * in order that this function generates SIGSEGV
			 * rather than returns error when a memory access error occurs,
			 * this function accesses memory in user mode.
			 */
			"test	%%rdx,%%rdx;"
			"jz	1f;"
			"mov	%%rax,(%%rdx);"
			"1:"
			: "=a" (t)
			: "a" (__NR_time), "d" (tp), "D" (0)
			: "%rcx", "%r11", "memory");

	return t;
}

extern int vsyscall_getcpu(unsigned *cpup, unsigned *nodep, void *tcachep)
	__attribute__ ((section (".vsyscall.getcpu")));

int vsyscall_getcpu(unsigned *cpup, unsigned *nodep, void *tcachep)
{
	int error;

	asm ("syscall" : "=a" (error)
			: "a" (__NR_getcpu), "D" (cpup), "S" (nodep), "d" (tcachep)
			: "%rcx", "%r11", "memory");

	return error;
}
