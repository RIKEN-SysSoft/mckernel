/**
 * \file vsyscall.c
 *  License details are found in the file LICENSE.
 * \brief
 *  implements x86's vsyscall
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2014  Hitachi, Ltd.
 */
/*
 * HISTORY:
 */

/*
 * .vsyscall.* section's LMAs are different from their VMA.
 * make sure that these are position-independent codes.
 */

#include <syscall.h>

extern int vsyscall_gettimeofday(void *tv, void *tz)
	__attribute__ ((section (".vsyscall.gettimeofday")));

int vsyscall_gettimeofday(void *tv, void *tz)
{
	int error;

	asm ("syscall" : "=a" (error)
			: "a" (__NR_gettimeofday), "D" (tv), "S" (tz)
			: "%rcx", "%r11", "memory");

	return error;
}

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
