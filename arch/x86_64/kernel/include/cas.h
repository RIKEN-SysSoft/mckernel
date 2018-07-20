/**
 * \file arch/x86/kernel/include/cas.h
 *  License details are found in the file LICENSE.
 * \brief
 *  compare and swap
 * \author Tomoki Shirasawa  <tomoki.shirasawa.kk@hitachi-solutions.com> \par
 *      Copyright (C) 2012 - 2013 Hitachi, Ltd.
 */
/*
 * HISTORY:
 */

#ifndef __HEADER_X86_COMMON_CAS_H
#define __HEADER_X86_COMMON_CAS_H
// return 0:fail, 1:success
static inline int
compare_and_swap(void *addr, unsigned long olddata, unsigned long newdata)
{
	unsigned long before;

	asm volatile (
		"lock; cmpxchgq %2,%1"
		: "=a" (before), "+m" (*(unsigned long *)addr)
		: "q" (newdata), "0" (olddata)
		: "cc");
	return before == olddata;
}

#if 0 // cmpxchg16b was not support on k1om
// return 0:fail, 1:success
static inline int
compare_and_swap16(void *addr, void *olddata, void *newdata)
{
	char rc;

	asm volatile (
		"lock; cmpxchg16b %0; setz %1"
		: "=m" (*(long *)addr), "=q" (rc)
		: "m" (*(long *)addr),
		  "d" (((long *)olddata)[0]), "a" (((long *)olddata)[1]),
		  "c" (((long *)newdata)[0]), "b" (((long *)newdata)[1])
		: "memory");
	return rc;
}
#endif
#endif /*__HEADER_X86_COMMON_CAS_H*/
