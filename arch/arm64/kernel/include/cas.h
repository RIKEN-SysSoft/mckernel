/* cas.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
#ifndef __HEADER_ARM64_COMMON_CAS_H
#define __HEADER_ARM64_COMMON_CAS_H

#include <arch/cpu.h>

/* @ref.impl arch/arm64/include/asm/cmpxchg.h::__cmpxchg (size == 8 case) */
/* 8 byte compare and swap, return 0:fail, 1:success */
static inline int
compare_and_swap(void *addr, unsigned long olddata, unsigned long newdata)
{
	unsigned long oldval = 0, res = 0;

	smp_mb();
	do {
		asm volatile("// __cmpxchg8\n"
		"	ldxr	%1, %2\n"
		"	mov	%w0, #0\n"
		"	cmp	%1, %3\n"
		"	b.ne	1f\n"
		"	stxr	%w0, %4, %2\n"
		"1:\n"
			: "=&r" (res), "=&r" (oldval), "+Q" (*(unsigned long *)addr)
			: "Ir" (olddata), "r" (newdata)
			: "cc");
	} while (res);
	smp_mb();

	return (oldval == olddata);
}

#endif /* !__HEADER_ARM64_COMMON_CAS_H */
