/* archdep.c COPYRIGHT FUJITSU LIMITED 2017 */

#include <asm/ptrace.h>

/* @ref.impl arch/arm64/include/asm/atomic_ll_sc.h::__ll_sc___cmpxchg_case_mb_8() */
unsigned long compare_and_swap(unsigned long *addr,
			       unsigned long old, unsigned long new)
{
	unsigned long tmp, oldval;

	asm volatile(
	"	prfm	pstl1strm, %2\n"
	"1:	ldxr	%1, %2\n"
	"	eor	%0, %1, %3\n"
	"	cbnz	%0, 2f\n"
	"	stlxr	%w0, %4, %2\n"
	"	cbnz	%w0, 1b\n"
	"	dmb	ish\n"
	"	mov	%1, %3\n"
	"2:"
	: "=&r"(tmp), "=&r"(oldval), "+Q"(*addr)
	: "Lr"(old), "r"(new)
	: "memory");

	return oldval;
}

/* @ref.impl arch/arm64/include/asm/atomic_ll_sc.h::__ll_sc___cmpxchg_case_mb_4() */
unsigned int compare_and_swap_int(unsigned int *addr,
				  unsigned int old, unsigned int new)
{
	unsigned long tmp, oldval;

	asm volatile(
	"	prfm	pstl1strm, %2\n"
	"1:	ldxr	%w1, %2\n"
	"	eor	%w0, %w1, %w3\n"
	"	cbnz	%w0, 2f\n"
	"	stlxr	%w0, %w4, %2\n"
	"	cbnz	%w0, 1b\n"
	"	dmb	ish\n"
	"	mov	%w1, %w3\n"
	"2:"
	: "=&r"(tmp), "=&r"(oldval), "+Q"(*addr)
	: "Lr"(old), "r"(new)
	: "memory");

	return oldval;
}
