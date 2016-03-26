/* bitops-clear_bit.h COPYRIGHT FUJITSU LIMITED 2014 */
#ifndef INCLUDE_BITOPS_CLEAR_BIT_H
#define INCLUDE_BITOPS_CLEAR_BIT_H

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = (1UL << (nr % BITS_PER_LONG));
	unsigned long *p = ((unsigned long *)addr) + (nr / BITS_PER_LONG);

	*p  &= ~mask;
}

#endif

