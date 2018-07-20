/**
 * \file arch-bitops.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Find last set bit in word.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef HEADER_X86_COMMON_ARCH_BITOPS_H
#define HEADER_X86_COMMON_ARCH_BITOPS_H

#define ARCH_HAS_FAST_MULTIPLIER 1

static inline int fls(int x)
{
	int r;
	asm("bsrl %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movl $-1,%0\n"
	    "1:" : "=r" (r) : "rm" (x));

	return r + 1;
}

/**
 * ffs - find first set bit in word
 * @x: the word to search
 *
 * This is defined the same way as the libc and compiler builtin ffs
 * routines, therefore differs in spirit from the other bitops.
 *
 * ffs(value) returns 0 if value is 0 or the position of the first
 * set bit if value is nonzero. The first (least significant) bit
 * is at position 1.
 */
static inline int ffs(int x)
{
	int r;
	asm("bsfl %1,%0\n\t"
	    "jnz 1f\n\t"
	    "movl $-1,%0\n"
	    "1:" : "=r" (r) : "rm" (x));
	return r + 1;
}


/**
 * __ffs - find first set bit in word
 * @word: The word to search
 *
 * Undefined if no bit exists, so code should check against 0 first.
 */
static inline unsigned long __ffs(unsigned long word)
{
	asm("bsf %1,%0"
		: "=r" (word)
		: "rm" (word));
	return word;
}

/**
 * ffz - find first zero bit in word
 * @word: The word to search
 *
 * Undefined if no zero exists, so code should check against ~0UL first.
 */
static inline unsigned long ffz(unsigned long word)
{
	asm("bsf %1,%0"
		: "=r" (word)
		: "r" (~word));
	return word;
}


#define ADDR (*(volatile long *)addr)

static inline void set_bit(int nr, volatile unsigned long *addr)
{
	asm volatile("lock; btsl %1,%0"
		     : "+m" (ADDR)
		     : "Ir" (nr)
		     : "memory");
}

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
	asm volatile("lock; btrl %1,%0"
		     : "+m" (ADDR)
		     : "Ir" (nr)
		     : "memory");
}

#endif
