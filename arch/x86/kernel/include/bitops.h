/**
 * \file bitops.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Find last set bit in word.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef HEADER_X86_COMMON_BITOPS_H
#define HEADER_X86_COMMON_BITOPS_H

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

#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size)); \
	     (bit) < (size); \
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

#define BITOP_WORD(nr)		((nr) / BITS_PER_LONG)

/*
 * Find the next set bit in a memory region.
 */
static unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
		unsigned long offset)
{
	const unsigned long *p = addr + BITOP_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
		tmp &= (~0UL << offset);
		if (size < BITS_PER_LONG)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG-1)) {
		if ((tmp = *(p++)))
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp &= (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)		/* Are any bits set? */
		return result + size;	/* Nope. */
found_middle:
	return result + __ffs(tmp);
}

/*
 * This implementation of find_{first,next}_zero_bit was stolen from
 * Linus' asm-alpha/bitops.h.
 */
static unsigned long find_next_zero_bit(const unsigned long *addr, 
		unsigned long size, unsigned long offset)
{
	const unsigned long *p = addr + BITOP_WORD(offset);
	unsigned long result = offset & ~(BITS_PER_LONG-1);
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset %= BITS_PER_LONG;
	if (offset) {
		tmp = *(p++);
		tmp |= ~0UL >> (BITS_PER_LONG - offset);
		if (size < BITS_PER_LONG)
			goto found_first;
		if (~tmp)
			goto found_middle;
		size -= BITS_PER_LONG;
		result += BITS_PER_LONG;
	}
	while (size & ~(BITS_PER_LONG-1)) {
		if (~(tmp = *(p++)))
			goto found_middle;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;
	tmp = *p;

found_first:
	tmp |= ~0UL << size;
	if (tmp == ~0UL)	/* Are any bits zero? */
		return result + size;	/* Nope. */
found_middle:
	return result + ffz(tmp);
}

/*
 * Find the first set bit in a memory region.
 */
static unsigned long find_first_bit(const unsigned long *addr, 
		unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long result = 0;
	unsigned long tmp;

	while (size & ~(BITS_PER_LONG-1)) {
		if ((tmp = *(p++)))
			goto found;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;

	tmp = (*p) & (~0UL >> (BITS_PER_LONG - size));
	if (tmp == 0UL)		/* Are any bits set? */
		return result + size;	/* Nope. */
found:
	return result + __ffs(tmp);
}

/*
 * Find the first cleared bit in a memory region.
 */
static unsigned long find_first_zero_bit(const unsigned long *addr, 
		unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long result = 0;
	unsigned long tmp;

	while (size & ~(BITS_PER_LONG-1)) {
		if (~(tmp = *(p++)))
			goto found;
		result += BITS_PER_LONG;
		size -= BITS_PER_LONG;
	}
	if (!size)
		return result;

	tmp = (*p) | (~0UL << size);
	if (tmp == ~0UL)	/* Are any bits zero? */
		return result + size;	/* Nope. */
found:
	return result + ffz(tmp);
}

#endif
