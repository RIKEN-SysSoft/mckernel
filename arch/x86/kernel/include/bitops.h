/**
 * \file bitops.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Find last set bit in word.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
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

#endif
