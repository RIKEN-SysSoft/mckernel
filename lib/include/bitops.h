/* bitops.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
#ifndef INCLUDE_BITOPS_H
#define INCLUDE_BITOPS_H

#include <types.h>

#define __BITS_TO_LONGS(n,d)	(((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr)	 __BITS_TO_LONGS(nr, BITS_PER_LONG)
#define DECLARE_BITMAP(name,bits) unsigned long name[BITS_TO_LONGS(bits)]

#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size)); \
	     (bit) < (size); \
	     (bit) = find_next_bit((addr), (size), (bit) + 1))

#ifndef __ASSEMBLY__

unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
			    unsigned long offset);

unsigned long find_next_zero_bit(const unsigned long *addr, 
				 unsigned long size, unsigned long offset);

unsigned long find_first_bit(const unsigned long *addr, 
			     unsigned long size);

unsigned long find_first_zero_bit(const unsigned long *addr, 
				  unsigned long size);

#include <bitops-test_bit.h>

extern unsigned int __sw_hweight32(unsigned int w);
extern unsigned int __sw_hweight16(unsigned int w);
extern unsigned int __sw_hweight8(unsigned int w);
extern unsigned long __sw_hweight64(uint64_t w);

static inline unsigned long hweight_long(unsigned long w)
{
	return sizeof(w) == 4 ? __sw_hweight32(w) : __sw_hweight64(w);
}

#define BIT(nr)			(1UL << (nr))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE		8

#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __ALIGN_MASK(x, mask)	__ALIGN_KERNEL_MASK((x), (mask))
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define IS_ALIGNED(x, a)                (((x) & ((typeof(x))(a) - 1)) == 0)

#endif /*__ASSEMBLY__*/

#include <arch-bitops.h>

#endif /*INCLUDE_BITOPS_H*/

