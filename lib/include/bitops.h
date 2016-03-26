/* bitops.h COPYRIGHT FUJITSU LIMITED 2014 */
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

#endif /*__ASSEMBLY__*/

#include <arch-bitops.h>

#endif /*INCLUDE_BITOPS_H*/

