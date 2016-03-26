/* bitops-__ffs.h COPYRIGHT FUJITSU LIMITED 2014 */
#ifndef INCLUDE_BITOPS___FFS_H
#define INCLUDE_BITOPS___FFS_H

static inline unsigned long __ffs(unsigned long word)
{
	int num = 0;

	if (BITS_PER_LONG == 64) {
		if ((word & 0xffffffff) == 0) {
			num += 32;
			word >>= 32;
		}
	}

	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

#endif
