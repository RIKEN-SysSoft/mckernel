/* bitops-fls.h COPYRIGHT FUJITSU LIMITED 2014 */
#ifndef INCLUDE_BITOPS_FLS_H
#define INCLUDE_BITOPS_FLS_H

static inline int fls(int x)
{
	int r = 32;
	if (!x) {
		return 0;
	}

	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

#endif

