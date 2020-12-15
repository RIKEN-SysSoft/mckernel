#ifndef INCLUDE_BITOPS_TEST_BIT_H
#define INCLUDE_BITOPS_TEST_BIT_H

static inline int test_bit(int nr, const void *addr)
{
	const uint32_t *p = (const uint32_t *)addr;

	return ((1UL << (nr & 31)) & (p[nr >> 5])) != 0;
}

#endif
