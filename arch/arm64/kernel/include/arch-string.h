/* arch-string.h COPYRIGHT FUJITSU LIMITED 2016-2017 */
#ifndef __HEADER_ARM64_COMMON_ARCH_STRING_H
#define __HEADER_ARM64_COMMON_ARCH_STRING_H

#define ARCH_FAST_MEMCPY

extern void *__inline_memcpy(void *to, const void *from, size_t t);

#define ARCH_FAST_MEMSET

extern void *__inline_memset(void *s, unsigned long c, size_t count);

#define ARCH_MEMCLEAR

extern void __memclear(void *addr, unsigned long len, void *tmp);
inline static void memclear(void *addr, unsigned long len)
{
	uint64_t q0q1[4];
	__memclear(addr, len, (void *)&q0q1);
}

#endif	/* __HEADER_ARM64_COMMON_ARCH_TIMER_H */
