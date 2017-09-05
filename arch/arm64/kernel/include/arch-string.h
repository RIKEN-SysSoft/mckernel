/* arch-string.h COPYRIGHT FUJITSU LIMITED 2016-2017 */
#ifndef __HEADER_ARM64_COMMON_ARCH_STRING_H
#define __HEADER_ARM64_COMMON_ARCH_STRING_H

#define ARCH_FAST_MEMCPY

extern void *__inline_memcpy(void *to, const void *from, size_t t);

#define ARCH_FAST_MEMSET

extern void *__inline_memset(void *s, unsigned long c, size_t count);

#endif	/* __HEADER_ARM64_COMMON_ARCH_TIMER_H */
