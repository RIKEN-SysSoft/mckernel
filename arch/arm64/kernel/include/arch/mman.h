/* mman.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
/* @ref.impl linux-linaro/include/uapi/asm-generic/mman.h */

#ifndef __HEADER_ARM64_ARCH_MMAN_H
#define __HEADER_ARM64_ARCH_MMAN_H

#include <arch-memory.h>

/*
 * mapping flags
 */
#define MAP_GROWSDOWN	0x0100		/* stack-like segment */
#define MAP_DENYWRITE	0x0800		/* ETXTBSY */
#define MAP_EXECUTABLE	0x1000		/* mark it as an executable */
#define MAP_LOCKED	0x2000		/* pages are locked */
#define MAP_NORESERVE	0x4000		/* don't check for reservations */
#define MAP_POPULATE	0x8000		/* populate (prefault) pagetables */
#define MAP_NONBLOCK	0x10000		/* do not block on IO */
#define MAP_STACK	0x20000		/* give out an address that is best suited for process/thread stacks */
#define MAP_HUGETLB	0x40000		/* create a huge page mapping */

/* Bits [26:31] are reserved, see mman-common.h for MAP_HUGETLB usage */
#define MAP_HUGE_SHIFT  26
#if FIRST_LEVEL_BLOCK_SUPPORT
# define MAP_HUGE_FIRST_BLOCK (__PTL3_SHIFT << MAP_HUGE_SHIFT)
# define MAP_HUGE_FIRST_CONT_BLOCK ((__PTL3_SHIFT + __PTL3_CONT_SHIFT) << MAP_HUGE_SHIFT)
#else
# define MAP_HUGE_FIRST_BLOCK -1 /* not supported */
# define MAP_HUGE_FIRST_CONT_BLOCK -1 /* not supported */
#endif
#define MAP_HUGE_SECOND_BLOCK (__PTL2_SHIFT << MAP_HUGE_SHIFT)
#define MAP_HUGE_SECOND_CONT_BLOCK ((__PTL2_SHIFT + __PTL2_CONT_SHIFT) << MAP_HUGE_SHIFT)
#define MAP_HUGE_THIRD_CONT_BLOCK  ((__PTL1_SHIFT + __PTL1_CONT_SHIFT) << MAP_HUGE_SHIFT)

/*
 * for mlockall()
 */
#define MCL_CURRENT	1		/* lock all current mappings */
#define MCL_FUTURE	2		/* lock all future mappings */

#endif /* __HEADER_ARM64_ARCH_MMAN_H */
