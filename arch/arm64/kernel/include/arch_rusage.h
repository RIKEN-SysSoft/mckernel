#ifndef ARCH_RUSAGE_H_INCLUDED
#define ARCH_RUSAGE_H_INCLUDED

#include <arch-memory.h>

//#define DEBUG_RUSAGE

extern struct rusage_global *rusage;

#define IHK_OS_PGSIZE_4KB  0
#define IHK_OS_PGSIZE_16KB 1
#define IHK_OS_PGSIZE_64KB 2

static inline int rusage_pgsize_to_pgtype(size_t pgsize)
{
	int ret = IHK_OS_PGSIZE_4KB;
	switch (pgsize) {
	case __PTL1_SIZE:
		ret = IHK_OS_PGSIZE_4KB;
		break;
	case __PTL2_SIZE:
		ret = IHK_OS_PGSIZE_16KB;
		break;
	case __PTL3_SIZE:
		ret = IHK_OS_PGSIZE_64KB;
		break;
	default:
		kprintf("%s: Error: Unknown pgsize=%ld\n", __FUNCTION__, pgsize);
		break;
	}
	return ret;
}

#endif /* !defined(ARCH_RUSAGE_H_INCLUDED) */
