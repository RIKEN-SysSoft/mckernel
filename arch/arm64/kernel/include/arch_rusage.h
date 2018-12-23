#ifndef ARCH_RUSAGE_H_INCLUDED
#define ARCH_RUSAGE_H_INCLUDED

#include <arch-memory.h>

#define DEBUG_RUSAGE

#define IHK_OS_PGSIZE_4KB 0
#define IHK_OS_PGSIZE_2MB 1
#define IHK_OS_PGSIZE_1GB 2

extern struct rusage_global rusage;

static inline int rusage_pgsize_to_pgtype(size_t pgsize)
{
	int ret = IHK_OS_PGSIZE_4KB;

	if (pgsize == PTL1_SIZE) {
		ret = IHK_OS_PGSIZE_4KB;
	}
	else if (pgsize == PTL2_SIZE) {
		ret = IHK_OS_PGSIZE_2MB;
	}
	else if (pgsize == PTL3_SIZE) {
		ret = IHK_OS_PGSIZE_1GB;
	}
	else {
		kprintf("%s: Error: Unknown pgsize=%ld\n", __FUNCTION__, pgsize);
	}
	return ret;
}

#endif /* !defined(ARCH_RUSAGE_H_INCLUDED) */
