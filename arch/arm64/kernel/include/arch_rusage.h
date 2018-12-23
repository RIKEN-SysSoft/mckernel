#ifndef ARCH_RUSAGE_H_INCLUDED
#define ARCH_RUSAGE_H_INCLUDED

#include <arch-memory.h>

#define DEBUG_RUSAGE

enum ihk_os_pgsize {
	IHK_OS_PGSIZE_4KB,
	IHK_OS_PGSIZE_64KB,
	IHK_OS_PGSIZE_2MB,
	IHK_OS_PGSIZE_32MB,
	IHK_OS_PGSIZE_1GB,
	IHK_OS_PGSIZE_16GB,
	IHK_OS_PGSIZE_512MB,
	IHK_OS_PGSIZE_4TB,
	IHK_OS_PGSIZE_COUNT
};

extern struct rusage_global rusage;

static inline int rusage_pgsize_to_pgtype(size_t pgsize)
{
	int ret = IHK_OS_PGSIZE_4KB;
	int pgshift = 63 - __builtin_clzl(pgsize);
	
	switch(pgshift) {
	case 12:
		ret = IHK_OS_PGSIZE_4KB;
		break;
	case 16:
		ret = IHK_OS_PGSIZE_64KB;
		break;
	case 21:
		ret = IHK_OS_PGSIZE_2MB;
		break;
	case 25:
		ret = IHK_OS_PGSIZE_32MB;
		break;
	case 30:
		ret = IHK_OS_PGSIZE_1GB;
		break;
	case 34:
		ret = IHK_OS_PGSIZE_16GB;
		break;
	case 29:
		ret = IHK_OS_PGSIZE_512MB;
		break;
	case 42:
		ret = IHK_OS_PGSIZE_4TB;
		break;
	default:
		kprintf("%s: Error: Unknown pgsize=%ld\n", __FUNCTION__, pgsize);
		break;
	}
		
	return ret;
}

#endif /* !defined(ARCH_RUSAGE_H_INCLUDED) */
