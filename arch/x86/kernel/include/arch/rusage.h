#ifndef ARCH_RUSAGE_H_INCLUDED
#define ARCH_RUSAGE_H_INCLUDED

#define DEBUG_RUSAGE

#define IHK_OS_PGSIZE_4KB 0
#define IHK_OS_PGSIZE_2MB 1
#define IHK_OS_PGSIZE_1GB 2

extern struct ihk_os_monitor *monitor;

extern int sprintf(char * buf, const char *fmt, ...);

#define DEBUG_ARCH_RUSAGE
#ifdef DEBUG_ARCH_RUSAGE
#define	dprintf(...)											\
	do {														\
		char msg[1024];											\
		sprintf(msg, __VA_ARGS__);								\
		kprintf("%s,%s", __FUNCTION__, msg);					\
	} while (0);
#define	eprintf(...)											\
	do {														\
		char msg[1024];											\
		sprintf(msg, __VA_ARGS__);								\
		kprintf("%s,%s", __FUNCTION__, msg);					\
	} while (0);
#else
#define dprintf(...) do {  } while (0)
#define	eprintf(...)											\
	do {														\
		char msg[1024];											\
		sprintf(msg, __VA_ARGS__);								\
		kprintf("%s,%s", __FUNCTION__, msg);					\
	} while (0);
#endif

static inline int rusage_pgsize_to_pgtype(size_t pgsize)
{
	int ret = IHK_OS_PGSIZE_4KB;
	switch (pgsize) {
	case PTL1_SIZE:
		ret = IHK_OS_PGSIZE_4KB;
		break;
	case PTL2_SIZE:
		ret = IHK_OS_PGSIZE_2MB;
		break;
	case PTL3_SIZE:
		ret = IHK_OS_PGSIZE_1GB;
		break;
	default:
		eprintf("unknown pgsize=%ld\n", pgsize);
		break;
	}
	return ret;
}

#endif /* !defined(ARCH_RUSAGE_H_INCLUDED) */
