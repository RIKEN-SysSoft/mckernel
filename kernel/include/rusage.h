/* Interface toward kernel and mcctrl */

#ifndef __RUSAGE_H
#define __RUSAGE_H

#include <ihk/ihk_rusage.h>

//#define RUSAGE_DEBUG

extern struct rusage_global rusage;

static inline int rusage_pgsize_to_pgtype(size_t pgsize)
{
	int ret = IHK_OS_PGSIZE_4KB;
	int pgshift = pgsize_to_pgshift(pgsize);

	switch (pgshift) {
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
		kprintf("%s: Error: Unknown pgsize=%ld\n",
			__func__, pgsize);
		break;
	}

	return ret;
}

struct rusage_percpu {
	unsigned long user_tsc;
	unsigned long system_tsc;
};

struct rusage_global {
	/* Memory usage accounting */
	long memory_stat_rss[IHK_MAX_NUM_PGSIZES];
	long memory_stat_mapped_file[IHK_MAX_NUM_PGSIZES];
	long rss_current; /* anon && user, used only for memory_max_usage */
	unsigned long memory_max_usage;
	unsigned long max_num_threads;
	unsigned long num_threads;
	unsigned long memory_kmem_usage;
	unsigned long memory_kmem_max_usage;
	unsigned long memory_numa_stat[IHK_MAX_NUM_NUMA_NODES];

	/* CPU usage accounting */
	struct rusage_percpu cpu[IHK_MAX_NUM_CPUS]; /* clv[i].monitor = &cpu[i] */

	/* OOM monitoring */
	unsigned long total_memory;
	unsigned long total_memory_usage;
	unsigned long total_memory_max_usage;
#ifdef RUSAGE_DEBUG
	unsigned long total_memory_max_usage_old; /* debug */
#endif
	/* Used for translating results into struct ihk_os_rusage */
	unsigned long num_numa_nodes;
	unsigned long num_processors;
	unsigned long ns_per_tsc;
};

#endif
