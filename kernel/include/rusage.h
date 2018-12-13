/* Interface toward kernel and mcctrl */

#ifndef __RUSAGE_H
#define __RUSAGE_H

//#define RUSAGE_DEBUG

#define IHK_MAX_NUM_PGSIZES 10
#define IHK_MAX_NUM_NUMA_NODES 1024
#define IHK_MAX_NUM_CPUS 1024

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
	/* Used for translating results into struct mckernel_rusage */
	unsigned long num_numa_nodes;
	unsigned long num_processors;
	unsigned long ns_per_tsc;
};

#endif
