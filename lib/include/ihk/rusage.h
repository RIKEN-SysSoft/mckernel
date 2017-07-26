#ifndef __IHK_RUSAGE_H
#define __IHK_RUSAGE_H

struct ihk_os_cpu_monitor {
	int status;
#define IHK_OS_MONITOR_NOT_BOOT 0
#define IHK_OS_MONITOR_IDLE 1
#define IHK_OS_MONITOR_USER 2
#define IHK_OS_MONITOR_KERNEL 3
#define IHK_OS_MONITOR_KERNEL_HEAVY 4
#define IHK_OS_MONITOR_KERNEL_OFFLOAD 5
#define IHK_OS_MONITOR_KERNEL_FREEZING 8
#define IHK_OS_MONITOR_KERNEL_FROZEN 9
#define IHK_OS_MONITOR_KERNEL_THAW 10
#define IHK_OS_MONITOR_PANIC 99
	int status_bak;
	unsigned long counter;
	unsigned long ocounter;
	unsigned long user_tsc;
	unsigned long system_tsc;
};

struct ihk_os_monitor {
	unsigned long rusage_max_num_threads;
	unsigned long rusage_num_threads;
	unsigned long rusage_rss_max;
	long rusage_rss_current;
	unsigned long rusage_kmem_usage;
	unsigned long rusage_kmem_max_usage;
	unsigned long rusage_hugetlb_usage;
	unsigned long rusage_hugetlb_max_usage;
	unsigned long rusage_total_memory;
	unsigned long rusage_total_memory_usage;
	unsigned long rusage_total_memory_max_usage;
	unsigned long num_numa_nodes;
	unsigned long num_processors;
	unsigned long ns_per_tsc;
	unsigned long reserve[128];
	unsigned long rusage_numa_stat[1024];

	struct ihk_os_cpu_monitor cpu[0];
};

enum RUSAGE_MEMBER {
	RUSAGE_RSS,
	RUSAGE_CACHE,
	RUSAGE_RSS_HUGE,
	RUSAGE_MAPPED_FILE,
	RUSAGE_MAX_USAGE,
	RUSAGE_KMEM_USAGE,
	RUSAGE_KMAX_USAGE,
	RUSAGE_NUM_NUMA_NODES,
	RUSAGE_NUMA_STAT,
	RUSAGE_HUGETLB ,
	RUSAGE_HUGETLB_MAX ,
	RUSAGE_STAT_SYSTEM ,
	RUSAGE_STAT_USER ,
	RUSAGE_USAGE ,
	RUSAGE_USAGE_PER_CPU ,
	RUSAGE_NUM_THREADS ,
	RUSAGE_MAX_NUM_THREADS
};

struct  r_data{
	unsigned long pid;
	unsigned long rss;
	unsigned long cache;
	unsigned long rss_huge;
	unsigned long mapped_file;
	unsigned long max_usage;
	unsigned long kmem_usage;
	unsigned long kmax_usage;
	unsigned long hugetlb;
	unsigned long hugetlb_max;
	unsigned long stat_system;
	unsigned long stat_user;
	unsigned long usage;
	struct r_data *next;
} ;

enum ihk_os_status {
	IHK_STATUS_INACTIVE,
	IHK_STATUS_BOOTING,
	IHK_STATUS_RUNNING,
	IHK_STATUS_SHUTDOWN,
	IHK_STATUS_PANIC,
	IHK_STATUS_HUNGUP,
	IHK_STATUS_FREEZING,
	IHK_STATUS_FROZEN,
};

enum sys_delegate_state_enum {
	ENTER_KERNEL,
	EXIT_KERNEL,
};

extern struct ihk_os_monitor *monitor;

extern void ihk_mc_set_os_status(unsigned long st);
extern unsigned long ihk_mc_get_os_status();

#endif
