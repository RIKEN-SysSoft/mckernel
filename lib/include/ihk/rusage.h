#ifndef __IHK_RUSAGE_H
#define __IHK_RUSAGE_H

#include <arch/rusage.h>
#include <ihk/monitor.h>

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
