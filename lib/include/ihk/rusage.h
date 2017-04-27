#ifndef __RUSAGE_H
#define __RUSAGE_H

#define RUSAGE_DEFAULT_SIZE 10

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
typedef struct r_data rusage_data;

rusage_data *rdata[RUSAGE_DEFAULT_SIZE];
unsigned long rusage_max_num_threads;
unsigned long rusage_num_threads;

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

enum ihk_os_status os_status;
unsigned long sys_delegate_count;
enum sys_delegate_state_enum {
	ENTER_KERNEL,
	EXIT_KERNEL,
};
enum sys_delegate_state_enum sys_delegate_state;

unsigned long rusage_kmem_usage;
unsigned long rusage_kmem_max_usage;
unsigned long rusage_hugetlb_usage;
unsigned long rusage_hugetlb_max_usage;
unsigned long rusage_usage_per_cpu[sizeof(cpu_set_t)/8];
unsigned long rusage_numa_stat[1024];

#endif
