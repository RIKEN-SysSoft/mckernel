#ifndef __RUSAGE_H
#define __RUSAGE_H

#include <config.h>

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

unsigned long rusage_rss_max;
long rusage_rss_current;
unsigned long rusage_kmem_usage;
unsigned long rusage_kmem_max_usage;
unsigned long rusage_hugetlb_usage;
unsigned long rusage_hugetlb_max_usage;
unsigned long rusage_numa_stat[1024];
unsigned long rusage_max_memory;

#define RUSAGE_MEM_LIMIT (2 * 1024 * 1024) // 2MB

void rusage_init();

#ifdef ENABLE_RUSAGE
extern void event_signal();

static inline void
rusage_max_memory_add(unsigned long size)
{
	rusage_max_memory += size;
}

static inline void
rusage_rss_add(unsigned long size)
{
	unsigned long newval = __sync_add_and_fetch(&rusage_rss_current, size);
	unsigned long oldval = rusage_rss_max;
	unsigned long retval;

	while (newval > oldval) {
		retval = __sync_val_compare_and_swap(&rusage_rss_max, oldval,
		                                     newval);
		if (retval == oldval) {
			if (rusage_max_memory - newval < RUSAGE_MEM_LIMIT) {
				event_signal();
			}
			break;
		}
		oldval = retval;
	}
}

static inline void
rusage_rss_sub(unsigned long size)
{
	__sync_sub_and_fetch(&rusage_rss_current, size);
}

static inline void
rusage_numa_add(int numa_id, unsigned long size)
{
	__sync_add_and_fetch(rusage_numa_stat + numa_id, size);
	rusage_rss_add(size);
}

static inline void
rusage_numa_sub(int numa_id, unsigned long size)
{
	rusage_rss_sub(size);
	__sync_sub_and_fetch(rusage_numa_stat + numa_id, size);
}

static inline void
rusage_num_threads_inc()
{
	unsigned long newval = __sync_add_and_fetch(&rusage_num_threads, 1);
	unsigned long oldval = rusage_max_num_threads;
	unsigned long retval;

	while (newval > oldval) {
		retval = __sync_val_compare_and_swap(&rusage_max_num_threads,
		                                     oldval, newval);
		if (retval == oldval) {
			break;
		}
		oldval = retval;
	}
}

static inline void
rusage_num_threads_dec()
{
	__sync_sub_and_fetch(&rusage_num_threads, 1);
}
#else
static inline void
rusage_max_memory_add(unsigned long size)
{
}

static inline void
rusage_rss_add(unsigned long size)
{
}

static inline void
rusage_rss_sub(unsigned long size)
{
}

static inline void
rusage_numa_add(int numa_id, unsigned long size)
{
}

static inline void
rusage_numa_sub(int numa_id, unsigned long size)
{
}

static inline void
rusage_num_threads_inc()
{
}

static inline void
rusage_num_threads_dec()
{
}
#endif // ENABLE_RUSAGE

#endif
