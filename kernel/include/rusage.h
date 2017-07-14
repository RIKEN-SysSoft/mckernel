#ifndef __RUSAGE_H
#define __RUSAGE_H

#include <config.h>
#include <ihk/rusage.h>

#ifdef ENABLE_RUSAGE
#define RUSAGE_MEM_LIMIT (2 * 1024 * 1024) // 2MB

extern void eventfd();

static inline void
rusage_total_memory_add(unsigned long size)
{
	monitor->rusage_total_memory += size;
}

static inline void
rusage_rss_add(unsigned long size)
{
	unsigned long newval;
	unsigned long oldval;
	unsigned long retval;

	newval = __sync_add_and_fetch(&monitor->rusage_rss_current, size);
	oldval = monitor->rusage_rss_max;
	while (newval > oldval) {
		retval = __sync_val_compare_and_swap(&monitor->rusage_rss_max,
		                                     oldval, newval);
		if (retval == oldval) {
			break;
		}
		oldval = retval;
	}
}

static inline void
rusage_rss_sub(unsigned long size)
{
	__sync_sub_and_fetch(&monitor->rusage_rss_current, size);
}

static inline void
rusage_kmem_add(unsigned long size)
{
	unsigned long newval;
	unsigned long oldval;
	unsigned long retval;

	newval = __sync_add_and_fetch(&monitor->rusage_kmem_usage, size);
	oldval = monitor->rusage_kmem_max_usage;
	while (newval > oldval) {
		retval = __sync_val_compare_and_swap(
		                                &monitor->rusage_kmem_max_usage,
		                                oldval, newval);
		if (retval == oldval) {
			break;
		}
		oldval = retval;
	}
}

static inline void
rusage_kmem_sub(unsigned long size)
{
	__sync_sub_and_fetch(&monitor->rusage_kmem_usage, size);
}

static inline void
rusage_numa_add(int numa_id, unsigned long size)
{
	__sync_add_and_fetch(monitor->rusage_numa_stat + numa_id, size);
	rusage_rss_add(size);
}

static inline void
rusage_numa_sub(int numa_id, unsigned long size)
{
	rusage_rss_sub(size);
	__sync_sub_and_fetch(monitor->rusage_numa_stat + numa_id, size);
}

static inline void
rusage_page_add(int numa_id, unsigned long pages, int is_user)
{
	unsigned long size = pages * PAGE_SIZE;
	unsigned long newval;
	unsigned long oldval;
	unsigned long retval;

	if (is_user)
		rusage_numa_add(numa_id, size);
	else
		rusage_kmem_add(size);

	newval = __sync_add_and_fetch(&monitor->rusage_total_memory_usage, size);
	oldval = monitor->rusage_total_memory_max_usage;
	while (newval > oldval) {
		retval = __sync_val_compare_and_swap(&monitor->rusage_total_memory_max_usage,
		                                     oldval, newval);
		if (retval == oldval) {
			if (monitor->rusage_total_memory - newval <
			    RUSAGE_MEM_LIMIT) {
				eventfd();
			}
			break;
		}
		oldval = retval;
	}
}

static inline void
rusage_page_sub(int numa_id, unsigned long pages, int is_user)
{
	unsigned long size = pages * PAGE_SIZE;

	__sync_sub_and_fetch(&monitor->rusage_total_memory_usage, size);

	if (is_user)
		rusage_numa_sub(numa_id, size);
	else
		rusage_kmem_sub(size);
}

static inline void
rusage_num_threads_inc()
{
	unsigned long newval;
	unsigned long oldval;
	unsigned long retval;

	newval = __sync_add_and_fetch(&monitor->rusage_num_threads, 1);
	oldval = monitor->rusage_max_num_threads;
	while (newval > oldval) {
		retval = __sync_val_compare_and_swap(&monitor->
		                                     rusage_max_num_threads,
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
	__sync_sub_and_fetch(&monitor->rusage_num_threads, 1);
}
#else
static inline void
rusage_total_memory_add(unsigned long size)
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
rusage_page_add(int numa_id, unsigned long size, int is_user)
{
}

static inline void
rusage_page_sub(int numa_id, unsigned long size, int is_user)
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
