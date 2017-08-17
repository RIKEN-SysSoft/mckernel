/* Interface toward kernel */

#ifndef RUSAGE_PRIVATE_H_INCLUDED
#define RUSAGE_PRIVATE_H_INCLUDED

#include <config.h>
#include <page.h>
#include <ihk/atomic.h>
#include <memobj.h>
#include <rusage.h>
#include <arch/rusage.h>

#ifdef ENABLE_RUSAGE

#define RUSAGE_MEM_LIMIT (2 * 1024 * 1024) // 2MB

extern void eventfd();

static inline void
rusage_total_memory_add(unsigned long size)
{
	rusage->total_memory += size;
}

static inline void
rusage_rss_add(unsigned long size)
{
	unsigned long newval;
	unsigned long oldval;
	unsigned long retval;

	newval = __sync_add_and_fetch(&rusage->rss_current, size);
	oldval = rusage->memory_max_usage;
	while (newval > oldval) {
		retval = __sync_val_compare_and_swap(&rusage->memory_max_usage,
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
	__sync_sub_and_fetch(&rusage->rss_current, size);
}

static inline void memory_stat_rss_add(unsigned long size, int pgsize)
{
	ihk_atomic_add_long(size, &rusage->memory_stat_rss[rusage_pgsize_to_pgtype(pgsize)]);
}

static inline void memory_stat_rss_sub(unsigned long size, int pgsize)
{
	ihk_atomic_add_long(-size, &rusage->memory_stat_rss[rusage_pgsize_to_pgtype(pgsize)]);
}

static inline void rusage_memory_stat_mapped_file_add(unsigned long size, int pgsize)
{
	ihk_atomic_add_long(size, &rusage->memory_stat_mapped_file[rusage_pgsize_to_pgtype(pgsize)]);
}

static inline void rusage_memory_stat_mapped_file_sub(unsigned long size, int pgsize)
{
	ihk_atomic_add_long(-size, &rusage->memory_stat_mapped_file[rusage_pgsize_to_pgtype(pgsize)]);
}

static inline int rusage_memory_stat_add(struct vm_range *range, uintptr_t phys, unsigned long size, int pgsize)
{
	/* Is it resident in main memory? */
	if (range->flag & (VR_REMOTE | VR_IO_NOCACHE | VR_RESERVED)) {
		return 0;
	}
	/* Is it anonymous and pre-paging? */
	if (!range->memobj) {
		memory_stat_rss_add(size, pgsize);
		return 1;
	}
	/* Is it devobj or (fileobj and pre-map) or xpmem attachment? */
	if ((range->memobj->flags & MF_DEV_FILE) ||
		(range->memobj->flags & MF_PREMAP) ||
		(range->memobj->flags & MF_XPMEM)
		) {
		return 0;
	}
	/* Is it anonymous and demand-paging? */
	if (range->memobj->flags & MF_ZEROOBJ) {
		memory_stat_rss_add(size, pgsize);
		return 1;
	}

	struct page *page = phys_to_page(phys);

	/* Is It file map and cow page? */
	if ((range->memobj->flags & (MF_DEV_FILE | MF_REG_FILE)) &&
		!page) {
		//kprintf("%s: cow,phys=%lx\n", __FUNCTION__, phys);
		memory_stat_rss_add(size, pgsize);
		return 1;
	}

	/* Is it a sharable page? */
	if (!page) {
		kprintf("%s: WARNING !page,phys=%lx\n", __FUNCTION__, phys);
		return 0;
	}
	/* Is this the first attempt to map the sharable page? */
	if(__sync_bool_compare_and_swap(&page->mapped.counter64, 0, 1)) {
		if(range->memobj->flags & MF_SHM) {
			memory_stat_rss_add(size, pgsize);
		} else {
			rusage_memory_stat_mapped_file_add(size, pgsize);
		}
		return 1;
	} else {
		return 0;
	}
	return 0;
}

static inline int rusage_memory_stat_add_with_page(struct vm_range *range, uintptr_t phys, unsigned long size, int pgsize, struct page *page)
{
	/* Is it resident in main memory? */
	if (range->flag & (VR_REMOTE | VR_IO_NOCACHE | VR_RESERVED)) {
		return 0;
	}
	/* Is it anonymous and pre-paging? */
	if (!range->memobj) {
		memory_stat_rss_add(size, pgsize);
		return 1;
	}
	/* Is it devobj or (fileobj and pre-map) or xpmem attachment? */
	if ((range->memobj->flags & MF_DEV_FILE) ||
		(range->memobj->flags & MF_PREMAP) ||
		(range->memobj->flags & MF_XPMEM)
		) {
		return 0;
	}
	/* Is it anonymous and demand-paging? */
	if (range->memobj->flags & MF_ZEROOBJ) {
		memory_stat_rss_add(size, pgsize);
		return 1;
	}

	/* Is It file map and cow page? */
	if ((range->memobj->flags & (MF_DEV_FILE | MF_REG_FILE)) &&
		!page) {
		//kprintf("%s: cow,phys=%lx\n", __FUNCTION__, phys);
		memory_stat_rss_add(size, pgsize);
		return 1;
	}

	/* Is it a sharable page? */
	if (!page) {
		kprintf("%s: WARNING !page,phys=%lx\n", __FUNCTION__, phys);
		return 0;
	}
	/* Is this the first attempt to map the sharable page? */
	if(__sync_bool_compare_and_swap(&page->mapped.counter64, 0, 1)) {
		if(range->memobj->flags & MF_SHM) {
			memory_stat_rss_add(size, pgsize);
		} else {
			rusage_memory_stat_mapped_file_add(size, pgsize);
		}
		return 1;
	} else {
		return 0;
	}
	return 0;
}

static inline void rusage_memory_stat_sub(struct memobj *memobj, unsigned long size, int pgsize)
{
	if(memobj->flags & MF_SHM) {
		memory_stat_rss_sub(size, pgsize); 
	} else {
		rusage_memory_stat_mapped_file_sub(size, pgsize); 
	}
}

static inline void
rusage_kmem_add(unsigned long size)
{
	unsigned long newval;
	unsigned long oldval;
	unsigned long retval;

	newval = __sync_add_and_fetch(&rusage->memory_kmem_usage, size);
	oldval = rusage->memory_kmem_max_usage;
	while (newval > oldval) {
		retval = __sync_val_compare_and_swap(
		                                &rusage->memory_kmem_max_usage,
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
	__sync_sub_and_fetch(&rusage->memory_kmem_usage, size);
}

static inline void
rusage_numa_add(int numa_id, unsigned long size)
{
	__sync_add_and_fetch(rusage->memory_numa_stat + numa_id, size);
	rusage_rss_add(size);
}

static inline void
rusage_numa_sub(int numa_id, unsigned long size)
{
	rusage_rss_sub(size);
	__sync_sub_and_fetch(rusage->memory_numa_stat + numa_id, size);
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

	newval = __sync_add_and_fetch(&rusage->total_memory_usage, size);
	oldval = rusage->total_memory_max_usage;
	while (newval > oldval) {
		retval = __sync_val_compare_and_swap(&rusage->total_memory_max_usage,
		                                     oldval, newval);
		if (retval == oldval) {
			if (rusage->total_memory - newval <
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

	__sync_sub_and_fetch(&rusage->total_memory_usage, size);

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

	newval = __sync_add_and_fetch(&rusage->num_threads, 1);
	oldval = rusage->max_num_threads;
	while (newval > oldval) {
		retval = __sync_val_compare_and_swap(&rusage->
		                                     max_num_threads,
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
	__sync_sub_and_fetch(&rusage->num_threads, 1);
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

static inline void memory_stat_rss_add(unsigned long size, size_t pgsize)
{
}

static inline void memory_stat_rss_sub(unsigned long size, size_t pgsize)
{
}

static inline void rusage_memory_stat_mapped_file_add(unsigned long size, int pgsize)
{
}

static inline void rusage_memory_stat_mapped_file_sub(unsigned long size, int pgsize)
{
}

static inline int rusage_memory_stat_add_with_page(struct vm_range *range, struct page *page, unsigned long size, int pgsize)
{
	return 0;
}

static inline int rusage_memory_stat_add(struct vm_range *range, uintptr_t phys, unsigned long size, int pgsize)
{
	return 0;
}

static inline void rusage_memory_stat_sub(struct memobj *memobj, unsigned long size, int pgsize)
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

extern struct rusage_global *rusage;

#endif /* !defined(RUSAGE_PRIVATE_H_INCLUDED) */
