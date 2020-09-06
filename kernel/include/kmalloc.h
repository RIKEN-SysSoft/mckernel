/**
 * \file kmalloc.h
 *  License details are found in the file LICENSE.
 * \brief
 *  kmalloc and kfree functions
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY:
 */

#ifndef __HEADER_KMALLOC_H
#define __HEADER_KMALLOC_H

#include "ihk/mm.h"
#include "cls.h"
#include <ihk/debug.h>

#define kmalloc(size, flag) ({\
void *r = _kmalloc(size, flag, __FILE__, __LINE__);\
if(r == NULL){\
kprintf("kmalloc: out of memory %s:%d no_preempt=%d\n", __FILE__, __LINE__, cpu_local_var(no_preempt)); \
}\
r;\
})
#define kfree(ptr) _kfree(ptr, __FILE__, __LINE__)
#define memcheck(ptr, msg) _memcheck(ptr, msg, __FILE__, __LINE__, 0)
void *_kmalloc(int size, ihk_mc_ap_flag flag, char *file, int line);
void _kfree(void *ptr, char *file, int line);
void *__kmalloc(int size, ihk_mc_ap_flag flag);
void __kfree(void *ptr);

int _memcheck(void *ptr, char *msg, char *file, int line, int free);
int memcheckall(void);
int freecheck(int runcount);
void kmalloc_consolidate_free_list(void);

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/*
 * Generic lockless kmalloc cache.
 */
static inline void kmalloc_cache_free(void *elem)
{
	struct kmalloc_cache_header *current = NULL;
	struct kmalloc_cache_header *new =
		(struct kmalloc_cache_header *)elem;
	struct kmalloc_header *header;
	register struct kmalloc_cache_header *cache;

	if (unlikely(!elem))
		return;

	/* Get cache pointer from kmalloc header */
	header = (struct kmalloc_header *)((void *)elem -
				sizeof(struct kmalloc_header));
	if (unlikely(!header->cache)) {
		kprintf("%s: WARNING: no cache for 0x%lx\n",
				__func__, elem);
		return;
	}

	cache = header->cache;

retry:
	current = cache->next;
	new->next = current;

	if (!__sync_bool_compare_and_swap(&cache->next, current, new)) {
		goto retry;
	}
}

static inline void kmalloc_cache_prealloc(struct kmalloc_cache_header *cache,
		size_t size, int nr_elem)
{
	struct kmalloc_cache_header *elem;
	int i;

	if (unlikely(cache->next))
		return;

	for (i = 0; i < nr_elem; ++i) {
		struct kmalloc_header *header;

		elem = (struct kmalloc_cache_header *)
			kmalloc(size, IHK_MC_AP_NOWAIT);

		if (!elem) {
			kprintf("%s: ERROR: allocating cache element\n", __func__);
			continue;
		}

		/* Store cache pointer in kmalloc_header */
		header = (struct kmalloc_header *)((void *)elem -
				sizeof(struct kmalloc_header));
		header->cache = cache;

		kmalloc_cache_free(elem);
	}
}

static inline void *kmalloc_cache_alloc(struct kmalloc_cache_header *cache,
		size_t size)
{
	register struct kmalloc_cache_header *first, *next;

retry:
	next = NULL;
	first = cache->next;

	if (first) {
		next = first->next;

		if (!__sync_bool_compare_and_swap(&cache->next,
					first, next)) {
			goto retry;
		}
	}
	else {
		kprintf("%s: calling pre-alloc for 0x%lx...\n", __func__, cache);

		kmalloc_cache_prealloc(cache, size, 384);
		goto retry;
	}

	return (void *)first;
}

#endif
