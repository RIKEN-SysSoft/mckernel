/**
 * \file page_alloc.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare functions acquire physical pages and assign virtual addresses
 *  to them. 
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * \author Balazs Gerofi <bgerofi@riken.jp> \par
 */
/*
 * HISTORY
 * 2016/12 - bgerofi - NUMA support
 * 2017/06 - bgerofi - rewrite physical memory mngt for red-black trees
 */

#ifndef __HEADER_GENERIC_IHK_PAGE_ALLOC
#define __HEADER_GENERIC_IHK_PAGE_ALLOC

#include <list.h>
#include <rbtree.h>

/* XXX: Physical memory management shouldn't be part of IHK */
struct node_distance {
	int id;
	int distance;
};

#define IHK_RBTREE_ALLOCATOR

#ifdef IHK_RBTREE_ALLOCATOR
struct free_chunk {
	unsigned long addr, size;
	struct rb_node node;
};
#endif

struct ihk_mc_numa_node {
	int id;
	int linux_numa_id;
	int type;
	struct list_head allocators;
	struct node_distance *nodes_by_distance;
#ifdef IHK_RBTREE_ALLOCATOR
	struct rb_root zeroed_chunks;
	struct rb_root free_chunks;
	mcs_lock_node_t lock;

	unsigned long nr_pages;
	/*
	 * nr_free_pages: all freed pages
	 * nr_zeroed_pages: zeroed free pages
	 * Invariant: nr_zeroed_pages <= nr_free_pages
	 */
	unsigned long nr_zeroed_pages;
	unsigned long nr_free_pages;
	unsigned long min_addr;
	unsigned long max_addr;
#endif
};

#ifdef IHK_RBTREE_ALLOCATOR
unsigned long ihk_numa_alloc_pages(struct ihk_mc_numa_node *node,
		int npages, int p2align);
void ihk_numa_free_pages(struct ihk_mc_numa_node *node,
		unsigned long addr, int npages);
int ihk_numa_add_free_pages(struct ihk_mc_numa_node *node,
		unsigned long addr, unsigned long size);
#endif

struct ihk_page_allocator_desc {
	unsigned long start, end;
	unsigned int last;
	unsigned int count;
	unsigned int flag;
	unsigned int shift;
	mcs_lock_node_t lock;
	struct list_head list;
	
	unsigned long map[0];
};

unsigned long ihk_pagealloc_count(void *__desc);
void *__ihk_pagealloc_init(unsigned long start, unsigned long size,
                           unsigned long unit, void *initial,
                           unsigned long *pdescsize);
void *ihk_pagealloc_init(unsigned long start, unsigned long size,
                         unsigned long unit);
void ihk_pagealloc_destroy(void *__desc);
unsigned long ihk_pagealloc_alloc(void *__desc, int npages, int p2align);
void ihk_pagealloc_reserve(void *desc, unsigned long start, unsigned long end);
void ihk_pagealloc_free(void *__desc, unsigned long address, int npages);
unsigned long ihk_pagealloc_count(void *__desc);
int ihk_pagealloc_query_free(void *__desc);

#endif
