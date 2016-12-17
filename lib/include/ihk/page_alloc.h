/**
 * \file page_alloc.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare functions acquire physical pages and assign virtual addresses
 *  to them. 
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef __HEADER_GENERIC_IHK_PAGE_ALLOC
#define __HEADER_GENERIC_IHK_PAGE_ALLOC

#include <list.h>

/* XXX: Physical memory management shouldn't be part of IHK */
struct node_distance {
	int id;
	int distance;
};

struct ihk_mc_numa_node {
	int id;
	int linux_numa_id;
	int type;
	struct list_head allocators;
	struct node_distance *nodes_by_distance;
};

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
