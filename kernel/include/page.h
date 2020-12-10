/**
 * \file page.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Structures and functions of memory page
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef __HEADER_PAGE_H
#define __HEADER_PAGE_H

#include <ihk/atomic.h>

struct page {
	struct list_head	list;
	struct list_head	hash;
	uint8_t			mode;
	uint64_t		phys;
	ihk_atomic_t		count;
	ihk_atomic64_t	mapped;
	off_t			offset;
};

/* mode */
enum page_mode {
	PM_NONE =		0x00,
	PM_PENDING_FREE =	0x01,
	PM_WILL_PAGEIO =	0x02,
	PM_PAGEIO =		0x03,
	PM_DONE_PAGEIO =	0x04,
	PM_PAGEIO_EOF =		0x05,
	PM_PAGEIO_ERROR =	0x06,
	PM_MAPPED =		0x07,
};

struct page *phys_to_page(uintptr_t phys);
uintptr_t page_to_phys(struct page *page);
int page_unmap(struct page *page);
struct page *phys_to_page_insert_hash(uint64_t phys);

void begin_free_pages_pending(void);
void finish_free_pages_pending(void);

static inline void page_map(struct page *page)
{
	ihk_atomic_inc(&page->count);
}

static inline int page_is_in_memobj(struct page *page)
{
	return (0
			|| (page->mode == PM_MAPPED)
			|| (page->mode == PM_PAGEIO)
			|| (page->mode == PM_WILL_PAGEIO)
			|| (page->mode == PM_DONE_PAGEIO)
			|| (page->mode == PM_PAGEIO_EOF)
			|| (page->mode == PM_PAGEIO_ERROR)
			);
}

static inline int page_is_multi_mapped(struct page *page)
{
	return (ihk_atomic_read(&page->count) > 1);
}

/* Should we take page faults on ANONYMOUS mappings? */
extern int anon_on_demand;
#ifdef ENABLE_FUGAKU_HACKS
extern int hugetlbfs_on_demand;
#endif
#endif
