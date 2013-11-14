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

struct page {
	struct list_head	list;
	uint8_t			mode;
	uint8_t			padding[3];
	int32_t			count;
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

void *allocate_pages(int npages, enum ihk_mc_ap_flag flag);
void free_pages(void *va, int npages);
void begin_free_pages_pending(void);
void finish_free_pages_pending(void);

#endif
