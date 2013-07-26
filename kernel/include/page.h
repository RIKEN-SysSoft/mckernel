#ifndef __HEADER_PAGE_H
#define __HEADER_PAGE_H

struct page {
	struct list_head list;
	uint64_t flags;
	int64_t count;
};

/* flags */
#define	PAGE_IN_LIST	0x0001UL

struct page *phys_to_page(uintptr_t phys);
uintptr_t page_to_phys(struct page *page);

void *allocate_pages(int npages, enum ihk_mc_ap_flag flag);
void free_pages(void *va, int npages);
void begin_free_pages_pending(void);
void finish_free_pages_pending(void);

#endif
