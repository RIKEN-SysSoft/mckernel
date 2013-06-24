#ifndef __HEADER_GENERIC_IHK_PAGE_ALLOC
#define __HEADER_GENERIC_IHK_PAGE_ALLOC

struct ihk_page_allocator_desc {
	unsigned long start;
	unsigned int last;
	unsigned int count;
	unsigned int flag;
	unsigned int shift;
	ihk_spinlock_t lock;
	unsigned int pad;
	
	unsigned long map[0];
};

unsigned long ihk_pagealloc_count(void *__desc);
void *__ihk_pagealloc_init(unsigned long start, unsigned long size,
                           unsigned long unit, void *initial,
                           unsigned long *pdescsize);
void *ihk_pagealloc_init(unsigned long start, unsigned long size,
                         unsigned long unit);
void ihk_pagealloc_destroy(void *__desc);
unsigned long ihk_pagealloc_alloc(void *__desc, int npages);
void ihk_pagealloc_reserve(void *desc, unsigned long start, unsigned long end);
void ihk_pagealloc_free(void *__desc, unsigned long address, int npages);
unsigned long ihk_pagealloc_count(void *__desc);
int ihk_pagealloc_query_free(void *__desc);

#endif
