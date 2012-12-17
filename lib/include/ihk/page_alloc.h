#ifndef __HEADER_GENERIC_AAL_PAGE_ALLOC
#define __HEADER_GENERIC_AAL_PAGE_ALLOC

struct aal_page_allocator_desc {
	unsigned long start;
	unsigned int last;
	unsigned int count;
	unsigned int flag;
	unsigned int shift;
	aal_spinlock_t lock;
	unsigned int pad;
	
	unsigned long map[0];
};

unsigned long aal_pagealloc_count(void *__desc);
void *__aal_pagealloc_init(unsigned long start, unsigned long size,
                           unsigned long unit, void *initial,
                           unsigned long *pdescsize);
void *aal_pagealloc_init(unsigned long start, unsigned long size,
                         unsigned long unit);
void aal_pagealloc_destroy(void *__desc);
unsigned long aal_pagealloc_alloc(void *__desc, int npages);
void aal_pagealloc_reserve(void *desc, unsigned long start, unsigned long end);
void aal_pagealloc_free(void *__desc, unsigned long address, int npages);
unsigned long aal_pagealloc_count(void *__desc);

#endif
