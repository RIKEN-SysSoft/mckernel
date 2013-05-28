#ifndef __HEADER_GENERIC_IHK_MM_H
#define __HEADER_GENERIC_IHK_MM_H

#include <memory.h>

enum ihk_mc_gma_type {
	IHK_MC_GMA_MAP_START,
	IHK_MC_GMA_MAP_END,
	IHK_MC_GMA_AVAIL_START,
	IHK_MC_GMA_AVAIL_END,
	IHK_MC_GMA_HEAP_START,
	IHK_MC_NR_RESERVED_AREAS,
	IHK_MC_RESERVED_AREA_START,
	IHK_MC_RESERVED_AREA_END,
};

enum ihk_mc_ma_type {
	IHK_MC_MA_AVAILABLE,
	IHK_MC_MA_RESERVED,
	IHK_MC_MA_SPECIAL,
};

enum ihk_mc_ap_flag {
	IHK_MC_AP_FLAG,
	IHK_MC_AP_CRITICAL, /* panic on no memory space */
	IHK_MC_AP_NOWAIT,   /* error return on no memory space */
	IHK_MC_AP_WAIT      /* wait on no memory space */
};

enum ihk_mc_pt_prepare_flag {
	IHK_MC_PT_FIRST_LEVEL,
	IHK_MC_PT_LAST_LEVEL,
};

struct ihk_mc_memory_area {
	unsigned long start;
	unsigned long size;
	enum ihk_mc_ma_type type;
};

struct ihk_mc_memory_node {
	int node;
	int nareas;
	struct ihk_mc_memory_area *areas;
};

unsigned long ihk_mc_get_memory_address(enum ihk_mc_gma_type, int);

void ihk_mc_reserve_arch_pages(unsigned long start, unsigned long end,
                               void (*cb)(unsigned long, unsigned long, int));

struct ihk_mc_pa_ops {
	void *(*alloc_page)(int, enum ihk_mc_ap_flag);
	void (*free_page)(void *, int);

	void *(*alloc)(int, enum ihk_mc_ap_flag);
	void (*free)(void *);
};

void ihk_mc_set_page_allocator(struct ihk_mc_pa_ops *);
void ihk_mc_set_page_fault_handler(void (*h)(unsigned long, void *, unsigned long));

unsigned long ihk_mc_map_memory(void *os, unsigned long phys, 
                                unsigned long size);
void ihk_mc_unmap_memory(void *os, unsigned long phys, unsigned long size);

void *ihk_mc_map_virtual(unsigned long phys, int npages,
                         enum ihk_mc_pt_attribute attr);
void ihk_mc_unmap_virtual(void *va, int npages, int free_physical);

extern void *sbox_base;
extern unsigned int free_bitmap_micpa;
void ihk_mc_map_micpa(unsigned long host_pa, unsigned long* mic_pa);
int ihk_mc_free_micpa(unsigned long mic_pa);
void ihk_mc_clean_micpa(void);

void *ihk_mc_alloc_pages(int npages, enum ihk_mc_ap_flag flag);
void ihk_mc_free_pages(void *p, int npages);
void *ihk_mc_allocate(int size, enum ihk_mc_ap_flag flag);
void ihk_mc_free(void *p);

void *arch_alloc_page(enum ihk_mc_ap_flag flag);
void arch_free_page(void *ptr);

typedef void *page_table_t;

int ihk_mc_pt_set_page(page_table_t pt, void *virt, unsigned long phys,
                       enum ihk_mc_pt_attribute attr);
int ihk_mc_pt_set_large_page(page_table_t pt, void *virt,
                       unsigned long phys, enum ihk_mc_pt_attribute attr);
int ihk_mc_pt_change_page(page_table_t pt, void *virt,
                          enum ihk_mc_pt_attribute);
int ihk_mc_pt_clear_page(page_table_t pt, void *virt);
int ihk_mc_pt_prepare_map(page_table_t pt, void *virt, unsigned long size,
                          enum ihk_mc_pt_prepare_flag);

struct page_table *ihk_mc_pt_create(enum ihk_mc_ap_flag ap_flag);
/* XXX: proper use of struct page_table and page_table_t is unknown */
void ihk_mc_pt_destroy(struct page_table *pt);
void ihk_mc_load_page_table(struct page_table *pt);
int ihk_mc_pt_virt_to_phys(struct page_table *pt,
                           void *virt, unsigned long *phys);

#endif
