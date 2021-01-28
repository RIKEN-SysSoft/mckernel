/**
 * \file mm.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare types and funcions for memory management.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 * 2014/07: bgerofi: remote TLB flush handler
 */
/* mm.h COPYRIGHT FUJITSU LIMITED 2019 */

#ifndef __HEADER_GENERIC_IHK_MM_H
#define __HEADER_GENERIC_IHK_MM_H

#include <ihk/types.h>
#include <memory.h>
#include <ihk/lock.h>
#include <ihk/atomic.h>
#include <arch/mm.h>
#include <page.h>
#include <ihk/debug.h>

struct memobj;
struct process_vm;
struct vm_range;

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

extern unsigned long bootstrap_mem_end;

enum ihk_mc_ma_type {
	IHK_MC_MA_AVAILABLE,
	IHK_MC_MA_RESERVED,
	IHK_MC_MA_SPECIAL,
};

typedef unsigned long ihk_mc_ap_flag;
/* Panic on no memory space */
#define IHK_MC_AP_CRITICAL        0x000001
/* Error return on no memory space */
#define IHK_MC_AP_NOWAIT          0x000002
/* Wait on no memory space */
#define IHK_MC_AP_WAIT            0x000004
#define IHK_MC_AP_USER            0x001000

#define IHK_MC_AP_BANDWIDTH       0x010000
#define IHK_MC_AP_LATENCY         0x020000
/* Only allocate from the closest NUMA node */
#define IHK_MC_AP_NUMA_STRICT     0x040000

#define IHK_MC_PG_KERNEL       0
#define IHK_MC_PG_USER         1

enum ihk_mc_pt_prepare_flag {
	IHK_MC_PT_FIRST_LEVEL,
	IHK_MC_PT_LAST_LEVEL,
};

enum visit_pte_flag {
	VPTEF_SKIP_NULL	= 0x0001,	/* skip null PTEs */

	VPTEF_DEFAULT	= 0,
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

struct ihk_page_allocator_desc;
void ihk_mc_reserve_arch_pages(struct ihk_page_allocator_desc *pa_allocator,
		unsigned long start, unsigned long end,
		void (*cb)(struct ihk_page_allocator_desc *, 
			unsigned long, unsigned long, int));

struct ihk_mc_pa_ops {
	void *(*alloc_page)(int, int, ihk_mc_ap_flag, int node, int is_user, uintptr_t virt_addr);
	void (*free_page)(void *, int, int is_user);

	void *(*alloc)(int, ihk_mc_ap_flag);
	void (*free)(void *);
};

void ihk_mc_set_page_allocator(struct ihk_mc_pa_ops *);
void ihk_mc_set_page_fault_handler(void (*h)(void *, uint64_t, void *));

unsigned long ihk_mc_map_memory(void *os, unsigned long phys, 
                                unsigned long size);
void ihk_mc_unmap_memory(void *os, unsigned long phys, unsigned long size);

void *ihk_mc_map_virtual(unsigned long phys, int npages,
                         enum ihk_mc_pt_attribute attr);
void ihk_mc_unmap_virtual(void *va, int npages);

extern void *sbox_base;
extern unsigned int free_bitmap_micpa;
void ihk_mc_map_micpa(unsigned long host_pa, unsigned long* mic_pa);
int ihk_mc_free_micpa(unsigned long mic_pa);
void ihk_mc_clean_micpa(void);

void *_ihk_mc_alloc_aligned_pages_node(int npages, int p2align,
	ihk_mc_ap_flag flag, int node, int is_user, uintptr_t virt_addr, char *file, int line);
#define ihk_mc_alloc_aligned_pages_node(npages, p2align, flag, node) ({\
void *r = _ihk_mc_alloc_aligned_pages_node(npages, p2align, flag, node, IHK_MC_PG_KERNEL, -1, __FILE__, __LINE__);\
r;\
})
#define ihk_mc_alloc_aligned_pages_node_user(npages, p2align, flag, node, virt_addr) ({\
void *r = _ihk_mc_alloc_aligned_pages_node(npages, p2align, flag, node, IHK_MC_PG_USER, virt_addr, __FILE__, __LINE__);\
r;\
})

#define ihk_mc_alloc_aligned_pages(npages, p2align, flag) ({\
void *r = _ihk_mc_alloc_aligned_pages_node(npages, p2align, flag, -1, IHK_MC_PG_KERNEL, -1, __FILE__, __LINE__);\
r;\
})

#define ihk_mc_alloc_aligned_pages_user(npages, p2align, flag, virt_addr) ({\
void *r = _ihk_mc_alloc_aligned_pages_node(npages, p2align, flag, -1, IHK_MC_PG_USER, virt_addr, __FILE__, __LINE__);\
r;\
})

#define ihk_mc_alloc_pages(npages, flag) ({\
void *r = _ihk_mc_alloc_aligned_pages_node(npages, PAGE_P2ALIGN, flag, -1, IHK_MC_PG_KERNEL, -1, __FILE__, __LINE__);\
r;\
})

#define ihk_mc_alloc_pages_user(npages, flag, virt_addr) ({\
void *r = _ihk_mc_alloc_aligned_pages_node(npages, PAGE_P2ALIGN, flag, -1, IHK_MC_PG_USER, virt_addr, __FILE__, __LINE__);\
r;\
})

void _ihk_mc_free_pages(void *ptr, int npages, int is_user, char *file, int line);
#define ihk_mc_free_pages(p, npages) ({\
_ihk_mc_free_pages(p, npages, IHK_MC_PG_KERNEL, __FILE__, __LINE__);\
})

#define ihk_mc_free_pages_user(p, npages) ({\
_ihk_mc_free_pages(p, npages, IHK_MC_PG_USER, __FILE__, __LINE__);\
})

void *ihk_mc_allocate(int size, int flag);
void ihk_mc_free(void *p);

int arch_get_smaller_page_size(void *args, size_t origsize, size_t *sizep, int *p2alignp);

typedef void *page_table_t;

int ihk_mc_pt_set_page(page_table_t pt, void *virt, unsigned long phys,
                       enum ihk_mc_pt_attribute attr);
int ihk_mc_pt_set_large_page(page_table_t pt, void *virt,
                       unsigned long phys, enum ihk_mc_pt_attribute attr);
int ihk_mc_pt_change_page(page_table_t pt, void *virt,
                          enum ihk_mc_pt_attribute);
int ihk_mc_pt_clear_page(page_table_t pt, void *virt);
int ihk_mc_pt_clear_large_page(page_table_t pt, void *virt);
int ihk_mc_clear_kernel_range(void *start, void *end);
int ihk_mc_pt_clear_range(page_table_t pt, struct process_vm *vm, 
		void *start, void *end);
int ihk_mc_pt_free_range(page_table_t pt, struct process_vm *vm, 
		void *start, void *end, struct memobj *memobj);
int ihk_mc_pt_change_attr_range(page_table_t pt, void *start, void *end,
		enum ihk_mc_pt_attribute clrattr,
		enum ihk_mc_pt_attribute setattr);
pte_t *ihk_mc_pt_lookup_pte(page_table_t pt, void *virt, int pgshift, void **pgbasep, size_t *pgsizep, int *p2alignp);
pte_t *ihk_mc_pt_lookup_fault_pte(struct process_vm *vm, void *virt,
		int pgshift, void **basep, size_t *sizep, int *p2alignp);
int ihk_mc_pt_set_range(page_table_t pt, struct process_vm *vm, void *start, 
		void *end, uintptr_t phys, enum ihk_mc_pt_attribute attr,
		int pgshift, struct vm_range *range, int overwrite);
int ihk_mc_pt_set_pte(page_table_t pt, pte_t *ptep, size_t pgsize, uintptr_t phys, enum ihk_mc_pt_attribute attr);
int ihk_mc_pt_prepare_map(page_table_t pt, void *virt, unsigned long size,
                          enum ihk_mc_pt_prepare_flag);
int ihk_mc_pt_split(page_table_t pt, struct process_vm *vm,
		struct vm_range *range, void *addr);
int is_splitable(struct page *page, uint32_t memobj_flags);

typedef int pte_visitor_t(void *arg, page_table_t pt, pte_t *ptep,
		void *pgaddr, int pgshift);
int visit_pte_range(page_table_t pt, void *start, void *end, int pgshift,
		enum visit_pte_flag flags, pte_visitor_t *funcp, void *arg);
int visit_pte_range_safe(page_table_t pt, void *start, void *end, int pgshift,
		enum visit_pte_flag flags, pte_visitor_t *funcp, void *arg);
int move_pte_range(page_table_t pt, struct process_vm *vm, 
				   void *src, void *dest, size_t size, struct vm_range *range);

struct page_table *ihk_mc_pt_create(ihk_mc_ap_flag ap_flag);
/* XXX: proper use of struct page_table and page_table_t is unknown */
void ihk_mc_pt_destroy(struct page_table *pt);
void ihk_mc_load_page_table(struct page_table *pt);
int ihk_mc_pt_virt_to_phys_size(struct page_table *pt,
                           const void *virt,
						   unsigned long *phys,
						   unsigned long *size);
int ihk_mc_pt_virt_to_phys(struct page_table *pt,
                           const void *virt, unsigned long *phys);
uint64_t ihk_mc_pt_virt_to_pagemap(struct page_table *pt, unsigned long virt);

int ihk_mc_get_nr_numa_nodes(void);
struct ihk_mc_numa_node *ihk_mc_get_numa_node_by_distance(int i);
void ihk_numa_zero_free_pages(struct ihk_mc_numa_node *__node);
extern int zero_at_free;

struct smp_coreset;
int ihk_mc_get_numa_node(int id, int *linux_numa_id, int *type);
int ihk_mc_get_numa_distance(int i, int j);
int ihk_mc_get_nr_memory_chunks(void);
int ihk_mc_get_linux_default_huge_page_shift(void);
int ihk_mc_get_memory_chunk(int id,
	unsigned long *start,
	unsigned long *end,
	int *numa_id);
#ifdef ENABLE_TOFU
int ihk_mc_get_memory_chunk_dma_addr(int id,
		int tni, int cqid,
		uintptr_t *dma_addr);
#endif

void remote_flush_tlb_cpumask(struct process_vm *vm, 
		unsigned long addr, int cpu_id);
void remote_flush_tlb_array_cpumask(struct process_vm *vm,
		unsigned long *addr,
		int nr_addr,
		int cpu_id);

int ihk_get_kmsg_buf(unsigned long *addr, unsigned long *size);
char *ihk_get_kargs(void);

int ihk_set_monitor(unsigned long addr, unsigned long size);
int ihk_set_rusage(unsigned long addr, unsigned long size);
int ihk_set_multi_intr_mode_addr(unsigned long addr);
int ihk_set_nmi_mode_addr(unsigned long addr);
int ihk_set_mckernel_do_futex(unsigned long addr);

extern void (*__tlb_flush_handler)(int vector);

struct tlb_flush_entry {
	struct process_vm *vm;
	unsigned long *addr;
	int nr_addr;
	ihk_atomic_t pending;
	ihk_spinlock_t lock;
} __attribute__((aligned(64)));

extern struct tlb_flush_entry tlb_flush_vector[IHK_TLB_FLUSH_IRQ_VECTOR_SIZE];

void ihk_mc_set_dump_level(unsigned int level);
unsigned int ihk_mc_get_dump_level(void);
struct ihk_dump_page_set *ihk_mc_get_dump_page_set(void);
struct ihk_dump_page *ihk_mc_get_dump_page(void);
void ihk_mc_query_mem_areas(void);
void ihk_mc_clear_dump_page_completion(void);
void ihk_mc_query_mem_user_page(void *dump_page_set);
void ihk_mc_query_mem_free_page(void *dump_page_set);
int ihk_mc_chk_page_address(pte_t mem_addr);
int ihk_mc_get_mem_user_page(void *arg0, page_table_t pt, pte_t *ptep, void *pgaddr, int pgshift);

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

extern int zero_at_free;

/*
 * Generic lockless page cache.
 * TODO: Store nr of pages in header and double-check at alloc time..
 */
struct ihk_mc_page_cache_header;

struct ihk_mc_page_cache_header {
	struct ihk_mc_page_cache_header *next;
};


static inline void ihk_mc_page_cache_free(
	struct ihk_mc_page_cache_header *cache, void *page)
{
	struct ihk_mc_page_cache_header *current = NULL;
	struct ihk_mc_page_cache_header *new =
		(struct ihk_mc_page_cache_header *)page;

	if (unlikely(!page))
		return;

retry:
	current = cache->next;
	new->next = current;

	if (!__sync_bool_compare_and_swap(&cache->next, current, new)) {
		goto retry;
	}
}

static inline void ihk_mc_page_cache_prealloc(
	struct ihk_mc_page_cache_header *cache,
	int nr_pages,
	int nr_elem)
{
	int i;

	if (unlikely(cache->next))
		return;

	for (i = 0; i < nr_elem; ++i) {
		void *pages;

		pages = ihk_mc_alloc_pages(nr_pages, IHK_MC_AP_NOWAIT);

		if (!pages) {
			kprintf("%s: ERROR: allocating pages..\n", __func__);
			continue;
		}

		ihk_mc_page_cache_free(cache, pages);
	}
}

static inline void *ihk_mc_page_cache_alloc(
	struct ihk_mc_page_cache_header *cache,
	int nr_pages)
{
	register struct ihk_mc_page_cache_header *first, *next;

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

		ihk_mc_page_cache_prealloc(cache, nr_pages, 256);
		goto retry;
	}

	return (void *)first;
}

#endif
