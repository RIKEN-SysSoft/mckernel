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

#ifndef __HEADER_GENERIC_IHK_MM_H
#define __HEADER_GENERIC_IHK_MM_H

#include <ihk/types.h>
#include <memory.h>
#include <ihk/lock.h>
#include <ihk/atomic.h>
#include <arch/mm.h>

struct memobj;
struct process_vm;

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

void ihk_mc_reserve_arch_pages(unsigned long start, unsigned long end,
                               void (*cb)(unsigned long, unsigned long, int));

struct ihk_mc_pa_ops {
	void *(*alloc_page)(int, int, enum ihk_mc_ap_flag);
	void (*free_page)(void *, int);

	void *(*alloc)(int, enum ihk_mc_ap_flag);
	void (*free)(void *);
};

void ihk_mc_set_page_allocator(struct ihk_mc_pa_ops *);
void ihk_mc_set_page_fault_handler(void (*h)(void *, uint64_t, void *));

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

void *ihk_mc_alloc_aligned_pages(int npages, int p2align, enum ihk_mc_ap_flag flag);
void *ihk_mc_alloc_pages(int npages, enum ihk_mc_ap_flag flag);
void ihk_mc_free_pages(void *p, int npages);
void *ihk_mc_allocate(int size, enum ihk_mc_ap_flag flag);
void ihk_mc_free(void *p);

void *arch_alloc_page(enum ihk_mc_ap_flag flag);
void arch_free_page(void *ptr);
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
int ihk_mc_pt_clear_range(page_table_t pt, struct process_vm *vm, 
		void *start, void *end);
int ihk_mc_pt_free_range(page_table_t pt, struct process_vm *vm, 
		void *start, void *end, struct memobj *memobj);
int ihk_mc_pt_change_attr_range(page_table_t pt, void *start, void *end,
		enum ihk_mc_pt_attribute clrattr,
		enum ihk_mc_pt_attribute setattr);
pte_t *ihk_mc_pt_lookup_pte(page_table_t pt, void *virt, int pgshift, void **pgbasep, size_t *pgsizep, int *p2alignp);
int ihk_mc_pt_set_range(page_table_t pt, struct process_vm *vm, void *start, 
		void *end, uintptr_t phys, enum ihk_mc_pt_attribute attr,
		int pgshift);
int ihk_mc_pt_set_pte(page_table_t pt, pte_t *ptep, size_t pgsize, uintptr_t phys, enum ihk_mc_pt_attribute attr);
int ihk_mc_pt_prepare_map(page_table_t pt, void *virt, unsigned long size,
                          enum ihk_mc_pt_prepare_flag);
int ihk_mc_pt_split(page_table_t pt, struct process_vm *vm, void *addr);

typedef int pte_visitor_t(void *arg, page_table_t pt, pte_t *ptep,
		void *pgaddr, int pgshift);
int visit_pte_range(page_table_t pt, void *start, void *end, int pgshift,
		enum visit_pte_flag flags, pte_visitor_t *funcp, void *arg);
int move_pte_range(page_table_t pt, struct process_vm *vm, 
		void *src, void *dest, size_t size);

struct page_table *ihk_mc_pt_create(enum ihk_mc_ap_flag ap_flag);
/* XXX: proper use of struct page_table and page_table_t is unknown */
void ihk_mc_pt_destroy(struct page_table *pt);
void ihk_mc_load_page_table(struct page_table *pt);
int ihk_mc_pt_virt_to_phys(struct page_table *pt,
                           const void *virt, unsigned long *phys);
uint64_t ihk_mc_pt_virt_to_pagemap(struct page_table *pt, unsigned long virt);

void remote_flush_tlb_cpumask(struct process_vm *vm, 
		unsigned long addr, int cpu_id);

extern void (*__tlb_flush_handler)(int vector);

struct tlb_flush_entry {
	struct process_vm *vm;
	unsigned long addr;
	ihk_atomic_t pending;
	ihk_spinlock_t lock;
} __attribute__((aligned(64)));

extern struct tlb_flush_entry tlb_flush_vector[IHK_TLB_FLUSH_IRQ_VECTOR_SIZE];

#endif
