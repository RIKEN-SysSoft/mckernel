/* memory.c COPYRIGHT FUJITSU LIMITED 2018 */
/**
 * \file memory.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Acquire physical pages and manipulate page table entries.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY
 */

#include <ihk/cpu.h>
#include <ihk/mm.h>
#include <types.h>
#include <memory.h>
#include <string.h>
#include <errno.h>
#include <list.h>
#include <process.h>
#include <page.h>
#include <cls.h>
#include <kmalloc.h>
#include <rusage_private.h>
#include <ihk/debug.h>

//#define DEBUG

#ifdef DEBUG
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

static char *last_page;
extern char _head[], _end[];

extern unsigned long linux_page_offset_base;
extern unsigned long x86_kernel_phys_base;

/* Arch specific early allocation routine */
void *early_alloc_pages(int nr_pages)
{
	void *p;

	if (!last_page) {
		last_page = (char *)(((unsigned long)_end + PAGE_SIZE - 1)
		                     & PAGE_MASK);
		/* Convert the virtual address from text's to straight maps */
		last_page = phys_to_virt(virt_to_phys(last_page));
	} else if (last_page == (void *)-1) {
		panic("Early allocator is already finalized. Do not use it.\n");
	} else {
        if(virt_to_phys(last_page) >= bootstrap_mem_end) {
            panic("Early allocator: Out of memory\n");
        }
    }
	p = last_page;
	last_page += (nr_pages * PAGE_SIZE);

	return p;
}

void early_alloc_invalidate(void)
{
	last_page = (void *)-1;
}

void *ihk_mc_allocate(int size, int flag)
{
	if (!cpu_local_var(kmalloc_initialized)) {
		kprintf("%s: error, kmalloc not yet initialized\n", __FUNCTION__);
		return NULL;
	}
	return kmalloc(size, IHK_MC_AP_NOWAIT);
}

void ihk_mc_free(void *p)
{
	if (!cpu_local_var(kmalloc_initialized)) {
		kprintf("%s: error, kmalloc not yet initialized\n", __FUNCTION__);
		return;
	}
	kfree(p);
}

void *get_last_early_heap(void)
{
	return last_page;
}

void flush_tlb(void)
{
	unsigned long cr3;

	asm volatile("movq %%cr3, %0; movq %0, %%cr3" : "=r"(cr3) : : "memory");
}

void flush_tlb_single(unsigned long addr)
{
   asm volatile("invlpg (%0)" :: "r" (addr) : "memory");
}

struct page_table {
	pte_t entry[PT_ENTRIES];
};

static struct page_table *init_pt;
static struct page_table *boot_pt;
static int init_pt_loaded = 0;
static ihk_spinlock_t init_pt_lock;

static int use_1gb_page = 0;

static void check_available_page_size(void)
{
	uint32_t edx;

	asm ("cpuid" : "=d" (edx) : "a" (0x80000001) : "%rbx", "%rcx");
	use_1gb_page = (edx & (1 << 26))? 1: 0;
	kprintf("use_1gb_page: %d\n", use_1gb_page);

	return;
}

static unsigned long setup_l2(struct page_table *pt,
                              unsigned long page_head, unsigned long start,
                              unsigned long end)
{
	int i;
	unsigned long phys;

	for (i = 0; i < PT_ENTRIES; i++) {
		phys = page_head + ((unsigned long)i << PTL2_SHIFT);

		if (phys + PTL2_SIZE <= start || phys >= end) {
			pt->entry[i] = 0;
			continue;
		}

		pt->entry[i] = phys | PFL2_KERN_ATTR | PFL2_SIZE;
	}

	return virt_to_phys(pt);
}

static unsigned long setup_l3(struct page_table *pt,
                              unsigned long page_head, unsigned long start,
                              unsigned long end)
{
	int i;
	unsigned long phys, pt_phys;

	for (i = 0; i < PT_ENTRIES; i++) {
		phys = page_head + ((unsigned long)i << PTL3_SHIFT);

		if (phys + PTL3_SIZE <= start || phys >= end) {
			pt->entry[i] = 0;
			continue;
		}
		pt_phys = setup_l2(ihk_mc_alloc_pages(1, IHK_MC_AP_CRITICAL), phys, start, end);

		pt->entry[i] = pt_phys | PFL3_PDIR_ATTR;
	}

	return virt_to_phys(pt);
}

static struct page_table *__alloc_new_pt(ihk_mc_ap_flag ap_flag)
{
	struct page_table *newpt = ihk_mc_alloc_pages(1, ap_flag);

	if(newpt)
		memset(newpt, 0, sizeof(struct page_table));

	return newpt;
}

/*
 * XXX: Confusingly, L4 and L3 automatically add PRESENT,
 *      but L2 and L1 do not!
 */

enum ihk_mc_pt_attribute attr_mask
		= 0
		| PTATTR_FILEOFF
		| PTATTR_WRITABLE
		| PTATTR_USER
		| PTATTR_ACTIVE
		| 0;
#define	ATTR_MASK	attr_mask

void enable_ptattr_no_execute(void)
{
	attr_mask |= PTATTR_NO_EXECUTE;
	return;
}

#if 0
static unsigned long attr_to_l4attr(enum ihk_mc_pt_attribute attr)
{
	return (attr & ATTR_MASK) | PFL4_PRESENT;
}
#endif
static unsigned long attr_to_l3attr(enum ihk_mc_pt_attribute attr)
{
	unsigned long r = (attr & (ATTR_MASK | PTATTR_LARGEPAGE));

	if ((attr & PTATTR_UNCACHABLE) && (attr & PTATTR_LARGEPAGE)) {
		return r | PFL3_PCD | PFL3_PWT;
	}
	return r;
}
static unsigned long attr_to_l2attr(enum ihk_mc_pt_attribute attr)
{
	unsigned long r = (attr & (ATTR_MASK | PTATTR_LARGEPAGE));

	if ((attr & PTATTR_UNCACHABLE) && (attr & PTATTR_LARGEPAGE)) {
		return r | PFL2_PCD | PFL2_PWT; 
	}
	return r;
}
static unsigned long attr_to_l1attr(enum ihk_mc_pt_attribute attr)
{
	if (attr & PTATTR_UNCACHABLE) {
		return (attr & ATTR_MASK) | PFL1_PCD | PFL1_PWT;
	} 
	else if (attr & PTATTR_WRITE_COMBINED) {
		return (attr & ATTR_MASK) | PFL1_PWT;
	}
	else { 
		return (attr & ATTR_MASK);
	}
}

#define PTLX_SHIFT(index) PTL ## index ## _SHIFT

#define GET_VIRT_INDEX(virt, index, dest) \
	dest = ((virt) >> PTLX_SHIFT(index)) & (PT_ENTRIES - 1)

#define GET_VIRT_INDICES(virt, l4i, l3i, l2i, l1i) \
	l4i = ((virt) >> PTL4_SHIFT) & (PT_ENTRIES - 1); \
	l3i = ((virt) >> PTL3_SHIFT) & (PT_ENTRIES - 1); \
	l2i = ((virt) >> PTL2_SHIFT) & (PT_ENTRIES - 1); \
	l1i = ((virt) >> PTL1_SHIFT) & (PT_ENTRIES - 1)

#define	GET_INDICES_VIRT(l4i, l3i, l2i, l1i)		\
		( ((uint64_t)(l4i) << PTL4_SHIFT)	\
		| ((uint64_t)(l3i) << PTL3_SHIFT)	\
		| ((uint64_t)(l2i) << PTL2_SHIFT)	\
		| ((uint64_t)(l1i) << PTL1_SHIFT)	\
		)

void set_pte(pte_t *ppte, unsigned long phys, enum ihk_mc_pt_attribute attr)
{
	if (attr & PTATTR_LARGEPAGE) {
		*ppte = phys | attr_to_l2attr(attr) | PFL2_SIZE;
	}
	else {
		*ppte = phys | attr_to_l1attr(attr);
	}
}


#if 0
/* 
 * get_pte() 
 *
 * Descripton: walks the page tables (creates tables if not existing)
 *             and returns a pointer to the PTE corresponding to the
 *             virtual address.
 */
pte_t *get_pte(struct page_table *pt, void *virt, enum ihk_mc_pt_attribute attr, ihk_mc_ap_flag ap_flag)
{
	int l4idx, l3idx, l2idx, l1idx;
	unsigned long v = (unsigned long)virt;
	struct page_table *newpt;

	if (!pt) {
		pt = init_pt;
	}

	GET_VIRT_INDICES(v, l4idx, l3idx, l2idx, l1idx);

    /* TODO: more detailed attribute check */
	if (pt->entry[l4idx] & PFL4_PRESENT) {
		pt = phys_to_virt(pt->entry[l4idx] & PAGE_MASK);
	} else {
		if((newpt = __alloc_new_pt(ap_flag)) == NULL)
			return NULL;
		pt->entry[l4idx] = virt_to_phys(newpt) | attr_to_l4attr(attr);
		pt = newpt;
	}

	if (pt->entry[l3idx] & PFL3_PRESENT) {
		pt = phys_to_virt(pt->entry[l3idx] & PAGE_MASK);
	} else {
		if((newpt = __alloc_new_pt(ap_flag)) == NULL)
			return NULL;
		pt->entry[l3idx] = virt_to_phys(newpt) | attr_to_l3attr(attr);
		pt = newpt;
	}

	/* PTATTR_LARGEPAGE */
	if (attr & PTATTR_LARGEPAGE) {
		return &(pt->entry[l2idx]);
	}

	/* Requested regular page, but large is allocated? */
	if (pt->entry[l2idx] & PFL2_SIZE) {
		return NULL;
	}

	if (pt->entry[l2idx] & PFL2_PRESENT) {
		pt = phys_to_virt(pt->entry[l2idx] & PAGE_MASK);
	} else {
		if((newpt = __alloc_new_pt(ap_flag)) == NULL)
			return NULL;
		pt->entry[l2idx] = virt_to_phys(newpt) | attr_to_l2attr(attr)
			| PFL2_PRESENT;
		pt = newpt;
	}

	return &(pt->entry[l1idx]);
}
#endif

static int __set_pt_page(struct page_table *pt, void *virt, unsigned long phys,
                         enum ihk_mc_pt_attribute attr)
{
	int l4idx, l3idx, l2idx, l1idx;
	unsigned long v = (unsigned long)virt;
	struct page_table *newpt;
	ihk_mc_ap_flag ap_flag;
	int in_kernel =
		(((unsigned long long)virt) >= 0xffff000000000000ULL);
	unsigned long init_pt_lock_flags;
	int ret = -ENOMEM;

	init_pt_lock_flags = 0;	/* for avoidance of warning */
	if (in_kernel) {
		init_pt_lock_flags = ihk_mc_spinlock_lock(&init_pt_lock);
	}

	ap_flag = (attr & PTATTR_FOR_USER) ?
	                IHK_MC_AP_NOWAIT: IHK_MC_AP_CRITICAL;

	if (!pt) {
		pt = init_pt;
	}
	if (attr & PTATTR_LARGEPAGE) {
		phys &= LARGE_PAGE_MASK;
	} else {
		phys &= PAGE_MASK;
	}

	GET_VIRT_INDICES(v, l4idx, l3idx, l2idx, l1idx);

	/* TODO: more detailed attribute check */
	if (pt->entry[l4idx] & PFL4_PRESENT) {
		pt = phys_to_virt(pt->entry[l4idx] & PAGE_MASK);
	} else {
		if((newpt = __alloc_new_pt(ap_flag)) == NULL)
			goto out;
		pt->entry[l4idx] = virt_to_phys(newpt) | PFL4_PDIR_ATTR;
		pt = newpt;
	}

	if (pt->entry[l3idx] & PFL3_PRESENT) {
		pt = phys_to_virt(pt->entry[l3idx] & PAGE_MASK);
	} else {
		if((newpt = __alloc_new_pt(ap_flag)) == NULL)
			goto out;
		pt->entry[l3idx] = virt_to_phys(newpt) | PFL3_PDIR_ATTR;
		pt = newpt;
	}

	if (attr & PTATTR_LARGEPAGE) {
		if (pt->entry[l2idx] & PFL2_PRESENT) {
			if ((pt->entry[l2idx] & PAGE_MASK) != phys) {
				goto out;
			} else {
				ret = 0;
				goto out;
			}
		} else {
			pt->entry[l2idx] = phys | attr_to_l2attr(attr)
				| PFL2_SIZE;
			ret = 0;
			goto out;
		}
	}

	if (pt->entry[l2idx] & PFL2_PRESENT) {
		pt = phys_to_virt(pt->entry[l2idx] & PAGE_MASK);
	} else {
		if((newpt = __alloc_new_pt(ap_flag)) == NULL)
			goto out;
		pt->entry[l2idx] = virt_to_phys(newpt) | PFL2_PDIR_ATTR;
		pt = newpt;
	}

	if (pt->entry[l1idx] & PFL1_PRESENT) {
		if ((pt->entry[l1idx] & PT_PHYSMASK) != phys) {
			kprintf("EBUSY: page table for 0x%lX is already set\n", virt);
			ret = -EBUSY;
			goto out;
		} else {
			ret = 0;
			goto out;
		}
	}
	pt->entry[l1idx] = phys | attr_to_l1attr(attr);
	ret = 0;
out:
	if (in_kernel) {
		ihk_mc_spinlock_unlock(&init_pt_lock, init_pt_lock_flags);
	}
	return ret;
}

static int __clear_pt_page(struct page_table *pt, void *virt, int largepage)
{
	int l4idx, l3idx, l2idx, l1idx;
	unsigned long v = (unsigned long)virt;

	if (!pt) {
		pt = init_pt;
	}
	if (largepage) {
		v &= LARGE_PAGE_MASK;
	} else {
		v &= PAGE_MASK;
	}

	GET_VIRT_INDICES(v, l4idx, l3idx, l2idx, l1idx);

	if (!(pt->entry[l4idx] & PFL4_PRESENT)) {
		return -EINVAL;
	}
	pt = phys_to_virt(pt->entry[l4idx] & PAGE_MASK);

	if (!(pt->entry[l3idx] & PFL3_PRESENT)) {
		return -EINVAL;
	}
	pt = phys_to_virt(pt->entry[l3idx] & PAGE_MASK);

	if (largepage) {
		if (!(pt->entry[l2idx] & PFL2_PRESENT)) {
			return -EINVAL;
		} else {
			pt->entry[l2idx] = 0;
			return 0;
		}
	}
	
	if (!(pt->entry[l2idx] & PFL2_PRESENT)) {
		return -EINVAL;
	}

	pt = phys_to_virt(pt->entry[l2idx] & PAGE_MASK);

	pt->entry[l1idx] = 0;

	return 0;
}

uint64_t ihk_mc_pt_virt_to_pagemap(struct page_table *pt, unsigned long virt)
{
	int error;
	unsigned long phys;
	uint64_t pagemap;

	error = ihk_mc_pt_virt_to_phys(pt, (void *)virt, &phys);
	if (error) {
		return PM_PSHIFT(PAGE_SHIFT);
	}

	pagemap = PM_PFRAME(phys >> PAGE_SHIFT);
	pagemap |= PM_PSHIFT(PAGE_SHIFT) | PM_PRESENT;

	return pagemap;
}

int ihk_mc_pt_virt_to_phys_size(struct page_table *pt,
                           const void *virt,
						   unsigned long *phys,
						   unsigned long *size)
{
	int l4idx, l3idx, l2idx, l1idx;
	unsigned long v = (unsigned long)virt;

	if (!pt) {
		pt = init_pt;
	}

	GET_VIRT_INDICES(v, l4idx, l3idx, l2idx, l1idx);

	if (!(pt->entry[l4idx] & PFL4_PRESENT)) {
		return -EFAULT;
	}
	pt = phys_to_virt(pte_get_phys(&pt->entry[l4idx]));

	if (!(pt->entry[l3idx] & PFL3_PRESENT)) {
		return -EFAULT;
	}
	if ((pt->entry[l3idx] & PFL3_SIZE)) {
		*phys = pte_get_phys(&pt->entry[l3idx])
			| (v & (PTL3_SIZE - 1));
		if (size) *size = PTL3_SIZE;
		return 0;
	}
	pt = phys_to_virt(pte_get_phys(&pt->entry[l3idx]));

	if (!(pt->entry[l2idx] & PFL2_PRESENT)) {
		return -EFAULT;
	}
	if ((pt->entry[l2idx] & PFL2_SIZE)) {
		*phys = pte_get_phys(&pt->entry[l2idx])
			| (v & (PTL2_SIZE - 1));
		if (size) *size = PTL2_SIZE;
		return 0;
	}
	pt = phys_to_virt(pte_get_phys(&pt->entry[l2idx]));

	if (!(pt->entry[l1idx] & PFL1_PRESENT)) {
		return -EFAULT;
	}

	*phys = pte_get_phys(&pt->entry[l1idx]) | (v & (PTL1_SIZE - 1));
	if (size) *size = PTL1_SIZE;
	return 0;
}

int ihk_mc_pt_virt_to_phys(struct page_table *pt,
                           const void *virt, unsigned long *phys)
{
	return ihk_mc_pt_virt_to_phys_size(pt, virt, phys, NULL);
}


int ihk_mc_pt_print_pte(struct page_table *pt, void *virt)
{
	int l4idx, l3idx, l2idx, l1idx;
	unsigned long v = (unsigned long)virt;

	if (!pt) {
		pt = init_pt;
	}

	GET_VIRT_INDICES(v, l4idx, l3idx, l2idx, l1idx);

	__kprintf("l4 table: 0x%lX l4idx: %d \n", virt_to_phys(pt), l4idx);
	if (!(pt->entry[l4idx] & PFL4_PRESENT)) {
		__kprintf("0x%lX l4idx not present! \n", (unsigned long)virt);
		return -EFAULT;
	}
	__kprintf("l4 entry: 0x%lX\n", pt->entry[l4idx]);
	pt = phys_to_virt(pt->entry[l4idx] & PAGE_MASK);

	__kprintf("l3 table: 0x%lX l3idx: %d \n", virt_to_phys(pt), l3idx);
	if (!(pt->entry[l3idx] & PFL3_PRESENT)) {
		__kprintf("0x%lX l3idx not present! \n", (unsigned long)virt);
		return -EFAULT;
	}
	__kprintf("l3 entry: 0x%lX\n", pt->entry[l3idx]);
	if ((pt->entry[l3idx] & PFL3_SIZE)) {
		__kprintf("l3 entry is 1G page\n");
		return 0;
	}
	pt = phys_to_virt(pt->entry[l3idx] & PAGE_MASK);
	
	__kprintf("l2 table: 0x%lX l2idx: %d \n", virt_to_phys(pt), l2idx);
	if (!(pt->entry[l2idx] & PFL2_PRESENT)) {
		__kprintf("0x%lX l2idx not present! \n", (unsigned long)virt);
		return -EFAULT;
	}
	__kprintf("l2 entry: 0x%lX\n", pt->entry[l2idx]);
	if ((pt->entry[l2idx] & PFL2_SIZE)) {
		__kprintf("l2 entry is 2M page\n");
		return 0;
	}
	pt = phys_to_virt(pt->entry[l2idx] & PAGE_MASK);

	__kprintf("l1 table: 0x%lX l1idx: %d \n", virt_to_phys(pt), l1idx);
	if (!(pt->entry[l1idx] & PFL1_PRESENT)) {
		__kprintf("0x%lX l1idx not present! \n", (unsigned long)virt);
		__kprintf("l1 entry: 0x%lX\n", pt->entry[l1idx]);
		return -EFAULT;
	}

	__kprintf("l1 entry: 0x%lX\n", pt->entry[l1idx]);
	return 0;
}

int set_pt_large_page(struct page_table *pt, void *virt, unsigned long phys,
                      enum ihk_mc_pt_attribute attr)
{
	return __set_pt_page(pt, virt, phys, attr | PTATTR_LARGEPAGE
	                     | PTATTR_ACTIVE);
}

int ihk_mc_pt_set_large_page(page_table_t pt, void *virt,
                       unsigned long phys, enum ihk_mc_pt_attribute attr)
{
	return __set_pt_page(pt, virt, phys, attr | PTATTR_LARGEPAGE
	                     | PTATTR_ACTIVE);
}

int ihk_mc_pt_set_page(page_table_t pt, void *virt,
                       unsigned long phys, enum ihk_mc_pt_attribute attr)
{
	return __set_pt_page(pt, virt, phys, attr | PTATTR_ACTIVE);
}

int ihk_mc_pt_prepare_map(page_table_t p, void *virt, unsigned long size,
                          enum ihk_mc_pt_prepare_flag flag)
{
	int l4idx, l4e, ret = 0;
	unsigned long v = (unsigned long)virt;
	struct page_table *pt = p, *newpt;
	unsigned long l;
	enum ihk_mc_pt_attribute attr = PTATTR_WRITABLE;

	if (!pt) {
		pt = init_pt;
	}

	l4idx = ((v) >> PTL4_SHIFT) & (PT_ENTRIES - 1);

	if (flag == IHK_MC_PT_FIRST_LEVEL) {
		l4e = ((v + size) >> PTL4_SHIFT)  & (PT_ENTRIES - 1);

		for (; l4idx <= l4e; l4idx++) {
			if (pt->entry[l4idx] & PFL4_PRESENT) {
				return 0;
			} else {
				newpt = __alloc_new_pt(IHK_MC_AP_CRITICAL);
				if (!newpt) {
					ret = -ENOMEM;
				} else { 
					pt->entry[l4idx] = virt_to_phys(newpt)
						| PFL4_PDIR_ATTR;
				}
			}
		}
	} else {
		/* Call without ACTIVE flag */
		l = v + size;
		for (; v < l; v += PAGE_SIZE) {
			if ((ret = __set_pt_page(pt, (void *)v, 0, attr))) {
				break;
			}
		}
	}
	return ret;
}

struct page_table *ihk_mc_pt_create(ihk_mc_ap_flag ap_flag)
{
	struct page_table *pt = ihk_mc_alloc_pages(1, ap_flag);

	if(pt == NULL)
		return NULL;

	memset(pt->entry, 0, PAGE_SIZE);
	/* Copy the kernel space */
	memcpy(pt->entry + PT_ENTRIES / 2, init_pt->entry + PT_ENTRIES / 2,
	       sizeof(pt->entry[0]) * PT_ENTRIES / 2);

	return pt;
}

static void destroy_page_table(int level, struct page_table *pt)
{
	int ix;
	unsigned long entry;
	struct page_table *lower;

	if ((level < 1) || (4 < level)) {
		panic("destroy_page_table: level is out of range");
	}
	if (pt == NULL) {
		panic("destroy_page_table: pt is NULL");
	}

	if (level > 1) {
		for (ix = 0; ix < PT_ENTRIES; ++ix) {
			entry = pt->entry[ix];
			if (!(entry & PF_PRESENT)) {
				/* entry is not valid */
				continue;
			}
			if (entry & PF_SIZE) {
				/* not a page table */
				continue;
			}
			lower = (struct page_table *)phys_to_virt(entry & PT_PHYSMASK);
			destroy_page_table(level-1, lower);
		}
	}

	ihk_mc_free_pages(pt, 1);
	return;
}

void ihk_mc_pt_destroy(struct page_table *pt)
{
	const int level = 4;	/* PML4 */

	/* clear shared entry */
	memset(pt->entry + PT_ENTRIES / 2, 0, sizeof(pt->entry[0]) * PT_ENTRIES / 2);

	destroy_page_table(level, pt);
	return;
}

int ihk_mc_pt_clear_page(page_table_t pt, void *virt)
{
	return __clear_pt_page(pt, virt, 0);
}

int ihk_mc_pt_clear_large_page(page_table_t pt, void *virt)
{
	return __clear_pt_page(pt, virt, 1);
}

typedef int walk_pte_fn_t(void *args, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end);

static int walk_pte_l1(struct page_table *pt, uint64_t base, uint64_t start,
		uint64_t end, walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;

	six = (start <= base)? 0: ((start - base) >> PTL1_SHIFT);
	eix = ((end == 0) || ((base + PTL2_SIZE) <= end))? PT_ENTRIES
		: (((end - base) + (PTL1_SIZE - 1)) >> PTL1_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		off = i * PTL1_SIZE;
		error = (*funcp)(args, &pt->entry[i], base+off, start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

static int walk_pte_l2(struct page_table *pt, uint64_t base, uint64_t start,
		uint64_t end, walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;

	six = (start <= base)? 0: ((start - base) >> PTL2_SHIFT);
	eix = ((end == 0) || ((base + PTL3_SIZE) <= end))? PT_ENTRIES
		: (((end - base) + (PTL2_SIZE - 1)) >> PTL2_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		off = i * PTL2_SIZE;
		error = (*funcp)(args, &pt->entry[i], base+off, start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

static int walk_pte_l3(struct page_table *pt, uint64_t base, uint64_t start,
		uint64_t end, walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;

	six = (start <= base)? 0: ((start - base) >> PTL3_SHIFT);
	eix = ((end == 0) || ((base + PTL4_SIZE) <= end))? PT_ENTRIES
		: (((end - base) + (PTL3_SIZE - 1)) >> PTL3_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		off = i * PTL3_SIZE;
		error = (*funcp)(args, &pt->entry[i], base+off, start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

static int walk_pte_l4(struct page_table *pt, uint64_t base, uint64_t start,
		uint64_t end, walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;

	six = (start <= base)? 0: ((start - base) >> PTL4_SHIFT);
	eix = (end == 0)? PT_ENTRIES
		:(((end - base) + (PTL4_SIZE - 1)) >> PTL4_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		off = i * PTL4_SIZE;
		error = (*funcp)(args, &pt->entry[i], base+off, start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

static int split_large_page(pte_t *ptep, size_t pgsize)
{
	struct page_table *pt;
	uintptr_t phys_base;
	int i;
	uintptr_t phys;
	struct page *page;
	pte_t pte;

	if ((pgsize != PTL3_SIZE) && (pgsize != PTL2_SIZE)) {
		ekprintf("split_large_page:invalid pgsize %#lx\n", pgsize);
		return -EINVAL;
	}

	pt = __alloc_new_pt(IHK_MC_AP_NOWAIT);
	if (pt == NULL) {
		ekprintf("split_large_page:__alloc_new_pt failed\n");
		return -ENOMEM;
	}

	pte = *ptep;
	if (pgsize == PTL2_SIZE) {
		/* break down to basic page size */
		pte &= ~PFL2_SIZE;
	}

	if (pte_is_fileoff(ptep, pgsize)) {
		phys_base = NOPHYS;
	}
	else {
		phys_base = pte_get_phys(ptep);
	}

	for (i = 0; i < PT_ENTRIES; ++i) {
		if (phys_base != NOPHYS) {
			phys = phys_base + (i * pgsize / PT_ENTRIES);
			page = phys_to_page(phys);
			if (page) {
				page_map(page);
			}
		}
		pt->entry[i] = pte;
		switch(pgsize) {
		case PTL3_SIZE:
			dkprintf("%lx+,%s: calling memory_stat_rss_add(),size=%ld,pgsize=%ld\n", pte_is_fileoff(ptep, pgsize) ? pte_get_off(&pte, pgsize) : pte_get_phys(&pte), __FUNCTION__, PTL2_SIZE, PTL2_SIZE);
			memory_stat_rss_add(PTL2_SIZE, PTL2_SIZE);
			break;
		case PTL2_SIZE:
			dkprintf("%lx+,%s: calling memory_stat_rss_add(),size=%ld,pgsize=%ld\n", pte_is_fileoff(ptep, pgsize) ? pte_get_off(&pte, pgsize) : pte_get_phys(&pte), __FUNCTION__, PTL1_SIZE, PTL1_SIZE);
			memory_stat_rss_add(PTL1_SIZE, PTL1_SIZE);
			break;
		}
		pte += pgsize / PT_ENTRIES;
	}

	*ptep = (virt_to_phys(pt) & PT_PHYSMASK) | PFL2_PDIR_ATTR;

	dkprintf("%lx-,%s: calling memory_stat_rss_sub(),size=%ld,pgsize=%ld\n", phys_base, __FUNCTION__, pgsize, pgsize);
	memory_stat_rss_sub(pgsize, pgsize);

	/* Do not do this check for large pages as they don't come from the zeroobj
	 * and are not actually mapped.
	 * TODO: clean up zeroobj as we don't really need it, anonymous mappings
	 * should be allocated for real */
	if (pgsize != PTL2_SIZE) {
		if (phys_base != NOPHYS) {
			page = phys_to_page(phys_base);
			if (pgsize != PTL2_SIZE && page && page_unmap(page)) {
				kprintf("split_large_page:page_unmap:%p\n", page);
				panic("split_large_page:page_unmap\n");
			}
		}
	}
	return 0;
}

struct visit_pte_args {
	page_table_t pt;
	enum visit_pte_flag flags;
	int pgshift;
	pte_visitor_t *funcp;
	void *arg;
};

static int visit_pte_l1(void *arg0, pte_t *ptep, uintptr_t base,
		uintptr_t start, uintptr_t end)
{
	struct visit_pte_args *args = arg0;

	if ((*ptep == PTE_NULL) && (args->flags & VPTEF_SKIP_NULL)) {
		return 0;
	}

	return (*args->funcp)(args->arg, args->pt, ptep, (void *)base,
			PTL1_SHIFT);
}

static int visit_pte_l2(void *arg0, pte_t *ptep, uintptr_t base,
		uintptr_t start, uintptr_t end)
{
	int error;
	struct visit_pte_args *args = arg0;
	struct page_table *pt;

	if ((*ptep == PTE_NULL) && (args->flags & VPTEF_SKIP_NULL)) {
		return 0;
	}

	if (((*ptep == PTE_NULL) || (*ptep & PFL2_SIZE))
			&& (start <= base)
			&& (((base + PTL2_SIZE) <= end)
				|| (end == 0))
			&& (!args->pgshift || (args->pgshift == PTL2_SHIFT))) {
		error = (*args->funcp)(args->arg, args->pt, ptep,
				(void *)base, PTL2_SHIFT);
		if (error != -E2BIG) {
			return error;
		}
	}

	if (*ptep & PFL2_SIZE) {
		ekprintf("visit_pte_l2:split large page\n");
		return -ENOMEM;
	}

	if (*ptep == PTE_NULL) {
		pt = __alloc_new_pt(IHK_MC_AP_NOWAIT);
		if (!pt) {
			return -ENOMEM;
		}
		*ptep = virt_to_phys(pt) | PFL2_PDIR_ATTR;
	}
	else {
		pt = phys_to_virt(*ptep & PT_PHYSMASK);
	}

	error = walk_pte_l1(pt, base, start, end, &visit_pte_l1, arg0);
	return error;
}

static int visit_pte_l3(void *arg0, pte_t *ptep, uintptr_t base,
		uintptr_t start, uintptr_t end)
{
	int error;
	struct visit_pte_args *args = arg0;
	struct page_table *pt;

	if ((*ptep == PTE_NULL) && (args->flags & VPTEF_SKIP_NULL)) {
		return 0;
	}

	if (((*ptep == PTE_NULL) || (*ptep & PFL3_SIZE))
			&& (start <= base)
			&& (((base + PTL3_SIZE) <= end)
				|| (end == 0))
			&& (!args->pgshift || (args->pgshift == PTL3_SHIFT))
			&& use_1gb_page) {
		error = (*args->funcp)(args->arg, args->pt, ptep,
				(void *)base, PTL3_SHIFT);
		if (error != -E2BIG) {
			return error;
		}
	}

	if (*ptep & PFL3_SIZE) {
		ekprintf("visit_pte_l3:split large page\n");
		return -ENOMEM;
	}

	if (*ptep == PTE_NULL) {
		pt = __alloc_new_pt(IHK_MC_AP_NOWAIT);
		if (!pt) {
			return -ENOMEM;
		}
		*ptep = virt_to_phys(pt) | PFL3_PDIR_ATTR;
	}
	else {
		pt = phys_to_virt(*ptep & PT_PHYSMASK);
	}

	error = walk_pte_l2(pt, base, start, end, &visit_pte_l2, arg0);
	return error;
}

static int visit_pte_l4(void *arg0, pte_t *ptep, uintptr_t base,
		uintptr_t start, uintptr_t end)
{
	int error;
	struct visit_pte_args *args = arg0;
	struct page_table *pt;

	if ((*ptep == PTE_NULL) && (args->flags & VPTEF_SKIP_NULL)) {
		return 0;
	}

	if (*ptep == PTE_NULL) {
		pt = __alloc_new_pt(IHK_MC_AP_NOWAIT);
		if (!pt) {
			return -ENOMEM;
		}
		*ptep = virt_to_phys(pt) | PFL4_PDIR_ATTR;
	}
	else {
		pt = phys_to_virt(*ptep & PT_PHYSMASK);
	}

	error = walk_pte_l3(pt, base, start, end, &visit_pte_l3, arg0);
	return error;
}

int visit_pte_range(page_table_t pt, void *start0, void *end0, int pgshift,
		enum visit_pte_flag flags, pte_visitor_t *funcp, void *arg)
{
	const uintptr_t start = (uintptr_t)start0;
	const uintptr_t end = (uintptr_t)end0;
	struct visit_pte_args args;

	args.pt = pt;
	args.flags = flags;
	args.funcp = funcp;
	args.arg = arg;
	args.pgshift = pgshift;

	return walk_pte_l4(pt, 0, start, end, &visit_pte_l4, &args);
}

static int walk_pte_l1_safe(struct page_table *pt, uint64_t base, uint64_t start,
		uint64_t end, walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;
	unsigned long phys;

	if (!pt)
		return 0;

	six = (start <= base)? 0: ((start - base) >> PTL1_SHIFT);
	eix = ((end == 0) || ((base + PTL2_SIZE) <= end))? PT_ENTRIES
		: (((end - base) + (PTL1_SIZE - 1)) >> PTL1_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {

		phys = pte_get_phys(&pt->entry[i]);
		if (-1 == ihk_mc_chk_page_address(phys))
			continue;

		off = i * PTL1_SIZE;
		error = (*funcp)(args, &pt->entry[i], base+off, start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

static int walk_pte_l2_safe(struct page_table *pt, uint64_t base, uint64_t start,
		uint64_t end, walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;
	unsigned long phys;

	if (!pt)
		return 0;

	six = (start <= base)? 0: ((start - base) >> PTL2_SHIFT);
	eix = ((end == 0) || ((base + PTL3_SIZE) <= end))? PT_ENTRIES
		: (((end - base) + (PTL2_SIZE - 1)) >> PTL2_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {

		phys = pte_get_phys(&pt->entry[i]);
		if (-1 == ihk_mc_chk_page_address(phys))
			continue;

		off = i * PTL2_SIZE;
		error = (*funcp)(args, &pt->entry[i], base+off, start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

static int walk_pte_l3_safe(struct page_table *pt, uint64_t base, uint64_t start,
		uint64_t end, walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;
	unsigned long phys;

	if (!pt)
		return 0;

	six = (start <= base)? 0: ((start - base) >> PTL3_SHIFT);
	eix = ((end == 0) || ((base + PTL4_SIZE) <= end))? PT_ENTRIES
		: (((end - base) + (PTL3_SIZE - 1)) >> PTL3_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {

		phys = pte_get_phys(&pt->entry[i]);
		if (-1 == ihk_mc_chk_page_address(phys))
			continue;

		off = i * PTL3_SIZE;
		error = (*funcp)(args, &pt->entry[i], base+off, start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

static int walk_pte_l4_safe(struct page_table *pt, uint64_t base, uint64_t start,
		uint64_t end, walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;
	unsigned long phys;

	if (!pt)
		return 0;

	six = (start <= base)? 0: ((start - base) >> PTL4_SHIFT);
	eix = (end == 0)? PT_ENTRIES
		:(((end - base) + (PTL4_SIZE - 1)) >> PTL4_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {

		phys = pte_get_phys(&pt->entry[i]);
		if (-1 == ihk_mc_chk_page_address(phys))
			continue;

		off = i * PTL4_SIZE;
		error = (*funcp)(args, &pt->entry[i], base+off, start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

static int visit_pte_l1_safe(void *arg0, pte_t *ptep, uintptr_t base,
		uintptr_t start, uintptr_t end)
{
	struct visit_pte_args *args = arg0;

	if (*ptep == PTE_NULL) {
		return 0;
	}

	return (*args->funcp)(args->arg, args->pt, ptep, (void *)base,
			PTL1_SHIFT);
}

static int visit_pte_l2_safe(void *arg0, pte_t *ptep, uintptr_t base,
		uintptr_t start, uintptr_t end)
{
	int error;
	struct visit_pte_args *args = arg0;
	struct page_table *pt;

	if (*ptep == PTE_NULL) {
		return 0;
	}

	if ((*ptep & PFL2_SIZE)
			&& (start <= base)
			&& (((base + PTL2_SIZE) <= end)
				|| (end == 0))
			&& (!args->pgshift || (args->pgshift == PTL2_SHIFT))) {
		error = (*args->funcp)(args->arg, args->pt, ptep,
				(void *)base, PTL2_SHIFT);
		if (error != -E2BIG) {
			return error;
		}
	}

	if (*ptep & PFL2_SIZE) {
		ekprintf("visit_pte_l2:split large page\n");
		return -ENOMEM;
	}

	pt = phys_to_virt(*ptep & PT_PHYSMASK);

	error = walk_pte_l1_safe(pt, base, start, end, &visit_pte_l1_safe, arg0);
	return error;
}

static int visit_pte_l3_safe(void *arg0, pte_t *ptep, uintptr_t base,
		uintptr_t start, uintptr_t end)
{
	int error;
	struct visit_pte_args *args = arg0;
	struct page_table *pt;

	if (*ptep == PTE_NULL) {
		return 0;
	}

	if ((*ptep & PFL3_SIZE)
			&& (start <= base)
			&& (((base + PTL3_SIZE) <= end)
				|| (end == 0))
			&& (!args->pgshift || (args->pgshift == PTL3_SHIFT))
			&& use_1gb_page) {
		error = (*args->funcp)(args->arg, args->pt, ptep,
				(void *)base, PTL3_SHIFT);
		if (error != -E2BIG) {
			return error;
		}
	}

	if (*ptep & PFL3_SIZE) {
		ekprintf("visit_pte_l3:split large page\n");
		return -ENOMEM;
	}

	pt = phys_to_virt(*ptep & PT_PHYSMASK);

	error = walk_pte_l2_safe(pt, base, start, end, &visit_pte_l2_safe, arg0);
	return error;
}

static int visit_pte_l4_safe(void *arg0, pte_t *ptep, uintptr_t base,
		uintptr_t start, uintptr_t end)
{
	int error;
	struct page_table *pt;

	if (*ptep == PTE_NULL) {
		return 0;
	}

	pt = phys_to_virt(*ptep & PT_PHYSMASK);

	error = walk_pte_l3_safe(pt, base, start, end, &visit_pte_l3_safe, arg0);
	return error;
}

int visit_pte_range_safe(page_table_t pt, void *start0, void *end0, int pgshift,
		enum visit_pte_flag flags, pte_visitor_t *funcp, void *arg)
{
	const uintptr_t start = (uintptr_t)start0;
	const uintptr_t end = (uintptr_t)end0;
	struct visit_pte_args args;

	args.pt = pt;
	args.flags = flags;
	args.funcp = funcp;
	args.arg = arg;
	args.pgshift = pgshift;

	return walk_pte_l4_safe(pt, 0, start, end, &visit_pte_l4_safe, &args);
}

struct clear_range_args {
	int free_physical;
	struct memobj *memobj;
	struct process_vm *vm;
	unsigned long *addr;
	int nr_addr;
	int max_nr_addr;
};

static void remote_flush_tlb_add_addr(struct clear_range_args *args,
		unsigned long addr)
{
	if (args->nr_addr < args->max_nr_addr) {
		args->addr[args->nr_addr] = addr;
		++args->nr_addr;
		return;
	}

	remote_flush_tlb_array_cpumask(args->vm, args->addr, args->nr_addr,
			ihk_mc_get_processor_id());

	args->addr[0] = addr;
	args->nr_addr = 1;
}

static int clear_range_l1(void *args0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	struct clear_range_args *args = args0;
	uint64_t phys;
	struct page *page;
	pte_t old;

	//dkprintf("%s: %lx,%lx,%lx\n", __FUNCTION__, base, start, end);

	if (*ptep == PTE_NULL) {
		return -ENOENT;
	}

	old = xchg(ptep, PTE_NULL);
	remote_flush_tlb_add_addr(args, base);

	page = NULL;
	if (!pte_is_fileoff(&old, PTL1_SIZE)) {
		phys = pte_get_phys(&old);
		page = phys_to_page(phys);
	}

	if (page) {
		dkprintf("%s: page=%p,is_in_memobj=%d,(old & PFL1_DIRTY)=%lx,memobj=%p,args->memobj->flags=%x\n", __FUNCTION__, page, page_is_in_memobj(page), (old & PFL1_DIRTY), args->memobj, args->memobj ? args->memobj->flags : -1);
	}

	if (page && page_is_in_memobj(page) &&
	    pte_is_dirty(&old, PTL1_SIZE) && args->memobj &&
	    !(args->memobj->flags & (MF_ZEROFILL | MF_PRIVATE))) {
		memobj_flush_page(args->memobj, phys, PTL1_SIZE);
	}

	if (!pte_is_fileoff(&old, PTL1_SIZE)) {
		if(args->free_physical) {
			if (!page) {
				/* Anonymous || !XPMEM attach */
				if (!args->memobj || !(args->memobj->flags & MF_XPMEM)) {
					ihk_mc_free_pages_user(phys_to_virt(phys), 1);
					dkprintf("%s: freeing regular page at 0x%lx\n", __FUNCTION__, base);
					dkprintf("%lx-,%s: calling memory_stat_rss_sub(),phys=%lx,size=%ld,pgsize=%ld\n", pte_get_phys(&old), __FUNCTION__, pte_get_phys(&old), PTL1_SIZE, PTL1_SIZE);
					memory_stat_rss_sub(PTL1_SIZE, PTL1_SIZE); 
				} else {
					dkprintf("%s: XPMEM attach,phys=%lx\n", __FUNCTION__, phys);
				}
			} else if (page_unmap(page)) {
				ihk_mc_free_pages_user(phys_to_virt(phys), 1);
				dkprintf("%s: freeing file-backed page at 0x%lx\n", __FUNCTION__, base);
				/* Track page->count for !MF_PREMAP pages */
				dkprintf("%lx-,%s: calling memory_stat_rss_sub(),phys=%lx,size=%ld,pgsize=%ld\n", pte_get_phys(&old), __FUNCTION__, pte_get_phys(&old), PTL1_SIZE, PTL1_SIZE);
				rusage_memory_stat_sub(args->memobj, PTL1_SIZE, PTL1_SIZE); 
			}
		}  else {
			dkprintf("%s: !calling memory_stat_rss_sub(),virt=%lx,phys=%lx\n", __FUNCTION__, base, pte_get_phys(&old));
		}
	}
	
	return 0;
}

static int clear_range_l2(void *args0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	struct clear_range_args *args = args0;
	uint64_t phys;
	struct page_table *pt;
	int error;
	struct page *page;
	pte_t old;

	//dkprintf("%s: %lx,%lx,%lx\n", __FUNCTION__, base, start, end);

	if (*ptep == PTE_NULL) {
		return -ENOENT;
	}

	if ((*ptep & PFL2_SIZE)
			&& ((base < start) || (end < (base + PTL2_SIZE)))) {
		error = -EINVAL;
		ekprintf("clear_range_l2(%p,%p,%lx,%lx,%lx):"
				"split page. %d\n",
				args0, ptep, base, start, end, error);
		return error;
	}

	if (*ptep & PFL2_SIZE) {
		old = xchg(ptep, PTE_NULL);
		remote_flush_tlb_add_addr(args, base);

		page = NULL;
		if (!pte_is_fileoff(&old, PTL2_SIZE)) {
			phys = pte_get_phys(&old);
			page = phys_to_page(phys);
		}

		if (page && page_is_in_memobj(page) &&
		    pte_is_dirty(&old, PTL2_SIZE) && args->memobj &&
		    !(args->memobj->flags & (MF_ZEROFILL | MF_PRIVATE))) {
			memobj_flush_page(args->memobj, phys, PTL2_SIZE);
		}

		if (!pte_is_fileoff(&old, PTL2_SIZE)) {
			if(args->free_physical) {
				if (!page) {
					/* Anonymous || !XPMEM attach */
					if (!args->memobj || !(args->memobj->flags & MF_XPMEM)) {
						ihk_mc_free_pages_user(phys_to_virt(phys),
											   PTL2_SIZE/PTL1_SIZE);
						dkprintf("%s: freeing large page at 0x%lx\n", __FUNCTION__, base);
						dkprintf("%lx-,%s: memory_stat_rss_sub(),phys=%lx,size=%ld,pgsize=%ld\n", pte_get_phys(&old),__FUNCTION__, pte_get_phys(&old), PTL2_SIZE, PTL2_SIZE);
						memory_stat_rss_sub(PTL2_SIZE, PTL2_SIZE); 
					} else {
						dkprintf("%s: XPMEM attach,phys=%lx\n", __FUNCTION__, phys);
					}
				} else if (page_unmap(page)) {
					ihk_mc_free_pages_user(phys_to_virt(phys),
				                           PTL2_SIZE/PTL1_SIZE);
					dkprintf("%s: having unmapped page-struct, freeing large page at 0x%lx\n", __FUNCTION__, base);
					/* Track page->count for !MF_PREMAP pages */
					dkprintf("%lx-,%s: calling memory_stat_rss_sub(),phys=%lx,size=%ld,pgsize=%ld\n", pte_get_phys(&old), __FUNCTION__, pte_get_phys(&old), PTL2_SIZE, PTL2_SIZE);
					rusage_memory_stat_sub(args->memobj, PTL2_SIZE, PTL2_SIZE); 
				}
			}
		}

		return 0;
	}

	pt = phys_to_virt(*ptep & PT_PHYSMASK);
	error = walk_pte_l1(pt, base, start, end, &clear_range_l1, args0);
	if (error && (error != -ENOENT)) {
		return error;
	}

	if ((start <= base) && ((base + PTL2_SIZE) <= end)) {
		*ptep = PTE_NULL;
		remote_flush_tlb_add_addr(args, base);
		ihk_mc_free_pages(pt, 1);
	}

	return 0;
}

static int clear_range_l3(void *args0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	struct clear_range_args *args = args0;
	int error;
	uint64_t phys = 0;
	pte_t old;
	struct page *page;
	struct page_table *pt;

	//dkprintf("%s: %lx,%lx,%lx\n", __FUNCTION__, base, start, end);

	if (*ptep == PTE_NULL) {
		return -ENOENT;
	}

	if ((*ptep & PFL3_SIZE)
			&& ((base < start) || (end < (base + PTL3_SIZE)))) {
		error = -EINVAL;
		ekprintf("clear_range_l3(%p,%p,%lx,%lx,%lx):"
				"split page. %d\n",
				args0, ptep, base, start, end, error);
		return error;
	}

	if (*ptep & PFL3_SIZE) {
		old = xchg(ptep, PTE_NULL);
		remote_flush_tlb_add_addr(args, base);

		page = NULL;
		if (!pte_is_fileoff(&old, PTL3_SIZE)) {
			phys = pte_get_phys(&old);
			page = phys_to_page(phys);
		}

		if (page && page_is_in_memobj(page) &&
		    pte_is_dirty(&old, PTL3_SIZE) && args->memobj &&
		    !(args->memobj->flags & (MF_ZEROFILL | MF_PRIVATE))) {
			memobj_flush_page(args->memobj, phys, PTL3_SIZE);
		}

		dkprintf("%s: phys=%ld, pte_get_phys(&old),PTL3_SIZE\n", __FUNCTION__, pte_get_phys(&old));

		if (!pte_is_fileoff(&old, PTL3_SIZE)) {
			if(args->free_physical) {
				if (!page) {
					/* Anonymous || !XPMEM attach */
					if (!args->memobj || !(args->memobj->flags & MF_XPMEM)) {
						ihk_mc_free_pages_user(phys_to_virt(phys),
											   PTL3_SIZE/PTL1_SIZE);
						dkprintf("%lx-,%s: calling memory_stat_rss_sub(),phys=%ld,size=%ld,pgsize=%ld\n", pte_get_phys(&old), __FUNCTION__, pte_get_phys(&old), PTL3_SIZE, PTL3_SIZE);
						memory_stat_rss_sub(PTL3_SIZE, PTL3_SIZE); 
					} else {
						dkprintf("%s: XPMEM attach,phys=%lx\n", __FUNCTION__, phys);
					}
				} else if (page_unmap(page)) {
					ihk_mc_free_pages_user(phys_to_virt(phys),
				                           PTL3_SIZE/PTL1_SIZE);
					/* Track page->count for !MF_PREMAP pages */
					dkprintf("%lx-,%s: calling memory_stat_rss_sub(),phys=%lx,size=%ld,pgsize=%ld\n", pte_get_phys(&old), __FUNCTION__, pte_get_phys(&old), PTL3_SIZE, PTL3_SIZE);
					rusage_memory_stat_sub(args->memobj, PTL3_SIZE, PTL3_SIZE); 
				}
			}
		}

		return 0;
	}

	pt = phys_to_virt(*ptep & PT_PHYSMASK);
	error = walk_pte_l2(pt, base, start, end, &clear_range_l2, args0);
	if (error && (error != -ENOENT)) {
		return error;
	}

	if (use_1gb_page && (start <= base) && ((base + PTL3_SIZE) <= end)) {
		*ptep = PTE_NULL;
		remote_flush_tlb_add_addr(args, base);
		ihk_mc_free_pages(pt, 1);
	}

	return 0;
}

static int clear_range_l4(void *args0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	struct page_table *pt;

	//dkprintf("%s: %lx,%lx,%lx\n", __FUNCTION__, base, start, end);

	if (*ptep == PTE_NULL) {
		return -ENOENT;
	}

	pt = phys_to_virt(*ptep & PT_PHYSMASK);
	return walk_pte_l3(pt, base, start, end, &clear_range_l3, args0);
}

#define TLB_INVALID_ARRAY_PAGES	(4)

static int clear_range(struct page_table *pt, struct process_vm *vm,
		uintptr_t start, uintptr_t end, int free_physical,
		struct memobj *memobj)
{
	int error;
	struct clear_range_args args;

	dkprintf("%s: %p,%lx,%lx,%d,%p\n",
			 __FUNCTION__, pt, start, end, free_physical, memobj);

	if ((start < vm->region.user_start)
			|| (vm->region.user_end < end)
			|| (end <= start)) {
		ekprintf("clear_range(%p,%p,%p,%x):"
				"invalid start and/or end.\n",
				pt, start, end, free_physical);
		return -EINVAL;
	}

	/* TODO: embedd this in tlb_flush_entry? */
	args.addr = (unsigned long *)ihk_mc_alloc_pages(
			TLB_INVALID_ARRAY_PAGES, IHK_MC_AP_CRITICAL);
	if (!args.addr) {
		ekprintf("%s: error: allocating address array\n", __FUNCTION__);
		return -ENOMEM;
	}
	args.nr_addr = 0;
	args.max_nr_addr = (TLB_INVALID_ARRAY_PAGES * PAGE_SIZE /
			sizeof(uint64_t));

	args.free_physical = free_physical;
	if (memobj && (memobj->flags & MF_DEV_FILE)) {
		args.free_physical = 0;
	}
	if (memobj && ((memobj->flags & MF_PREMAP))) {
		args.free_physical = 0;
	}

	if (vm->proc->straight_va &&
			(void *)start == vm->proc->straight_va &&
			(void *)end == (vm->proc->straight_va +
				vm->proc->straight_len)) {
		args.free_physical = 0;
	}

	args.memobj = memobj;
	args.vm = vm;

	error = walk_pte_l4(pt, 0, start, end, &clear_range_l4, &args);
	if (args.nr_addr) {
		remote_flush_tlb_array_cpumask(vm, args.addr, args.nr_addr,
				ihk_mc_get_processor_id());
	}

	ihk_mc_free_pages(args.addr, TLB_INVALID_ARRAY_PAGES);

	return error;
}

int ihk_mc_pt_clear_range(page_table_t pt, struct process_vm *vm, 
		void *start, void *end)
{
#define	KEEP_PHYSICAL	0
	return clear_range(pt, vm, (uintptr_t)start, (uintptr_t)end,
			KEEP_PHYSICAL, NULL);
}

int ihk_mc_pt_free_range(page_table_t pt, struct process_vm *vm, 
		void *start, void *end, struct memobj *memobj)
{
#define	FREE_PHYSICAL	1
	return clear_range(pt, vm, (uintptr_t)start, (uintptr_t)end,
			FREE_PHYSICAL, memobj);
}

struct change_attr_args {
	pte_t clrpte;
	pte_t setpte;
};

static int change_attr_range_l1(void *arg0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	struct change_attr_args *args = arg0;

	if ((*ptep == PTE_NULL) || (*ptep & PFL1_FILEOFF)) {
		return -ENOENT;
	}

	*ptep = (*ptep & ~args->clrpte) | args->setpte;
	return 0;
}

static int change_attr_range_l2(void *arg0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	struct change_attr_args *args = arg0;
	int error;
	struct page_table *pt;

	if ((*ptep == PTE_NULL) || (*ptep & PFL2_FILEOFF)) {
		return -ENOENT;
	}

	if ((*ptep & PFL2_SIZE)
			&& ((base < start) || (end < (base + PTL2_SIZE)))) {
		error = -EINVAL;
		ekprintf("change_attr_range_l2(%p,%p,%lx,%lx,%lx):"
				"split page. %d\n",
				arg0, ptep, base, start, end, error);
		return error;
	}

	if (*ptep & PFL2_SIZE) {
		if (!(*ptep & PFL2_FILEOFF)) {
			*ptep = (*ptep & ~args->clrpte) | args->setpte;
		}
		return 0;
	}

	pt = phys_to_virt(*ptep & PT_PHYSMASK);
	return walk_pte_l1(pt, base, start, end, &change_attr_range_l1, arg0);
}

static int change_attr_range_l3(void *arg0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	struct change_attr_args *args = arg0;
	int error;
	struct page_table *pt;

	if ((*ptep == PTE_NULL) || (*ptep & PFL3_FILEOFF)) {
		return -ENOENT;
	}

	if ((*ptep & PFL3_SIZE)
			&& ((base < start) || (end < (base + PTL3_SIZE)))) {
		error = -EINVAL;
		ekprintf("change_attr_range_l3(%p,%p,%lx,%lx,%lx):"
				"split page. %d\n",
				arg0, ptep, base, start, end, error);
		return error;
	}

	if (*ptep & PFL3_SIZE) {
		if (!(*ptep & PFL3_FILEOFF)) {
			*ptep = (*ptep & ~args->clrpte) | args->setpte;
		}
		return 0;
	}

	pt = phys_to_virt(*ptep & PT_PHYSMASK);
	return walk_pte_l2(pt, base, start, end, &change_attr_range_l2, arg0);
}

static int change_attr_range_l4(void *arg0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	struct page_table *pt;

	if (*ptep == PTE_NULL) {
		return -ENOENT;
	}

	pt = phys_to_virt(*ptep & PT_PHYSMASK);
	return walk_pte_l3(pt, base, start, end, &change_attr_range_l3, arg0);
}

int ihk_mc_pt_change_attr_range(page_table_t pt, void *start0, void *end0,
		enum ihk_mc_pt_attribute clrattr,
		enum ihk_mc_pt_attribute setattr)
{
	const intptr_t start = (intptr_t)start0;
	const intptr_t end = (intptr_t)end0;
	struct change_attr_args args;

	args.clrpte = attr_to_l1attr(clrattr);
	args.setpte = attr_to_l1attr(setattr);
	return walk_pte_l4(pt, 0, start, end, &change_attr_range_l4, &args);
}

static pte_t *lookup_pte(struct page_table *pt, uintptr_t virt, int pgshift,
		uintptr_t *basep, size_t *sizep, int *p2alignp)
{
	int l4idx, l3idx, l2idx, l1idx;
	pte_t *ptep;
	uintptr_t base;
	size_t size;
	int p2align;

	GET_VIRT_INDICES(virt, l4idx, l3idx, l2idx, l1idx);

	ptep = NULL;
	if (!pgshift) {
		pgshift = (use_1gb_page)? PTL3_SHIFT: PTL2_SHIFT;
	}

	if (pt->entry[l4idx] == PTE_NULL) {
		if (pgshift > PTL3_SHIFT) {
			pgshift = PTL3_SHIFT;
		}
		goto out;
	}

	pt = phys_to_virt(pte_get_phys(&pt->entry[l4idx]));
	if ((pt->entry[l3idx] == PTE_NULL)
			|| (pt->entry[l3idx] & PFL3_SIZE)) {
		if (pgshift >= PTL3_SHIFT) {
			ptep = &pt->entry[l3idx];
			pgshift = PTL3_SHIFT;
		}
		goto out;
	}

	pt = phys_to_virt(pte_get_phys(&pt->entry[l3idx]));
	if ((pt->entry[l2idx] == PTE_NULL)
			|| (pt->entry[l2idx] & PFL2_SIZE)) {
		if (pgshift >= PTL2_SHIFT) {
			ptep = &pt->entry[l2idx];
			pgshift = PTL2_SHIFT;
		}
		goto out;
	}

	pt = phys_to_virt(pte_get_phys(&pt->entry[l2idx]));
	ptep = &pt->entry[l1idx];
	pgshift = PTL1_SHIFT;

out:
	size = (size_t)1 << pgshift;
	base = virt & ~(size - 1);
	p2align = pgshift - PAGE_SHIFT;
	if (basep) *basep = base;
	if (sizep) *sizep = size;
	if (p2alignp) *p2alignp = p2align;

	return ptep;
}

pte_t *ihk_mc_pt_lookup_pte(page_table_t pt, void *virt, int pgshift,
		void **basep, size_t *sizep, int *p2alignp)
{
	pte_t *ptep;
	uintptr_t base;
	size_t size;
	int p2align;

	dkprintf("ihk_mc_pt_lookup_pte(%p,%p,%d)\n", pt, virt, pgshift);
	ptep = lookup_pte(pt, (uintptr_t)virt, pgshift, &base, &size, &p2align);
	if (basep) *basep = (void *)base;
	if (sizep) *sizep = size;
	if (p2alignp) *p2alignp = p2align;
	dkprintf("ihk_mc_pt_lookup_pte(%p,%p,%d): %p %lx %lx %d\n",
			pt, virt, pgshift, ptep, base, size, p2align);
	return ptep;
}

struct set_range_args {
	page_table_t pt;
	uintptr_t phys;
	enum ihk_mc_pt_attribute attr;
	int pgshift;
	uintptr_t diff;
	struct process_vm *vm;
	struct vm_range *range; /* To find pages we don't need to call memory_stat_rss_add() */
};

int set_range_l1(void *args0, pte_t *ptep, uintptr_t base, uintptr_t start,
		uintptr_t end)
{
	struct set_range_args *args = args0;
	int error;
	uintptr_t phys;

	dkprintf("set_range_l1(%lx,%lx,%lx)\n", base, start, end);

	if (*ptep != PTE_NULL) {
		error = -EBUSY;
		ekprintf("set_range_l1(%lx,%lx,%lx):page exists. %d %lx\n",
				base, start, end, error, *ptep);
		(void)clear_range(args->pt, args->vm, start, base, KEEP_PHYSICAL, NULL);
		goto out;
	}

	phys = args->phys + (base - start);
	*ptep = phys | attr_to_l1attr(args->attr);

	error = 0;
	// call memory_stat_rss_add() here because pgshift is resolved here
	if (rusage_memory_stat_add(args->range, phys, PTL1_SIZE, PTL1_SIZE)) {
		dkprintf("%lx+,%s: calling memory_stat_rss_add(),base=%lx,phys=%lx,size=%ld,pgsize=%ld\n", phys, __FUNCTION__, base, phys, PTL1_SIZE, PTL1_SIZE);
	} else {
		dkprintf("%s: !calling memory_stat_rss_add(),base=%lx,phys=%lx,size=%ld,pgsize=%ld\n", __FUNCTION__, base, phys, PTL1_SIZE, PTL1_SIZE);
	}

out:
	dkprintf("set_range_l1(%lx,%lx,%lx): %d %lx\n",
			base, start, end, error, *ptep);
	return error;
}

int set_range_l2(void *args0, pte_t *ptep, uintptr_t base, uintptr_t start,
		uintptr_t end)
{
	struct set_range_args *args = args0;
	int error;
	struct page_table *pt;
	uintptr_t phys;
	struct page_table *newpt = NULL;
	pte_t pte;

	dkprintf("set_range_l2(%lx,%lx,%lx)\n", base, start, end);

retry:
	if (*ptep == PTE_NULL) {
		if ((start <= base) && ((base + PTL2_SIZE) <= end)
				&& ((args->diff & (PTL2_SIZE - 1)) == 0)
				&& (!args->pgshift
					|| (args->pgshift == PTL2_SHIFT))) {
			phys = args->phys + (base - start);
			*ptep = phys | attr_to_l2attr(
					args->attr|PTATTR_LARGEPAGE);
			error = 0;
			dkprintf("set_range_l2(%lx,%lx,%lx):"
					"2MiB page. %d %lx\n",
					base, start, end, error, *ptep);
			// Call memory_stat_rss_add() here because pgshift is resolved here
			if (rusage_memory_stat_add(args->range, phys, PTL2_SIZE, PTL2_SIZE)) {
				dkprintf("%lx+,%s: calling memory_stat_rss_add(),base=%lx,phys=%lx,size=%ld,pgsize=%ld\n", phys, __FUNCTION__, base, phys, PTL2_SIZE, PTL2_SIZE);
			} else {
				dkprintf("%s: !calling memory_stat_rss_add(),base=%lx,phys=%lx,size=%ld,pgsize=%ld\n", __FUNCTION__, base, phys, PTL2_SIZE, PTL2_SIZE);
			}
			goto out;
		}

		if (!newpt) {
			newpt = __alloc_new_pt(IHK_MC_AP_NOWAIT);
			if (newpt == NULL) {
				error = -ENOMEM;
				ekprintf("set_range_l2(%lx,%lx,%lx):"
						"__alloc_new_pt failed. %d %lx\n",
						base, start, end, error, *ptep);
				(void)clear_range(args->pt, args->vm, start, base,
						KEEP_PHYSICAL, NULL);
				goto out;
			}
		}

		pte = virt_to_phys(newpt) | PFL2_PDIR_ATTR;
		pte = atomic_cmpxchg8(ptep, PTE_NULL, pte);
		if (pte != PTE_NULL) {
			/* failed to set PDTe */
			goto retry;
		}

		pt = newpt;
		newpt = NULL;
	}
	else if (*ptep & PFL2_SIZE) {
		error = -EBUSY;
		ekprintf("set_range_l2(%lx,%lx,%lx):"
				"page exists. %d %lx\n",
				base, start, end, error, *ptep);
		(void)clear_range(args->pt, args->vm, start, base, KEEP_PHYSICAL, NULL);
		goto out;
	}
	else {
		pt = phys_to_virt(*ptep & PT_PHYSMASK);
	}

	error = walk_pte_l1(pt, base, start, end, &set_range_l1, args0);
	if (error) {
		ekprintf("set_range_l2(%lx,%lx,%lx):"
				"walk_pte_l1 failed. %d %lx\n",
				base, start, end, error, *ptep);
		goto out;
	}

	error = 0;
out:
	if (newpt) {
		ihk_mc_free_pages(newpt, 1);
	}
	dkprintf("set_range_l2(%lx,%lx,%lx): %d %lx\n",
			base, start, end, error, *ptep);
	return error;
}

int set_range_l3(void *args0, pte_t *ptep, uintptr_t base, uintptr_t start,
		uintptr_t end)
{
	struct page_table *newpt = NULL;
	pte_t pte;
	struct page_table *pt;
	int error;
	struct set_range_args *args = args0;
	uintptr_t phys;

	dkprintf("set_range_l3(%lx,%lx,%lx)\n", base, start, end);

retry:
	if (*ptep == PTE_NULL) {
		if ((start <= base) && ((base + PTL3_SIZE) <= end)
				&& ((args->diff & (PTL3_SIZE - 1)) == 0)
				&& (!args->pgshift
					|| (args->pgshift == PTL3_SHIFT))
				&& use_1gb_page) {
			phys = args->phys + (base - start);
			*ptep = phys | attr_to_l3attr(
					args->attr|PTATTR_LARGEPAGE);
			error = 0;
			dkprintf("set_range_l3(%lx,%lx,%lx):"
					"1GiB page. %d %lx\n",
					base, start, end, error, *ptep);

			// Call memory_stat_rss_add() here because pgshift is resolved here
			if (rusage_memory_stat_add(args->range, phys, PTL3_SIZE, PTL3_SIZE)) {
				dkprintf("%lx+,%s: calling memory_stat_rss_add(),base=%lx,phys=%lx,size=%ld,pgsize=%ld\n", phys, __FUNCTION__, base, phys, PTL3_SIZE, PTL3_SIZE);
			} else {
				dkprintf("%s: !calling memory_stat_rss_add(),base=%lx,phys=%lx,size=%ld,pgsize=%ld\n", __FUNCTION__, base, phys, PTL3_SIZE, PTL3_SIZE);
			}
			goto out;
		}

		if (!newpt) {
			newpt = __alloc_new_pt(IHK_MC_AP_NOWAIT);
			if (newpt == NULL) {
				error = -ENOMEM;
				ekprintf("set_range_l3(%lx,%lx,%lx):"
						"__alloc_new_pt failed. %d %lx\n",
						base, start, end, error, *ptep);
				(void)clear_range(args->pt, args->vm, start,
						base, KEEP_PHYSICAL, NULL);
				goto out;
			}
		}

		pte = virt_to_phys(newpt) | PFL3_PDIR_ATTR;
		pte = atomic_cmpxchg8(ptep, PTE_NULL, pte);
		if (pte != PTE_NULL) {
			/* failed to set PDPTe */
			goto retry;
		}

		pt = newpt;
		newpt = NULL;
	}
	else if (*ptep & PFL3_SIZE) {
		error = -EBUSY;
		ekprintf("set_range_l3(%lx,%lx,%lx):"
				"page exists. %d %lx\n",
				base, start, end, error, *ptep);
		(void)clear_range(args->pt, args->vm, start, base,
				KEEP_PHYSICAL, NULL);
		goto out;
	}
	else {
		pt = phys_to_virt(*ptep & PT_PHYSMASK);
	}

	error = walk_pte_l2(pt, base, start, end, &set_range_l2, args0);
	if (error) {
		ekprintf("set_range_l3(%lx,%lx,%lx):"
				"walk_pte_l2 failed. %d %lx\n",
				base, start, end, error, *ptep);
		goto out;
	}

	error = 0;
out:
	if (newpt) {
		ihk_mc_free_pages(newpt, 1);
	}
	dkprintf("set_range_l3(%lx,%lx,%lx): %d\n",
			base, start, end, error, *ptep);
	return error;
}

int set_range_l4(void *args0, pte_t *ptep, uintptr_t base, uintptr_t start,
		uintptr_t end)
{
	struct set_range_args *args = args0;
	struct page_table *newpt = NULL;
	pte_t pte;
	struct page_table *pt;
	int error;

	dkprintf("set_range_l4(%lx,%lx,%lx)\n", base, start, end);

retry:
	if (*ptep == PTE_NULL) {
		if (!newpt) {
			newpt = __alloc_new_pt(IHK_MC_AP_NOWAIT);
			if (newpt == NULL) {
				error = -ENOMEM;
				ekprintf("set_range_l4(%lx,%lx,%lx):"
						"__alloc_new_pt failed. %d %lx\n",
						base, start, end, error, *ptep);
				(void)clear_range(args->pt, args->vm, start,
						base, KEEP_PHYSICAL, NULL);
				goto out;
			}
		}

		pte = virt_to_phys(newpt) | PFL4_PDIR_ATTR;
		pte = atomic_cmpxchg8(ptep, PTE_NULL, pte);
		if (pte != PTE_NULL) {
			/* failed to set PML4e */
			goto retry;
		}

		pt = newpt;
		newpt = NULL;
	}
	else {
		pt = phys_to_virt(*ptep & PT_PHYSMASK);
	}

	error =  walk_pte_l3(pt, base, start, end, &set_range_l3, args0);
	if (error) {
		ekprintf("set_range_l4(%lx,%lx,%lx):"
				"walk_pte_l3 failed. %d %lx\n",
				base, start, end, error, *ptep);
		goto out;
	}

	error = 0;
out:
	if (newpt) {
		ihk_mc_free_pages(newpt, 1);
	}
	dkprintf("set_range_l4(%lx,%lx,%lx): %d %lx\n",
			base, start, end, error, *ptep);
	return error;
}

int ihk_mc_pt_set_range(page_table_t pt, struct process_vm *vm, void *start, 
		void *end, uintptr_t phys, enum ihk_mc_pt_attribute attr,
		int pgshift, struct vm_range *range, int overwrite)
{
	int error;
	struct set_range_args args;

	dkprintf("ihk_mc_pt_set_range(%p,%p,%p,%lx,%x,%d,%lx-%lx)\n",
			 pt, start, end, phys, attr, pgshift, range->start, range->end);

	args.pt = pt;
	args.phys = phys;
	args.attr = attr;
	args.diff = (uintptr_t)start ^ phys;
	args.vm = vm;
	args.pgshift = pgshift;
	args.range = range;

	error = walk_pte_l4(pt, 0, (uintptr_t)start, (uintptr_t)end,
			&set_range_l4, &args);
	if (error) {
		ekprintf("ihk_mc_pt_set_range(%p,%p,%p,%lx,%x):"
				"walk_pte_l4 failed. %d\n",
				pt, start, end, phys, attr, error);
		goto out;
	}

	error = 0;
out:
	dkprintf("ihk_mc_pt_set_range(%p,%p,%p,%lx,%x): %d\n",
			pt, start, end, phys, attr, error);
	return error;
}

int ihk_mc_pt_set_pte(page_table_t pt, pte_t *ptep, size_t pgsize,
		uintptr_t phys, enum ihk_mc_pt_attribute attr)
{
	int error;

	dkprintf("ihk_mc_pt_set_pte(%p,%p,%lx,%lx,%x)\n",
			pt, ptep, pgsize, phys, attr);

	if (pgsize == PTL1_SIZE) {
		*ptep = phys | attr_to_l1attr(attr);
	}
	else if (pgsize == PTL2_SIZE) {
		if (phys & (PTL2_SIZE - 1)) {
			kprintf("%s: error: phys needs to be PTL2_SIZE aligned\n", __FUNCTION__);
			error = -1;
			goto out;
		}
		*ptep = phys | attr_to_l2attr(attr | PTATTR_LARGEPAGE);
	}
	else if ((pgsize == PTL3_SIZE) && (use_1gb_page)) {
		if (phys & (PTL3_SIZE - 1)) {
			kprintf("%s: error: phys needs to be PTL3_SIZE aligned\n", __FUNCTION__);
			error = -1;
			goto out;
		}
		*ptep = phys | attr_to_l3attr(attr | PTATTR_LARGEPAGE);
	}
	else {
		error = -EINVAL;
		ekprintf("ihk_mc_pt_set_pte(%p,%p,%lx,%lx,%x):"
				"page size. %d %lx\n",
				pt, ptep, pgsize, phys, attr, error, *ptep);
		panic("ihk_mc_pt_set_pte:page size");
		goto out;
	}

	error = 0;
out:
	dkprintf("ihk_mc_pt_set_pte(%p,%p,%lx,%lx,%x): %d %lx\n",
			pt, ptep, pgsize, phys, attr, error, *ptep);
	return error;
}

int ihk_mc_pt_split(page_table_t pt, struct process_vm *vm, void *addr)
{
	int error;
	pte_t *ptep;
	void *pgaddr;
	size_t pgsize;
	intptr_t phys;
	struct page *page;


retry:
	ptep = ihk_mc_pt_lookup_pte(pt, addr, 0, &pgaddr, &pgsize, NULL);
	if (ptep && !pte_is_null(ptep) && (pgaddr != addr)) {
		page = NULL;
		if (!pte_is_fileoff(ptep, pgsize)) {
			phys = pte_get_phys(ptep);
			page = phys_to_page(phys);
		}
		if (page && (page_is_in_memobj(page)
					|| page_is_multi_mapped(page))) {
			error = -EINVAL;
			kprintf("ihk_mc_pt_split:NYI:page break down\n");
			goto out;
		}

		error = split_large_page(ptep, pgsize);
		if (error) {
			kprintf("ihk_mc_pt_split:split_large_page failed. %d\n", error);
			goto out;
		}
		remote_flush_tlb_cpumask(vm, (intptr_t)pgaddr,
				ihk_mc_get_processor_id());
		goto retry;
	}

	error = 0;
out:
	return error;
} /* ihk_mc_pt_split() */

int arch_get_smaller_page_size(void *args, size_t cursize, size_t *newsizep,
		int *p2alignp)
{
	size_t newsize;
	int p2align;
	int error;

	if (0) {
		/* dummy */
		panic("not reached");
	}
	else if ((cursize > PTL3_SIZE) && use_1gb_page) {
		/* 1GiB */
		newsize = PTL3_SIZE;
		p2align = PTL3_SHIFT - PTL1_SHIFT;
	}
	else if (cursize > PTL2_SIZE) {
		/* 2MiB */
		newsize = PTL2_SIZE;
		p2align = PTL2_SHIFT - PTL1_SHIFT;
	}
	else if (cursize > PTL1_SIZE) {
		/* 4KiB : basic page size */
		newsize = PTL1_SIZE;
		p2align = PTL1_SHIFT - PTL1_SHIFT;
	}
	else {
		error = -ENOMEM;
		newsize = 0;
		p2align = -1;
		goto out;
	}

	error = 0;
	if (newsizep) *newsizep = newsize;
	if (p2alignp) *p2alignp = p2align;

out:
	/*dkprintf("arch_get_smaller_page_size(%p,%lx): %d %lx %d\n",
	  args, cursize, error, newsize, p2align);*/
	return error;
}

enum ihk_mc_pt_attribute arch_vrflag_to_ptattr(unsigned long flag, uint64_t fault, pte_t *ptep)
{
	enum ihk_mc_pt_attribute attr;

	attr = common_vrflag_to_ptattr(flag, fault, ptep);

	if ((fault & PF_PROT)
			|| ((fault & (PF_POPULATE | PF_PATCH))
				&& (flag & VR_PRIVATE))) {
		attr |= PTATTR_DIRTY;
	}

	return attr;
}

struct move_args {
	uintptr_t src;
	uintptr_t dest;
	struct process_vm *vm;
	struct vm_range *range;
};

static int move_one_page(void *arg0, page_table_t pt, pte_t *ptep, 
		void *pgaddr, int pgshift)
{
	int error;
	struct move_args *args = arg0;
	const size_t pgsize = (size_t)1 << pgshift;
	uintptr_t dest;
	pte_t apte;
	uintptr_t phys;
	enum ihk_mc_pt_attribute attr;

	dkprintf("move_one_page(%p,%p,%p %#lx,%p,%d)\n",
			arg0, pt, ptep, *ptep, pgaddr, pgshift);
	if (pte_is_fileoff(ptep, pgsize)) {
		error = -ENOTSUPP;
		kprintf("move_one_page(%p,%p,%p %#lx,%p,%d):fileoff. %d\n",
				arg0, pt, ptep, *ptep, pgaddr, pgshift, error);
		goto out;
	}

	dest = args->dest + ((uintptr_t)pgaddr - args->src);

	apte = PTE_NULL;
	pte_xchg(ptep, &apte);

	phys = apte & PT_PHYSMASK;
	attr = apte & ~PT_PHYSMASK;

	error = ihk_mc_pt_set_range(pt, args->vm, (void *)dest,
			(void *)(dest + pgsize), phys, attr, pgshift, args->range, 0);
	if (error) {
		kprintf("move_one_page(%p,%p,%p %#lx,%p,%d):"
				"set failed. %d\n",
				arg0, pt, ptep, *ptep, pgaddr, pgshift, error);
		goto out;
	}

	error = 0;
out:
	dkprintf("move_one_page(%p,%p,%p %#lx,%p,%d):%d\n",
			arg0, pt, ptep, *ptep, pgaddr, pgshift, error);
	return error;
}

int move_pte_range(page_table_t pt, struct process_vm *vm, 
				   void *src, void *dest, size_t size, struct vm_range *range)
{
	int error;
	struct move_args args;

	dkprintf("move_pte_range(%p,%p,%p,%#lx)\n", pt, src, dest, size);
	args.src = (uintptr_t)src;
	args.dest = (uintptr_t)dest;
	args.vm = vm;
	args.range = range;

	error = visit_pte_range(pt, src, src+size, 0, VPTEF_SKIP_NULL,
			&move_one_page, &args);
	flush_tlb();	/* XXX: TLB flush */
	if (error) {
		goto out;
	}

	error = 0;
out:
	dkprintf("move_pte_range(%p,%p,%p,%#lx):%d\n",
			pt, src, dest, size, error);
	return error;
}

void load_page_table(struct page_table *pt)
{
	unsigned long pt_addr;

	if (!pt) {
		pt = init_pt;
	}

	pt_addr = virt_to_phys(pt);

	asm volatile ("movq %0, %%cr3" : : "r"(pt_addr) : "memory");
}

void ihk_mc_load_page_table(struct page_table *pt)
{
	load_page_table(pt);
}

struct page_table *get_init_page_table(void)
{
	return init_pt;
}

struct page_table *get_boot_page_table(void)
{
	return boot_pt;
}

static unsigned long fixed_virt;
static void init_fixed_area(struct page_table *pt)
{
	fixed_virt = MAP_FIXED_START;

	return;
}

static void init_normal_area(struct page_table *pt)
{
	unsigned long map_start, map_end, phys;
	void *virt;

	map_start = ihk_mc_get_memory_address(IHK_MC_GMA_MAP_START, 0);
	map_end = ihk_mc_get_memory_address(IHK_MC_GMA_MAP_END, 0);
	virt = (void *)MAP_ST_START + map_start;

	kprintf("map_start = %lx, map_end = %lx, virt %lx\n",
		map_start, map_end, virt);

	for (phys = map_start; phys < map_end; phys += LARGE_PAGE_SIZE) {
		if (set_pt_large_page(pt, virt, phys, PTATTR_WRITABLE) != 0) {
			kprintf("%s: error setting mapping for 0x%lx\n",
					__func__, virt);
		}
		virt += LARGE_PAGE_SIZE;
	}
}

extern char *find_command_line(char *name);

static void init_linux_kernel_mapping(struct page_table *pt)
{
	unsigned long map_start, map_end, phys;
	void *virt;
	int nr_memory_chunks, chunk_id, numa_id;

	/* In case of safe_kernel_map option (safe_kernel_map == 1),
	 * processing to prevent destruction of the memory area on Linux side
	 * is executed */
	if (find_command_line("safe_kernel_map") == NULL) {
		kprintf("Straight-map entire physical memory\n");

		/* Map 2 TB for now */
		map_start = 0;
		map_end = 0x20000000000;

		virt = (void *)linux_page_offset_base;

		kprintf("Linux kernel virtual: 0x%lx - 0x%lx -> 0x%lx - 0x%lx\n",
			virt, virt + map_end, 0, map_end);

		for (phys = map_start; phys < map_end; phys += LARGE_PAGE_SIZE) {
			if (set_pt_large_page(pt, virt, phys, PTATTR_WRITABLE) != 0) {
				kprintf("%s: error setting mapping for 0x%lx\n", __FUNCTION__, virt);
			}
			virt += LARGE_PAGE_SIZE;
		}
	} else {
		kprintf("Straight-map physical memory areas allocated to McKernel\n");

		nr_memory_chunks = ihk_mc_get_nr_memory_chunks();
		if (nr_memory_chunks == 0) {
			kprintf("%s: ERROR: No memory chunk available.\n", __FUNCTION__);
			return;
		}

		for (chunk_id = 0; chunk_id < nr_memory_chunks; chunk_id++) {
			if (ihk_mc_get_memory_chunk(chunk_id, &map_start, &map_end, &numa_id)) {
				kprintf("%s: ERROR: Memory chunk id (%d) out of range.\n", __FUNCTION__, chunk_id);
				continue;
			}

			dkprintf("Linux kernel virtual: 0x%lx - 0x%lx -> 0x%lx - 0x%lx\n",
				 linux_page_offset_base + map_start,
				 linux_page_offset_base + map_end,
				 map_start, map_end);

			virt = (void *)(linux_page_offset_base + map_start);
			for (phys = map_start; phys < map_end; phys += LARGE_PAGE_SIZE, virt += LARGE_PAGE_SIZE) {
				if (set_pt_large_page(pt, virt, phys, PTATTR_WRITABLE) != 0) {
					kprintf("%s: set_pt_large_page() failed for 0x%lx\n", __FUNCTION__, virt);
				}
			}
		}
	}
}

void init_text_area(struct page_table *pt)
{
	unsigned long __end, phys, virt;
	int i, nlpages;

	__end = ((unsigned long)_end + LARGE_PAGE_SIZE * 2 - 1)
		& LARGE_PAGE_MASK;
	nlpages = (__end - MAP_KERNEL_START) >> LARGE_PAGE_SHIFT;

	kprintf("TEXT: # of large pages = %d\n", nlpages);
	kprintf("TEXT: Base address = %lx\n", x86_kernel_phys_base);

	phys = x86_kernel_phys_base;
	virt = MAP_KERNEL_START;
	for (i = 0; i < nlpages; i++) {
		set_pt_large_page(pt, (void *)virt, phys, PTATTR_WRITABLE);

		virt += LARGE_PAGE_SIZE;
		phys += LARGE_PAGE_SIZE;
	}
}

void *map_fixed_area(unsigned long phys, unsigned long size, int uncachable)
{
	unsigned long poffset, paligned;
	int i, npages;
	void *v = (void *)fixed_virt;
	enum ihk_mc_pt_attribute attr;

	poffset = phys & (PAGE_SIZE - 1);
	paligned = phys & PAGE_MASK;
	npages = (poffset + size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	attr = PTATTR_WRITABLE | PTATTR_ACTIVE;
#if 0	/* In the case of LAPIC MMIO, something will happen */
	attr |= PTATTR_NO_EXECUTE;
#endif
	if (uncachable) {
		attr |= PTATTR_UNCACHABLE;
	}

	dkprintf("map_fixed: phys: 0x%lx => 0x%lx (%d pages)\n",
			paligned, v, npages);

	for (i = 0; i < npages; i++) {
		if(__set_pt_page(init_pt, (void *)fixed_virt, paligned, attr)){
			return NULL;
		}

		fixed_virt += PAGE_SIZE;
		paligned += PAGE_SIZE;
	}
	
	flush_tlb();

	return (char *)v + poffset;
}

void init_low_area(struct page_table *pt)
{
	set_pt_large_page(pt, 0, 0, PTATTR_NO_EXECUTE|PTATTR_WRITABLE);
}

static void init_vsyscall_area(struct page_table *pt)
{
	extern char vsyscall_page[];
	int error;

#define	VSYSCALL_ADDR	((void *)(0xffffffffff600000))
	error = __set_pt_page(pt, VSYSCALL_ADDR,
			virt_to_phys(vsyscall_page), PTATTR_ACTIVE|PTATTR_USER);
	if (error) {
		panic("init_vsyscall_area:__set_pt_page failed");
	}

	return;
}

void init_page_table(void)
{
	check_available_page_size();
	init_pt = ihk_mc_alloc_pages(1, IHK_MC_AP_CRITICAL);
	ihk_mc_spinlock_init(&init_pt_lock);
	
	memset(init_pt, 0, sizeof(*init_pt));

	/* Normal memory area */
	init_normal_area(init_pt);
	init_linux_kernel_mapping(init_pt);
	init_fixed_area(init_pt);
	init_text_area(init_pt);
	init_vsyscall_area(init_pt);

	/* boot page table: needs zero mapping in order to execute the next
	 * instruction that jumps into regular regions
	 */
	boot_pt = ihk_mc_alloc_pages(1, IHK_MC_AP_CRITICAL);
	memcpy(boot_pt, init_pt, sizeof(*boot_pt));
	init_low_area(boot_pt);
	if (memcmp(init_pt, boot_pt, sizeof(*init_pt)) == 0)
		panic("init low area for boot pt did not affect toplevel entry");

	load_page_table(init_pt);
	init_pt_loaded = 1;
	kprintf("Page table is now at 0x%lx\n", init_pt);
}

extern void __reserve_arch_pages(unsigned long, unsigned long,
		void (*)(struct ihk_page_allocator_desc *, 
			unsigned long, unsigned long, int));

void ihk_mc_reserve_arch_pages(struct ihk_page_allocator_desc *pa_allocator,
		unsigned long start, unsigned long end,
		void (*cb)(struct ihk_page_allocator_desc *, 
			unsigned long, unsigned long, int))
{
	/* Reserve Text + temporal heap */
	cb(pa_allocator, virt_to_phys(_head), virt_to_phys(get_last_early_heap()), 0);
	/* Reserve trampoline area to boot the second ap */
	cb(pa_allocator, ap_trampoline, ap_trampoline + AP_TRAMPOLINE_SIZE, 0);
	/* Reserve the null page */
	cb(pa_allocator, 0, PAGE_SIZE, 0);
	/* 
	 * Micro-arch specific 
	 * TODO: this does nothing in SMP mode, update it for KNC if necessary 
	 */
	__reserve_arch_pages(start, end, cb);
}

unsigned long virt_to_phys(void *v)
{
	unsigned long va = (unsigned long)v;

	if (va >= MAP_KERNEL_START) {
		dkprintf("%s: MAP_KERNEL_START <= 0x%lx <= linux_page_offset_base\n",
				__FUNCTION__, va);
		return va - MAP_KERNEL_START + x86_kernel_phys_base;
	}
	else if (va >= linux_page_offset_base) {
		return va - linux_page_offset_base;
	}
	else if (va >= MAP_FIXED_START) {
		return va - MAP_FIXED_START;
	}
	else {
		dkprintf("%s: MAP_ST_START <= 0x%lx <= MAP_FIXED_START\n",
				__FUNCTION__, va);
		return va - MAP_ST_START;
	}
}

void *phys_to_virt(unsigned long p)
{
	/* Before loading our own PT use straight mapping */
	if (!init_pt_loaded) {
		return (void *)(p + MAP_ST_START);
	}

	return (void *)(p + linux_page_offset_base);
}

int copy_from_user(void *dst, const void *src, size_t siz)
{
	struct process_vm *vm = cpu_local_var(current)->vm;

	return read_process_vm(vm, dst, src, siz);
}

int strlen_user(const char *s)
{
	struct process_vm *vm = cpu_local_var(current)->vm;
	unsigned long pgstart;
	int maxlen;
	const char *head = s;
	int err;

	maxlen = 4096 - (((unsigned long)s) & 0x0000000000000fffUL);
	pgstart = ((unsigned long)s) & 0xfffffffffffff000UL;
	if(!pgstart || pgstart >= MAP_KERNEL_START)
		return -EFAULT;
	for(;;){
		if ((err = verify_process_vm(vm, s, 1)))
			return err;
		while(*s && maxlen > 0){
			s++;
			maxlen--;
		}
		if(!*s)
			break;
		maxlen = 4096;
		pgstart += 4096;
	}
	return s - head;
}

int strcpy_from_user(char *dst, const char *src)
{
	struct process_vm *vm = cpu_local_var(current)->vm;
	unsigned long pgstart;
	int maxlen;
	int err = 0;

	maxlen = 4096 - (((unsigned long)src) & 0x0000000000000fffUL);
	pgstart = ((unsigned long)src) & 0xfffffffffffff000UL;
	if(!pgstart || pgstart >= MAP_KERNEL_START)
		return -EFAULT;
	for(;;){
		if ((err = verify_process_vm(vm, src, 1)))
			return err;
		while(*src && maxlen > 0){
			*(dst++) = *(src++);
			maxlen--;
		}
		if(!*src){
			*dst = '\0';
			break;
		}
		maxlen = 4096;
		pgstart += 4096;
	}
	return err;
}

long getlong_user(long *dest, const long *p)
{
	int error;

	error = copy_from_user(dest, p, sizeof(long));
	if (error) {
		return error;
	}

	return 0;
}

int getint_user(int *dest, const int *p)
{
	int error;

	error = copy_from_user(dest, p, sizeof(int));
	if (error) {
		return error;
	}

	return 0;
}

int verify_process_vm(struct process_vm *vm,
		const void *usrc, size_t size)
{
	const uintptr_t ustart = (uintptr_t)usrc;
	const uintptr_t uend = ustart + size;
	uint64_t reason;
	uintptr_t addr;
	int error = 0;

	if ((ustart < vm->region.user_start)
			|| (vm->region.user_end <= ustart)
			|| ((vm->region.user_end - ustart) < size)) {
		kprintf("%s: error: out of user range\n", __FUNCTION__);
		return -EFAULT;
	}

	reason = PF_USER;	/* page not present */
	for (addr = ustart & PAGE_MASK; addr < uend; addr += PAGE_SIZE) {
		if (!addr)
			return -EINVAL;

		error = page_fault_process_vm(vm, (void *)addr, reason);
		if (error) {
			kprintf("%s: error: PF for %p failed\n", __FUNCTION__, addr);
			return error;
		}
	}

	return error;
}

int read_process_vm(struct process_vm *vm, void *kdst, const void *usrc, size_t siz)
{
	const uintptr_t ustart = (uintptr_t)usrc;
	const uintptr_t uend = ustart + siz;
	uint64_t reason;
	uintptr_t addr;
	int error;
	const void *from;
	void *to;
	size_t remain;
	size_t cpsize;
	unsigned long pa;
	void *va;

	if ((ustart < vm->region.user_start)
			|| (vm->region.user_end <= ustart)
			|| ((vm->region.user_end - ustart) < siz)) {
		kprintf("%s: error: out of user range\n", __FUNCTION__);
		return -EFAULT;
	}

	reason = PF_USER;	/* page not present */
	for (addr = ustart & PAGE_MASK; addr < uend; addr += PAGE_SIZE) {
		if (!addr)
			return -EINVAL;

		error = page_fault_process_vm(vm, (void *)addr, reason);
		if (error) {
			kprintf("%s: error: PF for %p failed\n", __FUNCTION__, addr);
			return error;
		}
	}

	from = usrc;
	to = kdst;
	remain = siz;
	while (remain > 0) {
		cpsize = PAGE_SIZE - ((uintptr_t)from & (PAGE_SIZE - 1));
		if (cpsize > remain) {
			cpsize = remain;
		}

		error = ihk_mc_pt_virt_to_phys(vm->address_space->page_table, from, &pa);
		if (error) {
			kprintf("%s: error: resolving physical address or %p\n", __FUNCTION__, from);
			return error;
		}

		if (!is_mckernel_memory(pa, pa + cpsize)) {
			dkprintf("%s: pa is outside of LWK memory, to: %p, pa: %p,"
				"cpsize: %d\n", __FUNCTION__, to, pa, cpsize);
			va = ihk_mc_map_virtual(pa, 1, PTATTR_ACTIVE);
			memcpy(to, va, cpsize);
			ihk_mc_unmap_virtual(va, 1);
		}
		else {
			va = phys_to_virt(pa);
			memcpy(to, va, cpsize);
		}

		from += cpsize;
		to += cpsize;
		remain -= cpsize;
	}

	return 0;
} /* read_process_vm() */

int copy_to_user(void *dst, const void *src, size_t siz)
{
	struct process_vm *vm = cpu_local_var(current)->vm;

	return write_process_vm(vm, dst, src, siz);
}

int setlong_user(long *dst, long data)
{
	return copy_to_user(dst, &data, sizeof(data));
}

int setint_user(int *dst, int data)
{
	return copy_to_user(dst, &data, sizeof(data));
}

int write_process_vm(struct process_vm *vm, void *udst, const void *ksrc, size_t siz)
{
	const uintptr_t ustart = (uintptr_t)udst;
	const uintptr_t uend = ustart + siz;
	uint64_t reason;
	uintptr_t addr;
	int error;
	const void *from;
	void *to;
	size_t remain;
	size_t cpsize;
	unsigned long pa;
	void *va;

	if ((ustart < vm->region.user_start)
			|| (vm->region.user_end <= ustart)
			|| ((vm->region.user_end - ustart) < siz)) {
		return -EFAULT;
	}

	reason = PF_POPULATE | PF_WRITE | PF_USER;
	for (addr = ustart & PAGE_MASK; addr < uend; addr += PAGE_SIZE) {
		error = page_fault_process_vm(vm, (void *)addr, reason);
		if (error) {
			return error;
		}
	}

	from = ksrc;
	to = udst;
	remain = siz;
	while (remain > 0) {
		cpsize = PAGE_SIZE - ((uintptr_t)to & (PAGE_SIZE - 1));
		if (cpsize > remain) {
			cpsize = remain;
		}

		error = ihk_mc_pt_virt_to_phys(vm->address_space->page_table, to, &pa);
		if (error) {
			return error;
		}

		if (!is_mckernel_memory(pa, pa + cpsize)) {
			dkprintf("%s: pa is outside of LWK memory, from: %p,"
				"pa: %p, cpsize: %d\n", __FUNCTION__, from, pa, cpsize);
			va = ihk_mc_map_virtual(pa, 1, PTATTR_ACTIVE);
			memcpy(va, from, cpsize);
			ihk_mc_unmap_virtual(va, 1);
		}
		else {
			va = phys_to_virt(pa);
			memcpy(va, from, cpsize);
		}

		from += cpsize;
		to += cpsize;
		remain -= cpsize;
	}

	return 0;
} /* write_process_vm() */

int patch_process_vm(struct process_vm *vm, void *udst, const void *ksrc, size_t siz)
{
	const uintptr_t ustart = (uintptr_t)udst;
	const uintptr_t uend = ustart + siz;
	uint64_t reason;
	uintptr_t addr;
	int error;
	const void *from;
	void *to;
	size_t remain;
	size_t cpsize;
	unsigned long pa;
	void *va;

	dkprintf("patch_process_vm(%p,%p,%p,%lx)\n", vm, udst, ksrc, siz);
	if ((ustart < vm->region.user_start)
			|| (vm->region.user_end <= ustart)
			|| ((vm->region.user_end - ustart) < siz)) {
		kprintf("patch_process_vm(%p,%p,%p,%lx):not in user\n", vm, udst, ksrc, siz);
		return -EFAULT;
	}

	reason = PF_PATCH | PF_WRITE | PF_USER;
	for (addr = ustart & PAGE_MASK; addr < uend; addr += PAGE_SIZE) {
		error = page_fault_process_vm(vm, (void *)addr, reason);
		if (error) {
			kprintf("patch_process_vm(%p,%p,%p,%lx):pf(%lx):%d\n", vm, udst, ksrc, siz, addr, error);
			return error;
		}
	}

	from = ksrc;
	to = udst;
	remain = siz;
	while (remain > 0) {
		cpsize = PAGE_SIZE - ((uintptr_t)to & (PAGE_SIZE - 1));
		if (cpsize > remain) {
			cpsize = remain;
		}

		error = ihk_mc_pt_virt_to_phys(vm->address_space->page_table, to, &pa);
		if (error) {
			kprintf("patch_process_vm(%p,%p,%p,%lx):v2p(%p):%d\n", vm, udst, ksrc, siz, to, error);
			return error;
		}

		if (!is_mckernel_memory(pa, pa + cpsize)) {
			dkprintf("%s: pa is outside of LWK memory, from: %p,"
				"pa: %p, cpsize: %d\n", __FUNCTION__, from, pa, cpsize);
			va = ihk_mc_map_virtual(pa, 1, PTATTR_ACTIVE);
			memcpy(va, from, cpsize);
			ihk_mc_unmap_virtual(va, 1);
		}
		else {
			va = phys_to_virt(pa);
			memcpy(va, from, cpsize);
		}

		from += cpsize;
		to += cpsize;
		remain -= cpsize;
	}

	dkprintf("patch_process_vm(%p,%p,%p,%lx):%d\n", vm, udst, ksrc, siz, 0);
	return 0;
} /* patch_process_vm() */
