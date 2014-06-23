/**
 * \file arch-memomry.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Define and declare memory management macros and functions
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef __HEADER_X86_COMMON_ARCH_MEMORY_H
#define __HEADER_X86_COMMON_ARCH_MEMORY_H

#include <ihk/types.h>

#define KERNEL_CS_ENTRY    4
#define KERNEL_DS_ENTRY    5
#define USER_CS_ENTRY      6
#define USER_DS_ENTRY      7
#define GLOBAL_TSS_ENTRY   8

#define KERNEL_CS          (KERNEL_CS_ENTRY * 8)
#define KERNEL_DS          (KERNEL_DS_ENTRY * 8)
#define USER_CS            (USER_CS_ENTRY * 8 + 3)
#define USER_DS            (USER_DS_ENTRY * 8 + 3)
#define GLOBAL_TSS         (GLOBAL_TSS_ENTRY * 8)

#define PAGE_SHIFT         12
#define PAGE_SIZE          (1UL << PAGE_SHIFT)
#define PAGE_MASK          (~((unsigned long)PAGE_SIZE - 1))
#define PAGE_P2ALIGN       0

#define LARGE_PAGE_SHIFT   21
#define LARGE_PAGE_SIZE    (1UL << LARGE_PAGE_SHIFT)
#define LARGE_PAGE_MASK    (~((unsigned long)LARGE_PAGE_SIZE - 1))
#define LARGE_PAGE_P2ALIGN (LARGE_PAGE_SHIFT - PAGE_SHIFT)

#define USER_END           0x0000800000000000UL
#define MAP_ST_START       0xffff800000000000UL
#define MAP_VMAP_START     0xfffff00000000000UL
#define MAP_FIXED_START    0xffffffff70000000UL
#define MAP_KERNEL_START   0xffffffff80000000UL

#define MAP_VMAP_SIZE      0x0000000100000000UL

#define KERNEL_PHYS_OFFSET MAP_ST_START

#define PTL4_SHIFT         39
#define PTL4_SIZE          (1UL << PTL4_SHIFT)
#define PTL3_SHIFT         30
#define PTL3_SIZE          (1UL << PTL3_SHIFT)
#define PTL2_SHIFT         21     
#define PTL2_SIZE          (1UL << PTL2_SHIFT)
#define PTL1_SHIFT         12
#define PTL1_SIZE          (1UL << PTL1_SHIFT)

#define PT_ENTRIES         512

/* mask of the physical address of the entry to the page table */
#define	PT_PHYSMASK	(((1UL << 52) - 1) & PAGE_MASK)

#define	PF_PRESENT	((pte_t)0x01)	/* entry is valid */
#define PF_WRITABLE	((pte_t)0x02)
#define	PF_SIZE		((pte_t)0x80)	/* entry points large page */

#define PFL4_PRESENT    ((pte_t)0x01)
#define PFL4_WRITABLE   ((pte_t)0x02)
#define PFL4_USER       ((pte_t)0x04)

#define PFL3_PRESENT    ((pte_t)0x01)
#define PFL3_WRITABLE   ((pte_t)0x02)
#define PFL3_USER       ((pte_t)0x04)
#define PFL3_PWT        ((pte_t)0x08)
#define PFL3_PCD        ((pte_t)0x10)
#define PFL3_ACCESSED   ((pte_t)0x20)
#define PFL3_DIRTY      ((pte_t)0x40)
#define PFL3_SIZE       ((pte_t)0x80)   /* Used in 1G page */
#define PFL3_GLOBAL     ((pte_t)0x100)
#define PFL3_IGNORED_11 ((pte_t)1 << 11)
#define PFL3_FILEOFF    PFL3_IGNORED_11

#define PFL2_PRESENT    ((pte_t)0x01)
#define PFL2_WRITABLE   ((pte_t)0x02)
#define PFL2_USER       ((pte_t)0x04)
#define PFL2_PWT        ((pte_t)0x08)
#define PFL2_PCD        ((pte_t)0x10)
#define PFL2_ACCESSED   ((pte_t)0x20)
#define PFL2_DIRTY      ((pte_t)0x40)
#define PFL2_SIZE       ((pte_t)0x80)   /* Used in 2M page */
#define PFL2_GLOBAL     ((pte_t)0x100)
#define PFL2_IGNORED_11 ((pte_t)1 << 11)
#define PFL2_FILEOFF    PFL2_IGNORED_11

#define PFL1_PRESENT    ((pte_t)0x01)
#define PFL1_WRITABLE   ((pte_t)0x02)
#define PFL1_USER       ((pte_t)0x04)
#define PFL1_PWT        ((pte_t)0x08)
#define PFL1_PCD        ((pte_t)0x10)
#define PFL1_ACCESSED   ((pte_t)0x20)
#define PFL1_DIRTY      ((pte_t)0x40)
#define PFL1_IGNORED_11 ((pte_t)1 << 11)
#define PFL1_FILEOFF    PFL1_IGNORED_11

/* We allow user programs to access all the memory */
#define PFL4_KERN_ATTR       (PFL4_PRESENT | PFL4_WRITABLE)
#define PFL3_KERN_ATTR       (PFL3_PRESENT | PFL3_WRITABLE)
#define PFL2_KERN_ATTR       (PFL2_PRESENT | PFL2_WRITABLE)
#define PFL1_KERN_ATTR       (PFL1_PRESENT | PFL1_WRITABLE)

/* for the page table entry that points another page table */
#define	PFL4_PDIR_ATTR	(PFL4_PRESENT | PFL4_WRITABLE | PFL4_USER)
#define	PFL3_PDIR_ATTR	(PFL3_PRESENT | PFL3_WRITABLE | PFL3_USER)
#define	PFL2_PDIR_ATTR	(PFL2_PRESENT | PFL2_WRITABLE | PFL2_USER)

#define	PTE_NULL ((pte_t)0)
typedef unsigned long pte_t;

/* For easy conversion, it is better to be the same as architecture's ones */
enum ihk_mc_pt_attribute {
	PTATTR_ACTIVE     = 0x01,
	PTATTR_WRITABLE   = 0x02,
	PTATTR_USER       = 0x04,
	PTATTR_DIRTY      = 0x40,
	PTATTR_LARGEPAGE  = 0x80,
	PTATTR_FILEOFF    = PFL2_FILEOFF,
	PTATTR_NO_EXECUTE = 0x8000000000000000,
	PTATTR_UNCACHABLE = 0x10000,
	PTATTR_FOR_USER   = 0x20000,
};

static inline int pte_is_null(pte_t *ptep)
{
	return (*ptep == PTE_NULL);
}

static inline int pte_is_present(pte_t *ptep)
{
	return !!(*ptep & PF_PRESENT);
}

static inline int pte_is_writable(pte_t *ptep)
{
	return !!(*ptep & PF_WRITABLE);
}

static inline int pte_is_dirty(pte_t *ptep, size_t pgsize)
{
	switch (pgsize) {
	case PTL1_SIZE:	return !!(*ptep & PFL1_DIRTY);
	case PTL2_SIZE:	return !!(*ptep & PFL2_DIRTY);
	case PTL3_SIZE:	return !!(*ptep & PFL3_DIRTY);
	default:
#if 0	/* XXX: workaround. cannot use panic() here */
		panic("pte_is_dirty");
#else
		return !!(*ptep & PTATTR_DIRTY);
#endif
	}
}

static inline int pte_is_fileoff(pte_t *ptep, size_t pgsize)
{
	switch (pgsize) {
	case PTL1_SIZE:	return !!(*ptep & PFL1_FILEOFF);
	case PTL2_SIZE:	return !!(*ptep & PFL2_FILEOFF);
	case PTL3_SIZE:	return !!(*ptep & PFL3_FILEOFF);
	default:
#if 0	/* XXX: workaround. cannot use panic() here */
		panic("pte_is_fileoff");
#else
		return !!(*ptep & PTATTR_FILEOFF);
#endif
	}
}

static inline uintptr_t pte_get_phys(pte_t *ptep)
{
	return (*ptep & PT_PHYSMASK);
}

static inline off_t pte_get_off(pte_t *ptep, size_t pgsize)
{
	return (off_t)(*ptep & PAGE_MASK);
}

static inline void pte_make_fileoff(off_t off,
		enum ihk_mc_pt_attribute ptattr, size_t pgsize, pte_t *ptep)
{
	uint64_t attr;

	attr = ptattr & ~PAGE_MASK;

	switch (pgsize) {
	case PTL1_SIZE:	attr |= PFL1_FILEOFF;			break;
	case PTL2_SIZE:	attr |= PFL2_FILEOFF | PFL2_SIZE;	break;
	case PTL3_SIZE:	attr |= PFL3_FILEOFF | PFL3_SIZE;	break;
	default:
#if 0	/* XXX: workaround. cannot use panic() here */
		panic("pte_make_fileoff");
#else
		attr |= PTATTR_FILEOFF;
#endif
		break;
	}
	*ptep = (off & PAGE_MASK) | attr;
}

#if 0	/* XXX: workaround. cannot use panic() here */
static inline void pte_xchg(pte_t *ptep, pte_t *valp)
{
	*valp = xchg(ptep, *valp);
}
#else
#define	pte_xchg(p,vp)	do { *(vp) = xchg((p), *(vp)); } while (0)
#endif

struct page_table;
void set_pte(pte_t *ppte, unsigned long phys, enum ihk_mc_pt_attribute attr);
pte_t *get_pte(struct page_table *pt, void *virt, enum ihk_mc_pt_attribute attr);

void *early_alloc_page(void);
void *get_last_early_heap(void);
void flush_tlb(void);
void flush_tlb_single(unsigned long addr);

void *map_fixed_area(unsigned long phys, unsigned long size, int uncachable);

#define AP_TRAMPOLINE       0x10000
#define AP_TRAMPOLINE_SIZE  0x4000

/* Local is cachable */
#define IHK_IKC_QUEUE_PT_ATTR (PTATTR_NO_EXECUTE | PTATTR_WRITABLE | PTATTR_UNCACHABLE)
#endif
