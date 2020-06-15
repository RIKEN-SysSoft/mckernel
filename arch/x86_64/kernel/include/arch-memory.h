/* arch-memory.h COPYRIGHT FUJITSU LIMITED 2018 */
/**
 * \file arch-memomry.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Define and declare memory management macros and functions
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY
 */

#ifndef __HEADER_X86_COMMON_ARCH_MEMORY_H
#define __HEADER_X86_COMMON_ARCH_MEMORY_H

#include <ihk/types.h>
#include <errno.h>

#define KERNEL_CS_ENTRY    4
#define KERNEL_DS_ENTRY    5
#define USER_CS_ENTRY      6
#define USER_DS_ENTRY      7
#define GLOBAL_TSS_ENTRY   8
#define GETCPU_ENTRY       15

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

#define USER_END              0x0000800000000000UL
#define LD_TASK_UNMAPPED_BASE 0x0000155555500000UL
#define TASK_UNMAPPED_BASE    0x00002AAAAAA00000UL

/*
 * Canonical negative addresses (i.e., the smallest kernel virtual address)
 * on x86 64 bit mode (in its most restricted 48 bit format) starts from
 * 0xffff800000000000, but Linux starts mapping physical memory at 0xffff880000000000.
 * The 0x80000000000 long gap (8TBs, i.e., 16 PGD level entries in the page tables)
 * is used for Xen hyervisor (see arch/x86/include/asm/page.h) and that is
 * what we utilize for McKernel.
 * This gives us the benefit of being able to use Linux kernel virtual
 * addresses identically as in Linux.
 *
 * NOTE: update these also in eclair.c when modified!
 */
#define MAP_ST_START       0xffff800000000000UL
#define MAP_VMAP_START     0xffff850000000000UL
#define MAP_FIXED_START    0xffff860000000000UL
#define LINUX_PAGE_OFFSET  0xffff880000000000UL
/*
 * MAP_KERNEL_START is 8MB below MODULES_END in Linux.
 * Placing the LWK image in the virtual address space at the end of
 * the Linux modules section enables us to map the LWK TEXT in Linux
 * as well, so that Linux can also call into LWK text.
 * It's defined by cmake.
 */
#define STACK_TOP(region)  ((region)->user_end)

#define MAP_VMAP_SIZE      0x0000000100000000UL

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
#define PFLX_PWT        ((pte_t)0x08)
#define PFLX_PCD        ((pte_t)0x10)
#define	PF_SIZE		((pte_t)0x80)	/* entry points large page */

#define PFL4_PRESENT    ((pte_t)0x01)
#define PFL4_WRITABLE   ((pte_t)0x02)
#define PFL4_USER       ((pte_t)0x04)

#define PFL3_PRESENT    ((pte_t)0x01)
#define PFL3_WRITABLE   ((pte_t)0x02)
#define PFL3_USER       ((pte_t)0x04)
#define PFL3_PWT        PFLX_PWT
#define PFL3_PCD        PFLX_PCD
#define PFL3_ACCESSED   ((pte_t)0x20)
#define PFL3_DIRTY      ((pte_t)0x40)
#define PFL3_SIZE       ((pte_t)0x80)   /* Used in 1G page */
#define PFL3_GLOBAL     ((pte_t)0x100)
#define PFL3_IGNORED_11 ((pte_t)1 << 11)
#define PFL3_FILEOFF    PFL3_IGNORED_11

#define PFL2_PRESENT    ((pte_t)0x01)
#define PFL2_WRITABLE   ((pte_t)0x02)
#define PFL2_USER       ((pte_t)0x04)
#define PFL2_PWT        PFLX_PWT
#define PFL2_PCD        PFLX_PCD
#define PFL2_ACCESSED   ((pte_t)0x20)
#define PFL2_DIRTY      ((pte_t)0x40)
#define PFL2_SIZE       ((pte_t)0x80)   /* Used in 2M page */
#define PFL2_GLOBAL     ((pte_t)0x100)
#define PFL2_IGNORED_11 ((pte_t)1 << 11)
#define PFL2_FILEOFF    PFL2_IGNORED_11

#define PFL1_PRESENT    ((pte_t)0x01)
#define PFL1_WRITABLE   ((pte_t)0x02)
#define PFL1_USER       ((pte_t)0x04)
#define PFL1_PWT        PFLX_PWT
#define PFL1_PCD        PFLX_PCD
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

/*
 * pagemap kernel ABI bits
 */
#define PM_ENTRY_BYTES      sizeof(uint64_t)
#define PM_STATUS_BITS      3
#define PM_STATUS_OFFSET    (64 - PM_STATUS_BITS)
#define PM_STATUS_MASK      (((1LL << PM_STATUS_BITS) - 1) << PM_STATUS_OFFSET)
#define PM_STATUS(nr)       (((nr) << PM_STATUS_OFFSET) & PM_STATUS_MASK)
#define PM_PSHIFT_BITS      6
#define PM_PSHIFT_OFFSET    (PM_STATUS_OFFSET - PM_PSHIFT_BITS)
#define PM_PSHIFT_MASK      (((1LL << PM_PSHIFT_BITS) - 1) << PM_PSHIFT_OFFSET)
#define PM_PSHIFT(x)        (((uint64_t) (x) << PM_PSHIFT_OFFSET) & PM_PSHIFT_MASK)
#define PM_PFRAME_MASK      ((1LL << PM_PSHIFT_OFFSET) - 1)
#define PM_PFRAME(x)        ((x) & PM_PFRAME_MASK)

#define PM_PRESENT          PM_STATUS(4LL)
#define PM_SWAP             PM_STATUS(2LL)

#define USER_STACK_PREPAGE_SIZE	LARGE_PAGE_SIZE
#define USER_STACK_PAGE_MASK	LARGE_PAGE_MASK
#define USER_STACK_PAGE_P2ALIGN	LARGE_PAGE_P2ALIGN
#define USER_STACK_PAGE_SHIFT	LARGE_PAGE_SHIFT

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
	PTATTR_WRITE_COMBINED = 0x40000,
};

enum ihk_mc_pt_attribute attr_mask;

static inline int pfn_is_write_combined(uintptr_t pfn)
{
	return ((pfn & PFL1_PWT) && !(pfn & PFL1_PCD));
}

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

static inline void pte_update_phys(pte_t *ptep, unsigned long phys)
{
	*ptep = (*ptep & ~PT_PHYSMASK) | (phys & PT_PHYSMASK);
}

static inline uintptr_t pte_get_phys(pte_t *ptep)
{
	return (*ptep & PT_PHYSMASK);
}

static inline off_t pte_get_off(pte_t *ptep, size_t pgsize)
{
	return (off_t)(*ptep & PAGE_MASK);
}

static inline enum ihk_mc_pt_attribute pte_get_attr(pte_t *ptep, size_t pgsize)
{
	enum ihk_mc_pt_attribute attr;

	attr = *ptep & attr_mask;
	if (*ptep & PFLX_PWT) {
		if (*ptep & PFLX_PCD) {
			attr |= PTATTR_UNCACHABLE;
		}
		else {
			attr |= PTATTR_WRITE_COMBINED;
		}
	}
	if (((pgsize == PTL2_SIZE) && (*ptep & PFL2_SIZE))
			|| ((pgsize == PTL3_SIZE) && (*ptep & PFL3_SIZE))) {
		attr |= PTATTR_LARGEPAGE;
	}

	return attr;
} /* pte_get_attr() */

static inline void pte_make_null(pte_t *ptep, size_t pgsize)
{
	*ptep = PTE_NULL;
	return;
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

static inline void pte_clear_dirty(pte_t *ptep, size_t pgsize)
{
	uint64_t mask;

	switch (pgsize) {
	default:	/* through */
	case PTL1_SIZE:	mask = ~PFL1_DIRTY;	break;
	case PTL2_SIZE:	mask = ~PFL2_DIRTY;	break;
	case PTL3_SIZE:	mask = ~PFL3_DIRTY;	break;
	}

	asm volatile ("lock andq %0,%1" :: "r"(mask), "m"(*ptep));
	return;
}

static inline void pte_set_dirty(pte_t *ptep, size_t pgsize)
{
	uint64_t mask;

	switch (pgsize) {
	default:	/* through */
	case PTL1_SIZE:	mask = PFL1_DIRTY;	break;
	case PTL2_SIZE:	mask = PFL2_DIRTY;	break;
	case PTL3_SIZE:	mask = PFL3_DIRTY;	break;
	}

	asm volatile ("lock orq %0,%1" :: "r"(mask), "m"(*ptep));
	return;
}

static inline int pte_is_contiguous(pte_t *ptep)
{
	return 0;
}

static inline int pgsize_is_contiguous(size_t pgsize)
{
	return 0;
}

static inline int pgsize_to_tbllv(size_t pgsize)
{
	switch (pgsize) {
	case PTL1_SIZE:	return 1;
	case PTL2_SIZE:	return 2;
	case PTL3_SIZE:	return 3;
	case PTL4_SIZE:	return 4;
	default:
#if 0	/* XXX: workaround. cannot use panic() here */
		panic("pgsize_to_tbllv");
#else
		return 0;
#endif
	}
	return 0;
}

static inline int pgsize_to_pgshift(size_t pgsize)
{
	switch (pgsize) {
	case PTL1_SIZE:	return PTL1_SHIFT;
	case PTL2_SIZE:	return PTL2_SHIFT;
	case PTL3_SIZE:	return PTL3_SHIFT;
	case PTL4_SIZE:	return PTL4_SHIFT;
	default: return -EINVAL;
	}
}

static inline size_t tbllv_to_pgsize(int level)
{
	switch (level) {
	case 1: return PTL1_SIZE;
	case 2: return PTL2_SIZE;
	case 3: return PTL3_SIZE;
	case 4: return PTL4_SIZE;
	default:
#if 0	/* XXX: workaround. cannot use panic() here */
		panic("tbllv_to_pgsize");
#else
		return 0;
#endif
	}
	return 0;
}

static inline size_t tbllv_to_contpgsize(int level)
{
	return 0;
}

static inline int tbllv_to_contpgshift(int level)
{
	return 0;
}

static inline pte_t *get_contiguous_head(pte_t *__ptep, size_t __pgsize)
{
	return __ptep;
}

static inline pte_t *get_contiguous_tail(pte_t *__ptep, size_t __pgsize)
{
	return __ptep;
}

static inline int split_contiguous_pages(pte_t *ptep, size_t pgsize)
{
	return 0;
}

static inline int page_is_contiguous_head(pte_t *ptep, size_t pgsize)
{
	return 0;
}

static inline int page_is_contiguous_tail(pte_t *ptep, size_t pgsize)
{
	return 0;
}

struct page_table;
static inline void arch_adjust_allocate_page_size(struct page_table *pt,
						  uintptr_t fault_addr,
						  pte_t *ptep,
						  void **pgaddrp,
						  size_t *pgsizep)
{
}
void set_pte(pte_t *ppte, unsigned long phys, enum ihk_mc_pt_attribute attr);
pte_t *get_pte(struct page_table *pt, void *virt, enum ihk_mc_pt_attribute attr);

void *early_alloc_pages(int nr_pages);
void *get_last_early_heap(void);
void flush_tlb(void);
void flush_tlb_single(unsigned long addr);

void *map_fixed_area(unsigned long phys, unsigned long size, int uncachable);

extern unsigned long ap_trampoline;
//#define AP_TRAMPOLINE       0x10000
#define AP_TRAMPOLINE_SIZE  0x2000

/* Local is cachable */
#define IHK_IKC_QUEUE_PT_ATTR (PTATTR_NO_EXECUTE | PTATTR_WRITABLE)

#ifdef ENABLE_FUGAKU_HACKS
#ifndef __ASSEMBLY__
# define ALIGN_UP(x, align)     ALIGN_DOWN((x) + (align) - 1, align)
# define ALIGN_DOWN(x, align)   ((x) & ~((align) - 1))
#endif /* !__ASSEMBLY__ */
#endif

#endif
