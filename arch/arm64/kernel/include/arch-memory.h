/* arch-memory.h COPYRIGHT FUJITSU LIMITED 2015-2018 */
#ifndef __HEADER_ARM64_COMMON_ARCH_MEMORY_H
#define __HEADER_ARM64_COMMON_ARCH_MEMORY_H

#include <const.h>
#include <errno.h>

#ifndef __ASSEMBLY__
#include <list.h>
#include <page.h>
void panic(const char *);
#endif  /*__ASSEMBLY__*/

#define _SZ4KB  (1UL<<12)
#define _SZ16KB (1UL<<14)
#define _SZ64KB (1UL<<16)

#ifdef CONFIG_ARM64_64K_PAGES
# define GRANULE_SIZE	_SZ64KB
# define BLOCK_SHIFT	PAGE_SHIFT
# define BLOCK_SIZE	PAGE_SIZE
# define TABLE_SHIFT	PMD_SHIFT
#else
# define GRANULE_SIZE	_SZ4KB
# define BLOCK_SHIFT	SECTION_SHIFT
# define BLOCK_SIZE	SECTION_SIZE
# define TABLE_SHIFT	PUD_SHIFT
#endif

#define VA_BITS		CONFIG_ARM64_VA_BITS

/*
 * Address define
 */
/* early alloc area address */
/* START:_end, SIZE:512 pages */
#define MAP_EARLY_ALLOC_SHIFT	5
#define MAP_EARLY_ALLOC_SIZE	(UL(1) << (PAGE_SHIFT + MAP_EARLY_ALLOC_SHIFT))

#ifndef __ASSEMBLY__
# define ALIGN_UP(x, align)     ALIGN_DOWN((x) + (align) - 1, align)
# define ALIGN_DOWN(x, align)   ((x) & ~((align) - 1))
extern char _end[];
# define MAP_EARLY_ALLOC	(ALIGN_UP((unsigned long)_end, BLOCK_SIZE))
# define MAP_EARLY_ALLOC_END	(MAP_EARLY_ALLOC + MAP_EARLY_ALLOC_SIZE)
#endif /* !__ASSEMBLY__ */

/* bootparam area address */
/* START:early alloc area end, SIZE:2MiB */
#define MAP_BOOT_PARAM_SHIFT	21
#define MAP_BOOT_PARAM_SIZE	(UL(1) << MAP_BOOT_PARAM_SHIFT)

#ifndef __ASSEMBLY__
# define MAP_BOOT_PARAM		(ALIGN_UP(MAP_EARLY_ALLOC_END, BLOCK_SIZE))
# define MAP_BOOT_PARAM_END	(MAP_BOOT_PARAM + MAP_BOOT_PARAM_SIZE)
#endif /* !__ASSEMBLY__ */

/*
 * MAP_KERNEL_START is HOST MODULES_END - 8MiB.
 * It's defined by cmake.
 */
#if (VA_BITS == 39 && GRANULE_SIZE == _SZ4KB) /* ARM64_MEMORY_LAYOUT=1 */
#
# define LD_TASK_UNMAPPED_BASE	UL(0x0000000400000000)
# define TASK_UNMAPPED_BASE	UL(0x0000000800000000)
# define USER_END		UL(0x0000002000000000)
# define MAP_VMAP_START		UL(0xffffffbdc0000000)
# define MAP_VMAP_SIZE		UL(0x0000000100000000)
# define MAP_FIXED_START	UL(0xffffffbffbdfd000)
# define MAP_ST_START		UL(0xffffffc000000000)
#
#elif (VA_BITS == 42 && GRANULE_SIZE == _SZ64KB) /* ARM64_MEMORY_LAYOUT=3 */
#
# define LD_TASK_UNMAPPED_BASE	UL(0x0000002000000000)
# define TASK_UNMAPPED_BASE	UL(0x0000004000000000)
# define USER_END		UL(0x0000010000000000)
# define MAP_VMAP_START		UL(0xfffffdfee0000000)
# define MAP_VMAP_SIZE		UL(0x0000000100000000)
# define MAP_FIXED_START	UL(0xfffffdfffbdd0000)
# define MAP_ST_START		UL(0xfffffe0000000000)
#
#elif (VA_BITS == 48 && GRANULE_SIZE == _SZ4KB) /* ARM64_MEMORY_LAYOUT=2 */
#
# define LD_TASK_UNMAPPED_BASE	UL(0x0000080000000000)
# define TASK_UNMAPPED_BASE	UL(0x0000100000000000)
# define USER_END		UL(0x0000400000000000)
# define MAP_VMAP_START		UL(0xffff7bffc0000000)
# define MAP_VMAP_SIZE		UL(0x0000000100000000)
# define MAP_FIXED_START	UL(0xffff7ffffbdfd000)
# define MAP_ST_START		UL(0xffff800000000000)
#
#elif (VA_BITS == 48 && GRANULE_SIZE == _SZ64KB) /* ARM64_MEMORY_LAYOUT=4 */
#
# define LD_TASK_UNMAPPED_BASE	UL(0x0000080000000000)
# define TASK_UNMAPPED_BASE	UL(0x0000100000000000)
# define USER_END		UL(0x0000400000000000)
# define MAP_VMAP_START		UL(0xffff780000000000)
# define MAP_VMAP_SIZE		UL(0x0000000100000000)
# define MAP_FIXED_START	UL(0xffff7ffffbdd0000)
# define MAP_ST_START		UL(0xffff800000000000)
#
#else
# error address space is not defined.
#endif

#define MAP_ST_SIZE		(MAP_KERNEL_START - MAP_ST_START)
#define STACK_TOP(region)	((region)->user_end)

/*
 * pagetable define
 */
#if GRANULE_SIZE == _SZ4KB
# define __PTL4_SHIFT  39
# define __PTL3_SHIFT  30
# define __PTL2_SHIFT  21
# define __PTL1_SHIFT  12
# define PTL4_INDEX_MASK ((UL(1) << 9) - 1)
# define PTL3_INDEX_MASK PTL4_INDEX_MASK
# define PTL2_INDEX_MASK PTL3_INDEX_MASK
# define PTL1_INDEX_MASK PTL2_INDEX_MASK
# define __PTL4_CONT_SHIFT (__PTL4_SHIFT + 0)
# define __PTL3_CONT_SHIFT (__PTL3_SHIFT + 4)
# define __PTL2_CONT_SHIFT (__PTL2_SHIFT + 4)
# define __PTL1_CONT_SHIFT (__PTL1_SHIFT + 4)
#elif GRANULE_SIZE == _SZ16KB
# define __PTL4_SHIFT  47
# define __PTL3_SHIFT  36
# define __PTL2_SHIFT  25
# define __PTL1_SHIFT  14
# define PTL4_INDEX_MASK ((UL(1) << 1) - 1)
# define PTL3_INDEX_MASK ((UL(1) << 11) - 1)
# define PTL2_INDEX_MASK PTL3_INDEX_MASK
# define PTL1_INDEX_MASK PTL2_INDEX_MASK
# define __PTL4_CONT_SHIFT (__PTL4_SHIFT + 0)
# define __PTL3_CONT_SHIFT (__PTL3_SHIFT + 0)
# define __PTL2_CONT_SHIFT (__PTL2_SHIFT + 5)
# define __PTL1_CONT_SHIFT (__PTL1_SHIFT + 7)
#elif GRANULE_SIZE == _SZ64KB
# define __PTL4_SHIFT  55
# define __PTL3_SHIFT  42
# define __PTL2_SHIFT  29
# define __PTL1_SHIFT  16
# define PTL4_INDEX_MASK 0
# define PTL3_INDEX_MASK ((UL(1) << 6) - 1)
# define PTL2_INDEX_MASK ((UL(1) << 13) - 1)
# define PTL1_INDEX_MASK PTL2_INDEX_MASK
# define __PTL4_CONT_SHIFT (__PTL4_SHIFT + 0)
# define __PTL3_CONT_SHIFT (__PTL3_SHIFT + 0)
# define __PTL2_CONT_SHIFT (__PTL2_SHIFT + 5)
# define __PTL1_CONT_SHIFT (__PTL1_SHIFT + 5)
#else
# error granule size error.
#endif

#ifndef __ASSEMBLY__
extern int first_level_block_support;
#endif /* __ASSEMBLY__ */

# define __PTL4_SIZE  (UL(1) << __PTL4_SHIFT)
# define __PTL3_SIZE  (UL(1) << __PTL3_SHIFT)
# define __PTL2_SIZE  (UL(1) << __PTL2_SHIFT)
# define __PTL1_SIZE  (UL(1) << __PTL1_SHIFT)
# define __PTL4_MASK  (~(__PTL4_SIZE - 1))
# define __PTL3_MASK  (~(__PTL3_SIZE - 1))
# define __PTL2_MASK  (~(__PTL2_SIZE - 1))
# define __PTL1_MASK  (~(__PTL1_SIZE - 1))

# define __PTL4_CONT_SIZE  (UL(1) << __PTL4_CONT_SHIFT)
# define __PTL3_CONT_SIZE  (UL(1) << __PTL3_CONT_SHIFT)
# define __PTL2_CONT_SIZE  (UL(1) << __PTL2_CONT_SHIFT)
# define __PTL1_CONT_SIZE  (UL(1) << __PTL1_CONT_SHIFT)
# define __PTL4_CONT_MASK  (~(__PTL4_CONT_SIZE - 1))
# define __PTL3_CONT_MASK  (~(__PTL3_CONT_SIZE - 1))
# define __PTL2_CONT_MASK  (~(__PTL2_CONT_SIZE - 1))
# define __PTL1_CONT_MASK  (~(__PTL1_CONT_SIZE - 1))
# define __PTL4_CONT_COUNT  (UL(1) << (__PTL4_CONT_SHIFT - __PTL4_SHIFT))
# define __PTL3_CONT_COUNT  (UL(1) << (__PTL3_CONT_SHIFT - __PTL3_SHIFT))
# define __PTL2_CONT_COUNT  (UL(1) << (__PTL2_CONT_SHIFT - __PTL2_SHIFT))
# define __PTL1_CONT_COUNT  (UL(1) << (__PTL1_CONT_SHIFT - __PTL1_SHIFT))

/* calculate entries */
#if (CONFIG_ARM64_PGTABLE_LEVELS > 3) && (VA_BITS > __PTL4_SHIFT)
# define __PTL4_ENTRIES  (UL(1) << (VA_BITS - __PTL4_SHIFT))
# define __PTL3_ENTRIES  (UL(1) << (__PTL1_SHIFT - 3))
# define __PTL2_ENTRIES  (UL(1) << (__PTL1_SHIFT - 3))
# define __PTL1_ENTRIES  (UL(1) << (__PTL1_SHIFT - 3))
#elif (CONFIG_ARM64_PGTABLE_LEVELS > 2) && (VA_BITS > __PTL3_SHIFT)
# define __PTL4_ENTRIES  1
# define __PTL3_ENTRIES  (UL(1) << (VA_BITS - __PTL3_SHIFT))
# define __PTL2_ENTRIES  (UL(1) << (__PTL1_SHIFT - 3))
# define __PTL1_ENTRIES  (UL(1) << (__PTL1_SHIFT - 3))
#elif (CONFIG_ARM64_PGTABLE_LEVELS > 1) && (VA_BITS > __PTL2_SHIFT)
# define __PTL4_ENTRIES  1
# define __PTL3_ENTRIES  1
# define __PTL2_ENTRIES  (UL(1) << (VA_BITS - __PTL2_SHIFT))
# define __PTL1_ENTRIES  (UL(1) << (__PTL1_SHIFT - 3))
#elif VA_BITS > __PTL1_SHIFT
# define __PTL4_ENTRIES  1
# define __PTL3_ENTRIES  1
# define __PTL2_ENTRIES  1
# define __PTL1_ENTRIES  (UL(1) << (VA_BITS - __PTL1_SHIFT))
#else
# define __PTL4_ENTRIES  1
# define __PTL3_ENTRIES  1
# define __PTL2_ENTRIES  1
# define __PTL1_ENTRIES  1
#endif

#ifndef __ASSEMBLY__
static const unsigned int  PTL4_SHIFT   = __PTL4_SHIFT;
static const unsigned int  PTL3_SHIFT   = __PTL3_SHIFT;
static const unsigned int  PTL2_SHIFT   = __PTL2_SHIFT;
static const unsigned int  PTL1_SHIFT   = __PTL1_SHIFT;
static const unsigned long PTL4_SIZE    = __PTL4_SIZE; 
static const unsigned long PTL3_SIZE    = __PTL3_SIZE; 
static const unsigned long PTL2_SIZE    = __PTL2_SIZE; 
static const unsigned long PTL1_SIZE    = __PTL1_SIZE; 
static const unsigned long PTL4_MASK    = __PTL4_MASK;
static const unsigned long PTL3_MASK    = __PTL3_MASK;
static const unsigned long PTL2_MASK    = __PTL2_MASK;
static const unsigned long PTL1_MASK    = __PTL1_MASK;
static const unsigned int  PTL4_ENTRIES = __PTL4_ENTRIES;
static const unsigned int  PTL3_ENTRIES = __PTL3_ENTRIES;
static const unsigned int  PTL2_ENTRIES = __PTL2_ENTRIES;
static const unsigned int  PTL1_ENTRIES = __PTL1_ENTRIES;
static const unsigned int  PTL4_CONT_SHIFT = __PTL4_CONT_SHIFT;
static const unsigned int  PTL3_CONT_SHIFT = __PTL3_CONT_SHIFT;
static const unsigned int  PTL2_CONT_SHIFT = __PTL2_CONT_SHIFT;
static const unsigned int  PTL1_CONT_SHIFT = __PTL1_CONT_SHIFT;
static const unsigned long PTL4_CONT_SIZE  = __PTL4_CONT_SIZE;
static const unsigned long PTL3_CONT_SIZE  = __PTL3_CONT_SIZE;
static const unsigned long PTL2_CONT_SIZE  = __PTL2_CONT_SIZE;
static const unsigned long PTL1_CONT_SIZE  = __PTL1_CONT_SIZE;
static const unsigned long PTL4_CONT_MASK  = __PTL4_CONT_MASK;
static const unsigned long PTL3_CONT_MASK  = __PTL3_CONT_MASK;
static const unsigned long PTL2_CONT_MASK  = __PTL2_CONT_MASK;
static const unsigned long PTL1_CONT_MASK  = __PTL1_CONT_MASK;
static const unsigned int  PTL4_CONT_COUNT = __PTL4_CONT_COUNT;
static const unsigned int  PTL3_CONT_COUNT = __PTL3_CONT_COUNT;
static const unsigned int  PTL2_CONT_COUNT = __PTL2_CONT_COUNT;
static const unsigned int  PTL1_CONT_COUNT = __PTL1_CONT_COUNT;
#else
# define PTL4_SHIFT   __PTL4_SHIFT
# define PTL3_SHIFT   __PTL3_SHIFT
# define PTL2_SHIFT   __PTL2_SHIFT
# define PTL1_SHIFT   __PTL1_SHIFT
# define PTL4_SIZE    __PTL4_SIZE
# define PTL3_SIZE    __PTL3_SIZE
# define PTL2_SIZE    __PTL2_SIZE
# define PTL1_SIZE    __PTL1_SIZE
# define PTL4_MASK    __PTL4_MASK
# define PTL3_MASK    __PTL3_MASK
# define PTL2_MASK    __PTL2_MASK
# define PTL1_MASK    __PTL1_MASK
# define PTL4_ENTRIES __PTL4_ENTRIES
# define PTL3_ENTRIES __PTL3_ENTRIES
# define PTL2_ENTRIES __PTL2_ENTRIES
# define PTL1_ENTRIES __PTL1_ENTRIES
# define PTL4_CONT_SHIFT __PTL4_CONT_SHIFT
# define PTL3_CONT_SHIFT __PTL3_CONT_SHIFT
# define PTL2_CONT_SHIFT __PTL2_CONT_SHIFT
# define PTL1_CONT_SHIFT __PTL1_CONT_SHIFT
# define PTL4_CONT_SIZE __PTL4_CONT_SIZE
# define PTL3_CONT_SIZE __PTL3_CONT_SIZE
# define PTL2_CONT_SIZE __PTL2_CONT_SIZE
# define PTL1_CONT_SIZE __PTL1_CONT_SIZE
# define PTL4_CONT_MASK __PTL4_CONT_MASK
# define PTL3_CONT_MASK __PTL3_CONT_MASK
# define PTL2_CONT_MASK __PTL2_CONT_MASK
# define PTL1_CONT_MASK __PTL1_CONT_MASK
# define PTL4_CONT_COUNT __PTL4_CONT_COUNT
# define PTL3_CONT_COUNT __PTL3_CONT_COUNT
# define PTL2_CONT_COUNT __PTL2_CONT_COUNT
# define PTL1_CONT_COUNT __PTL1_CONT_COUNT
#endif/*__ASSEMBLY__*/

#define __page_size(pgshift)        (UL(1) << (pgshift))
#define __page_mask(pgsize)         (~((pgsize) - 1))
#define __page_offset(addr, size)   ((unsigned long)(addr) & ((size) - 1))
#define __page_align(addr, size)    ((unsigned long)(addr) & ~((size) - 1))
#define __page_align_up(addr, size) __page_align((unsigned long)(addr) + (size) - 1, size)

/*
 * nornal page
 */
#define PAGE_SHIFT          __PTL1_SHIFT
#define PAGE_SIZE           __page_size(PAGE_SHIFT)
#define PAGE_MASK           __page_mask(PAGE_SIZE)
#define PAGE_P2ALIGN        0
#define page_offset(addr)   __page_offset(addr, PAGE_SIZE)
#define page_align(addr)    __page_align(addr, PAGE_SIZE)
#define page_align_up(addr) __page_align_up(addr, PAGE_SIZE)

/*
 * large page
 */
#define LARGE_PAGE_SHIFT          __PTL2_SHIFT
#define LARGE_PAGE_SIZE           __page_size(LARGE_PAGE_SHIFT)
#define LARGE_PAGE_MASK           __page_mask(LARGE_PAGE_SIZE)
#define LARGE_PAGE_P2ALIGN        (LARGE_PAGE_SHIFT - PAGE_SHIFT)
#define large_page_offset(addr)   __page_offset(addr, LARGE_PAGE_SIZE)
#define large_page_align(addr)    __page_align(addr, LARGE_PAGE_SIZE)
#define large_page_align_up(addr) __page_align_up(addr, LARGE_PAGE_SIZE)

/*
 *
 */
#define TTBR_ASID_SHIFT  48
#define TTBR_ASID_MASK   (0xFFFFUL << TTBR_ASID_SHIFT)
#define TTBR_BADDR_MASK  (~TTBR_ASID_MASK)

#include "pgtable-hwdef.h"

#define KERNEL_PHYS_OFFSET

#define PT_PHYSMASK PHYS_MASK
/* We allow user programs to access all the memory (D_Block, D_Page) */
#define PFL_KERN_BLK_ATTR		PROT_SECT_NORMAL_EXEC
#define PFL_KERN_PAGE_ATTR		PAGE_KERNEL_EXEC
/* for the page table entry that points another page table (D_Table) */
#define PFL_PDIR_TBL_ATTR		PMD_TYPE_TABLE

#ifdef CONFIG_ARM64_64K_PAGES
# define SWAPPER_PGTABLE_LEVELS	(CONFIG_ARM64_PGTABLE_LEVELS)
#else
# define SWAPPER_PGTABLE_LEVELS	(CONFIG_ARM64_PGTABLE_LEVELS - 1)
#endif
#define SWAPPER_DIR_SIZE	(SWAPPER_PGTABLE_LEVELS * PAGE_SIZE)
#define IDMAP_DIR_SIZE		(3 * PAGE_SIZE)

/* [Page level Write Throgh] ページキャッシュ方式  0:ライトバック 1:ライトスルー */
#define PFL1_PWT		0 //< DEBUG_ARCH_DEP, devobj.cの直接参照を関数化 (is_pte_pwd)
/* [Page level Cache Disable] ページキャッシュ 0:有効 1:無効 */
#define PFL1_PCD		0 //< DEBUG_ARCH_DEP, devobj.cの直接参照を関数化 (is_pte_pcd)

#define	PTE_NULL		(0)

#define PTE_FILEOFF		PTE_SPECIAL

#ifdef CONFIG_ARM64_64K_PAGES
# define USER_STACK_PREPAGE_SIZE	PAGE_SIZE
# define USER_STACK_PAGE_MASK		PAGE_MASK
# define USER_STACK_PAGE_P2ALIGN	PAGE_P2ALIGN
# define USER_STACK_PAGE_SHIFT		PAGE_SHIFT
#else
# define USER_STACK_PREPAGE_SIZE	LARGE_PAGE_SIZE
# define USER_STACK_PAGE_MASK		LARGE_PAGE_MASK
# define USER_STACK_PAGE_P2ALIGN	LARGE_PAGE_P2ALIGN
# define USER_STACK_PAGE_SHIFT		LARGE_PAGE_SHIFT
#endif

#define PT_ENTRIES		(PAGE_SIZE >> 3)

#ifndef __ASSEMBLY__

#include <ihk/types.h>

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


/* For easy conversion, it is better to be the same as architecture's ones */
enum ihk_mc_pt_attribute {
	/* ページが物理メモリにロードされているか */
	PTATTR_ACTIVE     = PTE_VALID,
	/* Read/Writeフラグ */
	PTATTR_WRITABLE   = PTE_RDONLY,	//共通定義と意味が反転するので注意
	/* ユーザ/特権フラグ */
	PTATTR_USER       = PTE_USER | PTE_NG,
	/* ページの変更を示す */
	PTATTR_DIRTY      = PTE_DIRTY,
	/* ラージページを示す */
	PTATTR_LARGEPAGE  = PMD_TABLE_BIT, //共通定義と意味が反転するので注意
	/* remap_file_page フラグ */
	PTATTR_FILEOFF    = PTE_FILEOFF,
	/* 実行不可フラグ */
	PTATTR_NO_EXECUTE = PTE_UXN,
	/* キャッシュ無し */
	PTATTR_UNCACHABLE = PTE_ATTRINDX(1),
	/* ユーザ空間向けを示す */
	PTATTR_FOR_USER   = UL(1) << (PHYS_MASK_SHIFT - 1),
	/* WriteCombine */
	PTATTR_WRITE_COMBINED = PTE_ATTRINDX(2),
	/* converted flag */
	ARCH_PTATTR_FLIPPED = PTE_PROT_NONE,
};
extern enum ihk_mc_pt_attribute attr_mask;

static inline int pfn_is_write_combined(uintptr_t pfn)
{
	return ((pfn & PTE_ATTRINDX_MASK) == PTE_ATTRINDX(MT_NORMAL_NC));
}

//共通部と意味がするビット定義
#define attr_flip_bits (PTATTR_WRITABLE | PTATTR_LARGEPAGE)

static inline int pgsize_to_tbllv(size_t pgsize);
static inline int pte_is_type_page(const pte_t *ptep, size_t pgsize)
{
	int ret = 0; //default D_TABLE
	int level = pgsize_to_tbllv(pgsize);

	switch (level) {
	case 4:
	case 3:
	case 2:
		// check D_BLOCK
		ret = ((*ptep & PMD_TYPE_MASK) == PMD_TYPE_SECT);
		break;
	case 1:
		// check D_PAGE
		ret = ((*ptep & PTE_TYPE_MASK) == PTE_TYPE_PAGE);
		break;
	}
	return ret;
}

static inline int pte_is_null(pte_t *ptep)
{
	return (*ptep == PTE_NULL);
}

static inline int pte_is_present(pte_t *ptep)
{
	return !!(*ptep & PMD_SECT_VALID);
}

static inline int pte_is_writable(pte_t *ptep)
{
	extern int kprintf(const char *format, ...);
	kprintf("ERROR: %s is not implemented. \n", __func__);
	return 0;
}

static inline int pte_is_dirty(pte_t *ptep, size_t pgsize)
{
	int ret = 0;
	int do_check = pte_is_type_page(ptep, pgsize);
	if (do_check) {
		ret = !!(*ptep & PTE_DIRTY);
	}	
	return ret;
}

static inline int pte_is_fileoff(pte_t *ptep, size_t pgsize)
{
	int ret = 0;
	int do_check = pte_is_type_page(ptep, pgsize);
	if (do_check) {
		ret = !!(*ptep & PTE_FILEOFF);
	}

	return ret;
}

static inline void pte_update_phys(pte_t *ptep, unsigned long phys)
{
	*ptep = (*ptep & ~PT_PHYSMASK) | (phys & PT_PHYSMASK);
}

static inline uintptr_t pte_get_phys(pte_t *ptep)
{
	return (uintptr_t)(*ptep & PT_PHYSMASK);
}

static inline off_t pte_get_off(pte_t *ptep, size_t pgsize)
{
	return (off_t)(*ptep & PHYS_MASK);
}

static inline enum ihk_mc_pt_attribute pte_get_attr(pte_t *ptep, size_t pgsize)
{
	enum ihk_mc_pt_attribute attr;

	attr = *ptep & attr_mask;
	attr ^= attr_flip_bits;
	if ((*ptep & PTE_ATTRINDX_MASK) == PTE_ATTRINDX(MT_DEVICE_nGnRE)) {
		attr |= PTATTR_UNCACHABLE;
	} else if ((*ptep & PTE_ATTRINDX_MASK) == PTE_ATTRINDX(MT_NORMAL_NC)) {
		attr |= PTATTR_WRITE_COMBINED;
	}
	if (((pgsize == PTL2_SIZE) || (pgsize == PTL3_SIZE))
	    && ((*ptep & PMD_TYPE_MASK) == PMD_TYPE_SECT)) {
		attr |= PTATTR_LARGEPAGE;
	}

	return attr;
}

static inline void pte_make_null(pte_t *ptep, size_t pgsize)
{
	*ptep = PTE_NULL;
}

static inline void pte_make_fileoff(off_t off,
		enum ihk_mc_pt_attribute ptattr, size_t pgsize, pte_t *ptep)
{
	if (((PTL4_SIZE == pgsize || PTL4_CONT_SIZE == pgsize)
				&& CONFIG_ARM64_PGTABLE_LEVELS > 3) ||
	    ((PTL3_SIZE == pgsize || PTL3_CONT_SIZE == pgsize)
				&& CONFIG_ARM64_PGTABLE_LEVELS > 2) ||
	     (PTL2_SIZE == pgsize || PTL2_CONT_SIZE == pgsize) ||
	     (PTL1_SIZE == pgsize || PTL1_CONT_SIZE == pgsize)) {
		*ptep = PTE_FILEOFF | off | PTE_TYPE_PAGE;
	}
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
	int do_clear = pte_is_type_page(ptep, pgsize);
	if (do_clear) {
		*ptep = *ptep & ~PTE_DIRTY;
	}
}

static inline void pte_set_dirty(pte_t *ptep, size_t pgsize)
{
	int do_set = pte_is_type_page(ptep, pgsize);
	if (do_set) {
		*ptep |= PTE_DIRTY;
	}
}

static inline int pte_is_contiguous(const pte_t *ptep)
{
	return !!(*ptep & PTE_CONT);
}

static inline int pgsize_is_contiguous(size_t pgsize)
{
	int ret = 0;

	if ((pgsize == PTL4_CONT_SIZE && CONFIG_ARM64_PGTABLE_LEVELS > 3) ||
	    (pgsize == PTL3_CONT_SIZE && CONFIG_ARM64_PGTABLE_LEVELS > 2) ||
	    (pgsize == PTL2_CONT_SIZE) ||
	    (pgsize == PTL1_CONT_SIZE)) {
		ret = 1;
	}
	return ret;
}

static inline int pgsize_to_tbllv(size_t pgsize)
{
	int level = -EINVAL;

	if ((pgsize == PTL4_CONT_SIZE || pgsize == PTL4_SIZE)
	    && (CONFIG_ARM64_PGTABLE_LEVELS > 3)) {
		level = 4;
	} else if ((pgsize == PTL3_CONT_SIZE || pgsize == PTL3_SIZE)
		   && (CONFIG_ARM64_PGTABLE_LEVELS > 2)) {
		level = 3;
	} else if (pgsize == PTL2_CONT_SIZE || pgsize == PTL2_SIZE) {
		level = 2;
	} else if (pgsize == PTL1_CONT_SIZE || pgsize == PTL1_SIZE) {
		level = 1;
	}
	return level;
}

static inline int pgsize_to_pgshift(size_t pgsize)
{
	/* We need to use if instead of switch because
	 * sometimes PTLX_CONT_SIZE == PTLX_SIZE
	 */
	if (pgsize == PTL4_CONT_SIZE) {
		if (CONFIG_ARM64_PGTABLE_LEVELS > 3) {
			return PTL4_CONT_SHIFT;
		}
	} else if (pgsize == PTL4_SIZE) {
		if (CONFIG_ARM64_PGTABLE_LEVELS > 3) {
			return PTL4_SHIFT;
		}
	} else if (pgsize == PTL3_CONT_SIZE) {
		if (CONFIG_ARM64_PGTABLE_LEVELS > 2) {
			return PTL3_CONT_SHIFT;
		}
	} else if (pgsize == PTL3_SIZE) {
		if (CONFIG_ARM64_PGTABLE_LEVELS > 2) {
			return PTL3_SHIFT;
		}
	} else if (pgsize == PTL2_CONT_SIZE) {
		return PTL2_CONT_SHIFT;
	} else if (pgsize == PTL2_SIZE) {
		return PTL2_SHIFT;
	} else if (pgsize == PTL1_CONT_SIZE) {
		return PTL1_CONT_SHIFT;
	} else if (pgsize == PTL1_SIZE) {
		return PTL1_SHIFT;
	}

	return -EINVAL;
}

static inline size_t tbllv_to_pgsize(int level)
{
	size_t pgsize = 0;

	switch (level) {
	case 4:
		if (CONFIG_ARM64_PGTABLE_LEVELS > 3) {
			pgsize = PTL4_SIZE;
		} else {
			panic("page table level 4 is invalid.");
		}
		break;
	case 3:
		if (CONFIG_ARM64_PGTABLE_LEVELS > 2) {
			pgsize = PTL3_SIZE;
		} else {
			panic("page table level 3 is invalid.");
		}
		break;
	case 2:
		pgsize = PTL2_SIZE;
		break;
	case 1:
		pgsize = PTL1_SIZE;
		break;
	default:
		panic("page table level is invalid.");
	}
	return pgsize;
}

static inline size_t tbllv_to_contpgsize(int level)
{
	size_t pgsize = 0;

	switch (level) {
	case 4:
		if (CONFIG_ARM64_PGTABLE_LEVELS > 3) {
			pgsize = PTL4_CONT_SIZE;
		} else {
			panic("page table level 4 is invalid.");
		}
		break;
	case 3:
		if (CONFIG_ARM64_PGTABLE_LEVELS > 2) {
			pgsize = PTL3_CONT_SIZE;
		} else {
			panic("page table level 3 is invalid.");
		}
		break;
	case 2:
		pgsize = PTL2_CONT_SIZE;
		break;
	case 1:
		pgsize = PTL1_CONT_SIZE;
		break;
	default:
		panic("page table level is invalid.");
	}
	return pgsize;
}

static inline int tbllv_to_contpgshift(int level)
{
	int ret = 0;

	switch (level) {
	case 4:
		if (CONFIG_ARM64_PGTABLE_LEVELS > 3) {
			ret = PTL4_CONT_SHIFT;
		} else {
			panic("page table level 4 is invalid.");
		}

		break;
	case 3:
		if (CONFIG_ARM64_PGTABLE_LEVELS > 2) {
			ret = PTL3_CONT_SHIFT;
		} else {
			panic("page table level 3 is invalid.");
		}

		break;
	case 2:
		ret = PTL2_CONT_SHIFT;
		break;
	case 1:
		ret = PTL1_CONT_SHIFT;
		break;
	default:
		panic("page table level is invalid.");
	}
	return ret;
}

static inline pte_t *get_contiguous_head(pte_t *__ptep, size_t __pgsize)
{
	unsigned long align;
	int shift = 0;

	switch (pgsize_to_tbllv(__pgsize)) {
	case 4:
		if (CONFIG_ARM64_PGTABLE_LEVELS > 3) {
			shift = PTL4_CONT_SHIFT - PTL4_SHIFT;
		} else {
			panic("page table level 4 is invalid.");
		}
		break;
	case 3:
		if (CONFIG_ARM64_PGTABLE_LEVELS > 2) {
			shift = PTL3_CONT_SHIFT - PTL3_SHIFT;
		} else {
			panic("page table level 3 is invalid.");
		}
		break;
	case 2:
		shift = PTL2_CONT_SHIFT - PTL2_SHIFT;
		break;
	case 1:
		shift = PTL1_CONT_SHIFT - PTL1_SHIFT;
		break;
	default:
		panic("page table level is invalid.");
	}
	align = sizeof(*__ptep) << shift;
	return  (pte_t *)__page_align(__ptep, align);
}

static inline pte_t *get_contiguous_tail(pte_t *__ptep, size_t __pgsize)
{
	unsigned long align;
	int shift = 0;

	switch (pgsize_to_tbllv(__pgsize)) {
	case 4:
		if (CONFIG_ARM64_PGTABLE_LEVELS > 3) {
			shift = PTL4_CONT_SHIFT - PTL4_SHIFT;
		} else {
			panic("page table level 4 is invalid.");
		}
		break;
	case 3:
		if (CONFIG_ARM64_PGTABLE_LEVELS > 2) {
			shift = PTL3_CONT_SHIFT - PTL3_SHIFT;
		} else {
			panic("page table level 3 is invalid.");
		}
		break;
	case 2:
		shift = PTL2_CONT_SHIFT - PTL2_SHIFT;
		break;
	case 1:
		shift = PTL1_CONT_SHIFT - PTL1_SHIFT;
		break;
	default:
		panic("page table level is invalid.");
	}
	align = sizeof(*__ptep) << shift;
	return  (pte_t *)__page_align_up(__ptep + 1, align) - 1;
}

static inline int split_contiguous_pages(pte_t *ptep, size_t pgsize)
{
	int ret;
	pte_t *head = get_contiguous_head(ptep, pgsize);
	pte_t *tail = get_contiguous_tail(ptep, pgsize);
	pte_t *ptr;

	uintptr_t phys;
	struct page *page;

	phys = pte_get_phys(head);
	page = phys_to_page(phys);
	if (page && (page_is_in_memobj(page)
		     || page_is_multi_mapped(page))) {
		ret = -EINVAL;
		goto out;
	}

	for (ptr = head; ptr <= tail; ptr++) {
		*ptr &= ~PTE_CONT;
	}

	ret = 0;
out:
	return ret;
}

static inline int page_is_contiguous_head(pte_t *ptep, size_t pgsize)
{
	pte_t *ptr = get_contiguous_head(ptep, pgsize);

	return (ptr == ptep);
}

static inline int page_is_contiguous_tail(pte_t *ptep, size_t pgsize)
{
	pte_t *ptr = get_contiguous_tail(ptep, pgsize);

	return (ptr == ptep);
}

/* Return true if PTE doesn't belong to a contiguous PTE group or PTE
 * is the head of a contiguous PTE group
 */
static inline int pte_is_head(pte_t *ptep, pte_t *old, size_t cont_size)
{
	if (!pte_is_contiguous(old))
		return 1;
	return page_is_contiguous_head(ptep, cont_size);
}

struct page_table;
void arch_adjust_allocate_page_size(struct page_table *pt,
				    uintptr_t fault_addr,
				    pte_t *ptep,
				    void **pgaddrp,
				    size_t *pgsizep);
void set_pte(pte_t *ppte, unsigned long phys, enum ihk_mc_pt_attribute attr);
pte_t *get_pte(struct page_table *pt, void *virt, enum ihk_mc_pt_attribute attr);

struct page_table *get_init_page_table(void);
void *early_alloc_pages(int nr_pages);
void *get_last_early_heap(void);
void flush_tlb(void);
void flush_tlb_single(unsigned long addr);

void *map_fixed_area(unsigned long phys, unsigned long size, int uncachable);

void set_address_space_id(struct page_table *pt, int asid);
int get_address_space_id(const struct page_table *pt);

typedef pte_t translation_table_t;
void set_translation_table(struct page_table *pt, translation_table_t* tt);
translation_table_t* get_translation_table(const struct page_table *pt);
translation_table_t* get_translation_table_as_paddr(const struct page_table *pt);

extern unsigned long ap_trampoline;
//#define AP_TRAMPOLINE       0x10000
#define AP_TRAMPOLINE_SIZE  0x2000

/* Local is cachable */
#define IHK_IKC_QUEUE_PT_ATTR (PTATTR_NO_EXECUTE | PTATTR_WRITABLE)

#endif /* !__ASSEMBLY__ */

#endif /* !__HEADER_ARM64_COMMON_ARCH_MEMORY_H */
