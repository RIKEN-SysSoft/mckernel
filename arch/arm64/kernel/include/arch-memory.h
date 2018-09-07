/* arch-memory.h COPYRIGHT FUJITSU LIMITED 2015-2017 */
#ifndef __HEADER_ARM64_COMMON_ARCH_MEMORY_H
#define __HEADER_ARM64_COMMON_ARCH_MEMORY_H

#include <const.h>

#define _SZ4KB  (1UL<<12)
#define _SZ16KB (1UL<<14)
#define _SZ64KB (1UL<<16)

#ifdef CONFIG_ARM64_64K_PAGES
# define GRANULE_SIZE _SZ64KB
#else
# define GRANULE_SIZE _SZ4KB
#endif
#define VA_BITS		CONFIG_ARM64_VA_BITS

/*
 * Address define
 */
#define MAP_KERNEL_SHIFT	21
#define MAP_KERNEL_SIZE		(UL(1) << MAP_KERNEL_SHIFT)
#define MAP_EARLY_ALLOC_SHIFT	9
#define MAP_EARLY_ALLOC_SIZE	(UL(1) << (PAGE_SHIFT + MAP_EARLY_ALLOC_SHIFT))
#define MAP_BOOT_PARAM_SHIFT	21
#define MAP_BOOT_PARAM_SIZE	(UL(1) << MAP_BOOT_PARAM_SHIFT)

#if (VA_BITS == 39 && GRANULE_SIZE == _SZ4KB)
#
# define TASK_UNMAPPED_BASE	UL(0x0000000800000000)
# define USER_END		UL(0x0000002000000000)
# define MAP_VMAP_START		UL(0xffffffbdc0000000)
# define MAP_VMAP_SIZE		UL(0x0000000100000000)
# define MAP_FIXED_START	UL(0xffffffbffbdfd000)
# define MAP_ST_START		UL(0xffffffc000000000)
# define MAP_KERNEL_START	UL(0xffffffffff800000)                   // 0xffff_ffff_ff80_0000
# define MAP_ST_SIZE		(MAP_KERNEL_START - MAP_ST_START)        // 0x0000_003f_ff80_0000
# define MAP_EARLY_ALLOC	(MAP_KERNEL_START + MAP_KERNEL_SIZE)     // 0xffff_ffff_ffa0_0000
# define MAP_EARLY_ALLOC_END	(MAP_EARLY_ALLOC + MAP_EARLY_ALLOC_SIZE)
# define MAP_BOOT_PARAM		(MAP_EARLY_ALLOC_END)                    // 0xffff_ffff_ffc0_0000
# define MAP_BOOT_PARAM_END	(MAP_BOOT_PARAM + MAP_BOOT_PARAM_SIZE)   // 0xffff_ffff_ffe0_0000
#
#elif (VA_BITS == 42 && GRANULE_SIZE == _SZ64KB)
#
# define TASK_UNMAPPED_BASE	UL(0x0000004000000000)
# define USER_END		UL(0x0000010000000000)
# define MAP_VMAP_START		UL(0xfffffdfee0000000)
# define MAP_VMAP_SIZE		UL(0x0000000100000000)
# define MAP_FIXED_START	UL(0xfffffdfffbdd0000)
# define MAP_ST_START		UL(0xfffffe0000000000)
# define MAP_KERNEL_START	UL(0xffffffffe0000000)                   // 0xffff_ffff_e000_0000
# define MAP_ST_SIZE		(MAP_KERNEL_START - MAP_ST_START)        // 0x0000_01ff_e000_0000
# define MAP_EARLY_ALLOC	(MAP_KERNEL_START + MAP_KERNEL_SIZE)     // 0xffff_ffff_e020_0000
# define MAP_EARLY_ALLOC_END	(MAP_EARLY_ALLOC + MAP_EARLY_ALLOC_SIZE)
# define MAP_BOOT_PARAM		(MAP_EARLY_ALLOC_END)                    // 0xffff_ffff_e220_0000
# define MAP_BOOT_PARAM_END	(MAP_BOOT_PARAM + MAP_BOOT_PARAM_SIZE)   // 0xffff_ffff_e240_0000
#
#elif (VA_BITS == 48 && GRANULE_SIZE == _SZ4KB)
#
# define TASK_UNMAPPED_BASE	UL(0x0000100000000000)
# define USER_END		UL(0x0000400000000000)
# define MAP_VMAP_START		UL(0xffff7bffc0000000)
# define MAP_VMAP_SIZE		UL(0x0000000100000000)
# define MAP_FIXED_START	UL(0xffff7ffffbdfd000)
# define MAP_ST_START		UL(0xffff800000000000)
# define MAP_KERNEL_START	UL(0xffffffffff800000)                   // 0xffff_ffff_ff80_0000
# define MAP_ST_SIZE		(MAP_KERNEL_START - MAP_ST_START)        // 0x0000_7fff_ff80_0000
# define MAP_EARLY_ALLOC	(MAP_KERNEL_START + MAP_KERNEL_SIZE)     // 0xffff_ffff_ffa0_0000
# define MAP_EARLY_ALLOC_END	(MAP_EARLY_ALLOC + MAP_EARLY_ALLOC_SIZE)
# define MAP_BOOT_PARAM		(MAP_EARLY_ALLOC_END)                    // 0xffff_ffff_ffc0_0000
# define MAP_BOOT_PARAM_END	(MAP_BOOT_PARAM + MAP_BOOT_PARAM_SIZE)   // 0xffff_ffff_ffe0_0000
#
#
#elif (VA_BITS == 48 && GRANULE_SIZE == _SZ64KB)
#
# define TASK_UNMAPPED_BASE	UL(0x0000100000000000)
# define USER_END		UL(0x0000400000000000)
# define MAP_VMAP_START		UL(0xffff780000000000)
# define MAP_VMAP_SIZE		UL(0x0000000100000000)
# define MAP_FIXED_START	UL(0xffff7ffffbdd0000)
# define MAP_ST_START		UL(0xffff800000000000)
# define MAP_KERNEL_START	UL(0xffffffffe0000000)                   // 0xffff_ffff_e000_0000
# define MAP_ST_SIZE		(MAP_KERNEL_START - MAP_ST_START)        // 0x0000_7fff_e000_0000
# define MAP_EARLY_ALLOC	(MAP_KERNEL_START + MAP_KERNEL_SIZE)     // 0xffff_ffff_e020_0000
# define MAP_EARLY_ALLOC_END	(MAP_EARLY_ALLOC + MAP_EARLY_ALLOC_SIZE)
# define MAP_BOOT_PARAM		(MAP_EARLY_ALLOC_END)                    // 0xffff_ffff_e220_0000
# define MAP_BOOT_PARAM_END	(MAP_BOOT_PARAM + MAP_BOOT_PARAM_SIZE)   // 0xffff_ffff_e240_0000
#
#else
# error address space is not defined.
#endif

#define STACK_TOP(region)  ((region)->user_end)

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
# define FIRST_LEVEL_BLOCK_SUPPORT  1
#elif GRANULE_SIZE == _SZ16KB
# define __PTL4_SHIFT  47
# define __PTL3_SHIFT  36
# define __PTL2_SHIFT  25
# define __PTL1_SHIFT  14
# define PTL4_INDEX_MASK ((UL(1) << 1) - 1)
# define PTL3_INDEX_MASK ((UL(1) << 11) - 1)
# define PTL2_INDEX_MASK PTL3_INDEX_MASK
# define PTL1_INDEX_MASK PTL2_INDEX_MASK
# define FIRST_LEVEL_BLOCK_SUPPORT  0
#elif GRANULE_SIZE == _SZ64KB
# define __PTL4_SHIFT  0
# define __PTL3_SHIFT  42
# define __PTL2_SHIFT  29
# define __PTL1_SHIFT  16
# define PTL4_INDEX_MASK 0
# define PTL3_INDEX_MASK ((UL(1) << 6) - 1)
# define PTL2_INDEX_MASK ((UL(1) << 13) - 1)
# define PTL1_INDEX_MASK PTL2_INDEX_MASK
# define FIRST_LEVEL_BLOCK_SUPPORT  0
#else
# error granule size error.
#endif

# define __PTL4_SIZE  (UL(1) << __PTL4_SHIFT)
# define __PTL3_SIZE  (UL(1) << __PTL3_SHIFT)
# define __PTL2_SIZE  (UL(1) << __PTL2_SHIFT)
# define __PTL1_SIZE  (UL(1) << __PTL1_SHIFT)
# define __PTL4_MASK  (~__PTL4_SIZE - 1)
# define __PTL3_MASK  (~__PTL3_SIZE - 1)
# define __PTL2_MASK  (~__PTL2_SIZE - 1)
# define __PTL1_MASK  (~__PTL1_SIZE - 1)

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
#endif/*__ASSEMBLY__*/

#define __page_offset(addr, size)   ((unsigned long)(addr) & ((size) - 1))
#define __page_align(addr, size)    ((unsigned long)(addr) & ~((size) - 1))
#define __page_align_up(addr, size) __page_align((unsigned long)(addr) + (size) - 1, size)

/*
 * nornal page
 */
#define PAGE_SHIFT          __PTL1_SHIFT
#define PAGE_SIZE           (UL(1) << __PTL1_SHIFT)
#define PAGE_MASK           (~(PTL1_SIZE - 1))
#define PAGE_P2ALIGN        0
#define page_offset(addr)   __page_offset(addr, PAGE_SIZE)
#define page_align(addr)    __page_align(addr, PAGE_SIZE)
#define page_align_up(addr) __page_align_up(addr, PAGE_SIZE)

/*
 * large page
 */
#define LARGE_PAGE_SHIFT          __PTL2_SHIFT
#define LARGE_PAGE_SIZE           (UL(1) << __PTL2_SHIFT)
#define LARGE_PAGE_MASK           (~(PTL2_SIZE - 1))
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

static inline int pte_is_type_page(const pte_t *ptep, size_t pgsize)
{
	int ret = 0; //default D_TABLE
	if ((PTL4_SIZE == pgsize && CONFIG_ARM64_PGTABLE_LEVELS > 3) ||
	    (PTL3_SIZE == pgsize && CONFIG_ARM64_PGTABLE_LEVELS > 2) ||
	    (PTL2_SIZE == pgsize)) {
		// check D_BLOCK
		ret = ((*ptep & PMD_TYPE_MASK) == PMD_TYPE_SECT);
	}
	else if (PTL1_SIZE == pgsize) {
		// check D_PAGE
		ret = ((*ptep & PTE_TYPE_MASK) == PTE_TYPE_PAGE);
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
	if ((PTL4_SIZE == pgsize && CONFIG_ARM64_PGTABLE_LEVELS > 3) ||
	    (PTL3_SIZE == pgsize && CONFIG_ARM64_PGTABLE_LEVELS > 2) ||
	    (PTL2_SIZE == pgsize) || 
	    (PTL1_SIZE == pgsize)) {
		*ptep = PTE_NULL;
	}
}

static inline void pte_make_fileoff(off_t off,
		enum ihk_mc_pt_attribute ptattr, size_t pgsize, pte_t *ptep)
{
	if ((PTL4_SIZE == pgsize && CONFIG_ARM64_PGTABLE_LEVELS > 3) ||
	    (PTL3_SIZE == pgsize && CONFIG_ARM64_PGTABLE_LEVELS > 2) ||
	    (PTL2_SIZE == pgsize) ||
	    (PTL1_SIZE == pgsize)) {
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

struct page_table;
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
