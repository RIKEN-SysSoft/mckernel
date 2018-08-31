/* pgtable-hwdef.h COPYRIGHT FUJITSU LIMITED 2015 */
#ifndef __HEADER_ARM64_COMMON_PGTABLE_HWDEF_H
#define __HEADER_ARM64_COMMON_PGTABLE_HWDEF_H

#ifndef __HEADER_ARM64_COMMON_ARCH_MEMORY_H
# error arch-memory.h
#endif

#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))

/*
 * PMD_SHIFT determines the size a level 2 page table entry can map.
 */
#if CONFIG_ARM64_PGTABLE_LEVELS > 2
# define PMD_SHIFT		((PAGE_SHIFT - 3) * 2 + 3)
# define PMD_SIZE		(1UL << PMD_SHIFT)
# define PMD_MASK		(~(PMD_SIZE-1))
# define PTRS_PER_PMD		PTRS_PER_PTE
#endif

 /*
  * PUD_SHIFT determines the size a level 1 page table entry can map.
  */
#if CONFIG_ARM64_PGTABLE_LEVELS > 3
# define PUD_SHIFT		((PAGE_SHIFT - 3) * 3 + 3)
# define PUD_SIZE		(1UL << PUD_SHIFT)
# define PUD_MASK		(~(PUD_SIZE-1))
# define PTRS_PER_PUD		PTRS_PER_PTE
#endif
 
/*
 * PGDIR_SHIFT determines the size a top-level page table entry can map
 * (depending on the configuration, this level can be 0, 1 or 2).
 */
#define PGDIR_SHIFT		((PAGE_SHIFT - 3) * CONFIG_ARM64_PGTABLE_LEVELS + 3)
#define PGDIR_SIZE		(_AC(1, UL) << PGDIR_SHIFT)
#define PGDIR_MASK		(~(PGDIR_SIZE-1))
#define PTRS_PER_PGD		(1 << (VA_BITS - PGDIR_SHIFT))

/*
 * Section address mask and size definitions.
 */
#define SECTION_SHIFT		PMD_SHIFT
#define SECTION_SIZE		(UL(1) << SECTION_SHIFT)
#define SECTION_MASK		(~(SECTION_SIZE-1))

/*
 * Contiguous page definitions.
 */
#ifdef CONFIG_ARM64_64K_PAGES
#define CONT_PTE_SHIFT		5   //Contiguousでまとまるエントリ数のシフト値
#define CONT_PMD_SHIFT		5
#elif defined(CONFIG_ARM64_16K_PAGES)
#define CONT_PTE_SHIFT		7
#define CONT_PMD_SHIFT		5
#else
#define CONT_PTE_SHIFT		4
#define CONT_PMD_SHIFT		4
#endif

#define CONT_PTES		(1 << CONT_PTE_SHIFT)
#define CONT_PTE_SIZE		(CONT_PTES * PAGE_SIZE)
#define CONT_PTE_MASK		(~(CONT_PTE_SIZE - 1))
#define CONT_PMDS		(1 << CONT_PMD_SHIFT)
#define CONT_PMD_SIZE		(CONT_PMDS * PMD_SIZE)
#define CONT_PMD_MASK		(~(CONT_PMD_SIZE - 1))
/* the the numerical offset of the PTE within a range of CONT_PTES */
#define CONT_RANGE_OFFSET(addr) (((addr)>>PAGE_SHIFT)&(CONT_PTES-1))

/*
 * Level 2 descriptor (PMD).
 */
#define PMD_TYPE_MASK		(UL(3) << 0)
#define PMD_TYPE_FAULT		(UL(0) << 0)
#define PMD_TYPE_TABLE		(UL(3) << 0)
#define PMD_TYPE_SECT		(UL(1) << 0)
#define PMD_TABLE_BIT		(UL(1) << 1)

/*
 * Table (D_Block)
 */
#define PMD_TBL_PXNT		(UL(1) << 59)
#define PMD_TBL_UXNT		(UL(1) << 60)
#define PMD_TBL_APT_USER	(UL(1) << 61) /* 0:Access at EL0 permitted, 1:Access at EL0 not permitted */
#define PMD_TBL_APT_RDONLY	(UL(2) << 61) /* 0:read write(EL0-3) 0:read only(EL0-3) */
#define PMD_TBL_NST		(UL(1) << 63) /* 0:secure, 1:non-secure */

/*
 * Section (D_Page)
 */
#define PMD_SECT_VALID		(UL(1) << 0)
#define PMD_SECT_PROT_NONE	(UL(1) << 58)
#define PMD_SECT_USER		(UL(1) << 6)		/* AP[1] */
#define PMD_SECT_RDONLY		(UL(1) << 7)		/* AP[2] */
#define PMD_SECT_S		(UL(3) << 8)
#define PMD_SECT_AF		(UL(1) << 10)
#define PMD_SECT_NG		(UL(1) << 11)
#define PMD_SECT_CONT		(UL(1) << 52)
#define PMD_SECT_PXN		(UL(1) << 53)
#define PMD_SECT_UXN		(UL(1) << 54)

/*
 * AttrIndx[2:0] encoding (mapping attributes defined in the MAIR* registers).
 */
#define PMD_ATTRINDX(t)		(UL(t) << 2)
#define PMD_ATTRINDX_MASK	(UL(7) << 2)

/*
 * Level 3 descriptor (PTE).
 */
#define PTE_TYPE_MASK		(UL(3) << 0)
#define PTE_TYPE_FAULT		(UL(0) << 0)
#define PTE_TYPE_PAGE		(UL(3) << 0)
#define PTE_TABLE_BIT		(UL(1) << 1)
#define PTE_USER		(UL(1) << 6)	/* AP[1] */
#define PTE_RDONLY		(UL(1) << 7)	/* AP[2] */
#define PTE_SHARED		(UL(3) << 8)	/* SH[1:0], inner shareable */
#define PTE_AF			(UL(1) << 10)	/* Access Flag */
#define PTE_NG			(UL(1) << 11)	/* nG */
#define PTE_CONT		(UL(1) << 52)	/* Contiguous range */
#define PTE_PXN			(UL(1) << 53)	/* Privileged XN */
#define PTE_UXN			(UL(1) << 54)	/* User XN */
/* Software defined PTE bits definition.*/
#define PTE_VALID		(UL(1) << 0)
#define PTE_FILE		(UL(1) << 2)	/* only when !pte_present() */
#define PTE_DIRTY		(UL(1) << 55)
#define PTE_SPECIAL		(UL(1) << 56)
#define PTE_WRITE		(UL(1) << 57)
#define PTE_PROT_NONE		(UL(1) << 58) /* only when !PTE_VALID */

/*
 * AttrIndx[2:0] encoding (mapping attributes defined in the MAIR* registers).
 */
#define PTE_ATTRINDX(t)		(UL(t) << 2)
#define PTE_ATTRINDX_MASK	(UL(7) << 2)

/*
 * Highest possible physical address supported.
 */
#define PHYS_MASK_SHIFT		(48)
#define PHYS_MASK		(((UL(1) << PHYS_MASK_SHIFT) - 1) & PAGE_MASK)

/*
 * TCR flags.
 */
#define TCR_TxSZ(x)		(((UL(64) - (x)) << 16) | ((UL(64) - (x)) << 0))
#define TCR_IRGN_NC		((UL(0) << 8) | (UL(0) << 24))
#define TCR_IRGN_WBWA		((UL(1) << 8) | (UL(1) << 24))
#define TCR_IRGN_WT		((UL(2) << 8) | (UL(2) << 24))
#define TCR_IRGN_WBnWA		((UL(3) << 8) | (UL(3) << 24))
#define TCR_IRGN_MASK		((UL(3) << 8) | (UL(3) << 24))
#define TCR_ORGN_NC		((UL(0) << 10) | (UL(0) << 26))
#define TCR_ORGN_WBWA		((UL(1) << 10) | (UL(1) << 26))
#define TCR_ORGN_WT		((UL(2) << 10) | (UL(2) << 26))
#define TCR_ORGN_WBnWA		((UL(3) << 10) | (UL(3) << 26))
#define TCR_ORGN_MASK		((UL(3) << 10) | (UL(3) << 26))
#define TCR_SHARED		((UL(3) << 12) | (UL(3) << 28))
#define TCR_TG0_4K		(UL(0) << 14)
#define TCR_TG0_64K		(UL(1) << 14)
#define TCR_TG0_16K		(UL(2) << 14)
#define TCR_TG1_16K		(UL(1) << 30)
#define TCR_TG1_4K		(UL(2) << 30)
#define TCR_TG1_64K		(UL(3) << 30)
#define TCR_ASID16		(UL(1) << 36)
#define TCR_TBI0		(UL(1) << 37)

/*
 * Memory types available.
 */
#define MT_DEVICE_nGnRnE	0
#define MT_DEVICE_nGnRE		1
#define MT_DEVICE_GRE		2
#define MT_NORMAL_NC		3
#define MT_NORMAL		4

/*
 * page table entry attribute set.
 */
#define PROT_DEFAULT		(PTE_TYPE_PAGE | PTE_AF | PTE_SHARED)
#define PROT_SECT_DEFAULT	(PMD_TYPE_SECT | PMD_SECT_AF | PMD_SECT_S)

#define PROT_DEVICE_nGnRE	(PROT_DEFAULT | PTE_PXN | PTE_UXN | PTE_ATTRINDX(MT_DEVICE_nGnRE))
#define PROT_NORMAL_NC		(PROT_DEFAULT | PTE_PXN | PTE_UXN | PTE_ATTRINDX(MT_NORMAL_NC))
#define PROT_NORMAL		(PROT_DEFAULT | PTE_PXN | PTE_UXN | PTE_ATTRINDX(MT_NORMAL))

#define PROT_SECT_DEVICE_nGnRE	(PROT_SECT_DEFAULT | PMD_SECT_PXN | PMD_SECT_UXN | PMD_ATTRINDX(MT_DEVICE_nGnRE))
#define PROT_SECT_NORMAL	(PROT_SECT_DEFAULT | PMD_SECT_PXN | PMD_SECT_UXN | PMD_ATTRINDX(MT_NORMAL))
#define PROT_SECT_NORMAL_EXEC	(PROT_SECT_DEFAULT | PMD_SECT_UXN | PMD_ATTRINDX(MT_NORMAL))

#define _PAGE_DEFAULT		(PROT_DEFAULT | PTE_ATTRINDX(MT_NORMAL))

#define PAGE_KERNEL		(_PAGE_DEFAULT | PTE_PXN | PTE_UXN | PTE_DIRTY | PTE_WRITE)
#define PAGE_KERNEL_EXEC	(_PAGE_DEFAULT | PTE_UXN | PTE_DIRTY | PTE_WRITE)

#define PAGE_NONE		(((_PAGE_DEFAULT) & ~PTE_TYPE_MASK) | PTE_PROT_NONE | PTE_PXN | PTE_UXN)
#define PAGE_SHARED		(_PAGE_DEFAULT | PTE_USER | PTE_NG | PTE_PXN | PTE_UXN | PTE_WRITE)
#define PAGE_SHARED_EXEC	(_PAGE_DEFAULT | PTE_USER | PTE_NG | PTE_PXN | PTE_WRITE)
#define PAGE_COPY		(_PAGE_DEFAULT | PTE_USER | PTE_NG | PTE_PXN | PTE_UXN)
#define PAGE_COPY_EXEC		(_PAGE_DEFAULT | PTE_USER | PTE_NG | PTE_PXN)
#define PAGE_READONLY		(_PAGE_DEFAULT | PTE_USER | PTE_NG | PTE_PXN | PTE_UXN)
#define PAGE_READONLY_EXEC	(_PAGE_DEFAULT | PTE_USER | PTE_NG | PTE_PXN)

#define __P000  PAGE_NONE
#define __P001  PAGE_READONLY
#define __P010  PAGE_COPY
#define __P011  PAGE_COPY
#define __P100  PAGE_READONLY_EXEC
#define __P101  PAGE_READONLY_EXEC
#define __P110  PAGE_COPY_EXEC
#define __P111  PAGE_COPY_EXEC

#define __S000  PAGE_NONE
#define __S001  PAGE_READONLY
#define __S010  PAGE_SHARED
#define __S011  PAGE_SHARED
#define __S100  PAGE_READONLY_EXEC
#define __S101  PAGE_READONLY_EXEC
#define __S110  PAGE_SHARED_EXEC
#define __S111  PAGE_SHARED_EXEC

#endif /* !__HEADER_ARM64_COMMON_PGTABLE_HWDEF_H */
