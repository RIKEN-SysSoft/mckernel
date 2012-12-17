#ifndef __HEADER_X86_COMMON_ARCH_MEMORY_H
#define __HEADER_X86_COMMON_ARCH_MEMORY_H

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

#define LARGE_PAGE_SHIFT   21
#define LARGE_PAGE_SIZE    (1UL << LARGE_PAGE_SHIFT)
#define LARGE_PAGE_MASK    (~((unsigned long)LARGE_PAGE_SIZE - 1))

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

#define PFL4_PRESENT    0x01
#define PFL4_WRITABLE   0x02
#define PFL4_USER       0x04

#define PFL3_PRESENT    0x01
#define PFL3_WRITABLE   0x02
#define PFL3_USER       0x04
#define PFL3_ACCESSED   0x20
#define PFL3_DIRTY      0x40
#define PFL3_SIZE       0x80   /* Used in 1G page */
#define PFL3_GLOBAL     0x100

#define PFL2_PRESENT    0x01
#define PFL2_WRITABLE   0x02
#define PFL2_USER       0x04
#define PFL2_ACCESSED   0x20
#define PFL2_DIRTY      0x40
#define PFL2_SIZE       0x80   /* Used in 2M page */
#define PFL2_GLOBAL     0x100
#define PFL2_PWT        0x08
#define PFL2_PCD        0x10

#define PFL1_PRESENT    0x01
#define PFL1_WRITABLE   0x02
#define PFL1_USER       0x04
#define PFL1_ACCESSED   0x20
#define PFL1_DIRTY      0x40
#define PFL1_PWT        0x08
#define PFL1_PCD        0x10

/* We allow user programs to access all the memory */
#define PFL4_KERN_ATTR       (PFL4_PRESENT | PFL4_WRITABLE)
#define PFL3_KERN_ATTR       (PFL3_PRESENT | PFL3_WRITABLE)
#define PFL2_KERN_ATTR       (PFL2_PRESENT | PFL2_WRITABLE)
#define PFL1_KERN_ATTR       (PFL1_PRESENT | PFL1_WRITABLE)

/* For easy conversion, it is better to be the same as architecture's ones */
enum aal_mc_pt_attribute {
	PTATTR_ACTIVE     = 0x01,
	PTATTR_WRITABLE   = 0x02,
	PTATTR_USER       = 0x04,
	PTATTR_LARGEPAGE  = 0x80,
	PTATTR_UNCACHABLE = 0x10000,
};

typedef unsigned long pte_t;

struct page_table;
void set_pte(pte_t *ppte, unsigned long phys, int attr);
pte_t *get_pte(struct page_table *pt, void *virt, int attr);

void *early_alloc_page(void);
void *get_last_early_heap(void);
void flush_tlb(void);
void flush_tlb_single(unsigned long addr);

void *map_fixed_area(unsigned long phys, unsigned long size, int uncachable);

#define AP_TRAMPOLINE       0x10000
#define AP_TRAMPOLINE_SIZE  0x4000

/* Local is cachable */
#define AAL_IKC_QUEUE_PT_ATTR (PTATTR_WRITABLE | PTATTR_UNCACHABLE)
#endif
