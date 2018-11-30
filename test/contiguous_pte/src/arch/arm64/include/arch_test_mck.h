/* arch_test_mck.h COPYRIGHT FUJITSU LIMITED 2018 */
#ifndef __ARM64_ARCH_TEST_MCK_H
#define __ARM64_ARCH_TEST_MCK_H

/* config */
//#define CONFIG_ARM64_VA_BITS        39
#define CONFIG_ARM64_PGTABLE_LEVELS 3
#define CONFIG_ARM64_VA_BITS        48
//#define CONFIG_ARM64_PGTABLE_LEVELS 4
#define CONFIG_ARM64_64K_PAGES    1
#define VA_BITS                     CONFIG_ARM64_VA_BITS

/* auxv */
extern char *auxv_name[];

/* memory */
#if !defined(CONFIG_ARM64_64K_PAGES)
# define PAGE_SHIFT        12 //4KB
# define CONT_PAGE_SHIFT         (PAGE_SHIFT + 7)
# define CONT_LARGE_PAGE_SHIFT   (LARGE_PAGE_SHIFT + 5)
# define CONT_LARGEST_PAGE_SHIFT (LARGEST_PAGE_SHIFT + 0)
#else
# define PAGE_SHIFT        16 //64KB
# define CONT_PAGE_SHIFT         (PAGE_SHIFT + 5)
# define CONT_LARGE_PAGE_SHIFT   (LARGE_PAGE_SHIFT + 5)
# define CONT_LARGEST_PAGE_SHIFT (LARGEST_PAGE_SHIFT + 5)
#endif

#define LARGE_PAGE_SHIFT	(PAGE_SHIFT + 9 + (PAGE_SHIFT - 12))
#define LARGEST_PAGE_SHIFT	(LARGE_PAGE_SHIFT + 9 + (PAGE_SHIFT - 12))
#if (PAGE_SHIFT == 12) || (PAGE_SHIFT == 16)
# define ENABLE_LARGEST_PAGE 1
#else
# define ENABLE_LARGEST_PAGE 0
#endif

#if (VA_BITS == 39 && PAGE_SHIFT == 12)
# define MMAP_START_ADDR 0x0000000800000000UL /* in McKernel TASK_UNMAPPED_BASE value */
# define MMAP_END_ADDR   0x0000002000000000UL /* in McKernel USER_END value */
#elif (VA_BITS == 42 && PAGE_SHIFT == 16)
# define MMAP_START_ADDR 0x0000004000000000UL /* in McKernel TASK_UNMAPPED_BASE value */
# define MMAP_END_ADDR   0x0000010000000000UL /* in McKernel USER_END value */
#elif (VA_BITS == 48 && PAGE_SHIFT == 12)
# define MMAP_START_ADDR 0x0000100000000000UL /* in McKernel TASK_UNMAPPED_BASE value */
# define MMAP_END_ADDR   0x0000400000000000UL /* in McKernel USER_END value */
#elif (VA_BITS == 48 && PAGE_SHIFT == 16)
# define MMAP_START_ADDR 0x0000100000000000UL /* in McKernel TASK_UNMAPPED_BASE value */
# define MMAP_END_ADDR   0x0000400000000000UL /* in McKernel USER_END value */
#else
# error virtual address space not defined.
#endif
#define MMAP_AREA_SIZE	(MMAP_END_ADDR - MMAP_START_ADDR)

#endif /* __ARM64_ARCH_TEST_MCK_H */
