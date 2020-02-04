/* arch-eclair.h COPYRIGHT FUJITSU LIMITED 2016-2019 */
#ifndef HEADER_USER_ARM64_ECLAIR_H
#define HEADER_USER_ARM64_ECLAIR_H

/* PHYS_OFFSET needs to be changed according to the environment. */
#define PHYS_OFFSET		0x40000000

#ifdef CONFIG_ARM64_64K_PAGES
#
# if (CONFIG_ARM64_VA_BITS == 42)
#  /* VA_BITS=42, 64K_PAGE address */
#  define MAP_ST		0xfffffe0000000000
#
# elif (CONFIG_ARM64_VA_BITS == 48)
#  /* VA_BITS=48, 64K_PAGE address */
#  define MAP_ST		0xffff800000000000
#
# else
#
#  error "No support VA_BITS and PAGE_SIZE"
#
# endif
#
#else /* CONFIG_ARM64_64K_PAGES */
#
# if (CONFIG_ARM64_VA_BITS == 39)
#  /* VA_BITS=39, 4K_PAGE address */
#  define MAP_ST		0xffffffc000000000
#
# elif (CONFIG_ARM64_VA_BITS == 48)
#  /* VA_BITS=48, 4K_PAGE address */
#  define MAP_ST		0xffff800000000000
#
# else
#
#  error "No support VA_BITS and PAGE_SIZE"
#
# endif
#
#endif /* CONFIG_ARM64_64K_PAGES */

#define ARCH_CLV_SPAN	"arm64_cpu_local_variables_span"

#define ARCH	"aarch64"

#define ARCH_REGS	34

#define PANIC_REGS_OFFSET	168

struct arch_kregs {
	unsigned long x19, x20, x21, x22, x23;
	unsigned long x24, x25, x26, x27, x28;
	unsigned long fp, sp, pc;
};

#endif	/* HEADER_USER_ARM64_ECLAIR_H */
