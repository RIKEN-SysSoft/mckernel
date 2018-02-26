/* arch-eclair.h COPYRIGHT FUJITSU LIMITED 2016 */
#ifndef HEADER_USER_ARM64_ECLAIR_H
#define HEADER_USER_ARM64_ECLAIR_H

/* VA_BITS=48, 4K_PAGE address */
#define MAP_KERNEL	0xffffffffff800000
#define MAP_ST		0xffff800000000000
#define MAP_KERNEL_TEXT	"0xffffffffff800000"

#define ARCH_CLV_SPAN	"arm64_cpu_local_variables_span"

#define ARCH	"aarch64"

#define ARCH_REGS	34

#define PANIC_REGS_OFFSET	160

struct arch_kregs {
	unsigned long x19, x20, x21, x22, x23;
	unsigned long x24, x25, x26, x27, x28;
	unsigned long fp, sp, pc;
};

#endif	/* HEADER_USER_ARM64_ECLAIR_H */
