/* arch-eclair.h COPYRIGHT FUJITSU LIMITED 2016 */
#ifndef HEADER_USER_X86_ECLAIR_H
#define HEADER_USER_X86_ECLAIR_H

#ifndef POSTK_DEBUG_ARCH_DEP_34
#define MAP_ST_START       0xffff800000000000UL
#define MAP_VMAP_START     0xffff850000000000UL
#define MAP_FIXED_START    0xffff860000000000UL
#define LINUX_PAGE_OFFSET  0xffff880000000000UL
#define MAP_KERNEL_START   0xFFFFFFFFFE800000UL
#endif	/* POSTK_DEBUG_ARCH_DEP_34 */

/* TODO: these should be updated when McKernel changes */
#define MCKERNEL_ELF_START "0xFFFFFFFFFE801000"
#define MCKERNEL_ELF_LEN   "0x0000000000100000"


#define ARCH_CLV_SPAN	"x86_cpu_local_variables_span"

#define ARCH	"i386:x86-64"

#define ARCH_REGS	21

#define PANIC_REGS_OFFSET	240

#define MAP_KERNEL_TEXT	"0xffffffff80001000"

struct arch_kregs {
	uintptr_t rsp, rbp, rbx, rsi;
	uintptr_t rdi, r12, r13, r14;
	uintptr_t r15, rflags, rsp0;
};

#endif	/* HEADER_USER_x86_ECLAIR_H */
