/* arch-eclair.h COPYRIGHT FUJITSU LIMITED 2016 */
#ifndef HEADER_USER_X86_ECLAIR_H
#define HEADER_USER_X86_ECLAIR_H

#define MAP_ST_START       0xffff800000000000UL
#define MAP_FIXED_START    0xffff860000000000UL
extern unsigned long linux_page_offset;
#define ARCH_CLV_SPAN	"x86_cpu_local_variables_span"

#define ARCH	"i386:x86-64"

#define ARCH_REGS	21

/* See struct x86_cpu_local_variables */
#define PANIC_REGS_OFFSET	288

struct arch_kregs {
	uintptr_t rsp, rbp, rbx, rsi;
	uintptr_t rdi, r12, r13, r14;
	uintptr_t r15, rflags, rsp0;
};

#endif	/* HEADER_USER_x86_ECLAIR_H */
