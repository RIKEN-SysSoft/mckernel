/* arch-eclair.h COPYRIGHT FUJITSU LIMITED 2016 */
#ifndef HEADER_USER_X86_ECLAIR_H
#define HEADER_USER_X86_ECLAIR_H

#define MAP_KERNEL	0xFFFFFFFF80000000
#define MAP_ST		0xFFFF800000000000

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
