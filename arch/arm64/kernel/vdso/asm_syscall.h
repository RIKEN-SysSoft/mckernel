/* asm_syscall.h COPYRIGHT FUJITSU LIMITED 2016 */
#ifndef __HEADER_ARM64_VDSO_SYSCALL_H
#define __HEADER_ARM64_VDSO_SYSCALL_H

#define DECLARATOR(number,name)		.equ __NR_##name, number
#define SYSCALL_HANDLED(number,name)	DECLARATOR(number,name)
#define SYSCALL_DELEGATED(number,name)	DECLARATOR(number,name)

#include <syscall_list.h>

#undef DECLARATOR
#undef SYSCALL_HANDLED
#undef SYSCALL_DELEGATED

#endif	/* !__HEADER_ARM64_VDSO_SYSCALL_H */
