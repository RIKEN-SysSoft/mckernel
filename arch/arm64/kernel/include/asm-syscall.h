/* asm-syscall.h COPYRIGHT FUJITSU LIMITED 2018 */
#ifndef __HEADER_ARM64_ASM_SYSCALL_H
#define __HEADER_ARM64_ASM_SYSCALL_H

#ifdef __ASSEMBLY__

#define DECLARATOR(number, name)	.equ __NR_##name, number
#define SYSCALL_HANDLED(number, name)	DECLARATOR(number, name)
#define SYSCALL_DELEGATED(number, name)	DECLARATOR(number, name)

#include <syscall_list.h>

#undef DECLARATOR
#undef SYSCALL_HANDLED
#undef SYSCALL_DELEGATED

#endif /* __ASSEMBLY__ */

#endif	/* !__HEADER_ARM64_ASM_SYSCALL_H */
