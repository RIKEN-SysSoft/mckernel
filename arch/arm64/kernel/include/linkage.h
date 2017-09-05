/* linkage.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
#ifndef __HEADER_ARM64_COMMON_LINKAGE_H
#define __HEADER_ARM64_COMMON_LINKAGE_H

#include <arch-memory.h>
#include <compiler.h>

#define ASM_NL		;

#define __ALIGN		.align 4
#define __ALIGN_STR	".align 4"

#define ENTRY(name)		\
	.globl name ASM_NL	\
	__ALIGN ASM_NL		\
	name:

#define END(name)		\
	.size name, .-name

#define ENDPROC(name)			\
	.type name, @function ASM_NL	\
	END(name)

#endif /* !__HEADER_ARM64_COMMON_LINKAGE_H */
