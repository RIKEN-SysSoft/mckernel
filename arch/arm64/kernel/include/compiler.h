/* compiler.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
#ifndef __ASM_COMPILER_H
#define __ASM_COMPILER_H

/* @ref.impl arch/arm64/include/asm/compiler.h::__asmeq(x,y) */
/*
 * This is used to ensure the compiler did actually allocate the register we
 * asked it for some inline assembly sequences.  Apparently we can't trust the
 * compiler from one version to another so a bit of paranoia won't hurt.  This
 * string is meant to be concatenated with the inline asm string and will
 * cause compilation to stop on mismatch.  (for details, see gcc PR 15089)
 */
#define __asmeq(x, y)  ".ifnc " x "," y " ; .err ; .endif\n\t"

/* @ref.impl include/linux/compiler.h::__section(S) */
/* Simple shorthand for a section definition */
# define __section(S)	__attribute__ ((__section__(#S)))

/* @ref.impl include/linux/compiler.h::__aligned(x) */
/*
 * From the GCC manual:
 *
 * Many functions have no effects except the return value and their
 * return value depends only on the parameters and/or global
 * variables.  Such a function can be subject to common subexpression
 * elimination and loop optimization just as an arithmetic operator
 * would be.
 * [...]
 */
#define __aligned(x)	__attribute__((aligned(x)))

#endif	/* __ASM_COMPILER_H */
