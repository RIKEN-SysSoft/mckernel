/* assembler.h COPYRIGHT FUJITSU LIMITED 2015-2017 */
#ifndef __HEADER_ARM64_COMMON_ASSEMBLER_H
#define __HEADER_ARM64_COMMON_ASSEMBLER_H

#include <thread_info.h>

#if defined(CONFIG_HAS_NMI)
#include <arm-gic-v3.h>
#endif /* defined(CONFIG_HAS_NMI) */

#if defined(CONFIG_HAS_NMI)
/*
 * Enable and disable pseudo NMI.
 */
	.macro	disable_nmi
	msr	daifset, #2
	.endm

	.macro	enable_nmi
	msr	daifclr, #2
	.endm

/*
 * Enable and disable interrupts.
 */
	.macro	disable_irq, tmp
	mov	\tmp, #ICC_PMR_EL1_MASKED
	msr_s	ICC_PMR_EL1, \tmp
	.endm

	.macro	enable_irq, tmp
	mov	\tmp, #ICC_PMR_EL1_UNMASKED
	msr_s	ICC_PMR_EL1, \tmp
	.endm

#else /* defined(CONFIG_HAS_NMI) */
/*
 * Enable and disable pseudo NMI.
 */
	.macro	disable_nmi
	.endm

	.macro	enable_nmi
	.endm

/*
 * Enable and disable interrupts.
 */
	.macro	disable_irq, tmp
	msr	daifset, #2
	.endm

	.macro	enable_irq, tmp
	msr	daifclr, #2
	.endm
#endif /* defined(CONFIG_HAS_NMI) */

/*
 * Enable and disable debug exceptions.
 */
	.macro	disable_dbg
	msr	daifset, #8
	.endm

	.macro	enable_dbg
	msr	daifclr, #8
	.endm

	.macro	disable_step_tsk, flgs, tmp
	tbz	\flgs, #TIF_SINGLESTEP, 9990f
	mrs	\tmp, mdscr_el1
	bic	\tmp, \tmp, #1
	msr	mdscr_el1, \tmp
	isb	// Synchronise with enable_dbg
9990:
	.endm

	.macro	enable_step_tsk, flgs, tmp
	tbz	\flgs, #TIF_SINGLESTEP, 9990f
	disable_dbg
	mrs	\tmp, mdscr_el1
	orr	\tmp, \tmp, #1
	msr	mdscr_el1, \tmp
	b	9991f
9990:
	mrs	\tmp, mdscr_el1
	bic	\tmp, \tmp, #1
	msr	mdscr_el1, \tmp
	isb	// Synchronise with enable_dbg
9991:
	.endm

/*
 * Enable both debug exceptions and interrupts. This is likely to be
 * faster than two daifclr operations, since writes to this register
 * are self-synchronising.
 */
#if defined(CONFIG_HAS_NMI)
 	.macro  enable_dbg_and_irq, tmp
 	enable_dbg
 	enable_irq \tmp
	.endm
#else /* defined(CONFIG_HAS_NMI) */
	.macro	enable_dbg_and_irq, tmp
	msr	daifclr, #(8 | 2)
	.endm
#endif /* defined(CONFIG_HAS_NMI) */

/*
 * Register aliases.
 */
lr	.req	x30		// link register

/*
 * Vector entry
 */
	 .macro ventry  label
	.align 7
	b	\label
	.endm

/*
 * Select code when configured for BE.
 */
//#ifdef CONFIG_CPU_BIG_ENDIAN
//#define CPU_BE(code...) code
//#else
#define CPU_BE(code...)
//#endif

/*
 * Select code when configured for LE.
 */
//#ifdef CONFIG_CPU_BIG_ENDIAN
//#define CPU_LE(code...)
//#else
#define CPU_LE(code...) code
//#endif

#endif /* !__HEADER_ARM64_COMMON_ASSEMBLER_H */
