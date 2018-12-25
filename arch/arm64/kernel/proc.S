/* proc.S COPYRIGHT FUJITSU LIMITED 2015-2017 */

#include <linkage.h>
#include <arch-memory.h>
#include <sysreg.h>
#include <assembler.h>
#include "proc-macros.S"

#ifdef CONFIG_ARM64_64K_PAGES
# define TCR_TG_FLAGS	TCR_TG0_64K | TCR_TG1_64K
#else
# define TCR_TG_FLAGS	TCR_TG0_4K | TCR_TG1_4K
#endif

//#ifdef CONFIG_SMP
#define TCR_SMP_FLAGS	TCR_SHARED
//#else
//#define TCR_SMP_FLAGS	0
//#endif

/* PTWs cacheable, inner/outer WBWA */
#define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA

#define MAIR(attr, mt)	((attr) << ((mt) * 8))

/*
 *	cpu_do_idle()
 *
 *	Idle the processor (wait for interrupt).
 */
#if defined(CONFIG_HAS_NMI)
#include <arm-gic-v3.h>
ENTRY(__cpu_do_idle)
	mrs	x0, daif			// save I bit
	msr	daifset, #2			// set I bit
	mrs_s	x1, ICC_PMR_EL1			// save PMR
	mov	x2, #ICC_PMR_EL1_UNMASKED
	msr_s	ICC_PMR_EL1, x2			// unmask at PMR
	dsb	sy				// WFI may enter a low-power mode
	wfi
	msr_s	ICC_PMR_EL1, x1			// restore PMR
	msr	daif, x0			// restore I bit
	ret
ENDPROC(__cpu_do_idle)
#else /* defined(CONFIG_HAS_NMI) */
ENTRY(__cpu_do_idle)
	dsb	sy				// WFI may enter a low-power mode
	wfi
	ret
ENDPROC(__cpu_do_idle)
#endif /* defined(CONFIG_HAS_NMI) */

/*
 *	cpu_do_switch_mm(pgd_phys, tsk)
 *
 *	Set the translation table base pointer to be pgd_phys.
 *
 *	- pgd_phys - physical address of new TTB
 */
ENTRY(cpu_do_switch_mm)
	//mmid	w1, x1				// get mm->context.id
	bfi	x0, x1, #48, #16		// set the ASID
	msr	ttbr0_el1, x0			// set TTBR0
	isb
	ret
ENDPROC(cpu_do_switch_mm)

	.section ".text.init", #alloc, #execinstr

/*
 *	__cpu_setup
 *
 *	Initialise the processor for turning the MMU on.  Return in x0 the
 *	value of the SCTLR_EL1 register.
 */
ENTRY(__cpu_setup)
	tlbi	vmalle1				// Invalidate local TLB
	dsb	nsh

	mov	x0, #3 << 20

	/* SVE */
	mrs	x5, id_aa64pfr0_el1
	ubfx	x5, x5, #ID_AA64PFR0_SVE_SHIFT, #4
	cbz	x5, 1f

	orr	x0, x0, #CPACR_EL1_ZEN		// SVE: trap disabled EL1 and EL0
1:	msr	cpacr_el1, x0			// Enable FP/ASIMD

	mov	x0, #1 << 12			// Reset mdscr_el1 and disable
	msr	mdscr_el1, x0			// access to the DCC from EL0
	isb					// Unmask debug exceptions now,
	enable_dbg				// since this is per-cpu

	/*
	 * Memory region attributes for LPAE:
	 *
	 *   n = AttrIndx[2:0]
	 *			n	MAIR
	 *   DEVICE_nGnRnE	000	00000000
	 *   DEVICE_nGnRE	001	00000100
	 *   DEVICE_GRE		010	00001100
	 *   NORMAL_NC		011	01000100
	 *   NORMAL		100	11111111
	 */
	ldr	x5, =MAIR(0x00, MT_DEVICE_nGnRnE) | \
		     MAIR(0x04, MT_DEVICE_nGnRE) | \
		     MAIR(0x0c, MT_DEVICE_GRE) | \
		     MAIR(0x44, MT_NORMAL_NC) | \
		     MAIR(0xff, MT_NORMAL)
	msr	mair_el1, x5
	/*
	 * Prepare SCTLR
	 */
	adr	x5, crval
	ldp	w5, w6, [x5]
	mrs	x0, sctlr_el1
	bic	x0, x0, x5			// clear bits
	orr	x0, x0, x6			// set bits
	/*
	 * Set/prepare TCR and TTBR. We use 512GB (39-bit) address range for
	 * both user and kernel.
	 */
	ldr	x10, =TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SMP_FLAGS | \
			TCR_TG_FLAGS | TCR_ASID16 | TCR_TBI0
	/*
	 * Read the PARange bits from ID_AA64MMFR0_EL1 and set the IPS bits in
	 * TCR_EL1.
	 */
	mrs	x9, ID_AA64MMFR0_EL1
	bfi	x10, x9, #32, #3
	msr	tcr_el1, x10
	ret					// return to head.S
ENDPROC(__cpu_setup)

	/*
	 *                 n n            T
	 *       U E      WT T UD     US IHBS
	 *       CE0      XWHW CZ     ME TEEA S
	 * .... .IEE .... NEAI TE.I ..AD DEN0 ACAM
	 * 0011 0... 1101 ..0. ..0. 10.. .... .... < hardware reserved
	 * .... .1.. .... 01.1 11.1 ..01 0001 1101 < software settings
	 */
	.type	crval, #object
crval:
	.word	0x000802e2			// clear
	.word	0x0405d11d			// set

