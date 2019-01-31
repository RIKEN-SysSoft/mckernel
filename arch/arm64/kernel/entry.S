/* entry.S COPYRIGHT FUJITSU LIMITED 2015-2018 */

#include <linkage.h>
#include <assembler.h>
#include <asm-offsets.h>
#include <esr.h>
#include <thread_info.h>
#include <asm-syscall.h>

/*
 * Bad Abort numbers
 *-----------------
 */
#define BAD_SYNC	0
#define BAD_IRQ		1
#define BAD_FIQ		2
#define BAD_ERROR	3

	.macro	kernel_entry, el, regsize = 64
	sub	sp, sp, #S_FRAME_SIZE
	.if	\regsize == 32
	mov	w0, w0				// zero upper 32 bits of x0
	.endif
	stp	x0, x1, [sp, #16 * 0]
	stp	x2, x3, [sp, #16 * 1]
	stp	x4, x5, [sp, #16 * 2]
	stp	x6, x7, [sp, #16 * 3]
	stp	x8, x9, [sp, #16 * 4]
	stp	x10, x11, [sp, #16 * 5]
	stp	x12, x13, [sp, #16 * 6]
	stp	x14, x15, [sp, #16 * 7]
	stp	x16, x17, [sp, #16 * 8]
	stp	x18, x19, [sp, #16 * 9]
	stp	x20, x21, [sp, #16 * 10]
	stp	x22, x23, [sp, #16 * 11]
	stp	x24, x25, [sp, #16 * 12]
	stp	x26, x27, [sp, #16 * 13]
	stp	x28, x29, [sp, #16 * 14]

	.if	\el == 0
	mrs	x21, sp_el0
	get_thread_info tsk			// Ensure MDSCR_EL1.SS is clear,
	ldr	x19, [tsk, #TI_FLAGS]		// since we can unmask debug
	disable_step_tsk x19, x20		// exceptions when scheduling.
	.else
	add	x21, sp, #S_FRAME_SIZE
	.endif
	mrs	x22, elr_el1
	mrs	x23, spsr_el1
#if defined(CONFIG_HAS_NMI)
	mrs_s	x20, ICC_PMR_EL1		// Get PMR
	and	x20, x20, #ICC_PMR_EL1_G_BIT	// Extract mask bit
	lsl	x20, x20, #PSR_G_PMR_G_SHIFT	// Shift to a PSTATE RES0 bit
	eor	x20, x20, #PSR_G_BIT		// Invert bit
	orr	x23, x20, x23		 	// Store PMR within PSTATE
	mov	x20, #ICC_PMR_EL1_MASKED
	msr_s	ICC_PMR_EL1, x20		// Mask normal interrupts at PMR
#endif /* defined(CONFIG_HAS_NMI) */
	stp	lr, x21, [sp, #S_LR]
	stp	x22, x23, [sp, #S_PC]

	/*
	 * Set syscallno to -1 by default (overridden later if real syscall).
	 */
	.if	\el == 0
	mvn	x21, xzr
	str	x21, [sp, #S_SYSCALLNO]
	.endif

	/*
	 * Registers that may be useful after this macro is invoked:
	 *
	 * x21 - aborted SP
	 * x22 - aborted PC
	 * x23 - aborted PSTATE
	*/
	.endm

	.macro	kernel_exit, el, need_enable_step = 0
	.if 	\el == 0
	bl	check_sig_pending
	bl	check_need_resched		// or reschedule is needed.
	mov	x0, #0
	mov	x1, sp
	mov	x2, #0
	bl	check_signal			// check whether the signal is delivered
	mov	x0, #0
	mov	x1, sp
	mov	x2, #0
	bl	check_signal_irq_disabled	// check whether the signal is delivered(for kernel_exit)
	.endif
	.if	\el == 1
	bl	check_sig_pending
	.endif
	disable_irq x1				// disable interrupts
	.if	\need_enable_step == 1
	ldr	x1, [tsk, #TI_FLAGS]
	enable_step_tsk x1, x2
	.endif
	disable_nmi
	ldp	x21, x22, [sp, #S_PC]		// load ELR, SPSR
	.if	\el == 0
//	ct_user_enter				// McKernel, disable (debugcode?)
	ldr	x23, [sp, #S_SP]		// load return stack pointer
	msr	sp_el0, x23
	.endif
#if defined(CONFIG_HAS_NMI)
	and	x20, x22, #PSR_G_BIT		// Get stolen PSTATE bit
	and	x22, x22, #~PSR_G_BIT		// Clear stolen bit
	lsr	x20, x20, #PSR_G_PMR_G_SHIFT	// Shift back to PMR mask
	eor	x20, x20, #ICC_PMR_EL1_UNMASKED	// x20 gets 0xf0 or 0xb0
	msr_s	ICC_PMR_EL1, x20		// Write to PMR
#endif /* defined(CONFIG_HAS_NMI) */
	msr	elr_el1, x21			// set up the return data
	msr	spsr_el1, x22
	ldp	x0, x1, [sp, #16 * 0]
	ldp	x2, x3, [sp, #16 * 1]
	ldp	x4, x5, [sp, #16 * 2]
	ldp	x6, x7, [sp, #16 * 3]
	ldp	x8, x9, [sp, #16 * 4]
	ldp	x10, x11, [sp, #16 * 5]
	ldp	x12, x13, [sp, #16 * 6]
	ldp	x14, x15, [sp, #16 * 7]
	ldp	x16, x17, [sp, #16 * 8]
	ldp	x18, x19, [sp, #16 * 9]
	ldp	x20, x21, [sp, #16 * 10]
	ldp	x22, x23, [sp, #16 * 11]
	ldp	x24, x25, [sp, #16 * 12]
	ldp	x26, x27, [sp, #16 * 13]
	ldp	x28, x29, [sp, #16 * 14]
	ldr	lr, [sp, #S_LR]
	add	sp, sp, #S_FRAME_SIZE		// restore sp
	eret					// return to kernel
	.endm

	.macro	get_thread_info, rd
	mov	\rd, sp
	and	\rd, \rd, #~(KERNEL_STACK_SIZE - 1)	// top of stack
	.endm

/*
 * These are the registers used in the syscall handler, and allow us to
 * have in theory up to 7 arguments to a function - x0 to x6.
 *
 * x7 is reserved for the system call number in 32-bit mode.
 */
sc_nr	.req	x25		// number of system calls
scno	.req	x26		// syscall number
stbl	.req	x27		// syscall table pointer
tsk	.req	x28		// current thread_info

/*
 * Interrupt handling.
 */
	.macro	irq_handler
	adrp	x1, handle_arch_irq
	ldr	x1, [x1, #:lo12:handle_arch_irq]
	mov	x0, sp
	blr	x1
	.endm

	.text

/*
 * Exception vectors.
 */

	.align	11
ENTRY(vectors)
	ventry	el1_sync_invalid		// Synchronous EL1t
	ventry	el1_irq_invalid			// IRQ EL1t
	ventry	el1_fiq_invalid			// FIQ EL1t
	ventry	el1_error_invalid		// Error EL1t

	ventry	el1_sync			// Synchronous EL1h
	ventry	el1_irq				// IRQ EL1h
	ventry	el1_fiq_invalid			// FIQ EL1h
	ventry	el1_error_invalid		// Error EL1h

	ventry	el0_sync			// Synchronous 64-bit EL0
	ventry	el0_irq				// IRQ 64-bit EL0
	ventry	el0_fiq_invalid			// FIQ 64-bit EL0
	ventry	el0_error_invalid		// Error 64-bit EL0

	ventry	el0_sync_invalid		// Synchronous 32-bit EL0
	ventry	el0_irq_invalid			// IRQ 32-bit EL0
	ventry	el0_fiq_invalid			// FIQ 32-bit EL0
	ventry	el0_error_invalid		// Error 32-bit EL0
END(vectors)

/*
 * Invalid mode handlers
 */
	.macro	inv_entry, el, reason, regsize = 64
	kernel_entry el, \regsize
	mov	x0, sp
	mov	x1, #\reason
	mrs	x2, esr_el1
	enable_nmi
	.if	\el == 0
	bl	bad_mode
	b	ret_to_user
	.else
	b	bad_mode
	.endif
	.endm

el0_sync_invalid:
	inv_entry 0, BAD_SYNC
ENDPROC(el0_sync_invalid)

el0_irq_invalid:
	inv_entry 0, BAD_IRQ
ENDPROC(el0_irq_invalid)

el0_fiq_invalid:
	inv_entry 0, BAD_FIQ
ENDPROC(el0_fiq_invalid)

el0_error_invalid:
	inv_entry 0, BAD_ERROR
ENDPROC(el0_error_invalid)

el1_sync_invalid:
	inv_entry 1, BAD_SYNC
ENDPROC(el1_sync_invalid)

el1_irq_invalid:
	inv_entry 1, BAD_IRQ
ENDPROC(el1_irq_invalid)

el1_fiq_invalid:
	inv_entry 1, BAD_FIQ
ENDPROC(el1_fiq_invalid)

el1_error_invalid:
	inv_entry 1, BAD_ERROR
ENDPROC(el1_error_invalid)

/*
 * EL1 mode handlers.
 */
	.align	6
el1_sync:
	kernel_entry 1
	mrs	x1, esr_el1			// read the syndrome register
	lsr	x24, x1, #ESR_ELx_EC_SHIFT	// exception class
	cmp	x24, #ESR_ELx_EC_DABT_CUR	// data abort in EL1
	b.eq	el1_da
//	cmp	x24, #ESR_ELx_EC_IABT_CUR	// instruction abort in EL1
//	b.eq	el1_ia
	cmp	x24, #ESR_ELx_EC_SYS64		// configurable trap
	b.eq	el1_undef
	cmp	x24, #ESR_ELx_EC_SP_ALIGN	// stack alignment exception
	b.eq	el1_sp_pc
	cmp	x24, #ESR_ELx_EC_PC_ALIGN	// pc alignment exception
	b.eq	el1_sp_pc
	cmp	x24, #ESR_ELx_EC_UNKNOWN	// unknown exception in EL1
	b.eq	el1_undef
	// cmp	x24, #ESR_ELx_EC_BREAKPT_CUR	// debug exception in EL1
	// b.ge	el1_dbg
	b	el1_inv
el1_ia:
	/*
	 * Fall through to the Data abort case
	 */
el1_da:
	/*
	 * Data abort handling
	 */
	mrs	x0, far_el1
	enable_nmi
	enable_dbg
#if defined(CONFIG_HAS_NMI)
# define PSR_INTR_SHIFT PSR_G_SHIFT  // PSR_G_BIT
#else /* defined(CONFIG_HAS_NMI) */
# define PSR_INTR_SHIFT 7            // PSR_I_BIT
#endif /* defined(CONFIG_HAS_NMI) */
	// re-enable interrupts if they were enabled in the aborted context
	tbnz	x23, #PSR_INTR_SHIFT, 1f
	enable_irq	x2
1:
	mov	x2, sp				// struct pt_regs
	bl	do_mem_abort

	// disable interrupts before pulling preserved data off the stack
	kernel_exit 1

el1_sp_pc:
	/*
	 * Stack or PC alignment exception handling
	 */
	mrs	x0, far_el1
	enable_nmi
	enable_dbg
	mov	x2, sp
	b	do_sp_pc_abort
el1_undef:
	/*
	 * Undefined instruction
	 */
	enable_nmi
	enable_dbg
	mov	x0, sp
	b	do_undefinstr
// el1_dbg:
// 	/*
// 	 * Debug exception handling
// 	 */
// 	cmp	x24, #ESR_ELx_EC_BRK64		// if BRK64
// 	cinc	x24, x24, eq			// set bit '0'
// 	tbz	x24, #0, el1_inv		// EL1 only
// 	mrs	x0, far_el1
// 	mov	x2, sp				// struct pt_regs
// 	bl	do_debug_exception
// 	kernel_exit 1
el1_inv:
	// TODO: add support for undefined instructions in kernel mode
	mov	x0, sp
	mov	x1, #BAD_SYNC
	mrs	x2, esr_el1
	enable_nmi
	enable_dbg
	b	bad_mode
ENDPROC(el1_sync)

/*
 * EL1 mode handlers.
 */
	.align	6
el1_irq:
	kernel_entry 1
	enable_dbg

	irq_handler

	kernel_exit 1
ENDPROC(el1_irq)

/*
 * EL0 mode handlers.
 */
	.align	6
el0_sync:
	kernel_entry 0
	mrs	x25, esr_el1			// read the syndrome register
	lsr	x24, x25, #ESR_ELx_EC_SHIFT	// exception class
	cmp	x24, #ESR_ELx_EC_SVC64		// SVC in 64-bit state
	b.eq	el0_svc
	cmp	x24, #ESR_ELx_EC_DABT_LOW	// data abort in EL0
	b.eq	el0_da
	cmp	x24, #ESR_ELx_EC_IABT_LOW	// instruction abort in EL0
	b.eq	el0_ia
	cmp	x24, #ESR_ELx_EC_FP_ASIMD	// FP/ASIMD access
	b.eq	el0_fpsimd_acc
#ifdef CONFIG_ARM64_SVE
	cmp	x24, #ESR_ELx_EC_SVE		// SVE access
	b.eq	el0_sve_acc
#endif
	cmp	x24, #ESR_ELx_EC_FP_EXC64	// FP/ASIMD exception
	b.eq	el0_fpsimd_exc
	cmp	x24, #ESR_ELx_EC_SYS64		// configurable trap
	b.eq	el0_undef
	cmp	x24, #ESR_ELx_EC_SP_ALIGN	// stack alignment exception
	b.eq	el0_sp_pc
	cmp	x24, #ESR_ELx_EC_PC_ALIGN	// pc alignment exception
	b.eq	el0_sp_pc
	cmp	x24, #ESR_ELx_EC_UNKNOWN	// unknown exception in EL0
	b.eq	el0_undef
	cmp	x24, #ESR_ELx_EC_BREAKPT_LOW	// debug exception in EL0
	b.ge	el0_dbg
	b	el0_inv
el0_svc:
	uxtw	scno, w8			// syscall number in w8
	cmp	scno, #__NR_rt_sigreturn
	b.eq	1f
	str	x0, [sp, #S_ORIG_X0]		// save the original x0
	ldr	x16, [sp, #S_PC]
	str	x16, [sp, #S_ORIG_PC]		// save the original pc
1:	str	scno, [sp, #S_SYSCALLNO]	// save syscall number
	enable_nmi
	enable_dbg_and_irq x0
	adrp	x16, __arm64_syscall_handler
	ldr	x16, [x16, #:lo12:__arm64_syscall_handler]
	mov	x0, scno
	mov	x1, sp
	blr	x16				// __arm64_syscall_handler(int, syscall_num, ihk_mc_user_context_t *uctx);
	/* Signal check has been completed at the stage of came back. */
	b	ret_fast_syscall
el0_da:
	/*
	 * Data abort handling
	 */
	mrs	x26, far_el1
	// enable interrupts before calling the main handler
	enable_nmi
	enable_dbg_and_irq x0
	// ct_user_exit
	bic	x0, x26, #(0xff << 56)
	mov	x1, x25
	mov	x2, sp
	bl	do_mem_abort
	b	ret_to_user
el0_ia:
	/*
	 * Instruction abort handling
	 */
	mrs	x26, far_el1
	// enable interrupts before calling the main handler
	enable_nmi
	enable_dbg_and_irq x0
	// ct_user_exit
	mov	x0, x26
	mov	x1, x25
	mov	x2, sp
	bl	do_mem_abort
	b	ret_to_user
el0_fpsimd_acc:
	/*
	 * Floating Point or Advanced SIMD access
	 */
	enable_nmi
	enable_dbg
	// ct_user_exit
	mov	x0, x25
	mov	x1, sp
	bl	do_fpsimd_acc
	b	ret_to_user
#ifdef CONFIG_ARM64_SVE
	/*
	 * Scalable Vector Extension access
	 */
el0_sve_acc:
	enable_nmi
	enable_dbg
	// ct_user_exit
	mov	x0, x25
	mov	x1, sp
	bl	do_sve_acc
	b	ret_to_user
#endif
el0_fpsimd_exc:
	/*
	 * Floating Point, Advanced SIMD or SVE exception
	 */
	enable_nmi
	enable_dbg
	// ct_user_exit
	mov	x0, x25
	mov	x1, sp
	bl	do_fpsimd_exc
	b	ret_to_user
el0_sp_pc:
	/*
	 * Stack or PC alignment exception handling
	 */
	mrs	x26, far_el1
	// enable interrupts before calling the main handler
	enable_nmi
	enable_dbg_and_irq x0
	mov	x0, x26
	mov	x1, x25
	mov	x2, sp
	bl	do_sp_pc_abort
	b	ret_to_user
el0_undef:
	/*
	 * Undefined instruction
	 */
	// enable interrupts before calling the main handler
	enable_nmi
	enable_dbg_and_irq x0
	// ct_user_exit
	mov	x0, sp
	bl	do_undefinstr
	b	ret_to_user
el0_dbg:
 	/*
 	 * Debug exception handling
 	 */
 	tbnz	x24, #0, el0_inv		// EL0 only
 	mrs	x0, far_el1
 	mov	x1, x25
 	mov	x2, sp
	enable_nmi
 	bl	do_debug_exception
 	enable_dbg
 	// ct_user_exit
 	b	ret_to_user
el0_inv:
	enable_dbg
	mov	x0, sp
	mov	x1, #BAD_SYNC
	mrs	x2, esr_el1
	enable_nmi
	bl	bad_mode
	b	ret_to_user
ENDPROC(el0_sync)
	.align	6
el0_irq:
	kernel_entry 0
	enable_dbg
	irq_handler
	b	ret_to_user
ENDPROC(el0_irq)

/*
 * Register switch for AArch64. The callee-saved registers need to be saved
 * and restored. On entry:
 *   x0 = previous task_struct (must be preserved across the switch)
 *   x1 = next task_struct
 * Previous and next are guaranteed not to be the same.
 *
 */
ENTRY(cpu_switch_to)
	cmp	x0, xzr				// for idle process branch(skip save)
	b.eq	1f
	add	x8, x0, #TI_CPU_CONTEXT
	mov	x9, sp
	stp	x19, x20, [x8], #16		// store callee-saved registers
	stp	x21, x22, [x8], #16
	stp	x23, x24, [x8], #16
	stp	x25, x26, [x8], #16
	stp	x27, x28, [x8], #16
	stp	x29, x9, [x8], #16
	str	lr, [x8]
1:	add	x8, x1, #TI_CPU_CONTEXT
	ldp	x19, x20, [x8], #16		// restore callee-saved registers
	ldp	x21, x22, [x8], #16
	ldp	x23, x24, [x8], #16
	ldp	x25, x26, [x8], #16
	ldp	x27, x28, [x8], #16
	ldp	x29, x9, [x8], #16
	ldr	lr, [x8]
	mov	sp, x9
	mov	x0, x2				// return void *prev
	ret
ENDPROC(cpu_switch_to)


ret_fast_syscall:
	kernel_exit 0, 1
ENDPROC(ret_fast_syscall)

/*
 * "slow" syscall return path.
 */
ret_to_user:
no_work_pending:
	kernel_exit 0, 1
ENDPROC(ret_to_user)

/*
 * This is how we return from a fork.
 */
ENTRY(ret_from_fork)
//	bl	schedule_tail
	cbz	x19, 1f				// not a kernel thread
	mov	x0, x20
	blr	x19
1:	get_thread_info tsk
	bl	release_runq_lock
	bl	load_executable
	bl	utilthr_migrate
	b	ret_to_user
ENDPROC(ret_from_fork)

