/* interrupt.S COPYRIGHT FUJITSU LIMITED 2019 */
/**
 * \file interrupt.S
 *  License details are found in the file LICENSE.
 * \brief
 *  Interrupt handler entries.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 * 
 * 2014/04 - bgerofi: save/restore rbp when entering/leaving kernel (for glibc)
 * 2013/?? - bgerofi + shimosawa: handle rsp correctly for nested interrupts
 */

#define X86_CPU_LOCAL_OFFSET_TSS    176
#define X86_TSS_OFFSET_SP0          4
#define X86_CPU_LOCAL_OFFSET_SP0 \
		(X86_CPU_LOCAL_OFFSET_TSS + X86_TSS_OFFSET_SP0)
#define X86_CPU_LOCAL_OFFSET_KSTACK 16
#define X86_CPU_LOCAL_OFFSET_USTACK 24
#define KERNEL_CS                   32
#define KERNEL_DS                   40
#define USER_CS                     (48 + 3)
#define USER_DS                     (56 + 3)

/* struct x86_user_context */
#define X86_SREGS_BASE  (0)
#define X86_SREGS_SIZE  48

#define X86_FLAGS_BASE  (X86_SREGS_BASE + X86_SREGS_SIZE)
#define X86_FLAGS_SIZE  8

#define X86_REGS_BASE   (X86_FLAGS_BASE + X86_FLAGS_SIZE)
#define RAX_OFFSET      (X86_REGS_BASE + 80)
#define ERROR_OFFSET    (X86_REGS_BASE + 120)
#define RSP_OFFSET      (X86_REGS_BASE + 152)

#define PUSH_ALL_REGS   \
        pushq %rdi;     \
        pushq %rsi;     \
        pushq %rdx;     \
        pushq %rcx;     \
        pushq %rax;     \
        pushq %r8;      \
        pushq %r9;      \
        pushq %r10;     \
        pushq %r11;     \
        pushq %rbx;     \
        pushq %rbp;     \
        pushq %r12;     \
        pushq %r13;     \
        pushq %r14;     \
        pushq %r15;     \
        pushq $1;               /* is_gpr_valid is set, and others are cleared */ \
        subq  $X86_FLAGS_BASE,%rsp      /* for x86_sregs, etc. */

#define POP_ALL_REGS    \
        movq  $0,X86_FLAGS_BASE(%rsp);  /* clear all flags */ \
        addq  $X86_REGS_BASE,%rsp;      /* discard x86_sregs, flags, etc. */ \
        popq  %r15;     \
        popq  %r14;     \
        popq  %r13;     \
        popq  %r12;     \
        popq  %rbp;     \
        popq  %rbx;     \
        popq  %r11;     \
        popq  %r10;     \
        popq  %r9;      \
        popq  %r8;      \
        popq  %rax;     \
        popq  %rcx;     \
        popq  %rdx;     \
        popq  %rsi;     \
        popq  %rdi

.data
.globl generic_common_handlers
generic_common_handlers:
.text
vector=0
.rept 256
1:      
        cld
		pushq   $vector
        jmp     common_interrupt
.previous
        .quad   1b
.text
vector=vector+1
.endr

common_interrupt:
#define MULT_INTR_VECTOR 242
		cmp $(MULT_INTR_VECTOR),%rdi
		je  1f
		PUSH_ALL_REGS
		movq    ERROR_OFFSET(%rsp), %rdi
		movq	%rsp, %rsi
		call 	handle_interrupt /* Enter C code */
		POP_ALL_REGS
		addq	$8, %rsp
		iretq


.globl  nmi_handler
nmi_handler:
		cld
		pushq   $0 /* error field of x86_basic_regs */
		PUSH_ALL_REGS
		movq	%rsp, %rdi
		call 	multi_nm_interrupt_handler /* Enter C code */
		POP_ALL_REGS
		addq	$8, %rsp
		iretq


.globl __page_fault_handler_address
__page_fault_handler_address:
		.quad	0

.globl page_fault
page_fault:
		cld
		PUSH_ALL_REGS
		movq	%cr2, %rdi
		movq	ERROR_OFFSET(%rsp),%rsi
		movq	%rsp,%rdx
		movq	__page_fault_handler_address(%rip), %rax
		andq	%rax, %rax
		jz		1f
		call	*%rax
		POP_ALL_REGS
		addq	$8, %rsp
		iretq
1:		
		jmp		1b

.globl general_protection_exception
general_protection_exception:
		cld
		PUSH_ALL_REGS
		movq	%rsp, %rdi
		call	gpe_handler
		POP_ALL_REGS
		addq	$8, %rsp
		iretq

.global __freeze
__freeze:
		PUSH_ALL_REGS
		callq	freeze
		POP_ALL_REGS
		iretq

.globl x86_syscall
x86_syscall:
		cld
		movq	%rsp, %gs:X86_CPU_LOCAL_OFFSET_USTACK
		movq	%gs:(X86_CPU_LOCAL_OFFSET_SP0), %rsp

		pushq	$(USER_DS)
		pushq	$0
		pushq	%r11
		pushq   $(USER_CS)
		pushq	%rcx
		pushq	%rax		/* error code (= system call number) */
		PUSH_ALL_REGS
		movq	%gs:X86_CPU_LOCAL_OFFSET_USTACK, %rcx
		movq	%rcx, RSP_OFFSET(%rsp)
		movq	RAX_OFFSET(%rsp), %rdi
		movw	%ss, %ax
		movw	%ax, %ds
		movq	%rsp, %rsi
		callq	*__x86_syscall_handler(%rip)
1:		
		movq	%rax, RAX_OFFSET(%rsp)
		POP_ALL_REGS
#ifdef USE_SYSRET
		movq	32(%rsp), %rsp
		sysretq
#else
		addq	$8, %rsp
		iretq
#endif
		
.globl enter_user_mode
enter_user_mode:
		callq	release_runq_lock
		callq   load_executable
		movq	$0,  %rdi
		movq	%rsp, %rsi
		call	check_signal
		call	utilthr_migrate
		movq	$0,  %rdi
		call	set_cputime
		POP_ALL_REGS
		addq	$8, %rsp
		iretq

.globl debug_exception
debug_exception:
		cld
		pushq   $0	/* error */
		PUSH_ALL_REGS
		movq	%rsp, %rdi
		call	debug_handler
		POP_ALL_REGS
		addq	$8, %rsp
		iretq

.globl int3_exception
int3_exception:
		cld
		pushq   $0	/* error */
		PUSH_ALL_REGS
		movq	%rsp, %rdi
		call	int3_handler
		POP_ALL_REGS
		addq	$8, %rsp
		iretq
