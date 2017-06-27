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
		PUSH_ALL_REGS
		movq    ERROR_OFFSET(%rsp), %rdi
		movq	%rsp, %rsi
		call 	handle_interrupt /* Enter C code */
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

.globl nmi
nmi:
#define PANICED 232
#define PANIC_REGS 240
		movq	%rax,%gs:PANIC_REGS+0x00
		movq	%rsp,%gs:PANIC_REGS+0x08

		movl	nmi_mode(%rip),%eax
		cmp	$1,%rax
		je	1f
		cmp	$2,%rax
		jne	3f
1:
		cld
		movq	%gs:PANIC_REGS+0x00,%rax
		PUSH_ALL_REGS
		subq	$40, %rsp
		movq	%rsp,%gs:PANIC_REGS+0x10
		movq	%rsp, %rdi
		call	freeze_thaw
		cmpq	$0, %rax
		jnz	2f
		addq	$40, %rsp
2:
		POP_ALL_REGS
		iretq
3:
		movq	%rbx,%gs:PANIC_REGS+0x08
		movq	%rcx,%gs:PANIC_REGS+0x10
		movq	%rdx,%gs:PANIC_REGS+0x18
		movq	%rsi,%gs:PANIC_REGS+0x20
		movq	%rdi,%gs:PANIC_REGS+0x28
		movq	%rbp,%gs:PANIC_REGS+0x30
		movq	0x18(%rsp),%rax		/* rsp */
		movq	%rax,%gs:PANIC_REGS+0x38
		movq	%r8, %gs:PANIC_REGS+0x40
		movq	%r9, %gs:PANIC_REGS+0x48
		movq	%r10,%gs:PANIC_REGS+0x50
		movq	%r11,%gs:PANIC_REGS+0x58
		movq	%r12,%gs:PANIC_REGS+0x60
		movq	%r13,%gs:PANIC_REGS+0x68
		movq	%r14,%gs:PANIC_REGS+0x70
		movq	%r15,%gs:PANIC_REGS+0x78
		movq	0x00(%rsp),%rax		/* rip */
		movq	%rax,%gs:PANIC_REGS+0x80
		movq	0x10(%rsp),%rax		/* rflags */
		movl	%eax,%gs:PANIC_REGS+0x88
		movq	0x08(%rsp),%rax		/* cs */
		movl	%eax,%gs:PANIC_REGS+0x8C
		movq	0x20(%rsp),%rax		/* ss */
		movl	%eax,%gs:PANIC_REGS+0x90
		xorq	%rax,%rax
		movw	%ds,%ax
		movl	%eax,%gs:PANIC_REGS+0x94
		movw	%es,%ax
		movl	%eax,%gs:PANIC_REGS+0x98
		movw	%fs,%ax
		movl	%eax,%gs:PANIC_REGS+0x9C
		movw	%gs,%ax
		movl	%eax,%gs:PANIC_REGS+0xA0
		movq	$1,%gs:PANICED
1:
		hlt
		jmp	1b

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
