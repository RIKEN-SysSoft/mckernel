#define X86_CPU_LOCAL_OFFSET_TSS    128
#define X86_TSS_OFFSET_SP0          4
#define X86_CPU_LOCAL_OFFSET_SP0 \
		(X86_CPU_LOCAL_OFFSET_TSS + X86_TSS_OFFSET_SP0)
#define X86_CPU_LOCAL_OFFSET_KSTACK 16
#define X86_CPU_LOCAL_OFFSET_USTACK 24
#define KERNEL_CS                   32
#define KERNEL_DS                   40
#define USER_CS                     (48 + 3)
#define USER_DS                     (56 + 3)

#define PUSH_ALL_REGS     \
        pushq %rax; \
        pushq %rbx; \
        pushq %rcx; \
        pushq %rdx; \
        pushq %rsi; \
        pushq %rdi; \
        pushq %r8;  \
        pushq %r9; \
        pushq %r10; \
        pushq %r11; 
#define POP_ALL_REGS      \
        popq  %r11; \
        popq  %r10; \
        popq  %r9;  \
        popq  %r8;  \
        popq  %rdi; \
        popq  %rsi; \
        popq  %rdx; \
        popq  %rcx; \
        popq  %rbx; \
        popq  %rax
		
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
		movq    80(%rsp), %rdi
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
		movq	%rsp, %rsi
		movq    %rbp, %rdx
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

.globl x86_syscall
x86_syscall:
		cld
		movq	%rsp, %gs:24
		movq	%gs:(X86_CPU_LOCAL_OFFSET_SP0), %rsp

		pushq	$(USER_DS)
		pushq	$0
		pushq	%r11
		pushq   $(USER_CS)
		pushq	%rcx
		pushq	$0
		movq	%gs:24, %rcx
		movq	%rcx, 32(%rsp)
		PUSH_ALL_REGS
		movq	72(%rsp), %rdi
		movw	%ss, %ax
		movw	%ax, %ds
		movq	%rsp, %rsi
		callq	*__x86_syscall_handler(%rip)
1:		
		movq	%rax, 72(%rsp)
		POP_ALL_REGS
#ifdef USE_SYSRET
		movq	8(%rsp), %rcx
		movq	24(%rsp), %r11
		movq	32(%rsp), %rsp
		sysretq
#else
		addq	$8, %rsp
		iretq
#endif
		
.globl enter_user_mode
enter_user_mode:		
		POP_ALL_REGS
		addq	$8, %rsp
		iretq
