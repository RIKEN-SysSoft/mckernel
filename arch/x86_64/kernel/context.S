/**
 * \file context.S
 *  License details are found in the file LICENSE.
 * \brief
 *  Save registers of old context and load registers of new context.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#define X86_CPU_LOCAL_OFFSET_TSS    176
#define X86_TSS_OFFSET_SP0          4
#define X86_CPU_LOCAL_OFFSET_SP0 \
		(X86_CPU_LOCAL_OFFSET_TSS + X86_TSS_OFFSET_SP0)

.text

.globl ihk_mc_switch_context
ihk_mc_switch_context:
		/*
		 * rdi - ihk_mc_kernel_context_t *old_ctx
		 * rsi - ihk_mc_kernel_context_t *new_ctx
		 * rdx - void *prev
		 */
		pushfq
		popq	%rax
		testq	%rdi, %rdi
		jz		1f				/* skip saving if "old_ctx" is null. */
		movq	%rbp, 8(%rdi)
		movq	%rbx, 16(%rdi)
		movq	%rax, 72(%rdi)	/* rflags */
		movq	%rsi, 24(%rdi)
		movq	%rdi, 32(%rdi)
		movq	%r12, 40(%rdi)
		movq	%r13, 48(%rdi)
		movq	%r14, 56(%rdi)
		movq	%r15, 64(%rdi)
		movq	%rsp, 0(%rdi)
1:
		movq	0(%rsi), %rsp
		movq	80(%rsi), %rbp
		movq	%rbp, %gs:(X86_CPU_LOCAL_OFFSET_SP0)
		movq	64(%rsi), %r15
		movq	56(%rsi), %r14
		movq	48(%rsi), %r13
		movq	40(%rsi), %r12
		movq	32(%rsi), %rdi
		movq	16(%rsi), %rbx
		movq	72(%rsi), %rax
		pushq	%rax
		popfq
		movq	8(%rsi), %rbp
		movq	24(%rsi), %rsi
		movq	%rdx,%rax
		retq
