/**
 * \file head.S
 *  License details are found in the file LICENSE.
 * \brief
 *  Entry point calling to elfboot_main.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */
.text
.globl _start
_start:	
		leaq _stack_end(%rip), %rsp
		/* preserve arguments */
		pushq %rdi
		pushq %rsi
		pushq %rdx
		pushq %rcx
		leaq _stack_end(%rip), %rdi
		call elfboot_main
		andq %rax, %rax
		jz   1f
		popq %rcx
		popq %rdx
		popq %rsi
		popq %rdi
		jmpq *%rax				
1:		
		cli
		hlt
		jmp 1b
		