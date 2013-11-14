/**
 * \file trampoline.c
 *  License details are found in the file LICENSE.
 * \brief
 *  (1) Set-up page table address, (2) Transition to 64-bit and paging mode,
 *  (3) Jump to specified address
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#define BOOT_CS       0x10
#define BOOT_DS       0x18
#define BOOT_CS64     0x20

#define MSR_EFER                0xc0000080
#define EFER_LME                (1 << 8)
	
.section .rodata, "a", @progbits
.code16

.globl trampoline_code_data
base = .
trampoline_code_data:
	jmp     cpu_start_body

	.org	8
header_pgtbl:
	.quad	0		/* page table address */
func_address:	
	.quad	0		/* load address */
arg:	
	.quad	0		/* next address */
stack_ptr:
	.quad	0		/* initial stack */
debug:
	.quad	0		/* debug area */
transit_pgtbl:
	.quad	0		/* 32->64 bit table address */
		
cpu_start_body:
	cli
	wbinvd

	movw	%cs, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss

	xorl	%ebx, %ebx
	movw	%cs, %bx
	shll	$4, %ebx

	movw	$0x29, debug - base

	/* Adjust GDT ptr to the 32-bit physical address */
	addl	%ebx, boot_gdtptr + 2 - base
	addl    %ebx, 2f - base
	addl    %ebx, start_64_vec - base
	
	lgdtl	boot_gdtptr - base
	lidtl	boot_idtptr - base

	jmp     1f
1:	
	
	movl	%cr0, %edx
	orb	$1, %dl
	movl	%edx, %cr0

	ljmpl	*(2f - base)
2:	.long	protect_start - base
	.word	BOOT_CS

.balign  8
.code32
protect_start:
	movl    $(BOOT_DS), %eax
	movl	%eax, %ds
	movl    %eax, %ss

	/* Enable PAE */
	movl    %cr4, %eax
	orl     $0x20, %eax
	movl    %eax, %cr4

	leal    (stack_end - base)(%ebx), %esp
	
	/* Load a page table */
	movl    (transit_pgtbl - base)(%ebx), %eax
	movl	%eax, %cr3
	
1:

	/* Enable Long Mode */
	movl    $MSR_EFER, %ecx
	movl 	$EFER_LME, %eax
	xorl	%edx, %edx
	wrmsr

	/* Enable Paging */
	movl	%cr0, %edx
	orl	$0x80000000, %edx
	movl	%edx, %cr0

	ljmp    *(start_64_vec - base)(%ebx)
	
.code64
.balign 8 
start_64:
	/* Okay, we are completely in the long mode ! */
	/* So, use the real page table! */
	movq	(header_pgtbl - base)(%ebx), %rax
	movq	%rax, %cr3

	movq    (func_address - base)(%ebx), %rcx
	cmpq	$0, %rcx
	/* If Loading IP is zero, just enter the infinite loop */
	jz	3f

	movq	(stack_ptr - base)(%ebx), %rax
	cmpq	$0, %rax
	jz	1f
	movq	%rax, %rsp
1:
	/* Now, we prepare the parameters */
	movq	(arg - base)(%ebx), %rdi
	jmp	*%rcx

3:	
	cli
	hlt
	jmp	3b

boot_idtptr:
	.short	0
	.long	0
	
boot_gdtptr:
	.short	boot_gdt32_end - boot_gdt32
	.long	boot_gdt32 - base
	.align	4
boot_gdt32:
	.quad	0
	.quad	0
	.quad	0x00cf9b000000ffff
	.quad	0x00cf93000000ffff
	.quad   0x00af9b000000ffff
	.quad	0x0000890000000067
boot_gdt32_end:

start_64_vec:
	.long   start_64 - base
	.word   BOOT_CS64, 0
	
stack:
	.org    0x1000
stack_end:
.globl trampoline_code_data_end
trampoline_code_data_end:

