/* trampoline.S COPYRIGHT FUJITSU LIMITED 2015 */
.section .rodata, "a", @progbits

.globl trampoline_code_data
base = .
trampoline_code_data:

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

.balign  8
protect_start:
	
.balign 8 
start_64:

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
	.word   0
	
stack:
	.org    0x1000
stack_end:
.globl trampoline_code_data_end
trampoline_code_data_end:

