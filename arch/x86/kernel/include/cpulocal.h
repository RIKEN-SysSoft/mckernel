#ifndef HEADER_X86_COMMON_CPULOCAL_H
#define HEADER_X86_COMMON_CPULOCAL_H

#include <types.h>
#include <registers.h>

/*
 * CPU Local Page
 * 0 -    : struct x86_cpu_local_varibles
 * - 4096 : kernel stack
 */

#define X86_CPU_LOCAL_OFFSET_TSS    128
#define X86_CPU_LOCAL_OFFSET_KSTACK 16
#define X86_CPU_LOCAL_OFFSET_USTACK 24

struct x86_cpu_local_variables {
/* 0 */
	unsigned long processor_id;

	unsigned long apic_id;
/* 16 */
	unsigned long kernel_stack;
	unsigned long user_stack;

/* 32 */
	struct x86_desc_ptr gdt_ptr;
	unsigned short pad[3];
/* 48 */
	uint64_t gdt[10];
/* 128 */
	struct tss64 tss;

} __attribute__((packed));

struct x86_cpu_local_variables *get_x86_cpu_local_variable(int id);


#endif
