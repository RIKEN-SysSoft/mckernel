/**
 * \file cpulocal.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare information for individual CPUs.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef HEADER_X86_COMMON_CPULOCAL_H
#define HEADER_X86_COMMON_CPULOCAL_H

#include <types.h>
#include <registers.h>

/*
 * CPU Local Page
 * 0 -    : struct x86_cpu_local_varibles
 * - 4096 : kernel stack
 */

#define X86_CPU_LOCAL_OFFSET_TSS    176
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
	uint64_t gdt[16];
/* 176 */
	struct tss64 tss;
/* 280 */
	unsigned long paniced;
	uint64_t panic_regs[21];
/* 456 */
} __attribute__((packed));

struct x86_cpu_local_variables *get_x86_cpu_local_variable(int id);
struct x86_cpu_local_variables *get_x86_this_cpu_local(void);
void *get_x86_cpu_local_kstack(int id);
void *get_x86_this_cpu_kstack(void);

#define LOCALS_SPAN (4 * PAGE_SIZE)
#define KERNEL_STACK_SIZE LOCALS_SPAN

#endif
