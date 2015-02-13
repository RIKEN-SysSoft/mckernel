/**
 * \file registers.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare macros and functions to manipulate
 *  Machine Specific Registers (MSR)
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef __HEADER_X86_COMMON_REGISTERS_H
#define __HEADER_X86_COMMON_REGISTERS_H

#include <types.h>

#define RFLAGS_CF      (1 << 0)
#define RFLAGS_PF      (1 << 2)
#define RFLAGS_AF      (1 << 4)
#define RFLAGS_ZF      (1 << 6)
#define RFLAGS_SF      (1 << 7)
#define RFLAGS_TF      (1 << 8)
#define RFLAGS_IF      (1 << 9)
#define RFLAGS_DF      (1 << 10)
#define RFLAGS_OF      (1 << 11)
#define RFLAGS_IOPL    (3 << 12)
#define RFLAGS_NT      (1 << 14)
#define RFLAGS_RF      (1 << 16)
#define RFLAGS_VM      (1 << 17)
#define RFLAGS_AC      (1 << 18)
#define RFLAGS_VIF     (1 << 19)
#define RFLAGS_VIP     (1 << 20)
#define RFLAGS_ID      (1 << 21)

#define DB6_B0         (1 << 0)
#define DB6_B1         (1 << 1)
#define DB6_B2         (1 << 2)
#define DB6_B3         (1 << 3)
#define DB6_BD         (1 << 13)
#define DB6_BS         (1 << 14)
#define DB6_BT         (1 << 15)

#define MSR_EFER       0xc0000080
#define MSR_STAR       0xc0000081
#define MSR_LSTAR      0xc0000082
#define MSR_FMASK      0xc0000084
#define MSR_FS_BASE    0xc0000100
#define MSR_GS_BASE    0xc0000101

#define MSR_IA32_APIC_BASE 0x000000001b

#define CVAL(event, mask) \
        ((((event) & 0xf00) << 24) | ((mask) << 8) | ((event) & 0xff))
#define CVAL2(event, mask, inv, count)    \
        ((((event) & 0xf00) << 24) | ((mask) << 8) | ((event) & 0xff) | \
         ((inv & 1) << 23) | ((count & 0xff) << 24))

/* AMD */
#define MSR_PERF_CTL_0 0xc0010000
#define MSR_PERF_CTR_0 0xc0010004

static unsigned long xgetbv(unsigned int index)
{
	unsigned int low, high;

	asm volatile("xgetbv" : "=a" (low), "=d" (high) : "c" (index));

	return low | ((unsigned long)high << 32);
}

static void xsetbv(unsigned int index, unsigned long val)
{
	unsigned int low, high;

	low = val;
	high = val >> 32;

	asm volatile("xsetbv" : : "a" (low), "d" (high), "c" (index));
}

static void wrmsr(unsigned int idx, unsigned long value){
	unsigned int high, low;

	high = value >> 32;
	low = value & 0xffffffffU;

	asm volatile("wrmsr" : : "c" (idx), "a" (low), "d" (high) : "memory");
}

static unsigned long rdpmc(unsigned int counter)
{
	unsigned int high, low;

	asm volatile("rdpmc" : "=a" (low), "=d" (high) : "c" (counter));

	return (unsigned long)high << 32 | low;
}

static unsigned long rdmsr(unsigned int index)
{
	unsigned int high, low;

	asm volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (index));

	return (unsigned long)high << 32 | low;
}

static unsigned long rdtsc(void)
{
	unsigned int high, low;

	asm volatile("rdtsc" : "=a" (low), "=d" (high));

	return (unsigned long)high << 32 | low;
}

static void set_perfctl(int counter, int event, int mask)
{
	unsigned long value;

	value = ((unsigned long)(event & 0x700) << 32)
		| (event & 0xff) | ((mask & 0xff) << 8) | (1 << 18)
		 | (1 << 17);

	wrmsr(MSR_PERF_CTL_0 + counter, value);
}

static void start_perfctr(int counter)
{
	unsigned long value;

	value = rdmsr(MSR_PERF_CTL_0 + counter);
	value |= (1 << 22);
	wrmsr(MSR_PERF_CTL_0 + counter, value);
}
static void stop_perfctr(int counter)
{
	unsigned long value;

	value = rdmsr(MSR_PERF_CTL_0 + counter);
	value &= ~(1 << 22);
	wrmsr(MSR_PERF_CTL_0 + counter, value);
}

static void clear_perfctl(int counter)
{
	wrmsr(MSR_PERF_CTL_0 + counter, 0);
}

static void set_perfctr(int counter, unsigned long value)
{
	wrmsr(MSR_PERF_CTR_0 + counter, value);
}

static unsigned long read_perfctr(int counter)
{
	return rdpmc(counter);
}

#define ihk_mc_mb()   asm volatile("mfence" : : : "memory");

struct x86_desc_ptr {
        uint16_t size;
        uint64_t address;
} __attribute__((packed));

struct tss64 {
        unsigned int reserved0;
        unsigned long rsp0;
        unsigned long rsp1;
        unsigned long rsp2;
        unsigned int reserved1, reserved2;
        unsigned long ist[7];
        unsigned int reserved3, reserved4;
        unsigned short reserved5;
        unsigned short iomap_address;
} __attribute__((packed));

struct x86_regs {
	unsigned long r15, r14, r13, r12, r11, r10, r9, r8;
	unsigned long rdi, rsi, rdx, rcx, rbx, rax, rbp;
	unsigned long error, rip, cs, rflags, rsp, ss;
};

#define	REGS_GET_STACK_POINTER(regs)	(((struct x86_regs *)regs)->rsp)

/*
 * Page fault error code bits:
 *
 *   bit 0 ==	0: no page found	1: protection fault
 *   bit 1 ==	0: read access		1: write access
 *   bit 2 ==	0: kernel-mode access	1: user-mode access
 *   bit 3 ==	1: use of reserved bit detected
 *   bit 4 ==	1: fault was an instruction fetch
 *
 *   internal use:
 *   bit 30 ==	1: don't use COW page to resolve page fault.
 */
enum x86_pf_error_code {
	PF_PROT		=		1 << 0,
	PF_WRITE	=		1 << 1,
	PF_USER		=		1 << 2,
	PF_RSVD		=		1 << 3,
	PF_INSTR	=		1 << 4,

	PF_POPULATE	=		1 << 30,
};

#endif
