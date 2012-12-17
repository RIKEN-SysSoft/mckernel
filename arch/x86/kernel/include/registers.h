#ifndef __HEADER_X86_COMMON_REGISTERS_H
#define __HEADER_X86_COMMON_REGISTERS_H

#include <types.h>

#define RFLAGS_IF      (1 << 9)

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

#define aal_mc_mb()   asm volatile("mfence" : : : "memory");

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
	unsigned long r11, r10, r9, r8;
	unsigned long rdi, rsi, rdx, rcx, rbx, rax;
	unsigned long error, rip, cs, rflags, rsp, ss;
};

/*
 * Page fault error code bits:
 *
 *   bit 0 ==	0: no page found	1: protection fault
 *   bit 1 ==	0: read access		1: write access
 *   bit 2 ==	0: kernel-mode access	1: user-mode access
 *   bit 3 ==	1: use of reserved bit detected
 *   bit 4 ==	1: fault was an instruction fetch
 */
enum x86_pf_error_code {
	PF_PROT		=		1 << 0,
	PF_WRITE	=		1 << 1,
	PF_USER		=		1 << 2,
	PF_RSVD		=		1 << 3,
	PF_INSTR	=		1 << 4,
};

#endif
