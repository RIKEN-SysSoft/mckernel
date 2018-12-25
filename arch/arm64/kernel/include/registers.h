/* registers.h COPYRIGHT FUJITSU LIMITED 2015-2018 */
#ifndef __HEADER_ARM64_COMMON_REGISTERS_H
#define __HEADER_ARM64_COMMON_REGISTERS_H

#include <types.h>
#include <arch/cpu.h>
#include <sysreg.h>

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
#define MSR_PLATFORM_INFO  0x000000ce
#define MSR_IA32_PERF_CTL  0x00000199
#define MSR_IA32_MISC_ENABLE		0x000001a0
#define MSR_IA32_ENERGY_PERF_BIAS	0x000001b0
#define MSR_NHM_TURBO_RATIO_LIMIT	0x000001ad
#define MSR_IA32_CR_PAT			0x00000277


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
	return 0;
}

static void xsetbv(unsigned int index, unsigned long val)
{
}

static unsigned long rdpmc(unsigned int counter)
{
	return 0;
}

static unsigned long rdmsr(unsigned int index)
{
	return 0;
}

/* @ref.impl linux4.10.16 */
/* arch/arm64/include/asm/arch_timer.h:arch_counter_get_cntvct() */
static inline unsigned long rdtsc(void)
{
	isb();
	return read_sysreg(cntvct_el0);
}

static void set_perfctl(int counter, int event, int mask)
{
}

static void start_perfctr(int counter)
{
}
static void stop_perfctr(int counter)
{
}

static void clear_perfctl(int counter)
{
}

static void set_perfctr(int counter, unsigned long value)
{
}

static unsigned long read_perfctr(int counter)
{
	return 0;
}

#define ihk_mc_mb()	do {} while(0);

#define	REGS_GET_STACK_POINTER(regs)	(((struct pt_regs *)regs)->sp)

enum arm64_pf_error_code {
	PF_PROT		=	1 << 0,
	PF_WRITE	=	1 << 1,
	PF_USER		=	1 << 2,
	PF_RSVD		=	1 << 3,
	PF_INSTR	=	1 << 4,

	PF_PATCH	=	1 << 29,
	PF_POPULATE	=	1 << 30,
};

#endif /* !__HEADER_ARM64_COMMON_REGISTERS_H */
