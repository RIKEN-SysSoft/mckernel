/* irq.h COPYRIGHT FUJITSU LIMITED 2015-2017 */

#ifndef __HEADER_ARM64_IRQ_H
#define __HEADER_ARM64_IRQ_H

#include <ihk/debug.h>
#include <ihk/context.h>
#include <sysreg.h>
#include <cputype.h>

/* use SGI interrupt number */
#define INTRID_CPU_NOTIFY	0
#define INTRID_IKC		1
#define INTRID_QUERY_FREE_MEM	2
#define INTRID_CPU_STOP		3
#define INTRID_TLB_FLUSH	4
#define INTRID_MEMDUMP		7

/* use PPI interrupt number */
#define INTRID_HYP_PHYS_TIMER	26 /* cnthp */
#define INTRID_VIRT_TIMER	27 /* cntv */
#define INTRID_HYP_VIRT_TIMER	28 /* cnthv */
#define INTRID_PHYS_TIMER	30 /* cntp */

/* timer intrid getter */
static int get_virt_timer_intrid(void)
{
#ifdef CONFIG_ARM64_VHE
	unsigned long mmfr = read_cpuid(ID_AA64MMFR1_EL1);

	if ((mmfr >> ID_AA64MMFR1_VHE_SHIFT) & 1UL) {
		return INTRID_HYP_VIRT_TIMER;
	}
#endif /* CONFIG_ARM64_VHE */
	return INTRID_VIRT_TIMER;
}

static int get_phys_timer_intrid(void)
{
#ifdef CONFIG_ARM64_VHE
	unsigned long mmfr = read_cpuid(ID_AA64MMFR1_EL1);

	if ((mmfr >> ID_AA64MMFR1_VHE_SHIFT) & 1UL) {
		return INTRID_HYP_PHYS_TIMER;
	}
#endif /* CONFIG_ARM64_VHE */
	return INTRID_PHYS_TIMER;
}

/* use timer checker */
extern unsigned long is_use_virt_timer(void);

/* Functions for GICv2 */
extern void gic_dist_init_gicv2(unsigned long dist_base_pa, unsigned long size);
extern void gic_cpu_init_gicv2(unsigned long cpu_base_pa, unsigned long size);
extern void gic_enable_gicv2(void);
extern void arm64_issue_ipi_gicv2(unsigned int cpuid, unsigned int vector);
extern void handle_interrupt_gicv2(struct pt_regs *regs);

/* Functions for GICv3 */
extern void gic_dist_init_gicv3(unsigned long dist_base_pa, unsigned long size);
extern void gic_cpu_init_gicv3(unsigned long cpu_base_pa, unsigned long size);
extern void gic_enable_gicv3(void);
extern void arm64_issue_ipi_gicv3(unsigned int cpuid, unsigned int vector);
extern void handle_interrupt_gicv3(struct pt_regs *regs);

void handle_IPI(unsigned int vector, struct pt_regs *regs);

#endif /* __HEADER_ARM64_IRQ_H */
