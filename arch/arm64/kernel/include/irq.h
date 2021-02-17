/* irq.h COPYRIGHT FUJITSU LIMITED 2015-2019 */

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
#define INTRID_STACK_TRACE	5
#define INTRID_MULTI_INTR	6
#define INTRID_MULTI_NMI	7
#define LOCAL_SMP_FUNC_CALL_VECTOR   1 /* same as IKC */

/* use PPI interrupt number */
#define INTRID_PERF_OVF		23
#define INTRID_HYP_PHYS_TIMER	26 /* cnthp */
#define INTRID_VIRT_TIMER	27 /* cntv */
#define INTRID_HYP_VIRT_TIMER	28 /* cnthv */
#define INTRID_PHYS_TIMER	30 /* cntp */

/* Functions for GICv2 */
extern void gic_dist_init_gicv2(unsigned long dist_base_pa, unsigned long size);
extern void gic_cpu_init_gicv2(unsigned long cpu_base_pa, unsigned long size);
extern void gic_enable_gicv2(void);
extern void arm64_issue_ipi_gicv2(unsigned int cpuid, unsigned int vector);
extern void arm64_issue_host_ipi_gicv2(uint32_t cpuid, uint32_t vector);
extern void handle_interrupt_gicv2(struct pt_regs *regs);

/* Functions for GICv3 */
extern void gic_dist_init_gicv3(unsigned long dist_base_pa, unsigned long size);
extern void gic_cpu_init_gicv3(unsigned long cpu_base_pa, unsigned long size);
extern void gic_enable_gicv3(void);
extern void arm64_issue_ipi_gicv3(unsigned int cpuid, unsigned int vector);
extern void arm64_issue_host_ipi_gicv3(uint32_t cpuid, uint32_t vector);
extern void handle_interrupt_gicv3(struct pt_regs *regs);

void handle_IPI(unsigned int vector, struct pt_regs *regs);

#endif /* __HEADER_ARM64_IRQ_H */
