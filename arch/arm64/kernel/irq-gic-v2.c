/* irq-gic-v2.c COPYRIGHT FUJITSU LIMITED 2015-2016 */

#include <ihk/cpu.h>
#include <irq.h>
#include <arm-gic-v2.h>
#include <io.h>
#include <arch/cpu.h>
#include <memory.h>
#include <syscall.h>
#include <debug.h>

// #define DEBUG_GICV2

#ifdef DEBUG_GICV2
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

void *dist_base;
void *cpu_base;

#define gic_hwid_to_affinity(hw_cpuid)	(1UL << hw_cpuid)

/**
 * arm64_raise_sgi_gicv2
 * @ref.impl drivers/irqchip/irq-gic.c:gic_raise_softirq
 *
 * @note Because it performs interrupt control at a higher 
 * function, it is not necessary to perform the disable/enable
 * interrupts in this function as gic_raise_softirq() .
 */
static void arm64_raise_sgi_gicv2(unsigned int cpuid, unsigned int vector)
{
	/* Build interrupt destination of the target cpu */
	unsigned int hw_cpuid = ihk_mc_get_cpu_info()->hw_ids[cpuid];
	uint8_t cpu_target_list = gic_hwid_to_affinity(hw_cpuid);

	/*
	 * Ensure that stores to Normal memory are visible to the
	 * other CPUs before they observe us issuing the IPI.
	 */
	dmb(ishst);

	/* write to GICD_SGIR */
	writel_relaxed(
		cpu_target_list << 16 | vector, 
		(void *)(dist_base + GIC_DIST_SOFTINT)
	);
}

/**
 * arm64_raise_spi_gicv2
 * @ref.impl nothing.
 */
extern unsigned int ihk_ikc_irq_apicid;
static void arm64_raise_spi_gicv2(unsigned int cpuid, unsigned int vector)
{
	uint64_t spi_reg_offset;
	uint32_t spi_set_pending_bitpos;

	if (cpuid != ihk_ikc_irq_apicid) {
		ekprintf("SPI(irq#%d) cannot send other than the host.\n", vector);
		return;
	}

	/**
	 * calculates register offset and bit position corresponding to the numbers.
	 *
	 * For interrupt vector m, 
	 * - the corresponding GICD_ISPENDR number, n, is given by n = m / 32 
	 * - the offset of the required GICD_ISPENDR is (0x200 + (4*n)) 
	 * - the bit number of the required Set-pending bit in this register is m % 32.
	 */
	spi_reg_offset = vector / 32 * 4;
	spi_set_pending_bitpos = vector % 32;

	/* write to GICD_ISPENDR */
	writel_relaxed(
		1 << spi_set_pending_bitpos, 
		(void *)(dist_base + GIC_DIST_PENDING_SET + spi_reg_offset)
	);
}

/**
 * arm64_issue_ipi_gicv2
 * @param cpuid : hardware cpu id
 * @param vector : interrupt vector number
 */
void arm64_issue_ipi_gicv2(unsigned int cpuid, unsigned int vector)
{
	dkprintf("Send irq#%d to cpuid=%d\n", vector, cpuid);

	if(vector < 16){
		// send SGI
		arm64_raise_sgi_gicv2(cpuid, vector);
	} else if (32 <= vector && vector < 1020) {
		// send SPI (allow only to host)
		arm64_raise_spi_gicv2(cpuid, vector);
	} else {
		ekprintf("#%d is bad irq number.", vector);
	}
}

/**
 * handle_interrupt_gicv2
 * @ref.impl drivers/irqchip/irq-gic.c:gic_handle_irq
 */
extern int interrupt_from_user(void *);
void handle_interrupt_gicv2(struct pt_regs *regs)
{
	unsigned int irqstat, irqnr;

	set_cputime(interrupt_from_user(regs)? 1: 2);
	do {
		// get GICC_IAR.InterruptID
		irqstat = readl_relaxed(cpu_base + GIC_CPU_INTACK);
		irqnr = irqstat & GICC_IAR_INT_ID_MASK;

		if (irqnr < 32) {
			writel_relaxed(irqstat, cpu_base + GIC_CPU_EOI);
			handle_IPI(irqnr, regs);
			continue;
		} else if (irqnr != 1023) {
			panic("PANIC: handle_interrupt_gicv2(): catch invalid interrupt.");
		}

		/*
		 * If another interrupt is not pending, GICC_IAR.InterruptID
		 * returns 1023 (see GICv2 spec. Chap. 4.4.4) .
		 */
		break;
	} while (1);
	set_cputime(0);
}

void gic_dist_init_gicv2(unsigned long dist_base_pa, unsigned long size)
{
	dist_base = map_fixed_area(dist_base_pa, size, 1 /*non chachable*/);
}

void gic_cpu_init_gicv2(unsigned long cpu_base_pa, unsigned long size)
{
	cpu_base = map_fixed_area(cpu_base_pa, size, 1 /*non chachable*/);
}

void gic_enable_gicv2(void)
{
	unsigned int enable_ppi_sgi = 0;

	if (is_use_virt_timer()) {
		enable_ppi_sgi |= GICD_ENABLE << get_virt_timer_intrid();
	} else {
		enable_ppi_sgi |= GICD_ENABLE << get_phys_timer_intrid();
	}
	writel_relaxed(enable_ppi_sgi, dist_base + GIC_DIST_ENABLE_SET);
}
