/* cpu.c COPYRIGHT FUJITSU LIMITED 2015-2019 */

#include <cpu.h>

/* we not have "pause" instruction, instead "yield" instruction */
void cpu_pause(void)
{
	asm volatile("yield" ::: "memory");
}

#if defined(CONFIG_HAS_NMI)
#include <arm-gic-v3.h>

/* restore interrupt (ICC_PMR_EL1 <= flags) */
void cpu_restore_interrupt(unsigned long flags)
{
	asm volatile(
		"msr_s  " __stringify(ICC_PMR_EL1) ",%0"
		:
		: "r" (flags)
		: "memory");
}

/* save ICC_PMR_EL1 & disable interrupt (ICC_PMR_EL1 <= ICC_PMR_EL1_MASKED) */
unsigned long cpu_disable_interrupt_save(void)
{
	unsigned long flags;
	unsigned long masked = ICC_PMR_EL1_MASKED;

	asm volatile(
		"mrs_s  %0, " __stringify(ICC_PMR_EL1) "\n"
		"msr_s  " __stringify(ICC_PMR_EL1) ",%1"
		: "=&r" (flags)
		: "r" (masked)
		: "memory");
	return flags;
}

/* save ICC_PMR_EL1 & enable interrupt (ICC_PMR_EL1 <= ICC_PMR_EL1_UNMASKED) */
unsigned long cpu_enable_interrupt_save(void)
{
	unsigned long flags;
	unsigned long masked = ICC_PMR_EL1_UNMASKED;

	asm volatile(
		"mrs_s  %0, " __stringify(ICC_PMR_EL1) "\n"
		"msr_s  " __stringify(ICC_PMR_EL1) ",%1"
		: "=&r" (flags)
		: "r" (masked)
		: "memory");
	return flags;
}

#else /* defined(CONFIG_HAS_NMI) */

/* @ref.impl arch/arm64/include/asm/spinlock.h::arch_local_irq_restore */
/* restore interrupt (PSTATE.DAIF = flags restore) */
void cpu_restore_interrupt(unsigned long flags)
{
	asm volatile(
		"msr    daif, %0	// arch_local_irq_restore"
		:
		: "r" (flags)
		: "memory");
}

/* @ref.impl arch/arm64/include/asm/irqflags.h::arch_local_irq_save */
/* save PSTATE.DAIF & disable interrupt (PSTATE.DAIF I bit set) */
unsigned long cpu_disable_interrupt_save(void)
{
	unsigned long flags;

	asm volatile(
		"mrs    %0, daif	// arch_local_irq_save\n"
		"msr    daifset, #2"
		: "=r" (flags)
		:
		: "memory");
	return flags;
}

/* save PSTATE.DAIF & enable interrupt (PSTATE.DAIF I bit set) */
unsigned long cpu_enable_interrupt_save(void)
{
	unsigned long flags;

	asm volatile(
		"mrs    %0, daif	// arch_local_irq_save\n"
		"msr    daifclr, #2"
		: "=r" (flags)
		:
		: "memory");
	return flags;
}
#endif /* defined(CONFIG_HAS_NMI) */

