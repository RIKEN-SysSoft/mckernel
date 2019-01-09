/* timer.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <ihk/types.h>
#include <ihk/cpu.h>
#include <ihk/lock.h>
#include <sysreg.h>
#include <kmalloc.h>
#include <cls.h>
#include <cputype.h>
#include <irq.h>
#include <arch-timer.h>
#include <debug.h>

//#define DEBUG_PRINT_TIMER

#ifdef DEBUG_PRINT_TIMER
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

static unsigned int per_cpu_timer_val[NR_CPUS] = { 0 };
static int timer_intrid = INTRID_VIRT_TIMER;

static void arch_timer_virt_reg_write(enum arch_timer_reg reg, uint32_t val);
static void (*arch_timer_reg_write)(enum arch_timer_reg, uint32_t) =
	arch_timer_virt_reg_write;

static uint32_t arch_timer_virt_reg_read(enum arch_timer_reg reg);
static uint32_t (*arch_timer_reg_read)(enum arch_timer_reg) =
	arch_timer_virt_reg_read;

static void arch_timer_phys_reg_write(enum arch_timer_reg reg, uint32_t val)
{
	switch (reg) {
	case ARCH_TIMER_REG_CTRL:
		write_sysreg(val, cntp_ctl_el0);
		break;
	case ARCH_TIMER_REG_TVAL:
		write_sysreg(val, cntp_tval_el0);
		break;
	}
	isb();
}

static void arch_timer_virt_reg_write(enum arch_timer_reg reg, uint32_t val)
{
	switch (reg) {
	case ARCH_TIMER_REG_CTRL:
		write_sysreg(val, cntv_ctl_el0);
		break;
	case ARCH_TIMER_REG_TVAL:
		write_sysreg(val, cntv_tval_el0);
		break;
	}
	isb();
}

static uint32_t arch_timer_phys_reg_read(enum arch_timer_reg reg)
{
	uint32_t val = 0;

	switch (reg) {
	case ARCH_TIMER_REG_CTRL:
		val = read_sysreg(cntp_ctl_el0);
		break;
	case ARCH_TIMER_REG_TVAL:
		val = read_sysreg(cntp_tval_el0);
		break;
	}
	return val;
}

static uint32_t arch_timer_virt_reg_read(enum arch_timer_reg reg)
{
	uint32_t val = 0;

	switch (reg) {
	case ARCH_TIMER_REG_CTRL:
		val = read_sysreg(cntv_ctl_el0);
		break;
	case ARCH_TIMER_REG_TVAL:
		val = read_sysreg(cntv_tval_el0);
		break;
	}
	return val;
}

static void timer_handler(void *priv)
{
	unsigned long ctrl;
	const int cpu = ihk_mc_get_processor_id();

	dkprintf("CPU%d: catch %s timer\n", cpu,
		 ((timer_intrid == INTRID_PHYS_TIMER) ||
		  (timer_intrid == INTRID_HYP_PHYS_TIMER)) ?
		 "physical" : "virtual");

	ctrl = arch_timer_reg_read(ARCH_TIMER_REG_CTRL);
	if (ctrl & ARCH_TIMER_CTRL_IT_STAT) {
		const unsigned int clocks = per_cpu_timer_val[cpu];
		struct cpu_local_var *v = get_this_cpu_local_var();
		unsigned long irqstate;

		/* set resched flag */
		irqstate = ihk_mc_spinlock_lock(&v->runq_lock);
		v->flags |= CPU_FLAG_NEED_RESCHED;
		ihk_mc_spinlock_unlock(&v->runq_lock, irqstate);

		/* gen control register value */
		ctrl &= ~ARCH_TIMER_CTRL_IT_STAT;

		/* set timer re-enable for periodic */
		arch_timer_reg_write(ARCH_TIMER_REG_TVAL, clocks);
		arch_timer_reg_write(ARCH_TIMER_REG_CTRL, ctrl);
	}
}

static unsigned long is_use_virt_timer(void)
{
	extern unsigned long ihk_param_use_virt_timer;

	switch (ihk_param_use_virt_timer) {
	case 0: /* physical */
	case 1: /* virtual */
		break;
	default: /* invalid */
		panic("PANIC: is_use_virt_timer(): timer select neither phys-timer nor virt-timer.\n");
		break;
	}
	return ihk_param_use_virt_timer;
}

static struct ihk_mc_interrupt_handler timer_interrupt_handler = {
	.func = timer_handler,
	.priv = NULL,
};

/* other source use functions */

struct ihk_mc_interrupt_handler *get_timer_handler(void)
{
	return &timer_interrupt_handler;
}

void
lapic_timer_enable(unsigned int clocks)
{
	unsigned long ctrl = 0;

	/* gen control register value */
	ctrl = arch_timer_reg_read(ARCH_TIMER_REG_CTRL);
	ctrl |= ARCH_TIMER_CTRL_ENABLE;
	ctrl &= ~(ARCH_TIMER_CTRL_IT_MASK | ARCH_TIMER_CTRL_IT_STAT);
	arch_timer_reg_write(ARCH_TIMER_REG_TVAL, clocks);
	arch_timer_reg_write(ARCH_TIMER_REG_CTRL, ctrl);

	per_cpu_timer_val[ihk_mc_get_processor_id()] = clocks;
}

void
lapic_timer_disable()
{
	unsigned long ctrl = 0;

	ctrl = arch_timer_reg_read(ARCH_TIMER_REG_CTRL);
	ctrl &= ~ARCH_TIMER_CTRL_ENABLE;
	arch_timer_reg_write(ARCH_TIMER_REG_CTRL, ctrl);

	per_cpu_timer_val[ihk_mc_get_processor_id()] = 0;
}

int get_timer_intrid(void)
{
	return timer_intrid;
}

void arch_timer_init(void)
{
	const unsigned long is_virt = is_use_virt_timer();
#ifdef CONFIG_ARM64_VHE
	const unsigned long mmfr = read_cpuid(ID_AA64MMFR1_EL1);
#endif /* CONFIG_ARM64_VHE */

	if (is_virt) {
		timer_intrid = INTRID_VIRT_TIMER;
		arch_timer_reg_write = arch_timer_virt_reg_write;
		arch_timer_reg_read = arch_timer_virt_reg_read;
	} else {
		timer_intrid = INTRID_PHYS_TIMER;
		arch_timer_reg_write = arch_timer_phys_reg_write;
		arch_timer_reg_read = arch_timer_phys_reg_read;
	}
#ifdef CONFIG_ARM64_VHE
	if ((mmfr >> ID_AA64MMFR1_VHE_SHIFT) & 1UL) {
		if (is_virt) {
			timer_intrid = INTRID_HYP_VIRT_TIMER;
		} else {
			timer_intrid = INTRID_HYP_PHYS_TIMER;
		}
	}
#endif /* CONFIG_ARM64_VHE */
}
