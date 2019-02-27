/* debug-monitors.c COPYRIGHT FUJITSU LIMITED 2016-2017 */
#include <cputype.h>
#include <irqflags.h>
#include <ihk/context.h>
#include <signal.h>
#include <errno.h>
#include <debug-monitors.h>
#include <cls.h>
#include <thread_info.h>

/* @ref.impl arch/arm64/kernel/debug-monitors.c::debug_monitors_arch */
/* Determine debug architecture. */
unsigned char debug_monitors_arch(void)
{
	return read_cpuid(ID_AA64DFR0_EL1) & 0xf;
}

/* @ref.impl arch/arm64/kernel/debug-monitors.c::mdscr_write */
void mdscr_write(unsigned int mdscr)
{
	unsigned long flags = local_dbg_save();
	asm volatile("msr mdscr_el1, %0" :: "r" (mdscr));
	local_dbg_restore(flags);
}

/* @ref.impl arch/arm64/kernel/debug-monitors.c::mdscr_read */
unsigned int mdscr_read(void)
{
	unsigned int mdscr;
	asm volatile("mrs %0, mdscr_el1" : "=r" (mdscr));
	return mdscr;
}

/* @ref.impl arch/arm64/kernel/debug-monitors.c::clear_os_lock */
static void clear_os_lock(void)
{
	asm volatile("msr oslar_el1, %0" : : "r" (0));
}

/* @ref.impl arch/arm64/kernel/debug-monitors.c::debug_monitors_init */
void debug_monitors_init(void)
{
	clear_os_lock();
}

/* @ref.impl arch/arm64/kernel/debug-monitors.c::set_regs_spsr_ss */
void set_regs_spsr_ss(struct pt_regs *regs)
{
	unsigned long spsr;

	spsr = regs->pstate;
	spsr &= ~DBG_SPSR_SS;
	spsr |= DBG_SPSR_SS;
	regs->pstate = spsr;
}

/* @ref.impl arch/arm64/kernel/debug-monitors.c::set_regs_spsr_ss */
void clear_regs_spsr_ss(struct pt_regs *regs)
{
	unsigned long spsr;

	spsr = regs->pstate;
	spsr &= ~DBG_SPSR_SS;
	regs->pstate = spsr;
}

extern int interrupt_from_user(void *);
extern void clear_single_step(struct thread *thread);

/* @ref.impl arch/arm64/kernel/debug-monitors.c::single_step_handler */
int single_step_handler(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	siginfo_t info;
	int ret = -EFAULT;

	if (interrupt_from_user(regs)) {
		info.si_signo = SIGTRAP;
		info.si_errno = 0;
		info.si_code  = TRAP_HWBKPT;
		info._sifields._sigfault.si_addr = (void *)regs->pc;
		set_signal(SIGTRAP, regs, &info);
		clear_single_step(cpu_local_var(current));

		ret = 0;
	} else {
		kprintf("Unexpected kernel single-step exception at EL1\n");
	}
	return ret;
}

/* @ref.impl arch/arm64/kernel/debug-monitors.c::brk_handler */
int brk_handler(unsigned long addr, unsigned int esr, struct pt_regs *regs)
{
	siginfo_t info;
	int ret = -EFAULT;

	if (interrupt_from_user(regs)) {
		info.si_signo = SIGTRAP;
		info.si_errno = 0;
		info.si_code  = TRAP_BRKPT;
		info._sifields._sigfault.si_addr = (void *)regs->pc;
		set_signal(SIGTRAP, regs, &info);

		ret = 0;
	} else {
		kprintf("Unexpected kernel BRK exception at EL1\n");
	}
	return ret;
}
