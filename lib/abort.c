#include <ihk/debug.h>
#include <ihk/cpu.h>
#include <cls.h>
#include <ihk/monitor.h>

extern struct cpu_local_var *clv;
void eventfd(int type);
void arch_print_stack(void);
void arch_cpu_stop(void);

void panic(const char *msg)
{
	if (clv) {
		struct ihk_os_cpu_monitor *monitor = cpu_local_var(monitor);
		//kprintf("%s: calling eventfd\n", __FUNCTION__);
		monitor->status = IHK_OS_MONITOR_PANIC;
		eventfd(IHK_OS_EVENTFD_TYPE_STATUS);
	}
	cpu_disable_interrupt();

	kprintf("%s\n", msg);

	arch_print_stack();

#ifndef ENABLE_FUGAKU_HACKS
	/* do not assume anything after this is executed */
	arch_cpu_stop();

	while (1) {
		cpu_halt();
	}
#else
	while (1) {
		cpu_halt_panic();
	}
#endif
}

extern void arch_show_interrupt_context(const void*);

void ihk_mc_debug_show_interrupt_context(const void *reg)
{
	arch_show_interrupt_context(reg);
}

