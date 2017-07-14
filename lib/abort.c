#include <ihk/debug.h>
#include <ihk/cpu.h>
#include <cls.h>
#include <ihk/rusage.h>

extern struct cpu_local_var *clv;

void panic(const char *msg)
{
	if (clv) {
		struct ihk_os_cpu_monitor *monitor = cpu_local_var(monitor);

		monitor->status = IHK_OS_MONITOR_PANIC;
	}
	cpu_disable_interrupt();

	kprintf(msg);

	while (1) {
		cpu_halt();
	}
}

extern void arch_show_interrupt_context(const void*);

void ihk_mc_debug_show_interrupt_context(const void *reg)
{
	arch_show_interrupt_context(reg);
}

