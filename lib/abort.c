#include <ihk/debug.h>
#include <ihk/cpu.h>

void panic(const char *msg)
{
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

