#include <kmsg.h>
#include <aal/cpu.h>
#include <aal/debug.h>

extern struct aal_kmsg_buf kmsg_buf;

extern void arch_init(void);
extern void kmsg_init(void);
extern void mem_init(void);

int main(void)
{
	kmsg_init();

	kputs("MCK started.\n");

	arch_init();

	mem_init();

	cpu_enable_interrupt();

	while (1) {
		cpu_halt();
		kprintf("back from halt.\n");
	}
	return 0;
}
