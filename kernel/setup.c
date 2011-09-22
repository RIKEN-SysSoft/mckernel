#include <kmsg.h>
#include <aal/cpu.h>
#include <aal/debug.h>

extern struct aal_kmsg_buf kmsg_buf;

extern void arch_init(void);
extern void kmsg_init(void);

int main(void)
{
	kmsg_init();

	kputs("MCK started.\n");

	arch_init();

	cpu_disable_interrupt();
	while (1) {
		cpu_halt();
	}
	return 0;
}
