#include <types.h>
#include <kmsg.h>
#include <kmalloc.h>
#include <aal/cpu.h>
#include <aal/mm.h>
#include <aal/debug.h>
#include <cls.h>

extern struct aal_kmsg_buf kmsg_buf;

extern void arch_init(void);
extern void kmsg_init(void);
extern void mem_init(void);
extern void ikc_master_init(void);
extern void ap_init(void);
extern void arch_ready(void);
extern void mc_ikc_init(void);
extern void cpu_local_var_init(void);
extern void kmalloc_init(void);
extern void ap_start(void);

static aal_mc_kernel_context_t idle_ctx;

static void idle(void)
{
	while (1) {
		cpu_enable_interrupt();
		cpu_halt();
	}
}

extern int syscall(int, aal_mc_user_context_t *);

static void handler_init(void)
{
	aal_mc_set_syscall_handler(syscall);
}

static void rest_init(void)
{
	handler_init();

	ap_init();
	cpu_local_var_init();
	kmalloc_init();
	mc_ikc_init();

	ap_start();
}

int main(void)
{
	kmsg_init();

	kputs("MCK started.\n");

	arch_init();

	mem_init();

	ikc_master_init();

	rest_init();

	arch_ready();

	kputs("MCK/AAL booted.\n");

	aal_mc_init_context(&idle_ctx, NULL, idle);
	aal_mc_switch_context(NULL, &idle_ctx);

	return 0;
}
