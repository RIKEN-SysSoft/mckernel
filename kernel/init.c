#include <types.h>
#include <kmsg.h>
#include <kmalloc.h>
#include <aal/cpu.h>
#include <aal/mm.h>
#include <aal/debug.h>
#include <aal/dma.h>
#include <aal/perfctr.h>
#include <process.h>
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
extern void aal_mc_dma_init(void);
extern void init_host_syscall_channel(void);
extern void sched_init(void);

extern long syscall(int, aal_mc_user_context_t *);

static void handler_init(void)
{
	aal_mc_set_syscall_handler(syscall);
}

unsigned long data[1024] __attribute__((aligned(64)));

static void dma_test(void)
{
	struct aal_dma_request req;
	unsigned long fin = 0;

	memset(&req, 0, sizeof(req));
	req.src_phys = virt_to_phys(data);
	req.dest_phys = virt_to_phys(data + 256);
	req.size = 64;
	req.notify = (void *)virt_to_phys(&fin);
	req.priv = (void *)0x2984;
	
	aal_mc_dma_request(0, &req);

	while (!fin) {
		barrier();
	}
}

static void pc_test(void)
{
	int i;
	int kmode = PERFCTR_USER_MODE;
	int x[2][4] = { { APT_TYPE_L1D_MISS, APT_TYPE_L1I_MISS,
	                  APT_TYPE_L2_MISS, APT_TYPE_INSTRUCTIONS, },
	                { APT_TYPE_STALL,  APT_TYPE_L1I_MISS,
	                  APT_TYPE_L2_MISS, APT_TYPE_INSTRUCTIONS, }};

	for (i = 0; i < 4; i++) {
		aal_mc_perfctr_init(i, x[1][i], kmode);
	}
	aal_mc_perfctr_start(0xf);
/*
	aal_mc_perfctr_read_mask(0x0f, st);
	for (i = 0; i < 100000; i++) {
		data[i & 1023] += i;
		asm volatile("" : : : "memory");
	}
	aal_mc_perfctr_read_mask(0x0f, ed);
	aal_mc_perfctr_stop(1);

	kprintf("INS = %ld, %ld, %ld\n", st[0], ed[0], ed[0] - st[0]);
	kprintf("L2M = %ld, %ld, %ld\n", st[1], ed[1], ed[1] - st[1]);
*/
}

static void rest_init(void)
{
	handler_init();

	aal_mc_dma_init();
	dma_test();
	pc_test();

	ap_init();
	cpu_local_var_init();
	kmalloc_init();

	ikc_master_init();
	mc_ikc_init();

	sched_init();
	ap_start();
}

int host_ikc_inited = 0;

static void post_init(void)
{
	cpu_enable_interrupt();

	while (!host_ikc_inited) {
		barrier();
		cpu_pause();
	}

	init_host_syscall_channel();
}

int main(void)
{
	kmsg_init();

	kputs("MCK started.\n");

	arch_init();

	mem_init();

	rest_init();

	arch_ready();

	post_init();

	kputs("MCK/AAL booted.\n");

	schedule();

	return 0;
}
