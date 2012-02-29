#include <types.h>
#include <kmsg.h>
#include <kmalloc.h>
#include <aal/cpu.h>
#include <aal/mm.h>
#include <aal/debug.h>
#include <aal/dma.h>
#include <aal/perfctr.h>
#include <process.h>
#include <init.h>
#include <cls.h>

extern struct aal_kmsg_buf kmsg_buf;

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
	int i;

	for (i = 0; i < 8; i++) {
		data[i] = 8 - i;
	}

	kprintf("DMA Test Started.\n");
	memset(&req, 0, sizeof(req));
	req.src_os = AAL_THIS_OS;
	req.src_phys = virt_to_phys(data);
	req.dest_os = AAL_THIS_OS;
	req.dest_phys = virt_to_phys(data + 256);
	req.size = 64;
	req.notify = (void *)virt_to_phys(&fin);
	req.notify_os = AAL_THIS_OS;
	req.priv = (void *)0x2984;

	kprintf("VtoP : %p, %lx\n", data, virt_to_phys(data));
	kprintf("notify : %p, %lx (%lx)\n", &fin, virt_to_phys(&fin),
	        sizeof(req));

	if (aal_mc_dma_request(0, &req) != 0) {
		kprintf("Failed to request DMA!\n");
	}
	kprintf("DMA Test Wait.\n");
	while (!fin) {
		barrier();
	}
	kprintf("DMA Test End.\n");
}

extern char *aal_mc_get_kernel_args(void);

char *find_command_line(char *name)
{
	char *cmdline = aal_mc_get_kernel_args();

	if (!cmdline) {
		return NULL;
	}
	return strstr(cmdline, name);
}

void pc_init(void)
{
	int i;
	int kmode = PERFCTR_KERNEL_MODE;
	int imode = 1;
	char *p;

	int x[2][4] = { { APT_TYPE_INSTRUCTIONS,
	                  APT_TYPE_L1D_MISS,
	                  APT_TYPE_L2_MISS, APT_TYPE_L1I_MISS, },
	                { APT_TYPE_L1I_MISS, APT_TYPE_LLC_MISS,
	                  APT_TYPE_STALL, APT_TYPE_CYCLE },
	};

	if (!(p = find_command_line("perfctr"))) {
		kprintf("perfctr not initialized.\n");
		return;
	}
	if (p[7] == '=' && p[8] >= '0' && p[8] <= '5') {
		i = p[8] - '0';
		kmode = (i >> 1) + 1;
		imode = (i & 1);
	} else {
		kprintf("perfctr not initialized.\n");
		return;
	}
	kprintf("perfctr mode : priv = %d, set = %d\n", kmode, imode);

	for (i = 0; i < 4; i++) {
		aal_mc_perfctr_init(i, x[imode][i], kmode);
	}
	aal_mc_perfctr_start(0xf);
}

void pc_ap_init(void)
{
	pc_init();
}

static void pc_test(void)
{
	int i;
	unsigned long st[4], ed[4];

	pc_init();

	aal_mc_perfctr_read_mask(0xf, st);
	for (i = 0; i < sizeof(data) / sizeof(data[0]); i++) {
		data[i] += i;
		asm volatile ("" : : : "memory");
	}
	aal_mc_perfctr_read_mask(0xf, ed);

	kprintf("perfctr:(%ld) %ld, %ld, %ld, %ld\n", st[0], ed[0] - st[0],
	        ed[1] - st[1], ed[2] - st[2], ed[3] - st[3]);
}

static void rest_init(void)
{
	char *cmdline;
	cmdline = aal_mc_get_kernel_args();
	kprintf("KCommand Line: %s\n", cmdline);

	handler_init();

	aal_mc_dma_init();
	dma_test();
	pc_test();

	ap_init();
	cpu_local_var_init();
	kmalloc_init();

	ikc_master_init();

	sched_init();
}

int host_ikc_inited = 0;

static void post_init(void)
{
	cpu_enable_interrupt();

	while (!host_ikc_inited) {
		barrier();
		cpu_pause();
	}

	if (find_command_line("hidos")) {
		init_host_syscall_channel();
	}
	ap_start();
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
