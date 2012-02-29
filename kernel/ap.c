#include <types.h>
#include <kmsg.h>
#include <aal/cpu.h>
#include <aal/mm.h>
#include <aal/debug.h>
#include <process.h>
#include <init.h>

int num_processors = 1;
static volatile int ap_stop = 1;

void ap_idle(void)
{
	while (1) {
		cpu_halt();
	}
}

static void ap_wait(void)
{
	while (ap_stop) {
		barrier();
		cpu_pause();
	}
	kmalloc_init();
	sched_init();

	if (find_command_line("hidos")) {
		init_host_syscall_channel();
	}
	pc_ap_init();

	schedule();
}

void ap_start(void)
{
	ap_stop = 0;
}

void ap_init(void)
{
	struct aal_mc_cpu_info *cpu_info;
	int i;
	int bsp_hw_id;

	aal_mc_init_ap();

	cpu_info = aal_mc_get_cpu_info();
	bsp_hw_id = aal_mc_get_hardware_processor_id();

	/* If no information exists, UP mode */
	if (!cpu_info) {
		return;
	}

	kprintf("BSP HW ID = %d, ", bsp_hw_id);
	kprintf("AP Booting :");

	for (i = 0; i < cpu_info->ncpus; i++) {
		if (cpu_info->hw_ids[i] == bsp_hw_id) {
			continue;
		}
		aal_mc_boot_cpu(cpu_info->hw_ids[i], (unsigned long)ap_wait);
		kprintf(" %d", cpu_info->hw_ids[i]);

		num_processors++;
	}
	kprintf(" .. Done\n");
}

