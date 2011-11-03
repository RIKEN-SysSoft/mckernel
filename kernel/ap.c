#include <types.h>
#include <kmsg.h>
#include <aal/cpu.h>
#include <aal/mm.h>
#include <aal/debug.h>

void ap_idle(void)
{
	int id = aal_mc_get_hardware_processor_id();

	kprintf(" %d", id);
	while (1) {
		cpu_halt();
	}
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

	kprintf("BSP HW ID = %d\n", bsp_hw_id);
	kprintf("AP Booting :");
	for (i = 0; i < cpu_info->ncpus; i++) {
		if (cpu_info->hw_ids[i] == bsp_hw_id) {
			continue;
		}
		aal_mc_boot_cpu(cpu_info->hw_ids[i], (unsigned long)ap_idle);
	}
	kprintf(" .. Done\n");
}

