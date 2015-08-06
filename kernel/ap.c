/**
 * \file ap.c
 * Licence details are found in the file LICENSE.
 *  
 * \brief
 * Initiallization code for CPU cores other than the boot core. 
 *
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 * 
 * \author Balazs Gerofi  <bgerofi@riken.jp> \par
 * Copyright (C) 2012  RIKEN AICS
 *
 *
 * HISTORY:
 *  2012/10/10: bgerofi - enable syscall channels for all MIC cores
 *
 */
#include <types.h>
#include <kmsg.h>
#include <ihk/cpu.h>
#include <ihk/mm.h>
#include <ihk/debug.h>
#include <process.h>
#include <init.h>
#include <march.h>

int num_processors = 1;
static volatile int ap_stop = 1;

static void ap_wait(void)
{
	wrmsr(MSR_IA32_TIME_STAMP_COUNTER, 0);
	
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

	/* one of them listens */
	mc_ikc_test_init();

	schedule();
}

void ap_start(void)
{
	ap_stop = 0;
}

void ap_init(void)
{
	struct ihk_mc_cpu_info *cpu_info;
	int i;
	int bsp_hw_id;

	ihk_mc_init_ap();
	
	wrmsr(MSR_IA32_TIME_STAMP_COUNTER, 0);

	cpu_info = ihk_mc_get_cpu_info();
	bsp_hw_id = ihk_mc_get_hardware_processor_id();

	/* If no information exists, UP mode */
	if (!cpu_info) {
		return;
	}

	kprintf("BSP HW ID = %d\n", bsp_hw_id);

	for (i = 0; i < cpu_info->ncpus; i++) {
		if (cpu_info->hw_ids[i] == bsp_hw_id) {
			continue;
		}
		kprintf("AP Booting: %d (HW ID: %d)\n", i, cpu_info->hw_ids[i]);
		ihk_mc_boot_cpu(cpu_info->hw_ids[i], (unsigned long)ap_wait);

		num_processors++;
	}
	kprintf("AP Booting: Done\n");
}

