/* ap.c COPYRIGHT FUJITSU LIMITED 2015 */
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
#include <process.h>
#include <init.h>
#include <march.h>
#include <cls.h>
#include <time.h>
#include <syscall.h>
#include <rusage_private.h>
#include <ihk/debug.h>

//#define DEBUG_PRINT_AP

#ifdef DEBUG_PRINT_AP
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

int num_processors = 1;
static volatile int ap_stop = 1;

mcs_lock_node_t ap_syscall_semaphore;

static void ap_wait(void)
{
	init_tick();
	while (ap_stop) {
		barrier();
		cpu_pause();
	}
	sync_tick();

	kmalloc_init();
	sched_init();
	arch_start_pvclock();

	if (find_command_line("hidos")) {
		mcs_lock_node_t mcs_node;
		int ikc_cpu = ihk_mc_get_ikc_cpu(ihk_mc_get_processor_id());
		if(ikc_cpu < 0) {
			ekprintf("%s,ihk_mc_get_ikc_cpu failed\n", __FUNCTION__);
		}
		mcs_lock_lock_noirq(&ap_syscall_semaphore, &mcs_node);
		init_host_ikc2mckernel();
		init_host_ikc2linux(ikc_cpu);
		mcs_lock_unlock_noirq(&ap_syscall_semaphore, &mcs_node);
	}
	
	/* one of them listens */
	mc_ikc_test_init();

	schedule();
}

void ap_start(void)
{
	init_tick();
	mcs_lock_init(&ap_syscall_semaphore);
	ap_stop = 0;
	sync_tick();
}

void ap_init(void)
{
	struct ihk_mc_cpu_info *cpu_info;
	int i;
	int bsp_hw_id, bsp_cpu_id;

	ihk_mc_init_ap();
	init_delay();
	
	cpu_info = ihk_mc_get_cpu_info();
	bsp_hw_id = ihk_mc_get_hardware_processor_id();

	/* If no information exists, UP mode */
	if (!cpu_info) {
		return;
	}

	bsp_cpu_id = 0;
	for (i = 0; i < cpu_info->ncpus; ++i) {
		if (cpu_info->hw_ids[i] == bsp_hw_id) {
			bsp_cpu_id = i;
			break;
		}
	}

	kprintf("BSP: %d (HW ID: %d @ NUMA %d)\n", bsp_cpu_id,
			bsp_hw_id, cpu_info->nodes[0]);

	for (i = 0; i < cpu_info->ncpus; i++) {
		if (cpu_info->hw_ids[i] == bsp_hw_id) {
			continue;
		}
		dkprintf("AP Booting: %d (HW ID: %d @ NUMA %d)\n", i,
			cpu_info->hw_ids[i], cpu_info->nodes[i]);
		ihk_mc_boot_cpu(cpu_info->hw_ids[i], (unsigned long)ap_wait);

		num_processors++;
	}
	kprintf("BSP: booted %d AP CPUs\n", cpu_info->ncpus - 1);
}

