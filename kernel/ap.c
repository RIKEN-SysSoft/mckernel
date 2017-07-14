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
#include <cls.h>
#include <time.h>
#include <syscall.h>
#include <rusage.h>

//#define DEBUG_PRINT_AP

#ifdef DEBUG_PRINT_AP
#define dkprintf(...) do { kprintf(__VA_ARGS__); } while (0)
#define ekprintf(...) do { kprintf(__VA_ARGS__); } while (0)
#else
#define dkprintf(...) do { } while (0)
#define ekprintf(...) do { kprintf(__VA_ARGS__); } while (0)
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
	
	pc_ap_init();

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

#include <sysfs.h>
#include <kmalloc.h>
#include <string.h>
#include <vsprintf.h>

static ssize_t
show_int(struct sysfs_ops *ops, void *instance, void *buf, size_t size)
{
	int *p = instance;

	return snprintf(buf, size, "%d\n", *p);
}/* show_int() */

struct sysfs_ops show_int_ops = {
	.show = &show_int,
};

struct fake_cpu_info {
	int online;
};

static struct fake_cpu_info *fake_cpu_infos = NULL;

enum fake_cpu_info_member {
	ONLINE,
};

struct fake_cpu_info_ops {
	enum fake_cpu_info_member member;
	struct sysfs_ops ops;
};

static ssize_t
show_fake_cpu_info(struct sysfs_ops *ops0, void *instance, void *buf,
		size_t size)
{
	struct fake_cpu_info_ops *ops
		= container_of(ops0, struct fake_cpu_info_ops, ops);
	struct fake_cpu_info *info = instance;
	ssize_t n;

	switch (ops->member) {
	case ONLINE:
		n = snprintf(buf, size, "%d\n", info->online);
		break;
	default:
		n = -EINVAL;
		break;
	}

	if (n >= size) {
		n = -ENOSPC;
	}

	return n;
} /* show_fake_cpu_info() */

static ssize_t
store_fake_cpu_info(struct sysfs_ops *ops0, void *instance, void *buf,
		size_t size)
{
	struct fake_cpu_info_ops *ops
		= container_of(ops0, struct fake_cpu_info_ops, ops);
	struct fake_cpu_info *info = instance;
	ssize_t n;

	switch (ops->member) {
	case ONLINE:
		kprintf("NYI:store_fake_cpu_info(%p,%p,%p,%ld): "
				"online %d --> \"%.*s\"\n",
				ops0, instance, buf, size, info->online,
				(int)size, buf);
		n = size;
		break;
	default:
		n = -EIO;
		break;
	}

	return n;
} /* store_fake_cpu_info() */

static struct fake_cpu_info_ops show_fci_online = {
	.member = ONLINE,
	.ops.show = &show_fake_cpu_info,
	.ops.store = &store_fake_cpu_info,
};

void
cpu_sysfs_setup(void)
{
	int error;
	int cpu;
	sysfs_handle_t targeth;
	struct fake_cpu_info *info;

	/* sample of simple variable **********************************/
	error = sysfs_createf(&show_int_ops, &num_processors, 0444,
			"/sys/devices/system/cpu/num_processors");
	if (error) {
		panic("cpu_sysfs_setup:sysfs_createf(num_processors) failed\n");
	}

	/* sample of more complex variable ****************************/
	/* setup table */
	info = kmalloc(sizeof(*info) * num_processors, IHK_MC_AP_CRITICAL);
	for (cpu = 0; cpu < num_processors; ++cpu) {
		info[cpu].online = 1;
	}
	fake_cpu_infos = info;

	/* setup sysfs tree */
	for (cpu = 0; cpu < num_processors; ++cpu) {
		/* online */
		error = sysfs_createf(&show_fci_online.ops,
				&fake_cpu_infos[cpu], 0644,
				"/sys/devices/system/cpu/cpu%d/online", cpu);
		if (error) {
			panic("cpu_sysfs_setup:sysfs_createf failed\n");
		}

		/* link to cpu%d */
		error = sysfs_lookupf(&targeth,
				"/sys/devices/system/cpu/cpu%d", cpu);
		if (error) {
			panic("cpu_sysfs_setup:sysfs_lookupf failed\n");
		}

		error = sysfs_symlinkf(targeth, "/sys/bus/cpu/devices/cpu%d",
				cpu);
		if (error) {
			panic("cpu_sysfs_setup:sysfs_symlinkf failed\n");
		}
	}

	return;
} /* cpu_sysfs_setup() */
