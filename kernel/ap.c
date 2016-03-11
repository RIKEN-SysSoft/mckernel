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

int num_processors = 1;
static volatile int ap_stop = 1;

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
		info[cpu].online = 10+cpu;
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
