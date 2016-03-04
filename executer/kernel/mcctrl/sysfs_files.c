/**
 * \file sysfs_files.c
 *  License details are found in the file LICENSE.
 * \brief
 *  implement McKernel's sysfs files, IHK-Master side
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2016  RIKEN AICS
 */
/*
 * HISTORY:
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include "mcctrl.h"
#include "sysfs_msg.h"

#define dprintk(...) do { if (0) printk(KERN_DEBUG __VA_ARGS__); } while (0)
#define wprintk(...) do { if (1) printk(KERN_WARNING __VA_ARGS__); } while (0)
#define eprintk(...) do { if (1) printk(KERN_ERR __VA_ARGS__); } while (0)

static ssize_t
show_int(struct sysfsm_ops *ops, void *instance, void *buf, size_t size)
{
	int *p = instance;

	return snprintf(buf, size, "%d\n", *p);
} /* show_int() */

struct sysfsm_ops show_int_ops = {
	.show = &show_int,
};

void setup_local_snooping_samples(ihk_os_t os)
{
	static long lvalue = 0xf123456789abcde0;
	static char *svalue = "string(local)";
	int error;
	struct sysfsm_bitmap_param param;

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_d32, &lvalue, 0444, "/sys/test/local/d32");
	if (error) {
		panic("setup_local_snooping_samples: d32");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_d64, &lvalue, 0444, "/sys/test/local/d64");
	if (error) {
		panic("setup_local_snooping_samples: d64");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_u32, &lvalue, 0444, "/sys/test/local/u32");
	if (error) {
		panic("setup_local_snooping_samples: u32");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_u64, &lvalue, 0444, "/sys/test/local/u64");
	if (error) {
		panic("setup_local_snooping_samples: u64");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_s, svalue, 0444, "/sys/test/local/s");
	if (error) {
		panic("setup_local_snooping_samples: s");
	}

	param.nbits = 40;
	param.ptr = &lvalue;

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_pbl, &param, 0444, "/sys/test/local/pbl");
	if (error) {
		panic("setup_local_snooping_samples: pbl");
	}

	param.nbits = 40;
	param.ptr = &lvalue;

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_pb, &param, 0444, "/sys/test/local/pb");
	if (error) {
		panic("setup_local_snooping_samples: pb");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_u32K, &lvalue, 0444, "/sys/test/local/u32K");
	if (error) {
		panic("setup_local_snooping_samples: u32K");
	}

	return;
}

void setup_local_snooping_files(ihk_os_t os)
{
	struct ihk_cpu_info *info;
	struct mcctrl_usrdata *udp = ihk_host_os_get_usrdata(os);
	struct sysfsm_bitmap_param param;
	static unsigned long cpu_offline = 0x0;
	int i;
	int error;

	info = ihk_os_get_cpu_info(os);
	if (!info) {
		eprintk("mcctrl:ihk_os_get_cpu_info failed.\n");
		return;
	}

	memset(udp->cpu_online, 0, sizeof(udp->cpu_online));
	for (i = 0; i < info->n_cpus; i++) {
		udp->cpu_online[i / BITS_PER_LONG] = 
			udp->cpu_online[i / BITS_PER_LONG] | (1 << (i % BITS_PER_LONG));
	}

	param.nbits = CPU_LONGS * BITS_PER_LONG;
	param.ptr = udp->cpu_online;
	dprintk("mcctrl:setup_local_snooping_files: CPU_LONGS=%d, BITS_PER_LONG=%d\n", 
		CPU_LONGS, BITS_PER_LONG);

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_pbl, &param, 0444,
		"/sys/devices/system/cpu/online");
	if (error) {
		panic("setup_local_snooping_files: devices/system/cpu/online");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_pbl, &param, 0444,
		"/sys/devices/system/cpu/possible");
	if (error) {
		panic("setup_local_snooping_files: devices/system/cpu/possible");
	}

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_pbl, &param, 0444,
		"/sys/devices/system/cpu/present");
	if (error) {
		panic("setup_local_snooping_files: devices/system/cpu/present");
	}

	param.nbits = BITS_PER_LONG;
	param.ptr = &cpu_offline;

	error = sysfsm_createf(os, SYSFS_SNOOPING_OPS_pbl, &param, 0444,
		"/sys/devices/system/cpu/offline");
	if (error) {
		panic("setup_local_snooping_files: devices/system/cpu/offline");
	}

	return;
}

void setup_sysfs_files(ihk_os_t os)
{
	static int a_value = 35;
	int error;
	struct sysfs_handle handle;

	error = sysfsm_mkdirf(os, NULL, "/sys/test/x.dir");
	if (error) {
		panic("sysfsm_mkdir(x.dir)");
	}

	error = sysfsm_createf(os, &show_int_ops, &a_value, 0444,
			"/sys/test/a.dir/a_value");
	if (error) {
		panic("sysfsm_createf");
	}

	error = sysfsm_lookupf(os, &handle, "/sys/test/%s", "a.dir");
	if (error) {
		panic("sysfsm_lookupf(a.dir)");
	}

	error = sysfsm_symlinkf(os, handle, "/sys/test/%c.dir", 'L');
	if (error) {
		panic("sysfsm_symlinkf");
	}

	error = sysfsm_unlinkf(os, 0, "/sys/test/%s.dir", "x");
	if (error) {
		panic("sysfsm_unlinkf");
	}

	setup_local_snooping_samples(os);
	setup_local_snooping_files(os);
	return;
} /* setup_files() */

/**** End of File ****/
