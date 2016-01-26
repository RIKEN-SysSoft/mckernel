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

	return;
} /* setup_files() */

/**** End of File ****/
