/**
 * \file executer/kernel/driver.c
 *  License details are found in the file LICENSE.
 * \brief
 *  kernel module entry
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 * \author Balazs Gerofi  <bgerofi@riken.jp> \par
 *      Copyright (C) 2012  RIKEN AICS
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 *      Copyright (C) 2012 - 2013 Hitachi, Ltd.
 * \author Tomoki Shirasawa  <tomoki.shirasawa.kk@hitachi-solutions.com> \par
 *      Copyright (C) 2012 - 2013 Hitachi, Ltd.
 * \author Balazs Gerofi  <bgerofi@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2013  The University of Tokyo
 */
/*
 * HISTORY:
 *  2013/09/02 shirasawa add terminate thread
 *  2013/08/19 shirasawa mcexec forward signal to MIC process
 */

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/device.h>
#include "mcctrl.h"

#define OS_MAX_MINOR 64

extern long __mcctrl_control(ihk_os_t, unsigned int, unsigned long,
                             struct file *);
extern int prepare_ikc_channels(ihk_os_t os);
extern void destroy_ikc_channels(ihk_os_t os);
#ifndef DO_USER_MODE
extern void mcctrl_syscall_init(void);
#endif
extern void procfs_init(int);
extern void procfs_exit(int);

extern void rus_page_hash_init(void);
extern void rus_page_hash_put_pages(void);
extern void binfmt_mcexec_init(void);
extern void binfmt_mcexec_exit(void);

static long mcctrl_ioctl(ihk_os_t os, unsigned int request, void *priv,
                         unsigned long arg, struct file *file)
{
	return __mcctrl_control(os, request, arg, file);
}

static struct ihk_os_user_call_handler mcctrl_uchs[] = {
	{ .request = MCEXEC_UP_PREPARE_IMAGE, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_TRANSFER, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_START_IMAGE, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_WAIT_SYSCALL, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_RET_SYSCALL, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_LOAD_SYSCALL, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_SEND_SIGNAL, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_GET_CPU, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_STRNCPY_FROM_USER, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_NEW_PROCESS, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_PREPARE_DMA, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_FREE_DMA, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_OPEN_EXEC, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_CLOSE_EXEC, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_GET_CRED, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_GET_CREDV, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_SYS_MOUNT, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_SYS_UNSHARE, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_DEBUG_LOG, .func = mcctrl_ioctl },
};

static struct ihk_os_user_call mcctrl_uc_proto = {
	.num_handlers = sizeof(mcctrl_uchs) / sizeof(mcctrl_uchs[0]),
	.handlers = mcctrl_uchs,
};

static struct ihk_os_user_call mcctrl_uc[OS_MAX_MINOR];

static ihk_os_t os[OS_MAX_MINOR];

static int __init mcctrl_init(void)
{
	int	i;
	int	rc;

	rc = -ENOENT;
	for(i = 0; i < OS_MAX_MINOR; i++){
		os[i] = ihk_host_find_os(i, NULL);
		if (os[i]) {
			printk("OS #%d found.\n", i);
			rc = 0;
		}
	}
	if(rc){
		printk("OS not found.\n");
		return rc;
	}

	for(i = 0; i < OS_MAX_MINOR; i++){
		if (os[i]) {
			if (prepare_ikc_channels(os[i]) != 0) {
				printk("Preparing syscall channels failed.\n");
				os[i] = NULL;
			}
		}
	}

#ifndef DO_USER_MODE
	mcctrl_syscall_init();
#endif

	rus_page_hash_init();

	for(i = 0; i < OS_MAX_MINOR; i++){
		if (os[i]) {
			memcpy(mcctrl_uc + i, &mcctrl_uc_proto, sizeof mcctrl_uc_proto);
			rc = ihk_os_register_user_call_handlers(os[i], mcctrl_uc + i);
			if(rc < 0){
				destroy_ikc_channels(os[i]);
				os[i] = NULL;
			}
			procfs_init(i);
		}
	}

	binfmt_mcexec_init();

	return 0;
}

static void __exit mcctrl_exit(void)
{
	int	i;

	binfmt_mcexec_exit();
	printk("mcctrl: unregistered.\n");
	for(i = 0; i < OS_MAX_MINOR; i++){
		if(os[i]){
			sysfsm_cleanup(os[i]);
			ihk_os_unregister_user_call_handlers(os[i], mcctrl_uc + i);
			destroy_ikc_channels(os[i]);
			procfs_exit(i);
		}
	}

	rus_page_hash_put_pages();
}

MODULE_LICENSE("GPL v2");
module_init(mcctrl_init);
module_exit(mcctrl_exit);
