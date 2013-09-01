/*
 *
 */

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include "mcctrl.h"

#define OS_MAX_MINOR 64

extern long __mcctrl_control(ihk_os_t, unsigned int, unsigned long);
extern int prepare_ikc_channels(ihk_os_t os);
extern void destroy_ikc_channels(ihk_os_t os);
#ifndef DO_USER_MODE
extern void mcctrl_syscall_init(void);
#endif

static long mcctrl_ioctl(ihk_os_t os, unsigned int request, void *priv,
                         unsigned long arg)
{
	return __mcctrl_control(os, request, arg);
}

static struct ihk_os_user_call_handler mcctrl_uchs[] = {
	{ .request = MCEXEC_UP_PREPARE_IMAGE, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_LOAD_IMAGE, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_START_IMAGE, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_WAIT_SYSCALL, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_RET_SYSCALL, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_LOAD_SYSCALL, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_SEND_SIGNAL, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_GET_CPU, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_PREPARE_DMA, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_FREE_DMA, .func = mcctrl_ioctl },
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

	for(i = 0; i < OS_MAX_MINOR; i++){
		if (os[i]) {
			memcpy(mcctrl_uc + i, &mcctrl_uc_proto, sizeof mcctrl_uc_proto);
			rc = ihk_os_register_user_call_handlers(os[i], mcctrl_uc + i);
			if(rc < 0){
				destroy_ikc_channels(os[i]);
				os[i] = NULL;
			}
		}
	}
	return 0;
}

static void __exit mcctrl_exit(void)
{
	int	i;

	printk("mcctrl: unregistered.\n");
	for(i = 0; i < OS_MAX_MINOR; i++){
		if(os[i]){
			ihk_os_unregister_user_call_handlers(os[i], mcctrl_uc + i);
			destroy_ikc_channels(os[i]);
		}
	}
}

MODULE_LICENSE("GPL v2");
module_init(mcctrl_init);
module_exit(mcctrl_exit);
