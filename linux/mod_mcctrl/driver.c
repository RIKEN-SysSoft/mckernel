/*
 *
 */

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include "mcctrl.h"

extern long __mcctrl_control(aal_os_t, unsigned int, unsigned long);
extern int prepare_ikc_channels(aal_os_t os);
extern void destroy_ikc_channels(aal_os_t os);

static long mcctrl_ioctl(aal_os_t os, unsigned int request, void *priv,
                         unsigned long arg)
{
	return __mcctrl_control(os, request, arg);
}

static struct aal_os_user_call_handler mcctrl_uchs[] = {
	{ .request = MCEXEC_UP_PREPARE_IMAGE, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_LOAD_IMAGE, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_START_IMAGE, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_WAIT_SYSCALL, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_RET_SYSCALL, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_LOAD_SYSCALL, .func = mcctrl_ioctl },
	{ .request = MCEXEC_UP_PREPARE_DMA, .func = mcctrl_ioctl },
};

static struct aal_os_user_call mcctrl_uc = {
	.num_handlers = sizeof(mcctrl_uchs) / sizeof(mcctrl_uchs[0]),
	.handlers = mcctrl_uchs,
};

static aal_os_t os;

static int __init mcctrl_init(void)
{
	os = aal_host_find_os(0, NULL);
	if (!os) {
		printk("OS #0 not found.\n");
		return -ENOENT;
	}
	if (prepare_ikc_channels(os) != 0) {
		printk("Preparing syscall channels failed.\n");
		return -EINVAL;
	}

	return aal_os_register_user_call_handlers(os, &mcctrl_uc);
}

static void __exit mcctrl_exit(void)
{
	printk("mcctrl: unregistered.\n");
	aal_os_unregister_user_call_handlers(os, &mcctrl_uc);
	destroy_ikc_channels(os);
}

MODULE_LICENSE("GPL v2");
module_init(mcctrl_init);
module_exit(mcctrl_exit);
