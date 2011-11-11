/*
 *
 */

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include "mcctrl.h"

extern long __mcctrl_control(struct mcctrl_priv *, unsigned int, unsigned long);

static int mcctrl_open(struct inode *inode, struct file *file)
{
	struct mcctrl_priv *mcc_data;

	mcc_data = kzalloc(sizeof(struct mcctrl_priv), GFP_KERNEL);
	if (!mcc_data) {
		return -ENOMEM;
	}

	file->private_data = mcc_data;
	return 0;
}

static int mcctrl_release(struct inode *inode, struct file *file)
{
	struct mcctrl_priv *mcc_data = file->private_data;

	if (mcc_data) {
		if (mcc_data->desc) {
			kfree(mcc_data->desc);
		}
		kfree(mcc_data);
	}

	return 0;
}

static long mcctrl_ioctl(struct file *file, unsigned int request,
                         unsigned long arg)
{
	struct mcctrl_priv *mcc_data = file->private_data;

	return __mcctrl_control(mcc_data, request, arg);
}

static struct file_operations mcctrl_ops = {
	.open = mcctrl_open,
	.unlocked_ioctl = mcctrl_ioctl,
	.release = mcctrl_release,
};

static struct miscdevice mcctrl_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "mcctrl",
	.fops = &mcctrl_ops,
};

static int __init mcctrl_init(void)
{
	return misc_register(&mcctrl_dev);
}

static void __exit mcctrl_exit(void)
{
	misc_deregister(&mcctrl_dev);
}

MODULE_LICENSE("GPL v2");
module_init(mcctrl_init);
module_exit(mcctrl_exit);
