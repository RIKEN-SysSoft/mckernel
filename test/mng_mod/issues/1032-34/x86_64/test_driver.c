#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/time.h>

#define DEV_CLASS_NAME "dev_class"
#define DEVICE_NAME "test_rusage"

static int major_num = 0;
static struct class *test_class = NULL;
static struct device *test_dev = NULL;

static int dev_open(struct inode *inode, struct file *file)
{

	return 0;
}

static int dev_release(struct inode *inode, struct file *file)
{
	return 0;
}

static long dev_ioctl(struct file *file, unsigned int request, unsigned long arg)
{
	struct timespec s_time, c_time;

	getnstimeofday(&s_time);

	while (1) {
		getnstimeofday(&c_time);
		if ( c_time.tv_sec >= s_time.tv_sec + request &&
		     c_time.tv_nsec >= s_time.tv_nsec) {
			break;
		}
	}

	return 0;
}

static struct file_operations fops = {
	.open = dev_open,
	.release = dev_release,
	.unlocked_ioctl = dev_ioctl,
};

static int register_device(void)
{
	major_num = register_chrdev(0, DEVICE_NAME, &fops);
	if (major_num < 0) {
		printk(KERN_ALERT "failed\n");
		return major_num;
	}

	test_class = class_create(THIS_MODULE, DEV_CLASS_NAME);

	test_dev = device_create(test_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_NAME);

	return 0;
}

void unregister_device(void)
{
	device_destroy(test_class, MKDEV(major_num, 0));
	class_unregister(test_class);
	class_destroy(test_class);
	unregister_chrdev(major_num, DEVICE_NAME);
}

static int __init dev_init(void)
{
	register_device();
	return 0;
}

module_init(dev_init);

static void __exit dev_exit(void)
{
	unregister_device();
}

module_exit(dev_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Test for getrusage");
MODULE_VERSION("1.0");
