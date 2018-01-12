/*
 * This file is created by mixing the following two codes.
 *
 * URL: https://www.apriorit.com/dev-blog/195-simple-driver-for-linux-os
 * Author: Danil Ishkov, Apriorit
 *
 * URL: http://www.linuxdevcenter.com/pub/a/linux/2007/07/05/devhelloworld-a-simple-introduction-to-device-drivers-under-linux.html
 * Author: Valerie Henson <val@nmt.edu>
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <asm/errno.h>
#include <linux/init.h>

static int hello_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int hello_release(struct inode *inode, struct file *file)
{
	return 0;
}

static long hello_ioctl(struct file *file, unsigned int request, unsigned long arg)
{
	return 0;
}

static struct file_operations fops = {
	.open = hello_open,
	.release = hello_release,
	.unlocked_ioctl = hello_ioctl,
};

static int device_file_major_number = 0;
static const char device_name[] = "hello";
static int register_device(void)
{
	int result = 0;
	result = register_chrdev( 0, device_name, &fops );
	if( result < 0 ) {
            printk( KERN_WARNING "hello: register_chrdev failed,result=%i", result );
            return result;
	}
	device_file_major_number = result;
	printk( KERN_NOTICE "hello: major number=%i,try \"grep hello /proc/devices\"", device_file_major_number );
	return 0;
}

void unregister_device(void)
{
    printk( KERN_NOTICE "hello: unregister_device() is called" );
    if(device_file_major_number != 0) {
		unregister_chrdev(device_file_major_number, device_name);
	}
}

static int __init hello_init(void)
{
	register_device();
	return 0;
}

module_init(hello_init);

static void __exit hello_exit(void)
{
	unregister_device();
}

module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(" Danil Ishkov, Apriorit and Valerie Henson");
MODULE_DESCRIPTION("Module that does nothing");
MODULE_VERSION("1.0");
