/**
 * \file procfs.c
 *  License details are found in the file LICENSE.
 * \brief
 *  mcctrl procfs
 * \author Naoki Hamada <nao@axe.bz> \par
 * 	Copyright (C) 2014  AXE, Inc.
 */
/*
 * HISTORY:
 */

#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include "mcctrl.h"

//#define PROCFS_DEBUG

#ifdef PROCFS_DEBUG
#define	dprintk(...)	printk(__VA_ARGS__)
#else
#define	dprintk(...)
#endif

static DECLARE_WAIT_QUEUE_HEAD(procfsq);
static ssize_t mckernel_procfs_read(struct file *file, char __user *buf, 
		size_t nbytes, loff_t *ppos);

/* A private data for the procfs driver. */

struct procfs_list_entry {
	struct list_head list;
	struct proc_dir_entry *entry;
	struct proc_dir_entry *parent;
	ihk_os_t os;
	int osnum;
	int pid;
	int cpu;
	char fname[PROCFS_NAME_MAX];
};

/*
 * In the procfs_file_list, mckenrel procfs files are
 * listed in the manner that the leaf file is located 
 * always nearer to the list top than its parent node 
 * file.
 */

LIST_HEAD(procfs_file_list);
static ihk_spinlock_t procfs_file_list_lock;

/**
 * \brief Return specified procfs entry. 
 *
 * \param p a name of the procfs file
 * \param osnum os number
 * \param mode if zero create a directory otherwise a file
 *
 * return value: NULL: Something wrong has occurred.
 *               otherwise: address of the proc_dir_entry structure of the procfs file
 *
 * p should not be NULL nor terminated by "/".
 *
 * We create a procfs entry if there is not already one.
 * This process is recursive to the root of the procfs tree.
 */
/*
 * XXX: Two or more entries which have same name can be created.
 *
 * get_procfs_entry() avoids creating an entry which has already been created.
 * But, it allows creating an entry which is being created by another thread.
 *
 * This problem occurred when two requests which created files with a common
 * ancestor directory which was not explicitly created were racing.
 */

static struct proc_dir_entry *get_procfs_entry(char *p, int osnum, int mode)
{
	char *r;
	struct proc_dir_entry *ret = NULL, *parent = NULL;
	struct procfs_list_entry *e;
	char name[PROCFS_NAME_MAX];
	unsigned long irqflags;

	dprintk("get_procfs_entry: %s for osnum %d mode %o\n", p, osnum, mode);
	irqflags = ihk_ikc_spinlock_lock(&procfs_file_list_lock);
	list_for_each_entry(e, &procfs_file_list, list) {
		if (e == NULL) {
			kprintf("ERROR: The procfs_file_list has a null entry.\n");
			return NULL;
		}
		if (strncmp(e->fname, p, PROCFS_NAME_MAX) == 0) {
			/* We found the entry */
			ret = e->entry;
		}
	}
	ihk_ikc_spinlock_unlock(&procfs_file_list_lock, irqflags);
	if (ret != NULL) {
		return ret;
	}
	r = strrchr(p, '/');
	if (r != NULL) {
		/* We have non-null parent dir. */
		strncpy(name, p, r - p);
		name[r - p] = '\0'; 
		parent = get_procfs_entry(name, osnum, 0);
		if (parent == NULL) {
			/* We counld not get a parent procfs entry. Give up.*/
			return NULL;
		}
	}
	e = kmalloc(sizeof(struct procfs_list_entry), GFP_KERNEL);
	if (e == NULL) {
		kprintf("ERROR: not enough memory to create PROCFS entry.\n");
		return NULL;
	}
	/* Fill the fname field of the entry */
	strncpy(e->fname, p, PROCFS_NAME_MAX);

	if (r != NULL) {
		strncpy(name, r + 1, p + PROCFS_NAME_MAX - r - 1);
	} else {
		strncpy(name, p, PROCFS_NAME_MAX);
	}
	if (mode == 0) {
		ret = proc_mkdir(name, parent);
	} else {	
		ret = create_proc_entry(name, mode, parent);
	}
	if (ret == NULL) {
		kprintf("ERROR: cannot create a PROCFS entry for %s.\n", p);
		kfree(e);
		return NULL;
	}
	ret->data = e;
	e->osnum = osnum;
	e->entry = ret;
	e->parent = parent;

	irqflags = ihk_ikc_spinlock_lock(&procfs_file_list_lock);
	list_add(&(e->list), &procfs_file_list);
	ihk_ikc_spinlock_unlock(&procfs_file_list_lock, irqflags);

	dprintk("get_procfs_entry: %s done\n", p);
	return ret;
}

loff_t mckernel_procfs_lseek(struct file *file, loff_t offset, int orig)
{
	switch (orig) {
	case 0:
		file->f_pos = offset;
		break;
	case 1:
		file->f_pos += offset;
		break;
	default:
		return -EINVAL;
	}
	return file->f_pos;
}

static const struct file_operations mckernel_procfs_file_operations = {
	.llseek		= mckernel_procfs_lseek,
	.read		= mckernel_procfs_read,
	.write		= NULL,
};

/**
 * \brief Create a procfs entry.
 *
 * \param __os (opeque) os variable
 * \param ref cpuid of the requesting mckernel process
 * \param osnum osnum of the requesting mckernel process
 * \param pid pid of the requesting mckernel process
 * \param arg sent argument
 */

void procfs_create(void *__os, int ref, int osnum, int pid, unsigned long arg)
{
	struct proc_dir_entry *entry;
	struct procfs_list_entry *e;
	ihk_device_t dev = ihk_os_to_dev(__os);
	unsigned long parg;
	struct procfs_file *f;
	int mode;
	char name[PROCFS_NAME_MAX];

	dprintk("procfs_create: osnum: %d, cpu: %d, pid: %d\n", osnum, ref, pid);

	parg = ihk_device_map_memory(dev, arg, sizeof(struct procfs_file));
	f = ihk_device_map_virtual(dev, parg, sizeof(struct procfs_file), NULL, 0);

	dprintk("name: %s mode: %o\n", f->fname, f->mode);

	strncpy(name, f->fname, PROCFS_NAME_MAX);
	mode = f->mode;

	if (name[PROCFS_NAME_MAX - 1] != '\0') {
			printk("ERROR: procfs_creat: file name not properly terminated.\n");
			goto quit;
	}
	entry = get_procfs_entry(name, osnum, mode);
	if (entry == NULL) {
		printk("ERROR: could not create a procfs entry for %s.\n", name);
		goto quit;
	}

	e = entry->data;
	e->os = __os;
	e->cpu = ref;
	e->pid = pid;

	entry->proc_fops = &mckernel_procfs_file_operations;
quit:
	f->status = 1; /* Now the peer can free the data. */
	ihk_device_unmap_virtual(dev, f, sizeof(struct procfs_file));
	ihk_device_unmap_memory(dev, parg, sizeof(struct procfs_file));
	dprintk("procfs_create: done\n");
}

/**
 * \brief Delete a procfs entry.
 *
 * \param __os (opaque) os variable
 * \param osnum os number
 * \param arg sent argument
 */

void procfs_delete(void *__os, int osnum, unsigned long arg)
{
	ihk_device_t dev = ihk_os_to_dev(__os);
	unsigned long parg;
	struct procfs_file *f;
	struct procfs_list_entry *e;
	struct proc_dir_entry *parent = NULL;
	char name[PROCFS_NAME_MAX];
	char *r;
	unsigned long irqflags;

	dprintk("procfs_delete: \n");
	parg = ihk_device_map_memory(dev, arg, sizeof(struct procfs_file));
	f = ihk_device_map_virtual(dev, parg, sizeof(struct procfs_file), NULL, 0);
	dprintk("fname: %s.\n", f->fname);
	irqflags = ihk_ikc_spinlock_lock(&procfs_file_list_lock);
	list_for_each_entry(e, &procfs_file_list, list) {
		if ((strncmp(e->fname, f->fname, PROCFS_NAME_MAX) == 0) &&
		    (e->osnum == osnum)) {
			list_del(&e->list);
			e->entry->read_proc = NULL;
			e->entry->data = NULL;
			parent = e->parent;
			kfree(e);
			r = strrchr(f->fname, '/');
			if (r == NULL) {
				strncpy(name, f->fname, PROCFS_NAME_MAX);
			} else {
				strncpy(name, r + 1, PROCFS_NAME_MAX);
			}
			dprintk("found and remove %s from the list.\n", name);
			remove_proc_entry(name, parent);
			break;
		}
	}
	ihk_ikc_spinlock_unlock(&procfs_file_list_lock, irqflags);
	f->status = 1; /* Now the peer can free the data. */
	ihk_device_unmap_virtual(dev, f, sizeof(struct procfs_file));
	ihk_device_unmap_memory(dev, parg, sizeof(struct procfs_file));
	dprintk("procfs_delete: done\n");
}

/**
 * \brief Process SCD_MSG_PROCFS_ANSWER message.
 *
 * \param arg sent argument
 * \param err error info (redundant)
 */

void procfs_answer(unsigned int arg, int err)
{
	dprintk("procfs: received SCD_MSG_PROCFS_ANSWER message(err = %d).\n", err);
	wake_up_interruptible(&procfsq);
}

/**
 * \brief The callback funciton for McKernel procfs
 *
 * This function conforms to the 2) way of fs/proc/generic.c
 * from linux-2.6.39.4.
 */
static ssize_t
mckernel_procfs_read(struct file *file, char __user *buf, size_t nbytes,
	       loff_t *ppos)
{
	struct inode * inode = file->f_path.dentry->d_inode;
	char *kern_buffer;
	int order = 0;
	volatile struct procfs_read *r;
	struct ikc_scd_packet isp;
	int ret, retrycount = 0;
	unsigned long pbuf;
	unsigned long count = nbytes;
	struct proc_dir_entry *dp = PDE(inode);
	struct procfs_list_entry *e = dp->data;
	loff_t offset = *ppos;

	dprintk("mckernel_procfs_read: invoked for %s, offset: %lu, count: %d\n", 
			e->fname, offset, count); 
	
	if (count <= 0 || offset < 0) {
		return 0;
	}
	
	while ((1 << order) < count) ++order;
	if (order > 12) {
		order -= 12;
	}
	else {
		order = 1;
	}

	/* NOTE: we need physically contigous memory to pass through IKC */
	kern_buffer = (char *)__get_free_pages(GFP_KERNEL, order);
	if (!kern_buffer) {
		printk("mckernel_procfs_read(): ERROR: allocating kernel buffer\n");
		return -ENOMEM;
	}
	
	pbuf = virt_to_phys(kern_buffer);

	r = kmalloc(sizeof(struct procfs_read), GFP_KERNEL);
	if (r == NULL) {
		return -ENOMEM;
	}
retry:
	dprintk("offset: %lx, count: %d, cpu: %d\n", offset, count, e->cpu);

	r->pbuf = pbuf;
	r->eof = 0;
	r->ret = -EIO; /* default */
	r->status = 0;
	r->offset = offset;
	r->count = count;
	strncpy((char *)r->fname, e->fname, PROCFS_NAME_MAX);
	isp.msg = SCD_MSG_PROCFS_REQUEST;
	isp.ref = e->cpu;
	isp.arg = virt_to_phys(r);
	
	ret = mcctrl_ikc_send(e->os, e->cpu, &isp);
	
	if (ret < 0) {
		goto out; /* error */
	}
	
	/* Wait for a reply. */
	ret = -EIO; /* default exit code */
	dprintk("now wait for a relpy\n");
	
	/* Wait for the status field of the procfs_read structure set ready. */
	if (wait_event_interruptible_timeout(procfsq, r->status != 0, HZ) == 0) {
		kprintf("ERROR: mckernel_procfs_read: timeout (1 sec).\n");
		goto out;
	}
	
	/* Wake up and check the result. */
	dprintk("mckernel_procfs_read: woke up. ret: %d, eof: %d\n", r->ret, r->eof);
	if ((r->ret == 0) && (r->eof != 1)) {
		/* A miss-hit caused by migration has occurred.
		 * We simply retry the query with a new CPU.
		 */
		if (retrycount++ > 10) {
			kprintf("ERROR: mckernel_procfs_read: excessive retry.\n");
			goto out;
		}
		e->cpu = r->newcpu;
		dprintk("retry\n");
		goto retry;
	}
	
	if (copy_to_user(buf, kern_buffer, r->ret)) {
		kprintf("ERROR: mckernel_procfs_read: copy_to_user failed.\n");
		ret = -EFAULT;
		goto out;
	}

	*ppos += r->ret;
	ret = r->ret;

out:
	free_pages((uintptr_t)kern_buffer, order);
	kfree((void *)r);
	
	return ret;
}

/**
 * \brief Initialization for procfs
 *
 * \param osnum os number
 */

void procfs_init(int osnum) {
}

/**
 * \brief Finalization for procfs
 *
 * \param osnum os number
 */

void procfs_exit(int osnum) {
	char buf[20], *r;
	int error;
	mm_segment_t old_fs = get_fs();
	struct kstat stat;
	struct proc_dir_entry *parent;
	struct procfs_list_entry *e, *temp = NULL;
	unsigned long irqflags;

	dprintk("remove remaining mckernel procfs files.\n");

	irqflags = ihk_ikc_spinlock_lock(&procfs_file_list_lock);
	list_for_each_entry_safe(e, temp, &procfs_file_list, list) {
		if (e->osnum == osnum) {
			dprintk("found entry for %s.\n", e->fname);
			list_del(&e->list);
			e->entry->read_proc = NULL;
			e->entry->data = NULL;
			parent = e->parent;
			r = strrchr(e->fname, '/');
			if (r == NULL) {
				r = e->fname;
			} else {
				r += 1;
			}
			remove_proc_entry(r, parent);
			dprintk("free the entry\n");
			kfree(e);
		}
		dprintk("iterate it.\n");
	}
	ihk_ikc_spinlock_unlock(&procfs_file_list_lock, irqflags);

	sprintf(buf, "/proc/mcos%d", osnum);

	set_fs(KERNEL_DS);
	error = vfs_stat (buf, &stat);
	set_fs(old_fs);
	if (error != 0) {
		return;
	}

	printk("procfs_exit: We have to remove unexpectedly remaining %s.\n", buf);

	/* remove remnant of previous mcos%d */
	remove_proc_entry(buf + 6, NULL);
}
