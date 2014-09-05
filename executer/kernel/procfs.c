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
static unsigned long procfsq_channel;

int mckernel_procfs_read(char *buffer, char **start, off_t offset,
			 int count, int *peof, void *dat);

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

LIST_HEAD(procfs_file_list);
static ihk_spinlock_t procfs_file_list_lock;

/**
 * \brief Return specified procfs entry. 
 *
 * \param p a name of the procfs file
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

static struct proc_dir_entry *get_procfs_entry(char *p, int mode)
{
	char *r;
	struct proc_dir_entry *ret = NULL, *parent = NULL;
	struct procfs_list_entry *e;
	char name[PROCFS_NAME_MAX];
	unsigned long irqflags;

	dprintk("get_procfs_entry: %s for mode %o\n", p, mode);
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
		parent = get_procfs_entry(name, 0);
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
	e->entry = ret;
	e->parent = parent;

	irqflags = ihk_ikc_spinlock_lock(&procfs_file_list_lock);
	list_add(&(e->list), &procfs_file_list);
	ihk_ikc_spinlock_unlock(&procfs_file_list_lock, irqflags);

	dprintk("get_procfs_entry: %s done\n", p);
	return ret;
}

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
	f->status = 1; /* Now the peer can free the data. */

	ihk_device_unmap_virtual(dev, f, sizeof(struct procfs_file));
	ihk_device_unmap_memory(dev, parg, sizeof(struct procfs_file));

	if (name[PROCFS_NAME_MAX - 1] != '\0') {
			printk("ERROR: procfs_creat: file name not properly terminated.\n");
			goto quit;
	}
	entry = get_procfs_entry(name, mode);
	if (entry == NULL) {
		printk("ERROR: could not create a procfs entry for %s.\n", name);
		goto quit;
	}

	e = entry->data;
	e->osnum = osnum;
	e->os = __os;
	e->cpu = ref;
	e->pid = pid;

	entry->read_proc = mckernel_procfs_read;
quit:
	dprintk("procfs_create: done\n");
}

/**
 * \brief Delete a procfs entry.
 *
 * \param __os (opaque) os variable
 * \param arg sent argument
 */

void procfs_delete(void *__os, unsigned long arg)
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
		if (strncmp(e->fname, f->fname, PROCFS_NAME_MAX) == 0) {
			dprintk("found and delete an entry in the list.\n");
			list_del(&e->list);
			e->entry->read_proc = NULL;
			e->entry->data = NULL;
			parent = e->parent;
			kfree(e);
			break;
		}
	}
	ihk_ikc_spinlock_unlock(&procfs_file_list_lock, irqflags);
	r = strrchr(f->fname, '/');
	if (r == NULL) {
		strncpy(name, f->fname, PROCFS_NAME_MAX);
	} else {
		strncpy(name, r + 1, PROCFS_NAME_MAX);
	}
	remove_proc_entry(name, parent);
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
	procfsq_channel = arg;
	wake_up_interruptible(&procfsq);
}

/**
 * \brief The callback funciton for McKernel procfs
 *
 * This function conforms to the 2) way of fs/proc/generic.c
 * from linux-2.6.39.4.
 */

int mckernel_procfs_read(char *buffer, char **start, off_t offset,
			 int count, int *peof, void *dat)
{
	struct procfs_list_entry *e = dat;
	volatile struct procfs_read *r;
	struct ikc_scd_packet isp;
	int ret, retrycount = 0;
	unsigned long pbuf;

	dprintk("mckernel_procfs_read: invoked for %s\n", e->fname); 

	if (count <= 0 || dat == NULL || offset < 0) {
		return 0;
	}

	pbuf = virt_to_phys(buffer);
	if (pbuf / PAGE_SIZE != (pbuf + count - 1) / PAGE_SIZE) {
		/* Truncate the read count upto the nearest page boundary */
		count = ((pbuf + count - 1) / PAGE_SIZE) * PAGE_SIZE - pbuf;
	}
	r = kmalloc(sizeof(struct procfs_read), GFP_KERNEL);
	if (r == NULL) {
		return -ENOMEM;
	}
retry:
	dprintk("offset: %lx, count: %d, cpu: %d\n", offset, count, e->cpu);

	r->pbuf = pbuf;
	r->eof = 0;
	r->ret = -EIO;	/* default to error */
	r->offset = offset;
	r->count = count;
	strncpy(r->fname, e->fname, PROCFS_NAME_MAX);
	isp.msg = SCD_MSG_PROCFS_REQUEST;
	isp.ref = e->cpu;
	isp.arg = virt_to_phys(r);
	ret = mcctrl_ikc_send(e->os, e->cpu, &isp);
	if (ret < 0) {
		return ret; /* error */
	}
	/* Wait for a reply. */
	dprintk("now wait for a relpy\n");
	wait_event_interruptible(procfsq, procfsq_channel == virt_to_phys(r));
	/* Wake up and check the result. */
	dprintk("mckernel_procfs_read: woke up. ret: %d, eof: %d\n", r->ret, r->eof);
	if ((r->ret == 0) && (r->eof != 1)) {
		/* A miss-hit caused by migration has occurred.
		 * We simply retry the query with a new CPU.
		 */
		if (retrycount++ > 10) {
			kprintf("ERROR: mckernel_procfs_read: excessive retry.\n");
			return -EIO;
		}
		e->cpu = r->newcpu;
		dprintk("retry\n");
		goto retry;
	}
	if (r->eof == 1) {
		*peof = 1;
	}
	*start = buffer;
	ret = r->ret;
	kfree(r);
	
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
	char buf[20];
	int error;
	mm_segment_t old_fs = get_fs();
	struct kstat stat;

	sprintf(buf, "/proc/mcos%d", osnum);

	set_fs(KERNEL_DS);
	error = vfs_stat (buf, &stat);
	set_fs(old_fs);
	if (error != 0) {
		return;
	}

	/* remove remnant of previous mcos%d */
	remove_proc_entry(buf + 6, NULL);
}
