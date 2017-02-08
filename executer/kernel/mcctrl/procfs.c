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

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/resource.h>
#include <linux/interrupt.h>
#include "mcctrl.h"
#include <linux/version.h>
#include <linux/semaphore.h>

//#define PROCFS_DEBUG

#ifdef PROCFS_DEBUG
#define	dprintk(...)	printk(__VA_ARGS__)
#else
#define	dprintk(...)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
typedef uid_t kuid_t;
typedef gid_t kgid_t;
#endif

struct procfs_entry {
	char *name;
	mode_t mode;
	const struct file_operations *fops;
};

#define NOD(NAME, MODE, FOP) {				\
	.name = (NAME),					\
	.mode = MODE,					\
	.fops  = FOP,					\
}
#define PROC_DIR(NAME, MODE)				\
	NOD(NAME, (S_IFDIR|(MODE)), NULL)
#define PROC_REG(NAME, MODE, fops)			\
	NOD(NAME, (S_IFREG|(MODE)), fops)
#define PROC_TERM					\
	NOD(NULL, 0, NULL)

static const struct procfs_entry tid_entry_stuff[];
static const struct procfs_entry pid_entry_stuff[];
static const struct procfs_entry base_entry_stuff[];
static const struct file_operations mckernel_forward_ro;
static const struct file_operations mckernel_forward;

static ssize_t mckernel_procfs_read(struct file *file, char __user *buf, 
		size_t nbytes, loff_t *ppos);

/* A private data for the procfs driver. */
struct procfs_list_entry;

struct procfs_list_entry {
	struct list_head list;
	struct proc_dir_entry *entry;
	struct procfs_list_entry *parent;
	struct list_head children;
	int osnum;
	char *data;
	char name[0];
};

/*
 * In the procfs_file_list, mckenrel procfs files are
 * listed in the manner that the leaf file is located 
 * always nearer to the list top than its parent node 
 * file.
 */
LIST_HEAD(procfs_file_list);
DEFINE_SEMAPHORE(procfs_file_list_lock);

static char *
getpath(struct procfs_list_entry *e, char *buf, int bufsize)
{
	char	*w = buf + bufsize - 1;

	*w = '\0';
	for(;;){
		int l = strlen(e->name);
		w -= l;
		memcpy(w, e->name, l);
		e = e->parent;
		if(!e)
			return w;
		w--;
		*w = '/';
	}
}

/**
 * \brief Process SCD_MSG_PROCFS_ANSWER message.
 *
 * \param ud mcctrl_usrdata pointer
 * \param pid PID of the requesting process
 */
void procfs_answer(struct mcctrl_usrdata *ud, int pid)
{
	struct mcctrl_per_proc_data *ppd = NULL;

	if (pid > 0) {
		ppd = mcctrl_get_per_proc_data(ud, pid);

		if (unlikely(!ppd)) {
			kprintf("%s: ERROR: no per-process structure for PID %d\n",
					__FUNCTION__, pid);
			return;
		}
	}

	wake_up_all(pid > 0 ? &ppd->wq_procfs : &ud->wq_procfs);

	if (pid > 0) {
		mcctrl_put_per_proc_data(ppd);
	}
}

static struct procfs_list_entry *
find_procfs_entry(struct procfs_list_entry *parent, const char *name)
{
	struct list_head *list;
	struct procfs_list_entry *e;

	if(parent == NULL)
		list = &procfs_file_list;
	else
		list = &parent->children;

	list_for_each_entry(e, list, list) {
		if(!strcmp(e->name, name))
			return e;
	}

	return NULL;
}

static void
delete_procfs_entries(struct procfs_list_entry *top)
{
	struct procfs_list_entry *e;
	struct procfs_list_entry *n;

	list_del(&top->list);

	list_for_each_entry_safe(e, n, &top->children, list) {
		delete_procfs_entries(e);
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	e->entry->read_proc = NULL;
	e->entry->data = NULL;
#endif
	remove_proc_entry(top->name, top->parent? top->parent->entry: NULL);
	if(top->data)
		kfree(top->data);
	kfree(top);
}

static struct procfs_list_entry *
add_procfs_entry(struct procfs_list_entry *parent, const char *name, int mode,
                 kuid_t uid, kgid_t gid, const void *opaque)
{
	struct procfs_list_entry *e = find_procfs_entry(parent, name);
	struct proc_dir_entry *pde;
	struct proc_dir_entry *parent_pde = NULL;
	int f_mode = mode & 0777;

	if(e)
		delete_procfs_entries(e);

	e = kmalloc(sizeof(struct procfs_list_entry) + strlen(name) + 1,
	            GFP_KERNEL);
	if(!e){
		kprintf("ERROR: not enough memory to create PROCFS entry.\n");
		return NULL;
	}
	memset(e, '\0', sizeof(struct procfs_list_entry));
	INIT_LIST_HEAD(&e->children);
	strcpy(e->name, name);

	if(parent)
		parent_pde = parent->entry;

	if (mode & S_IFDIR) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		pde = proc_mkdir(name, parent_pde);
#else
		pde = proc_mkdir_data(name, f_mode, parent_pde, e);
#endif
	}
	else if ((mode & S_IFLNK) == S_IFLNK) {
		pde = proc_symlink(name, parent_pde, (char *)opaque);
	}
	else {
		const struct file_operations *fop;

		if(opaque)
			fop = (const struct file_operations *)opaque;
		else if(mode & S_IWUSR)
			fop = &mckernel_forward;
		else
			fop = &mckernel_forward_ro;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		pde = create_proc_entry(name, f_mode, parent_pde);
		if(pde)
			pde->proc_fops = fop;
#else
		pde = proc_create_data(name, f_mode, parent_pde, fop, e);
		if(pde)
			proc_set_user(pde, uid, gid);
#endif
	}
	if(!pde){
		kprintf("ERROR: cannot create a PROCFS entry for %s.\n", name);
		kfree(e);
		return NULL;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	pde->uid = uid;
	pde->gid = gid;
	pde->data = e;
#endif

	if(parent)
		e->osnum = parent->osnum;
	e->entry = pde;
	e->parent = parent;
	list_add(&(e->list), parent? &(parent->children): &procfs_file_list);

	return e;
}

static void
add_procfs_entries(struct procfs_list_entry *parent,
                   const struct procfs_entry *entries, kuid_t uid, kgid_t gid)
{
	const struct procfs_entry *p;

	for(p = entries; p->name; p++){
		add_procfs_entry(parent, p->name, p->mode, uid, gid, p->fops);
	}
}

static const struct cred *
get_pid_cred(int pid)
{
	struct task_struct *task = NULL;

	if (pid > 0) {
		rcu_read_lock();
		task = pid_task(find_vpid(pid), PIDTYPE_PID);
		rcu_read_unlock();
		if (task) {
			return __task_cred(task);
		}
	}
	return NULL;
}

static struct procfs_list_entry *
find_base_entry(int osnum)
{
	char name[12];

	sprintf(name, "mcos%d", osnum);
	return find_procfs_entry(NULL, name);
}

static struct procfs_list_entry *
find_pid_entry(int osnum, int pid)
{
	struct procfs_list_entry *e;
	char name[12];

	if(!(e = find_base_entry(osnum)))
		return NULL;
	sprintf(name, "%d", pid);
	return find_procfs_entry(e, name);
}

static struct procfs_list_entry *
find_tid_entry(int osnum, int pid, int tid)
{
	struct procfs_list_entry *e;
	char name[12];

	if(!(e = find_pid_entry(osnum, pid)))
		return NULL;
	if(!(e = find_procfs_entry(e, "task")))
		return NULL;
	sprintf(name, "%d", tid);
	return find_procfs_entry(e, name);
}

static struct procfs_list_entry *
get_base_entry(int osnum)
{
	struct procfs_list_entry *e;
	char name[12];
	kuid_t uid = KUIDT_INIT(0);
	kgid_t gid = KGIDT_INIT(0);

	sprintf(name, "mcos%d", osnum);
	e = find_procfs_entry(NULL, name);
	if(!e){
		e = add_procfs_entry(NULL, name, S_IFDIR | 0555,
		                     uid, gid, NULL);
		e->osnum = osnum;
	}
	return e;
}

static struct procfs_list_entry *
get_pid_entry(int osnum, int pid)
{
	struct procfs_list_entry *parent;
	struct procfs_list_entry *e;
	char name[12];
	kuid_t uid = KUIDT_INIT(0);
	kgid_t gid = KGIDT_INIT(0);

	sprintf(name, "mcos%d", osnum);
	if(!(parent = find_procfs_entry(NULL, name)))
		return NULL;
	sprintf(name, "%d", pid);
	e = find_procfs_entry(parent, name);
	if(!e)
		e = add_procfs_entry(parent, name, S_IFDIR | 0555,
		                     uid, gid, NULL);
	return e;
}

static struct procfs_list_entry *
get_tid_entry(int osnum, int pid, int tid)
{
	struct procfs_list_entry *parent;
	struct procfs_list_entry *e;
	char name[12];
	kuid_t uid = KUIDT_INIT(0);
	kgid_t gid = KGIDT_INIT(0);

	sprintf(name, "mcos%d", osnum);
	if(!(parent = find_procfs_entry(NULL, name)))
		return NULL;
	sprintf(name, "%d", pid);
	if(!(parent = find_procfs_entry(parent, name)))
		return NULL;
	if(!(parent = find_procfs_entry(parent, "task")))
		return NULL;
	sprintf(name, "%d", tid);
	e = find_procfs_entry(parent, name);
	if(!e)
		e = add_procfs_entry(parent, name, S_IFDIR | 0555,
		                     uid, gid, NULL);
	return e;
}

static void
_add_tid_entry(int osnum, int pid, int tid, const struct cred *cred)
{
	struct procfs_list_entry *parent;
	struct procfs_list_entry *exe;

	parent = get_tid_entry(osnum, pid, tid);
	if(parent){
		add_procfs_entries(parent, tid_entry_stuff,
		                   cred->uid, cred->gid);
		exe = find_procfs_entry(parent->parent->parent, "exe");
		if(exe){
			add_procfs_entry(parent, "exe", S_IFLNK | 0777,
			                 cred->uid, cred->gid, exe->data);
		}
		
	}
}

void
add_tid_entry(int osnum, int pid, int tid)
{
	const struct cred *cred = get_pid_cred(pid);

	if(!cred)
		return;
	down(&procfs_file_list_lock);
	_add_tid_entry(osnum, pid, tid, cred);
	up(&procfs_file_list_lock);
}

void
add_pid_entry(int osnum, int pid)
{
	struct procfs_list_entry *parent;
	const struct cred *cred = get_pid_cred(pid);

	if(!cred)
		return;
	down(&procfs_file_list_lock);
	parent = get_pid_entry(osnum, pid);
	add_procfs_entries(parent, pid_entry_stuff, cred->uid, cred->gid);
	_add_tid_entry(osnum, pid, pid, cred);
	up(&procfs_file_list_lock);
}

void
delete_tid_entry(int osnum, int pid, int tid)
{
	struct procfs_list_entry *e;

	down(&procfs_file_list_lock);
	e = find_tid_entry(osnum, pid, tid);
	if(e)
		delete_procfs_entries(e);
	up(&procfs_file_list_lock);
}

void
delete_pid_entry(int osnum, int pid)
{
	struct procfs_list_entry *e;

	down(&procfs_file_list_lock);
	e = find_pid_entry(osnum, pid);
	if(e)
		delete_procfs_entries(e);
	up(&procfs_file_list_lock);
}

void
proc_exe_link(int osnum, int pid, const char *path)
{
	struct procfs_list_entry *parent;
	kuid_t uid = KUIDT_INIT(0);
	kgid_t gid = KGIDT_INIT(0);

	down(&procfs_file_list_lock);
	parent = find_pid_entry(osnum, pid);
	if(parent){
		struct procfs_list_entry *task;
		struct procfs_list_entry *e;

		e = add_procfs_entry(parent, "exe", S_IFLNK | 0777, uid, gid,
		                     path);
		e->data = kmalloc(strlen(path) + 1, GFP_KERNEL);
		strcpy(e->data, path);
		task = find_procfs_entry(parent, "task");
		list_for_each_entry(parent, &task->children, list) {
			add_procfs_entry(parent, "exe", S_IFLNK | 0777,
			                 uid, gid, path);
		}
	}
	up(&procfs_file_list_lock);
}

/**
 * \brief Initialization for procfs
 *
 * \param osnum os number
 */
void
procfs_init(int osnum)
{
	struct procfs_list_entry *parent;
	kuid_t uid = KUIDT_INIT(0);
	kgid_t gid = KGIDT_INIT(0);

	down(&procfs_file_list_lock);
	parent = get_base_entry(osnum);
	add_procfs_entries(parent, base_entry_stuff, uid, gid);
	up(&procfs_file_list_lock);
}

/**
 * \brief Finalization for procfs
 *
 * \param osnum os number
 */
void
procfs_exit(int osnum)
{
	struct procfs_list_entry *e;

	down(&procfs_file_list_lock);
	e = find_base_entry(osnum);
	if (e) {
		delete_procfs_entries(e);
	}
	up(&procfs_file_list_lock);
}

/**
 * \brief The callback funciton for McKernel procfs
 *
 * This function conforms to the 2) way of fs/proc/generic.c
 * from linux-2.6.39.4.
 */
static ssize_t __mckernel_procfs_read_write(
		struct file *file,
		char __user *buf, size_t nbytes,
		loff_t *ppos, int read_write)
{
	struct inode * inode = file->f_inode;
	char *kern_buffer = NULL;
	int order = 0;
	volatile struct procfs_read *r = NULL;
	struct ikc_scd_packet isp;
	int ret, osnum, pid, retw;
	unsigned long pbuf;
	unsigned long count = nbytes;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct proc_dir_entry *dp = PDE(inode);
	struct procfs_list_entry *e = dp->data;
#else
	struct procfs_list_entry *e = PDE_DATA(inode);
#endif
	loff_t offset = *ppos;
	char pathbuf[PROCFS_NAME_MAX];
	char *path, *p;
	ihk_os_t os = NULL;
	struct mcctrl_usrdata *udp = NULL;
	struct mcctrl_per_proc_data *ppd = NULL;

	if (count <= 0 || offset < 0) {
		return 0;
	}

	path = getpath(e, pathbuf, PROCFS_NAME_MAX);
	dprintk("%s: invoked for %s, offset: %lu, count: %lu\n",
			__FUNCTION__, path,
			(unsigned long)offset, count);

	/* Verify OS number */
	ret = sscanf(path, "mcos%d/", &osnum);
	if (ret != 1) {
		printk("%s: error: couldn't determine OS number\n", __FUNCTION__);
		return -EINVAL;
	}

	if (osnum != e->osnum) {
		printk("%s: error: OS numbers don't match\n", __FUNCTION__);
		return -EINVAL;
	}

	/* Is this request for a specific process? */
	p = strchr(path, '/') + 1;
	ret = sscanf(p, "%d/", &pid);
	if (ret != 1) {
		pid = -1;
	}

	os = osnum_to_os(osnum);
	if (!os) {
		printk("%s: error: no IHK OS data found for OS %d\n",
				__FUNCTION__, osnum);
		return -EINVAL;
	}

	udp = ihk_host_os_get_usrdata(os);
	if (!udp) {
		printk("%s: error: no MCCTRL data found for OS %d\n",
				__FUNCTION__, osnum);
		return -EINVAL;
	}

	if (pid > 0) {
		ppd = mcctrl_get_per_proc_data(udp, pid);

		if (unlikely(!ppd)) {
			printk("%s: error: no per-process structure for PID %d",
					__FUNCTION__, pid);
			return -EINVAL;
		}
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
		printk("%s: ERROR: allocating kernel buffer\n", __FUNCTION__);
		ret = -ENOMEM;
		goto out;
	}

	pbuf = virt_to_phys(kern_buffer);

	r = kmalloc(sizeof(struct procfs_read), GFP_KERNEL);
	if (r == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	r->pbuf = pbuf;
	r->eof = 0;
	r->ret = -EIO; /* default */
	r->status = 0;
	r->offset = offset;
	r->count = count;
	r->readwrite = read_write;
	strncpy((char *)r->fname, path, PROCFS_NAME_MAX);
	isp.msg = SCD_MSG_PROCFS_REQUEST;
	isp.ref = 0;
	isp.arg = virt_to_phys(r);
	isp.pid = pid;

	ret = mcctrl_ikc_send(osnum_to_os(e->osnum),
			(pid > 0) ? ppd->ikc_target_cpu : 0, &isp);

	if (ret < 0) {
		goto out; /* error */
	}

	/* Wait for a reply. */
	ret = -EIO; /* default exit code */
	dprintk("%s: waiting for reply\n", __FUNCTION__);

retry_wait:
	/* Wait for the status field of the procfs_read structure,
	 * wait on per-process or OS specific data depending on
	 * who the request is for.
	 */
	if (pid > 0) {
		retw = wait_event_interruptible_timeout(ppd->wq_procfs,
				r->status != 0, 5 * HZ);
	}
	else {
		retw = wait_event_interruptible_timeout(udp->wq_procfs,
				r->status != 0, 5 * HZ);
	}

	/* Timeout? */
	if (retw == 0 && r->status == 0) {
		printk("%s: error: timeout (1 sec)\n", __FUNCTION__);
		goto out;
	}
	/* Interrupted? */
	else if (retw == -ERESTARTSYS) {
		ret = -ERESTART;
		goto out;
	}
	/* Were we woken up by a reply to another procfs request? */
	else if (r->status == 0) {
		/* TODO: r->status is not set atomically, we could be woken
		 * up with status == 0 and it could change to 1 while in this
		 * code, we could potentially miss the wake_up()... 
		 */
		printk("%s: stale wake-up, retrying\n", __FUNCTION__);
		goto retry_wait;
	}

	/* Wake up and check the result. */
	dprintk("%s: woke up. ret: %d, eof: %d\n",
			__FUNCTION__, r->ret, r->eof);

	if (r->ret > 0) {
		if (read_write == 0) {
			if (copy_to_user(buf, kern_buffer, r->ret)) {
				printk("%s: ERROR: copy_to_user failed.\n", __FUNCTION__);
				ret = -EFAULT;
				goto out;
			}
		}
		*ppos += r->ret;
	}
	ret = r->ret;

out:
	if (ppd)
		mcctrl_put_per_proc_data(ppd);
	if (kern_buffer)
		free_pages((uintptr_t)kern_buffer, order);
	if (r)
		kfree((void *)r);

	return ret;
}

static ssize_t mckernel_procfs_read(struct file *file,
		char __user *buf, size_t nbytes, loff_t *ppos)
{
	return __mckernel_procfs_read_write(file, buf, nbytes, ppos, 0);
}

static ssize_t mckernel_procfs_write(struct file *file,
		const char __user *buf, size_t nbytes, loff_t *ppos)
{
	return __mckernel_procfs_read_write(file,
			(char __user *)buf, nbytes, ppos, 1);
}

static loff_t
mckernel_procfs_lseek(struct file *file, loff_t offset, int orig)
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

struct procfs_work {
	void *os;
	int msg;
	int pid;
	unsigned long arg;
	struct work_struct work;
};

static void procfsm_work_main(struct work_struct *work0)
{
	struct procfs_work *work = container_of(work0, struct procfs_work, work);

	switch (work->msg) {
		case SCD_MSG_PROCFS_TID_CREATE:
			add_tid_entry(ihk_host_os_get_index(work->os), work->pid, work->arg);
			break;

		case SCD_MSG_PROCFS_TID_DELETE:
			delete_tid_entry(ihk_host_os_get_index(work->os), work->pid, work->arg);
			break;

		default:
			printk("%s: unknown work: msg: %d, pid: %d, arg: %lu)\n",
					__FUNCTION__, work->msg, work->pid, work->arg);
			break;
	}

	kfree(work);
	return;
}

int procfsm_packet_handler(void *os, int msg, int pid, unsigned long arg)
{
	struct procfs_work *work = NULL;

	work = kzalloc(sizeof(*work), GFP_ATOMIC);
	if (!work) {
		printk("%s: kzalloc failed\n", __FUNCTION__);
		return -1;
	}

	work->os = os;
	work->msg = msg;
	work->pid = pid;
	work->arg = arg;
	INIT_WORK(&work->work, &procfsm_work_main);

	schedule_work(&work->work);
	return 0;
}

static const struct file_operations mckernel_forward_ro = {
	.llseek		= mckernel_procfs_lseek,
	.read		= mckernel_procfs_read,
	.write		= NULL,
};

static const struct file_operations mckernel_forward = {
	.llseek		= mckernel_procfs_lseek,
	.read		= mckernel_procfs_read,
	.write		= mckernel_procfs_write,
};

static const struct procfs_entry tid_entry_stuff[] = {
//	PROC_REG("auxv",       S_IRUSR, NULL),
//	PROC_REG("clear_refs", S_IWUSR, NULL),
//	PROC_REG("cmdline",    S_IRUGO, NULL),
//	PROC_REG("comm",       S_IRUGO|S_IWUSR, NULL),
//	PROC_REG("environ",    S_IRUSR, NULL),
//	PROC_LNK("exe",        mckernel_readlink),
//	PROC_REG("limits",     S_IRUSR|S_IWUSR, NULL),
//	PROC_REG("maps",       S_IRUGO, NULL),
	PROC_REG("mem",        S_IRUSR|S_IWUSR, NULL),
//	PROC_REG("pagemap",    S_IRUGO, NULL),
//	PROC_REG("smaps",      S_IRUGO, NULL),
	PROC_REG("stat",       S_IRUGO, NULL),
//	PROC_REG("statm",      S_IRUGO, NULL),
//	PROC_REG("status",     S_IRUGO, NULL),
//	PROC_REG("syscall",    S_IRUGO, NULL),
//	PROC_REG("wchan",      S_IRUGO, NULL),
	PROC_TERM
};

static const struct procfs_entry pid_entry_stuff[] = {
	PROC_REG("auxv",       S_IRUSR, NULL),
	PROC_REG("cgroup",     S_IXUSR, NULL),
//	PROC_REG("clear_refs", S_IWUSR, NULL),
	PROC_REG("cmdline",    S_IRUGO, NULL),
//	PROC_REG("comm",       S_IRUGO|S_IWUSR, NULL),
//	PROC_REG("coredump_filter", S_IRUGO|S_IWUSR, NULL),
	PROC_REG("cpuset",     S_IXUSR, NULL),
//	PROC_REG("environ",    S_IRUSR, NULL),
//	PROC_LNK("exe",        mckernel_readlink),
//	PROC_REG("limits",     S_IRUSR|S_IWUSR, NULL),
	PROC_REG("maps",       S_IRUGO, NULL),
	PROC_REG("mem",        S_IRUSR|S_IWUSR, NULL),
	PROC_REG("pagemap",    S_IRUGO, NULL),
	PROC_REG("smaps",      S_IRUGO, NULL),
//	PROC_REG("stat",       S_IRUGO, NULL),
//	PROC_REG("statm",      S_IRUGO, NULL),
	PROC_REG("status",     S_IRUGO, NULL),
//	PROC_REG("syscall",    S_IRUGO, NULL),
	PROC_DIR("task",       S_IRUGO|S_IXUGO),
//	PROC_REG("wchan",      S_IRUGO, NULL),
	PROC_TERM
};

static const struct procfs_entry base_entry_stuff[] = {
//	PROC_REG("cmdline",    S_IRUGO, NULL),
//	PROC_REG("cpuinfo",    S_IRUGO, NULL),
//	PROC_REG("meminfo",    S_IRUGO, NULL),
//	PROC_REG("pagetypeinfo",S_IRUGO, NULL),
//	PROC_REG("softirq",    S_IRUGO, NULL),
	PROC_REG("stat",       S_IRUGO, NULL),
//	PROC_REG("uptime",     S_IRUGO, NULL),
//	PROC_REG("version",    S_IRUGO, NULL),
//	PROC_REG("vmallocinfo",S_IRUSR, NULL),
//	PROC_REG("vmstat",     S_IRUGO, NULL),
//	PROC_REG("zoneinfo",   S_IRUGO, NULL),
	PROC_TERM
};
