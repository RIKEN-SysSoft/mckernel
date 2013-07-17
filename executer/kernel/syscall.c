#include <linux/sched.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/anon_inodes.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/semaphore.h>
#include <asm/uaccess.h>
#include <asm/delay.h>
#include <asm/io.h>
#include "mcctrl.h"

#define ALIGN_WAIT_BUF(z)   (((z + 63) >> 6) << 6)

//#define SC_DEBUG

#ifdef SC_DEBUG
#define	dprintk(...)	printk(__VA_ARGS__)
#else
#define	dprintk(...)
#endif

#ifdef SC_DEBUG
//static struct ihk_dma_request last_request;

static void print_dma_lastreq(void)
{
	printk("SRC OS : %p | %lx\nDESTOS : %p | %lx\n", last_request.src_os,
	       last_request.src_phys, last_request.dest_os,
	       last_request.dest_phys);
	printk("SIZE   : %lx | NOTIFY : %p | PRIV : %p\n",
	       last_request.size, last_request.notify, last_request.priv);
}
#endif

#if 1	/* x86 depend, host OS side */
unsigned long translate_rva_to_rpa(ihk_os_t os, unsigned long rpt, unsigned long rva, unsigned fflags)
{
	unsigned long rpa;
	int offsh;
	int i;
	int ix;
	unsigned long phys;
	unsigned long *pt;

	rpa = rpt;
	offsh = 39;
	/* i = 0: PML4, 1: PDPT, 2: PDT, 3: PT */
	for (i = 0; i < 4; ++i) {
		ix = (rva >> offsh) & 0x1FF;
		phys = ihk_device_map_memory(ihk_os_to_dev(os), rpa, PAGE_SIZE);
		pt = ihk_device_map_virtual(ihk_os_to_dev(os), phys, PAGE_SIZE, NULL, 0);
		dprintk("rpa %#lx offsh %d ix %#x phys %#lx pt %p pt[ix] %#lx\n",
				rpa, offsh, ix, phys, pt, pt[ix]);

#define	PTE_P	0x001
		if (!(pt[ix] & PTE_P)) {
			ihk_device_unmap_virtual(ihk_os_to_dev(os), pt, PAGE_SIZE);
			ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);
			return -EFAULT;
		}

#define	PTE_RW	0x002
		if ((fflags & FAULT_FLAG_WRITE) && !(pt[ix] & PTE_RW)) {
			ihk_device_unmap_virtual(ihk_os_to_dev(os), pt, PAGE_SIZE);
			ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);
			return -EFAULT;
		}

#define	PTE_PS	0x080
		if (pt[ix] & PTE_PS) {
			rpa = pt[ix] & ((1UL << 52) - 1) & ~((1UL << offsh) - 1);
			rpa |= rva & ((1UL << offsh) - 1);
			ihk_device_unmap_virtual(ihk_os_to_dev(os), pt, PAGE_SIZE);
			ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);
			goto out;
		}

		rpa = pt[ix] & ((1UL << 52) - 1) & ~((1UL << 12) - 1);
		offsh -= 9;
		ihk_device_unmap_virtual(ihk_os_to_dev(os), pt, PAGE_SIZE);
		ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);
	}
	rpa |= rva & ((1UL << 12) - 1);
out:
	dprintk("translate_rva_to_rpa: rva %#lx --> rpa %#lx\n", rva, rpa);
	return rpa;
}
#endif

static int pager_call(ihk_os_t os, struct syscall_request *req);
static int remote_page_fault(struct mcctrl_usrdata *usrdata, struct vm_fault *vmf)
{
	int cpu;
	struct mcctrl_channel *channel;
	volatile struct syscall_request *req;
	volatile struct syscall_response *resp;

	printk("remote_page_fault(%p,%p %x)\n", usrdata, vmf->virtual_address, vmf->flags);
	/* get peer cpu */
	for (cpu = 0; cpu < usrdata->num_channels; ++cpu) {
		if (usrdata->channelowners[cpu] == current) {
			break;
		}
	}
	if (cpu >= usrdata->num_channels) {
		printk("cpu not found\n");
		return -ENOENT;
	}

	channel = &usrdata->channels[cpu];
	req = channel->param.request_va;
	resp = channel->param.response_va;

	/* request page fault */
	resp->ret = -EFAULT;
	resp->fault_address = (unsigned long)vmf->virtual_address;
	resp->fault_reason = (vmf->flags & FAULT_FLAG_WRITE)? 1: 0;

	req->valid = 0;
	resp->status = 3;

retry:
	/* wait for response */
	while (req->valid == 0) {
		schedule();
	}
	req->valid = 0;

	/* check result */
	if (req->number != __NR_mmap) {
		printk("remote_page_fault:invalid response. %lx %lx\n",
				req->number, req->args[0]);
		return -EIO;
	}
	else if (req->args[0] != 0x0101) {
		resp->ret = pager_call(usrdata->os, (void *)req);
		resp->status = 1;
		goto retry;
	}
	else if (req->args[1] != 0) {
		printk("remote_page_fault:response %d\n", (int)req->args[1]);
		return (int)req->args[1];
	}
	printk("remote_page_fault(%p,%p %x): 0\n", usrdata, vmf->virtual_address, vmf->flags);
	return 0;
}

static int rus_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct mcctrl_usrdata *	usrdata	= vma->vm_file->private_data;
	ihk_device_t		dev = ihk_os_to_dev(usrdata->os);
	unsigned long		rpa;
	unsigned long		phys;
	int			error;
	int			try;

	dprintk("mcctrl:page fault:flags %#x pgoff %#lx va %p page %p\n",
			vmf->flags, vmf->pgoff, vmf->virtual_address, vmf->page);

	for (try = 1; ; ++try) {
		rpa = translate_rva_to_rpa(usrdata->os, usrdata->rpgtable,
				(unsigned long)vmf->virtual_address,
				vmf->flags);
#define	NTRIES 2
		if (((long)rpa >= 0) || (try >= NTRIES)) {
			break;
		}

		error = remote_page_fault(usrdata, vmf);
		if (error) {
			printk("forward_page_fault failed. %d\n", error);
			break;
		}
	}
	if ((long)rpa < 0) {
		printk("mcctrl:page fault:flags %#x pgoff %#lx va %p page %p\n",
				vmf->flags, vmf->pgoff, vmf->virtual_address, vmf->page);
		return VM_FAULT_SIGBUS;
	}

	phys = ihk_device_map_memory(dev, rpa, PAGE_SIZE);
	error = vm_insert_pfn(vma, (unsigned long)vmf->virtual_address, phys>>PAGE_SHIFT);
	ihk_device_unmap_memory(dev, phys, PAGE_SIZE);
	if (error) {
		printk("mcctrl:page fault:flags %#x pgoff %#lx va %p page %p\n",
				vmf->flags, vmf->pgoff, vmf->virtual_address, vmf->page);
		return VM_FAULT_SIGBUS;
	}

	return VM_FAULT_NOPAGE;
}

static struct vm_operations_struct rus_vmops = {
	.fault = &rus_vm_fault,
};

static int rus_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_flags |= VM_IO | VM_RESERVED | VM_DONTEXPAND | VM_PFNMAP;
	vma->vm_ops = &rus_vmops;
	return 0;
}

static struct file_operations rus_fops = {
	.mmap = &rus_mmap,
};

struct vm_area_struct *rus_vma = NULL;
int reserve_user_space(struct mcctrl_usrdata *usrdata, unsigned long *startp, unsigned long *endp)
{
	struct file *file;
	struct vm_area_struct *vma;
	unsigned long start;
	unsigned long end;

	file = anon_inode_getfile("[mckernel]", &rus_fops, usrdata, O_RDWR);
	if (IS_ERR(file)) {
		return PTR_ERR(file);
	}

#define	DESIRED_USER_END	0x800000000000
#define	GAP_FOR_MCEXEC		0x008000000000UL
	end = DESIRED_USER_END;
	down_write(&current->mm->mmap_sem);
	vma = find_vma(current->mm, 0);
	if (vma) {
		end = (vma->vm_start - GAP_FOR_MCEXEC) & ~(GAP_FOR_MCEXEC - 1);
	}
	start = do_mmap_pgoff(file, 0, end,
			PROT_READ|PROT_WRITE, MAP_FIXED|MAP_SHARED, 0);
	vma = find_vma(current->mm, 0);
	up_write(&current->mm->mmap_sem);
	fput(file);
	if (IS_ERR_VALUE(start)) {
		printk("mcctrl:user space reservation failed.\n");
		return start;
	}

	rus_vma = vma;
	*startp = start;
	*endp = end;
	return 0;
}

//unsigned long last_thread_exec = 0;

#ifndef DO_USER_MODE
static struct {
	long (*do_sys_open)(int, const char __user *, int, int);
	long (*sys_lseek)(unsigned int, off_t, unsigned int);
	long (*sys_read)(unsigned int, char __user *, size_t);
	long (*sys_write)(unsigned int, const char __user *, size_t);
} syscalls;

void
mcctrl_syscall_init(void)
{
	printk("mcctrl_syscall_init\n");
	syscalls.do_sys_open = (void *)kallsyms_lookup_name("do_sys_open");
	syscalls.sys_lseek = (void *)kallsyms_lookup_name("sys_lseek");
	syscalls.sys_read = (void *)kallsyms_lookup_name("sys_read");
	syscalls.sys_write = (void *)kallsyms_lookup_name("sys_write");
	printk("syscalls.do_sys_open=%lx\n", (long)syscalls.do_sys_open);
	printk("syscalls.sys_lseek=%lx\n", (long)syscalls.sys_lseek);
	printk("syscalls.sys_read=%lx\n", (long)syscalls.sys_read);
	printk("syscalls.sys_write=%lx\n", (long)syscalls.sys_write);
}

static int do_async_copy(ihk_os_t os, unsigned long dest, unsigned long src,
                         unsigned long size, unsigned int inbound)
{
	struct ihk_dma_request request;
	ihk_dma_channel_t channel;
	unsigned long asize = ALIGN_WAIT_BUF(size);

	channel = ihk_device_get_dma_channel(ihk_os_to_dev(os), 0);
	if (!channel) {
		return -EINVAL;
	}

	memset(&request, 0, sizeof(request));
	request.src_os = inbound ? os : NULL;
	request.src_phys = src;
	request.dest_os = inbound ? NULL : os;
	request.dest_phys = dest;
	request.size = size;
	request.notify = (void *)(inbound ? dest + asize : src + asize);
	request.priv = (void *)1;

	*(unsigned long *)phys_to_virt((unsigned long)request.notify) = 0;
#ifdef SC_DEBUG
	last_request = request;
#endif

	ihk_dma_request(channel, &request);

	return 0;
}

//int mcctrl_dma_abort;

static void async_wait(ihk_os_t os, unsigned char *p, int size)
{
	int asize = ALIGN_WAIT_BUF(size);
	unsigned long long s, w;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	rdtscll(s);
	while (!p[asize]) {
		mb();
		cpu_relax();
		rdtscll(w);
		if (w > s + 1024UL * 1024 * 1024 * 10) {
			printk("DMA Timed out : %p (%p + %d) => %d\n",
			       p + asize, p, size, p[asize]);
#ifdef SC_DEBUG
			print_dma_lastreq();
#endif
			usrdata->mcctrl_dma_abort = 1;
			return;
		}
	}
}

static void clear_wait(unsigned char *p, int size)
{
	//int asize = ALIGN_WAIT_BUF(size);
	p[size] = 0;
}

static unsigned long translate_remote_va(struct mcctrl_channel *c,
                                         unsigned long rva)
{
	int i, n;
	struct syscall_post *p;

	p = c->param.post_va;

	n = (int)p->v[0];
	if (n < 0 || n >= PAGE_SIZE / sizeof(struct syscall_post)) {
		return -EINVAL;
	}
	for (i = 0; i < n; i++) {
		if (p[i + 1].v[0] != 1) {
			continue;
		}
		if (rva >= p[i + 1].v[1] && rva < p[i + 1].v[2]) {
			return p[i + 1].v[3] + (rva - p[i + 1].v[1]);
		}
	}

	return -EFAULT;
}

//extern struct mcctrl_channel *channels;

#if 0
int __do_in_kernel_syscall(ihk_os_t os, struct mcctrl_channel *c,
                           struct syscall_request *sc)
{
	int ret;
	mm_segment_t fs;
	unsigned long pa;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	switch (sc->number) {
	case 0: /* read */
	case 1024:
		if (sc->number & 1024) {
			sc->args[1] = translate_remote_va(c, sc->args[1]);
			if ((long)sc->args[1] < 0) {
				__return_syscall(c, -EFAULT);
				return 0;
			}
		}

		clear_wait(c->dma_buf, sc->args[2]);
		fs = get_fs();
		set_fs(KERNEL_DS);
		ret = syscalls.sys_read(sc->args[0], c->dma_buf, sc->args[2]);
		if (ret > 0) {
			do_async_copy(os, sc->args[1], virt_to_phys(c->dma_buf),
			              sc->args[2], 0);
			set_fs(fs);
			
			async_wait(os, c->dma_buf, sc->args[2]);
		}
		__return_syscall(c, ret);
		return 0;

	case 1: /* write */
	case 1025:
		if (sc->number & 1024) {
			sc->args[1] = translate_remote_va(c, sc->args[1]);
			if ((long)sc->args[1] < 0) {
				__return_syscall(c, -EFAULT);
				return 0;
			}
		}

		clear_wait(c->dma_buf, sc->args[2]);
		do_async_copy(os, virt_to_phys(c->dma_buf), sc->args[1],
		              sc->args[2], 1);
		fs = get_fs();
		set_fs(KERNEL_DS);
		async_wait(os, c->dma_buf, sc->args[2]);

		ret = syscalls.sys_write(sc->args[0], c->dma_buf, sc->args[2]);
		set_fs(fs);

		__return_syscall(c, ret);
		return 0;
		
	case 2: /* open */
	case 1026:
		if (sc->number & 1024) {
			sc->args[0] = translate_remote_va(c, sc->args[0]);
			if ((long)sc->args[0] < 0) {
				__return_syscall(c, -EFAULT);
				return 0;
			}
		}

		clear_wait(c->dma_buf, 256);
		do_async_copy(os, virt_to_phys(c->dma_buf), sc->args[0], 
		              256, 1);
		fs = get_fs();
		set_fs(KERNEL_DS);
		async_wait(os, c->dma_buf, 256);

		ret = syscalls.do_sys_open(AT_FDCWD, c->dma_buf, sc->args[1],
		                  sc->args[2]);
		set_fs(fs);

		__return_syscall(c, ret);
		return 0;

	case 3: /* Close */
		ret = sys_close(sc->args[0]);
		__return_syscall(c, ret);
		return 0;

	case 8: /* lseek */
		ret = syscalls.sys_lseek(sc->args[0], sc->args[1], sc->args[2]);
		__return_syscall(c, ret);
		return 0;

	case 56: /* Clone */
		usrdata->last_thread_exec++;
		if (mcctrl_ikc_is_valid_thread(usrdata->last_thread_exec)) {
			printk("Clone notification: %lx\n", sc->args[0]);
			if (channels[usrdata->last_thread_exec].param.post_va) {
				memcpy(usrdata->channels[usrdata->last_thread_exec].param.post_va,
				       c->param.post_va, PAGE_SIZE);
			}
			mcctrl_ikc_send_msg(usrdata->last_thread_exec,
			                    SCD_MSG_SCHEDULE_PROCESS,
			                    usrdata->last_thread_exec, sc->args[0]);
		}

		__return_syscall(c, 0);
		return 0;
		
	default:
		if (sc->number & 1024) {
			__return_syscall(c, -EFAULT);
			return 0;
		} else {
			return -ENOSYS;
		}
	}
}
#endif
#endif /* !DO_USER_MODE */

static void __return_syscall(struct mcctrl_channel *c, long ret)
{
	c->param.response_va->ret = ret;
	c->param.response_va->status = 1;
}

struct pager {
	struct list_head	list;
	struct inode *		inode;
	void *			handle;
};

/*
 * for linux v2.6.35 or prior
 */
#ifndef DEFINE_SEMAPHORE
#define DEFINE_SEMAPHORE(...)	DECLARE_MUTEX(__VA_ARGS__)
#endif

static DEFINE_SEMAPHORE(pager_sem);
static struct list_head pager_list = LIST_HEAD_INIT(pager_list);

struct pager_create_result {
	uintptr_t	handle;
	int		maxprot;
};

static int pager_req_create(ihk_os_t os, int fd, int flags, int prot, uintptr_t result_pa)
{
	const int ignore_flags = MAP_FIXED | MAP_DENYWRITE;
	const int ok_flags = MAP_PRIVATE;
	ihk_device_t dev = ihk_os_to_dev(os);
	int error;
	void *handle = NULL;
	struct pager_create_result *resp;
	int maxprot = -1;
	struct file *file = NULL;
	struct inode *inode;
	struct pager *pager;
	uintptr_t phys;

	printk("pager_req_create(%d,%x,%x,%lx)\n", fd, flags, prot, (long)result_pa);

	if (flags & ~(ignore_flags | ok_flags)) {
		printk("pager_req_create(%d,%x,%x,%lx):not supported flags %x\n",
				fd, flags, prot, (long)result_pa,
				flags & ~(ignore_flags | ok_flags));
		error = -EINVAL;
		goto out;
	}

	file = fget(fd);
	if (file == NULL) {
		error = -EBADF;
		printk("pager_req_create(%d,%x,%x,%lx):file not found. %d\n", fd, flags, prot, (long)result_pa, error);
		goto out;
	}

	inode = file->f_path.dentry->d_inode;
	if (inode == NULL) {
		error = -EBADF;
		printk("pager_req_create(%d,%x,%x,%lx):inode not found. %d\n", fd, flags, prot, (long)result_pa, error);
		goto out;
	}

	if (!(file->f_mode & (FMODE_READ | FMODE_WRITE))) {
		maxprot = PROT_NONE;
	}
	else {
		maxprot = 0;
		if (file->f_mode & FMODE_READ) {
			maxprot |= PROT_READ;
			maxprot |= PROT_EXEC;
		}
		if (file->f_mode & FMODE_WRITE) {
			maxprot |= PROT_WRITE;
		}
	}

	error = down_interruptible(&pager_sem);
	if (error) {
		error = -EINTR;
		printk("pager_req_create(%d,%x,%x,%lx):signaled. %d\n", fd, flags, prot, (long)result_pa, error);
		goto out;
	}

	list_for_each_entry(pager, &pager_list, list) {
		if (pager->inode == inode) {
			handle = pager->handle;
			error = -EALREADY;
			up(&pager_sem);
			goto found;
		}
	}

	pager = kzalloc(sizeof(*pager), GFP_KERNEL);
	if (pager == NULL) {
		error = -ENOMEM;
		printk("pager_req_create(%d,%x,%x,%lx):kzalloc failed. %d\n", fd, flags, prot, (long)result_pa, error);
		up(&pager_sem);
		goto out;
	}

	down_write(&current->mm->mmap_sem);
	handle = (void *)do_mmap_pgoff(file, 0, PAGE_SIZE, prot, (flags & ok_flags), 0);
	up_write(&current->mm->mmap_sem);
	if (IS_ERR(handle)) {
		error = PTR_ERR(handle);
		printk("pager_req_create(%d,%x,%x,%lx):mmap failed. %d\n",
				fd, flags, prot, (long)result_pa, error);
		kfree(pager);
		up(&pager_sem);
		goto out;
	}

	pager->inode = inode;
	pager->handle = handle;
	list_add(&pager->list, &pager_list);
	up(&pager_sem);

	error = 0;
found:
	phys = ihk_device_map_memory(dev, result_pa, sizeof(*resp));
	resp = ihk_device_map_virtual(dev, phys, sizeof(*resp), NULL, 0);
	resp->handle = (uintptr_t)handle;
	resp->maxprot = maxprot;
	ihk_device_unmap_virtual(dev, resp, sizeof(*resp));
	ihk_device_unmap_memory(dev, phys, sizeof(*resp));

out:
	if (file != NULL) {
		fput(file);
	}
	printk("pager_req_create(%d,%x,%x,%lx): %d %p %x\n",
			fd, flags, prot, (long)result_pa, error, handle, maxprot);
	return error;
}

static int pager_req_release(ihk_os_t os, uintptr_t handle)
{
	struct vm_area_struct *vma;
	int error;
	struct pager *pager;
	struct pager *next;

	printk("pager_req_relase(%p,%lx)\n", os, handle);

	error = down_interruptible(&pager_sem);
	if (error) {
		printk("pager_req_relase(%p,%lx):signaled. %d\n", os, handle, error);
		down_write(&current->mm->mmap_sem);
		goto out;
	}

	list_for_each_entry_safe(pager, next, &pager_list, list) {
		if ((uintptr_t)pager->handle == handle) {
			list_del(&pager->list);
			up(&pager_sem);
			kfree(pager);
			goto found;
		}
	}
	up(&pager_sem);

	error = -EBADF;
	printk("pager_req_relase(%p,%lx):pager not found. %d\n", os, handle, error);
	down_write(&current->mm->mmap_sem);
	goto out;

found:
	down_write(&current->mm->mmap_sem);
	vma = find_vma(current->mm, handle);
	if (vma == 0) {
		error = -EBADF;
		printk("pager_req_relase(%p,%lx):vma not found. %d\n", os, handle, error);
		goto out;
	}
	if ((vma->vm_start != handle) || (vma->vm_end != (handle + PAGE_SIZE))) {
		error = -EBADF;
		printk("pager_req_relase(%p,%lx):invalid vma. %d\n", os, handle, error);
		goto out;
	}
	if (vma->vm_file == NULL) {
		error = -EBADF;
		printk("pager_req_relase(%p,%lx):file not found. %d\n", os, handle, error);
		goto out;
	}

	error = do_munmap(current->mm, handle, PAGE_SIZE);
	if (error) {
		printk("pager_req_relase(%p,%lx):do_munmap failed. %d\n", os, handle, error);
		goto out;
	}

	error = 0;
out:
	up_write(&current->mm->mmap_sem);
	printk("pager_req_relase(%p,%lx): %d\n", os, handle, error);
	return error;
}

static int pager_req_read(ihk_os_t os, uintptr_t handle, off_t off, size_t size, uintptr_t rpa)
{
	ihk_device_t dev = ihk_os_to_dev(os);
	struct vm_area_struct *vma;
	int error;
	struct file *file;
	uintptr_t phys;
	void *buf;
	mm_segment_t fs;
	loff_t pos;
	ssize_t ss;

	printk("pager_req_read(%lx,%lx,%lx,%lx)\n", handle, off, size, rpa);

	down_read(&current->mm->mmap_sem);
	vma = find_vma(current->mm, handle);
	if (vma == 0) {
		error = -EBADF;
		printk("pager_req_read(%lx,%lx,%lx,%lx):vma not found. %d\n", handle, off, size, rpa, error);
		up_read(&current->mm->mmap_sem);
		goto out;
	}
	if ((vma->vm_start != handle) || (vma->vm_end != (handle + PAGE_SIZE))) {
		error = -EBADF;
		printk("pager_req_read(%lx,%lx,%lx,%lx):invalid vma. %d\n", handle, off, size, rpa, error);
		up_read(&current->mm->mmap_sem);
		goto out;
	}
	file = vma->vm_file;
	if (file == NULL) {
		error = -EBADF;
		printk("pager_req_read(%lx,%lx,%lx,%lx):file not found. %d\n", handle, off, size, rpa, error);
		up_read(&current->mm->mmap_sem);
		goto out;
	}
	get_file(file);
	up_read(&current->mm->mmap_sem);

	phys = ihk_device_map_memory(dev, rpa, size);
	buf = ihk_device_map_virtual(dev, phys, size, NULL, 0);
	fs = get_fs();
	set_fs(KERNEL_DS);
	pos = off;
	ss = vfs_read(file, buf, size, &pos);
	if ((ss >= 0) && (ss != size)) {
		if (clear_user(buf+ss, size-ss) == 0) {
			ss = size;
		}
		else {
			ss = -EIO;
		}
	}
	set_fs(fs);
	ihk_device_unmap_virtual(dev, buf, size);
	ihk_device_unmap_memory(dev, phys, size);
	fput(file);
	if (ss < 0) {
		error = ss;
		printk("pager_req_read(%lx,%lx,%lx,%lx):pread failed. %d\n", handle, off, size, rpa, error);
		goto out;
	}
	error = 0;
out:
	printk("pager_req_read(%lx,%lx,%lx,%lx): %d\n", handle, off, size, rpa, error);
	return error;
}

static int pager_call(ihk_os_t os, struct syscall_request *req)
{
	int error;

	printk("pager_call(%p %#lx)\n", req, req->args[0]);
	switch (req->args[0]) {
#define	PAGER_REQ_CREATE	0x0001
#define	PAGER_REQ_RELEASE	0x0002
#define	PAGER_REQ_READ		0x0003
	case PAGER_REQ_CREATE:
		error = pager_req_create(os, req->args[1], req->args[2], req->args[3], req->args[4]);
		break;

	case PAGER_REQ_RELEASE:
		error = pager_req_release(os, req->args[1]);
		break;

	case PAGER_REQ_READ:
		error = pager_req_read(os, req->args[1], req->args[2], req->args[3], req->args[4]);
		break;

	default:
		error = -ENOSYS;
		break;
	}

	printk("pager_call(%p %#lx): %d\n", req, req->args[0], error);
	return error;
}

int __do_in_kernel_syscall(ihk_os_t os, struct mcctrl_channel *c, struct syscall_request *sc)
{
	int error;
	long ret;

	printk("__do_in_kernel_syscall(%p,%p,%p %ld)\n", os, c, sc, sc->number);
	switch (sc->number) {
	case __NR_mmap:
		ret = pager_call(os, sc);
		break;

	default:
		error = -ENOSYS;
		goto out;
		break;
	}

	__return_syscall(c, ret);

	error = 0;
out:
	printk("__do_in_kernel_syscall(%p,%p,%p %ld): %d\n", os, c, sc, sc->number, error);
	return error;
}
