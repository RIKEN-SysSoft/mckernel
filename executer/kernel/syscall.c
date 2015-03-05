/**
 * \file executer/kernel/syscall.c
 *  License details are found in the file LICENSE.
 * \brief
 *  provide system calls
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
 *  2013/11/06 nakamura add shared mapped file
 *  2013/11/06 nakamura refuse the write to a read-only memory
 *  2013/09/05 nakamura add mcexec's PTE cleaning to munmap()/mmap(MAP_FIXED)
 *  2013/08/28 mcexec: upgrade CAP_SYS_RAWIO while do_mmap_pgoff()
 *  2013/08/09 nakamura support private mapped file
 *  2013/08/07 nakamura add page fault forwarding
 *  2013/07/10 rus_vm_fault(): add handling of page absence
 *  2013/04/17 nakamura add generic system call forwarding
 */
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
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/semaphore.h>
#include <linux/mount.h>
#include <asm/uaccess.h>
#include <asm/delay.h>
#include <asm/io.h>
#include "mcctrl.h"
#include <linux/version.h>

#define ALIGN_WAIT_BUF(z)   (((z + 63) >> 6) << 6)

//#define SC_DEBUG

#ifdef SC_DEBUG
#define	dprintk(...)	printk(__VA_ARGS__)
#else
#define	dprintk(...)
#endif

static long pager_call(ihk_os_t os, struct syscall_request *req);

#ifdef SC_DEBUG
static struct ihk_dma_request last_request;

static void print_dma_lastreq(void)
{
	printk("SRC OS : %p | %lx\nDESTOS : %p | %lx\n", last_request.src_os,
	       last_request.src_phys, last_request.dest_os,
	       last_request.dest_phys);
	printk("SIZE   : %lx | NOTIFY : %p | PRIV : %p\n",
	       last_request.size, last_request.notify, last_request.priv);
}
#endif

int init_peer_channel_registry(struct mcctrl_usrdata *ud)
{
	ud->keys = kzalloc(sizeof(void *) * ud->num_channels, GFP_KERNEL);
	if (!ud->keys) {
		printk("Error: cannot allocate usrdata.keys[].\n");
		return -ENOMEM;
	}

	return 0;
}

int register_peer_channel(struct mcctrl_usrdata *ud, void *key, struct mcctrl_channel *ch)
{
	int cpu;

	cpu = ch - ud->channels;
	if ((cpu < 0) || (ud->num_channels <= cpu)) {
		printk("register_peer_channel(%p,%p,%p):"
				"not a syscall channel. cpu=%d\n",
				ud, key, ch, cpu);
		return -EINVAL;
	}

	if (ud->keys[cpu] != NULL) {
		printk("register_peer_channel(%p,%p,%p):"
				"already registered. cpu=%d\n",
				ud, key, ch, cpu);
		/*
		 * When mcexec receives a signal,
		 * it may be finished without doing deregister_peer_channel().
		 * Therefore a substitute registration is necessary.
		 */
#if 0
		return -EBUSY;
#endif
	}

	ud->keys[cpu] = key;
	return 0;
}

int deregister_peer_channel(struct mcctrl_usrdata *ud, void *key, struct mcctrl_channel *ch)
{
	int cpu;

	cpu = ch - ud->channels;
	if ((cpu < 0) || (ud->num_channels <= cpu)) {
		printk("deregister_peer_channel(%p,%p,%p):"
				"not a syscall channel. cpu=%d\n",
				ud, key, ch, cpu);
		return -EINVAL;
	}

	if (ud->keys[cpu] && (ud->keys[cpu] != key)) {
		printk("deregister_peer_channel(%p,%p,%p):"
				"not registered. cpu=%d\n",
				ud, key, ch, cpu);
		return -EBUSY;
	}

	ud->keys[cpu] = NULL;
	return 0;
}

struct mcctrl_channel *get_peer_channel(struct mcctrl_usrdata *ud, void *key)
{
	int cpu;

	for (cpu = 0; cpu < ud->num_channels; ++cpu) {
		if (ud->keys[cpu] == key) {
			return &ud->channels[cpu];
		}
	}

	return NULL;
}

#if 1	/* x86 depend, host OS side */
int translate_rva_to_rpa(ihk_os_t os, unsigned long rpt, unsigned long rva,
		unsigned long *rpap, unsigned long *pgsizep)
{
	unsigned long rpa;
	int offsh;
	int i;
	int ix;
	unsigned long phys;
	unsigned long *pt;
	int error;
	unsigned long pgsize;

	rpa = rpt;
	offsh = 39;
	pgsize = 0;
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
			error = -EFAULT;
			dprintk("Remote PTE is not present for 0x%lx (rpt: %lx) ?\n", rva, rpt);
			goto out;
		}

#define	PTE_PS	0x080
		if (pt[ix] & PTE_PS) {
			pgsize = 1UL << offsh;
			rpa = pt[ix] & ((1UL << 52) - 1) & ~(pgsize - 1);
			rpa |= rva & (pgsize - 1);
			ihk_device_unmap_virtual(ihk_os_to_dev(os), pt, PAGE_SIZE);
			ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);
			error = 0;
			goto found;
		}

		rpa = pt[ix] & ((1UL << 52) - 1) & ~((1UL << 12) - 1);
		offsh -= 9;
		ihk_device_unmap_virtual(ihk_os_to_dev(os), pt, PAGE_SIZE);
		ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);
	}
	pgsize = 1UL << 12;
	rpa |= rva & (pgsize - 1);

found:
	error = 0;
	*rpap = rpa;
	*pgsizep = pgsize;

out:
	dprintk("translate_rva_to_rpa: %d rva %#lx --> rpa %#lx (%lx)\n",
			error, rva, rpa, pgsize);
	return error;
}
#endif

static int remote_page_fault(struct mcctrl_usrdata *usrdata, void *fault_addr, uint64_t reason)
{
	struct mcctrl_channel *channel;
	struct syscall_request *req;
	struct syscall_response *resp;
	int error;
	
	dprintk("remote_page_fault(%p,%p,%llx)\n", usrdata, fault_addr, reason);

	channel = get_peer_channel(usrdata, current);
	if (!channel) {
		error = -ENOENT;
		printk("remote_page_fault(%p,%p,%llx):channel not found. %d\n",
				usrdata, fault_addr, reason, error);
		goto out;
	}

	req = channel->param.request_va;
	resp = channel->param.response_va;

	/* request page fault */
	resp->ret = -EFAULT;
	resp->fault_address = (unsigned long)fault_addr;
	resp->fault_reason = reason;

#define STATUS_PAGER_COMPLETED	1
#define	STATUS_PAGE_FAULT	3
	req->valid = 0;
	mb();
	resp->status = STATUS_PAGE_FAULT;

	for (;;) {
		struct wait_queue_head_list_node *wqhln;
		struct wait_queue_head_list_node *wqhln_iter;
		unsigned long irqflags;
		
retry_alloc:
		wqhln = kmalloc(sizeof(*wqhln), GFP_KERNEL);
		if (!wqhln) {
			printk("WARNING: coudln't alloc wait queue head, retrying..\n");
			goto retry_alloc;
		}

		/* Prepare per-process wait queue head */
		wqhln->pid = current->tgid;	
		wqhln->req = 0;
		init_waitqueue_head(&wqhln->wq_syscall);

		irqflags = ihk_ikc_spinlock_lock(&channel->wq_list_lock);
		/* First see if there is a wait queue already */
		list_for_each_entry(wqhln_iter, &channel->wq_list, list) {
			if (wqhln_iter->pid == current->tgid) {
				kfree(wqhln);
				wqhln = wqhln_iter;
				list_del(&wqhln->list);
				break;
			}
		}
		list_add_tail(&wqhln->list, &channel->wq_list);
		ihk_ikc_spinlock_unlock(&channel->wq_list_lock, irqflags);

		/* wait for response */
		error = wait_event_interruptible(wqhln->wq_syscall, wqhln->req);

		/* Remove per-process wait queue head */
		irqflags = ihk_ikc_spinlock_lock(&channel->wq_list_lock);
		list_del(&wqhln->list);
		ihk_ikc_spinlock_unlock(&channel->wq_list_lock, irqflags);
		kfree(wqhln);

		if (error) {
			printk("remote_page_fault:interrupted. %d\n", error);
			goto out;
		}
		if (!req->valid) {
			printk("remote_page_fault:not valid\n");
		}
		req->valid = 0;

		/* check result */
		if (req->number != __NR_mmap) {
			printk("remote_page_fault:unexpected response. %lx %lx\n",
					req->number, req->args[0]);
			error = -EIO;
			goto out;
		}
#define	PAGER_REQ_RESUME	0x0101
		else if (req->args[0] != PAGER_REQ_RESUME) {
			resp->ret = pager_call(usrdata->os, (void *)req);
			mb();
			resp->status = STATUS_PAGER_COMPLETED;
			continue;
		}
		else {
			error = req->args[1];
			if (error) {
				printk("remote_page_fault:response %d\n", error);
				goto out;
			}
		}
		break;
	}

	error = 0;
out:
	dprintk("remote_page_fault(%p,%p,%llx): %d\n", usrdata, fault_addr, reason, error);
	return error;
}

/*
 * By remap_pfn_range(), VM_PFN_AT_MMAP may be raised.
 * VM_PFN_AT_MMAP cause the following problems.
 *
 * 1) vm_pgoff is changed. As a result, i_mmap tree is corrupted.
 * 2) duplicate free_memtype() calls occur.
 *
 * These problems may be solved in linux-3.7.
 * It uses vm_insert_pfn() until it is fixed.
 */

/* TODO: figure out the correct Linux kernel version for this check,
 * as for now, ihk-smp-x86 reloading works fine on 3.x.x kernels 
 * using remap_pfn_range().
 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,0,0)
#define	USE_VM_INSERT_PFN	0
#else
#define	USE_VM_INSERT_PFN	1
#endif

static int rus_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct mcctrl_usrdata *	usrdata	= vma->vm_file->private_data;
	ihk_device_t		dev = ihk_os_to_dev(usrdata->os);
	unsigned long		rpa;
	unsigned long		phys;
	int			error;
	int			try;
	uint64_t		reason;
	unsigned long		pgsize;
	unsigned long		rva;
	unsigned long		pfn;
#if USE_VM_INSERT_PFN
	size_t			pix;
#endif
	struct mcctrl_per_proc_data *ppd, *ppd_iter;
	unsigned long flags;

	dprintk("mcctrl:page fault:flags %#x pgoff %#lx va %p page %p\n",
			vmf->flags, vmf->pgoff, vmf->virtual_address, vmf->page);
	
	ppd = NULL;
	flags = ihk_ikc_spinlock_lock(&usrdata->per_proc_list_lock);
	
	list_for_each_entry(ppd_iter, &usrdata->per_proc_list, list) {
		if (ppd_iter->pid == current->tgid) {
			ppd = ppd_iter;
			break;
		}
	}
	ihk_ikc_spinlock_unlock(&usrdata->per_proc_list_lock, flags);

	if (!ppd) {
		printk("ERROR: no per process data for pid %d\n", current->tgid);
		return VM_FAULT_SIGBUS;
	}

	for (try = 1; ; ++try) {
		error = translate_rva_to_rpa(usrdata->os, ppd->rpgtable,
				(unsigned long)vmf->virtual_address,
				&rpa, &pgsize);
#define	NTRIES 2
		if (!error || (try >= NTRIES)) {
			if (error) {
				printk("translate_rva_to_rpa: error\n");
			}

			break;
		}

		reason = 0;
		if (vmf->flags & FAULT_FLAG_WRITE) {
#define	PF_WRITE	0x02
			reason |= PF_WRITE;
		}
		error = remote_page_fault(usrdata, vmf->virtual_address, reason);
		if (error) {
			printk("forward_page_fault failed. %d\n", error);
			break;
		}
	}
	if (error) {
		printk("mcctrl:page fault error:flags %#x pgoff %#lx va %p page %p\n",
				vmf->flags, vmf->pgoff, vmf->virtual_address, vmf->page);
		return VM_FAULT_SIGBUS;
	}

	rva = (unsigned long)vmf->virtual_address & ~(pgsize - 1);
	rpa = rpa & ~(pgsize - 1);

	phys = ihk_device_map_memory(dev, rpa, pgsize);
	pfn = phys >> PAGE_SHIFT;
#if USE_VM_INSERT_PFN
	for (pix = 0; pix < (pgsize / PAGE_SIZE); ++pix) {
		struct page *page;

		if (pfn_valid(pfn+pix)) {
			page = pfn_to_page(pfn+pix);
			if (!page_count(page)) {
				get_page(page);
				/*
				 * TODO:
				 * The pages which get_page() has been called with
				 * should be recorded.  Because these pages have to
				 * be passed to put_page() before they are freed.
				 */
			}
			error = vm_insert_page(vma, rva+(pix*PAGE_SIZE), page);
			if (error) {
				printk("vm_insert_page: %d\n", error);
			}
		}
		else
		error = vm_insert_pfn(vma, rva+(pix*PAGE_SIZE), pfn+pix);
		if (error) {
			break;
		}
	}
#else
	error = remap_pfn_range(vma, rva, pfn, pgsize, vma->vm_page_prot);
#endif
	ihk_device_unmap_memory(dev, phys, pgsize);
	if (error) {
		printk("mcctrl:page fault:remap error:flags %#x pgoff %#lx va %p page %p\n",
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	vma->vm_flags |= VM_RESERVED | VM_DONTEXPAND | VM_MIXEDMAP;
#else
	vma->vm_flags |= VM_DONTDUMP | VM_DONTEXPAND | VM_MIXEDMAP;
#endif
	vma->vm_ops = &rus_vmops;
	return 0;
}

static struct file_operations rus_fops = {
	.mmap = &rus_mmap,
};

int reserve_user_space(struct mcctrl_usrdata *usrdata, unsigned long *startp, unsigned long *endp)
{
	struct file *file;
	struct vm_area_struct *vma;
	unsigned long start;
	unsigned long end;
	struct cred *promoted;
	const struct cred *original;

	file = anon_inode_getfile("[mckernel]", &rus_fops, usrdata, O_RDWR);
	if (IS_ERR(file)) {
		return PTR_ERR(file);
	}

	promoted = prepare_creds();
	if (!promoted) {
		printk("mcctrl:user space reservation failed. ENOMEM\n");
		fput(file);
		return -ENOMEM;
	}
	/*
	 * CAP_SYS_RAWIO for mmap_min_addr check avoidance
	 */
	cap_raise(promoted->cap_effective, CAP_SYS_RAWIO);
	original = override_creds(promoted);

#define	DESIRED_USER_END	0x800000000000
#define	GAP_FOR_MCEXEC		0x008000000000UL
	end = DESIRED_USER_END;
	down_write(&current->mm->mmap_sem);
	vma = find_vma(current->mm, 0);
	if (vma) {
		end = (vma->vm_start - GAP_FOR_MCEXEC) & ~(GAP_FOR_MCEXEC - 1);
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
	start = do_mmap_pgoff(file, 0, end,
			PROT_READ|PROT_WRITE, MAP_FIXED|MAP_SHARED, 0);
#endif			

	up_write(&current->mm->mmap_sem);
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	start = vm_mmap(file, 0, end,
			PROT_READ|PROT_WRITE, MAP_FIXED|MAP_SHARED, 0);
#endif			

	revert_creds(original);
	put_cred(promoted);
	fput(file);
	if (IS_ERR_VALUE(start)) {
		printk("mcctrl:user space reservation failed.\n");
		return start;
	}

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

struct pager {
	struct list_head	list;
	struct inode *		inode;
	int			ref;
	struct file *		rofile;
	struct file *		rwfile;
	uintptr_t		map_uaddr;
	size_t			map_len;
	off_t			map_off;
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

static int pager_req_create(ihk_os_t os, int fd, uintptr_t result_pa)
{
	ihk_device_t dev = ihk_os_to_dev(os);
	int error;
	struct pager_create_result *resp;
	int maxprot = -1;
	struct file *file = NULL;
	struct inode *inode;
	struct pager *pager = NULL;
	struct pager *newpager = NULL;
	uintptr_t phys;
	struct kstat st;

	dprintk("pager_req_create(%d,%lx)\n", fd, (long)result_pa);

	error = vfs_fstat(fd, &st);
	if (error) {
		dprintk("pager_req_create(%d,%lx):vfs_stat failed. %d\n", fd, (long)result_pa, error);
		goto out;
	}
	if (!S_ISREG(st.mode)) {
		error = -ESRCH;
		dprintk("pager_req_create(%d,%lx):not VREG. %x\n", fd, (long)result_pa, st.mode);
		goto out;
	}

	file = fget(fd);
	if (!file) {
		error = -EBADF;
		dprintk("pager_req_create(%d,%lx):file not found. %d\n", fd, (long)result_pa, error);
		goto out;
	}

	inode = file->f_path.dentry->d_inode;
	if (!inode) {
		error = -EBADF;
		printk("pager_req_create(%d,%lx):inode not found. %d\n", fd, (long)result_pa, error);
		goto out;
	}

	maxprot = 0;
	if ((file->f_mode & FMODE_READ) && (file->f_mode & FMODE_PREAD)) {
		maxprot |= PROT_READ;
	}
	if ((file->f_mode & FMODE_WRITE) && (file->f_mode & FMODE_PWRITE)) {
		maxprot |= PROT_WRITE;
	}
	if (!(file->f_path.mnt->mnt_flags & MNT_NOEXEC)) {
		maxprot |= PROT_EXEC;
	}
	if (!(maxprot & PROT_READ)) {
		error = -EACCES;
		dprintk("pager_req_create(%d,%lx):cannot read file. %d\n", fd, (long)result_pa, error);
		goto out;
	}

	for (;;) {
		error = down_interruptible(&pager_sem);
		if (error) {
			error = -EINTR;
			printk("pager_req_create(%d,%lx):signaled. %d\n", fd, (long)result_pa, error);
			goto out;
		}

		list_for_each_entry(pager, &pager_list, list) {
			if (pager->inode == inode) {
				goto found;
			}
		}

		if (newpager) {
			newpager->inode = inode;
			newpager->ref = 0;
			list_add(&newpager->list, &pager_list);
			pager = newpager;
			newpager = NULL;
			break;
		}

		up(&pager_sem);

		newpager = kzalloc(sizeof(*newpager), GFP_KERNEL);
		if (!newpager) {
			error = -ENOMEM;
			printk("pager_req_create(%d,%lx):kzalloc failed. %d\n", fd, (long)result_pa, error);
			goto out;
		}
	}

found:
	++pager->ref;
	if (!pager->rwfile && (maxprot & PROT_WRITE)) {
		get_file(file);
		pager->rwfile = file;
	}
	else if (!pager->rofile && !(maxprot & PROT_WRITE)) {
		get_file(file);
		pager->rofile = file;
	}
	up(&pager_sem);

	phys = ihk_device_map_memory(dev, result_pa, sizeof(*resp));
	resp = ihk_device_map_virtual(dev, phys, sizeof(*resp), NULL, 0);
	resp->handle = (uintptr_t)pager;
	resp->maxprot = maxprot;
	ihk_device_unmap_virtual(dev, resp, sizeof(*resp));
	ihk_device_unmap_memory(dev, phys, sizeof(*resp));

	error = 0;
out:
	if (newpager) {
		kfree(newpager);
	}
	if (file) {
		fput(file);
	}
	dprintk("pager_req_create(%d,%lx): %d %p %x\n",
			fd, (long)result_pa, error, pager, maxprot);
	return error;
}

static int pager_req_release(ihk_os_t os, uintptr_t handle, int unref)
{
	int error;
	struct pager *p;
	struct pager *free_pager = NULL;

	dprintk("pager_req_relase(%p,%lx,%d)\n", os, handle, unref);

	error = down_interruptible(&pager_sem);
	if (error) {
		printk("pager_req_relase(%p,%lx,%d):signaled. %d\n", os, handle, unref, error);
		goto out;
	}

	error = -EBADF;
	list_for_each_entry(p, &pager_list, list) {
		if ((uintptr_t)p == handle) {
			error = 0;
			p->ref -= unref;
			if (p->ref <= 0) {
				list_del(&p->list);
				free_pager = p;
			}
			break;
		}
	}

	up(&pager_sem);

	if (error) {
		printk("pager_req_relase(%p,%lx,%d):pager not found. %d\n", os, handle, unref, error);
		goto out;
	}

	if (free_pager) {
		if (free_pager->rofile) {
			fput(free_pager->rofile);
		}
		if (free_pager->rwfile) {
			fput(free_pager->rwfile);
		}
		kfree(free_pager);
	}

	error = 0;
out:
	dprintk("pager_req_relase(%p,%lx,%d): %d\n", os, handle, unref, error);
	return error;
}

static int pager_req_read(ihk_os_t os, uintptr_t handle, off_t off, size_t size, uintptr_t rpa)
{
	ssize_t ss;
	struct pager *pager;
	struct file *file = NULL;
	uintptr_t phys = -1;
	ihk_device_t dev = ihk_os_to_dev(os);
	void *buf = NULL;
	mm_segment_t fs;
	loff_t pos;

	dprintk("pager_req_read(%lx,%lx,%lx,%lx)\n", handle, off, size, rpa);

	ss = down_interruptible(&pager_sem);
	if (ss) {
		printk("pager_req_read(%lx,%lx,%lx,%lx): signaled. %ld\n", handle, off, size, rpa, ss);
		goto out;
	}

	list_for_each_entry(pager, &pager_list, list) {
		if ((uintptr_t)pager == handle) {
			file = (pager->rofile)? pager->rofile: pager->rwfile;
			get_file(file);
			break;
		}
	}
	up(&pager_sem);

	if (!file) {
		ss = -EBADF;
		printk("pager_req_read(%lx,%lx,%lx,%lx):pager not found. %ld\n", handle, off, size, rpa, ss);
		goto out;
	}

	phys = ihk_device_map_memory(dev, rpa, size);
	buf = ihk_device_map_virtual(dev, phys, size, NULL, 0);
	fs = get_fs();
	set_fs(KERNEL_DS);
	pos = off;
	ss = vfs_read(file, buf, size, &pos);
	if ((ss != size) && (ss > 0)) {
		if (clear_user(buf+ss, size-ss) == 0) {
			ss = size;
		}
		else {
			ss = -EFAULT;
		}
	}
	set_fs(fs);
	if (ss < 0) {
		printk("pager_req_read(%lx,%lx,%lx,%lx):pread failed. %ld\n", handle, off, size, rpa, ss);
		goto out;
	}

out:
	if (buf) {
		ihk_device_unmap_virtual(dev, buf, size);
	}
	if (phys != (uintptr_t)-1) {
		ihk_device_unmap_memory(dev, phys, size);
	}
	if (file) {
		fput(file);
	}
	dprintk("pager_req_read(%lx,%lx,%lx,%lx): %ld\n", handle, off, size, rpa, ss);
	return ss;
}

static int pager_req_write(ihk_os_t os, uintptr_t handle, off_t off, size_t size, uintptr_t rpa)
{
	ssize_t ss;
	struct pager *pager;
	struct file *file = NULL;
	uintptr_t phys = -1;
	ihk_device_t dev = ihk_os_to_dev(os);
	void *buf = NULL;
	mm_segment_t fs;
	loff_t pos;
	loff_t fsize;
	size_t len;

	dprintk("pager_req_write(%lx,%lx,%lx,%lx)\n", handle, off, size, rpa);

	ss = down_interruptible(&pager_sem);
	if (ss) {
		printk("pager_req_write(%lx,%lx,%lx,%lx): signaled. %ld\n", handle, off, size, rpa, ss);
		goto out;
	}

	list_for_each_entry(pager, &pager_list, list) {
		if ((uintptr_t)pager == handle) {
			file = pager->rwfile;
			break;
		}
	}
	if (file) {
		get_file(file);
	}
	up(&pager_sem);

	if (!file) {
		ss = -EBADF;
		printk("pager_req_write(%lx,%lx,%lx,%lx):pager not found. %ld\n", handle, off, size, rpa, ss);
		goto out;
	}

	/*
	 * XXX: vfs_write 位の階層を使いつつ，
	 * ファイルサイズ更新を回避する方法ないかな？
	 */
	fsize = i_size_read(file->f_mapping->host);
	if (off >= fsize) {
		ss = 0;
		goto out;
	}

	phys = ihk_device_map_memory(dev, rpa, size);
	buf = ihk_device_map_virtual(dev, phys, size, NULL, 0);
	fs = get_fs();
	set_fs(KERNEL_DS);
	pos = off;
	len = size;
	if ((off + size) > fsize) {
		len = fsize - off;
	}
	ss = vfs_write(file, buf, len, &pos);
	set_fs(fs);
	if (ss < 0) {
		printk("pager_req_write(%lx,%lx,%lx,%lx):pwrite failed. %ld\n", handle, off, size, rpa, ss);
		goto out;
	}

out:
	if (buf) {
		ihk_device_unmap_virtual(dev, buf, size);
	}
	if (phys != (uintptr_t)-1) {
		ihk_device_unmap_memory(dev, phys, size);
	}
	if (file) {
		fput(file);
	}
	dprintk("pager_req_write(%lx,%lx,%lx,%lx): %ld\n", handle, off, size, rpa, ss);
	return ss;
}

struct pager_map_result {
	uintptr_t	handle;
	int		maxprot;
	int8_t		padding[4];
};

static int pager_req_map(ihk_os_t os, int fd, size_t len, off_t off, uintptr_t result_rpa)
{
	const ihk_device_t dev = ihk_os_to_dev(os);
	const off_t pgoff = off / PAGE_SIZE;
	int error;
	struct file *file = NULL;
	uintptr_t va = -1;
	int maxprot;
	struct pager *pager = NULL;
	struct pager_map_result *resp;
	uintptr_t phys;

	dprintk("pager_req_map(%p,%d,%lx,%lx,%lx)\n", os, fd, len, off, result_rpa);
	pager = kzalloc(sizeof(*pager), GFP_KERNEL);
	if (!pager) {
		error = -ENOMEM;
		printk("pager_req_map(%p,%d,%lx,%lx,%lx):kzalloc failed. %d\n", os, fd, len, off, result_rpa, error);
		goto out;
	}

	file = fget(fd);
	if (!file) {
		error = -EBADF;
		printk("pager_req_map(%p,%d,%lx,%lx,%lx):fget failed. %d\n", os, fd, len, off, result_rpa, error);
		goto out;
	}

	maxprot = 0;
	if (file->f_mode & FMODE_READ) {
		maxprot |= PROT_READ;
	}
	if (file->f_mode & FMODE_WRITE) {
		maxprot |= PROT_WRITE;
	}
	if (!(file->f_path.mnt->mnt_flags & MNT_NOEXEC)) {
		maxprot |= PROT_EXEC;
	}

	down_write(&current->mm->mmap_sem);
#define	ANY_WHERE 0

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
	va = do_mmap_pgoff(file, ANY_WHERE, len, maxprot, MAP_SHARED, pgoff);
#endif	

	up_write(&current->mm->mmap_sem);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	va = vm_mmap(file, ANY_WHERE, len, maxprot, MAP_SHARED, pgoff << PAGE_SHIFT);
#endif

	if (IS_ERR_VALUE(va)) {
		printk("pager_req_map(%p,%d,%lx,%lx,%lx):do_mmap_pgoff failed. %d\n", os, fd, len, off, result_rpa, (int)va);
		error = va;
		goto out;
	}

	pager->ref = 1;
	pager->map_uaddr = va;
	pager->map_len = len;
	pager->map_off = off;
	
	dprintk("pager_req_map(%s): 0x%lx - 0x%lx (len: %lu)\n", 
			file->f_dentry->d_name.name, va, va + len, len);

	phys = ihk_device_map_memory(dev, result_rpa, sizeof(*resp));
	resp = ihk_device_map_virtual(dev, phys, sizeof(*resp), NULL, 0);
	resp->handle = (uintptr_t)pager;
	resp->maxprot = maxprot;
	ihk_device_unmap_virtual(dev, resp, sizeof(*resp));
	ihk_device_unmap_memory(dev, phys, sizeof(*resp));

	error = 0;
	pager = 0; /* pager should be in list? */

out:
	if (file) {
		fput(file);
	}
	if (pager) {
		kfree(pager);
	}
	dprintk("pager_req_map(%p,%d,%lx,%lx,%lx): %d\n", os, fd, len, off, result_rpa, error);
	return error;
}


static int pager_req_pfn(ihk_os_t os, uintptr_t handle, off_t off, uintptr_t ppfn_rpa)
{
	const ihk_device_t dev = ihk_os_to_dev(os);
	struct pager * const pager = (void *)handle;
	int error;
	uintptr_t pfn;
	uintptr_t va;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	uintptr_t phys;
	uintptr_t *ppfn;

	dprintk("pager_req_pfn(%p,%lx,%lx)\n", os, handle, off);

	if ((off < pager->map_off) || ((pager->map_off+pager->map_len) < (off + PAGE_SIZE))) {
		error = -ERANGE;
		pfn = 0;
		printk("pager_req_pfn(%p,%lx,%lx):out of range. %d [%lx..%lx)\n", os, handle, off, error, pager->map_off, pager->map_off+pager->map_len);
		goto out;
	}

	va = pager->map_uaddr + (off - pager->map_off);
#define	PFN_VALID	((uintptr_t)1 << 63)
	pfn = PFN_VALID;	/* デフォルトは not present */

	down_read(&current->mm->mmap_sem);
	pgd = pgd_offset(current->mm, va);
	if (!pgd_none(*pgd) && !pgd_bad(*pgd) && pgd_present(*pgd)) {
		pud = pud_offset(pgd, va);
		if (!pud_none(*pud) && !pud_bad(*pud) && pud_present(*pud)) {
			pmd = pmd_offset(pud, va);
			if (!pmd_none(*pmd) && !pmd_bad(*pmd) && pmd_present(*pmd)) {
				pte = pte_offset_map(pmd, va);
				if (!pte_none(*pte) && pte_present(*pte)) {
					pfn = (uintptr_t)pte_pfn(*pte) << PAGE_SHIFT;
#define	PFN_PRESENT	((uintptr_t)1 << 0)
					pfn |= PFN_VALID | PFN_PRESENT;
					
					/* Check if mapping is write-combined */
					if (pte_flags(*pte) & _PAGE_CACHE_WC) {
						pfn |= _PAGE_CACHE_WC;
					}
				}
				pte_unmap(pte);
			}
		}
	}
	up_read(&current->mm->mmap_sem);

	phys = ihk_device_map_memory(dev, ppfn_rpa, sizeof(*ppfn));
	ppfn = ihk_device_map_virtual(dev, phys, sizeof(*ppfn), NULL, 0);
	*ppfn = pfn;
	ihk_device_unmap_virtual(dev, ppfn, sizeof(*ppfn));
	ihk_device_unmap_memory(dev, phys, sizeof(*ppfn));

	error = 0;
out:
	dprintk("pager_req_pfn(%p,%lx,%lx): %d %lx\n", os, handle, off, error, pfn);
	return error;
}

static int pager_req_unmap(ihk_os_t os, uintptr_t handle)
{
	struct pager * const pager = (void *)handle;
	int error;

	dprintk("pager_req_unmap(%p,%lx)\n", os, handle);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
	down_write(&current->mm->mmap_sem);
	error = do_munmap(current->mm, pager->map_uaddr, pager->map_len);
	up_write(&current->mm->mmap_sem);
#else
	error = vm_munmap(pager->map_uaddr, pager->map_len);
#endif

	if (error) {
		printk("pager_req_unmap(%p,%lx):do_munmap failed. %d\n", os, handle, error);
		/* through */
	}

	kfree(pager);
	dprintk("pager_req_unmap(%p,%lx): %d\n", os, handle, error);
	return error;
}

static long pager_call(ihk_os_t os, struct syscall_request *req)
{
	long ret;

	dprintk("pager_call(%#lx)\n", req->args[0]);
	switch (req->args[0]) {
#define	PAGER_REQ_CREATE	0x0001
#define	PAGER_REQ_RELEASE	0x0002
#define	PAGER_REQ_READ		0x0003
#define	PAGER_REQ_WRITE		0x0004
#define	PAGER_REQ_MAP		0x0005
#define	PAGER_REQ_PFN		0x0006
#define	PAGER_REQ_UNMAP		0x0007
	case PAGER_REQ_CREATE:
		ret = pager_req_create(os, req->args[1], req->args[2]);
		break;

	case PAGER_REQ_RELEASE:
		ret = pager_req_release(os, req->args[1], req->args[2]);
		break;

	case PAGER_REQ_READ:
		ret = pager_req_read(os, req->args[1], req->args[2], req->args[3], req->args[4]);
		break;

	case PAGER_REQ_WRITE:
		ret = pager_req_write(os, req->args[1], req->args[2], req->args[3], req->args[4]);
		break;

	case PAGER_REQ_MAP:
		ret = pager_req_map(os, req->args[1], req->args[2], req->args[3], req->args[4]);
		break;

	case PAGER_REQ_PFN:
		ret = pager_req_pfn(os, req->args[1], req->args[2], req->args[3]);
		break;

	case PAGER_REQ_UNMAP:
		ret = pager_req_unmap(os, req->args[1]);
		break;

	default:
		ret = -ENOSYS;
		printk("pager_call(%#lx):unknown req %ld\n", req->args[0], ret);
		break;
	}

	dprintk("pager_call(%#lx): %ld\n", req->args[0], ret);
	return ret;
}

static void __return_syscall(struct mcctrl_channel *c, int ret)
{
	c->param.response_va->ret = ret;
	mb();
	c->param.response_va->status = 1;
}

static int remap_user_space(uintptr_t rva, size_t len, int prot)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	struct file *file;
	uintptr_t start;
	pgoff_t pgoff;
	uintptr_t map;

	dprintk("remap_user_space(%lx,%lx,%x)\n", rva, len, prot);
	down_write(&mm->mmap_sem);
	vma = find_vma(mm, rva);
	if (!vma || (rva < vma->vm_start)) {
		printk("remap_user_space(%lx,%lx,%x):find_vma failed. %p %lx %lx\n",
				rva, len, prot, vma,
				(vma)? vma->vm_start: -1,
				(vma)? vma->vm_end: 0);
		up_write(&mm->mmap_sem);
		map = -ENOMEM;
		goto out;
	}

	file = vma->vm_file;
	start = rva;
	pgoff = vma->vm_pgoff + ((rva - vma->vm_start) >> PAGE_SHIFT);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
	map = do_mmap_pgoff(file, start, len,
			prot, MAP_FIXED|MAP_SHARED, pgoff);
#endif

	up_write(&mm->mmap_sem);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	map = vm_mmap(file, start, len,
			prot, MAP_FIXED|MAP_SHARED, pgoff << PAGE_SHIFT);
#endif

out:
	dprintk("remap_user_space(%lx,%lx,%x): %lx (%ld)\n",
			rva, len, prot, (long)map, (long)map);
	return (IS_ERR_VALUE(map))? (int)map: 0;
}

static int clear_pte_range(uintptr_t start, uintptr_t len)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	uintptr_t addr;
	uintptr_t end;
	int error;
	int ret;

	ret = 0;
	down_read(&mm->mmap_sem);
	addr = start;
	while (addr < (start + len)) {
		vma = find_vma(mm, addr);
		if (!vma) {
			break;
		}

		if (addr < vma->vm_start) {
			addr = vma->vm_start;
		}
		end = start + len;
		if (vma->vm_end < end) {
			end = vma->vm_end;
		}
		if (addr < end) {
			error = zap_vma_ptes(vma, addr, end-addr);
			if (ret == 0) {
				ret = error;
			}
		}
		addr = end;
	}
	up_read(&mm->mmap_sem);
	return ret;
}

/**
 * \brief Write out the core file image to a core file.
 *
 * \param os An ihk_os_t structure.
 * \param rcoretable The physical address of remote's coretable.
 * \param chunks The number of chunks which make a core file image in the whole.
 */

static int writecore(ihk_os_t os, unsigned long rcoretable, int chunks) {
	struct file *file;
	struct coretable *coretable;
	int ret, i, tablesize, size, error = 0;
	mm_segment_t oldfs = get_fs(); 
	unsigned long phys, tablephys, rphys;
	ihk_device_t dev = ihk_os_to_dev(os);
	char *pt;

	dprintk("coredump called as a pseudo syscall\n");

	if (chunks <= 0) {
		dprintk("no core data found!(%d)\n", chunks);
		error = -EINVAL;
		goto fail;
	}

	set_fs(KERNEL_DS);

	/* Every Linux documentation insists we should not 
	 * open a file in the kernel module, but our karma 
	 * leads us here. Precisely, Here we emulate the core 
	 * dump routine of the Linux kernel in linux/fs/exec.c. 
	 * So we have a legitimate reason to do this.
	 */
	file = filp_open("core", O_CREAT | O_RDWR | O_LARGEFILE, 0600);
	if (IS_ERR(file) || !file->f_op || !file->f_op->write) {
		dprintk("cannot open core file\n");
		error = PTR_ERR(file);
		goto fail;
	}			

	/* first we map the chunk table */
	tablesize = sizeof(struct coretable) * chunks;
	tablephys = ihk_device_map_memory(dev, rcoretable, tablesize);
	coretable = ihk_device_map_virtual(dev, tablephys, tablesize, NULL, 0);
	for (i = 0; i < chunks; i++) {
		/* map and write the chunk out */
		rphys = coretable[i].addr;
		size = coretable[i].len;
		if (rphys != 0) {
			dprintk("mapping remote %x@%lx -> ", size, rphys);
			phys = ihk_device_map_memory(dev, rphys, size);
			dprintk("physical %lx, ", phys);
			pt = ihk_device_map_virtual(dev, phys, size, NULL, 0);
			dprintk("virtual %p\n", pt);
			if (pt != NULL) {
				ret = file->f_op->write(file, pt, size, &file->f_pos);
			} else {
				dprintk("cannot map physical memory(%lx) to virtual memory.\n", 
					phys);
				ihk_device_unmap_memory(dev, phys, size);
				break;
			}			
			/* unmap the chunk */
			ihk_device_unmap_virtual(dev, pt, size);
			ihk_device_unmap_memory(dev, phys, size);
			if (ret != size) {
				dprintk("core file write failed(%d).\n", ret);
				error = PTR_ERR(file);
				break;
			}
		} else {
			/* We skip if the physical address is NULL
			   and make the core file sparse. */
			if (!file->f_op->llseek || (file->f_op->llseek == no_llseek)) {
				dprintk("We have no llseek. The core file is truncated.\n");
				error = -EINVAL;
			}
			ret = file->f_op->llseek(file, size, SEEK_CUR);
			if (ret < 0) {
				dprintk("core file seek failed(%d).\n", ret);
				error = PTR_ERR(file);
				break;
			}
		}
	}
	/* unmap the chunk table */
	ihk_device_unmap_virtual(dev, coretable, tablesize);
	ihk_device_unmap_memory(dev, tablephys, tablesize);
	filp_close(file, NULL);
fail:
	set_fs(oldfs);
	if (error == -ENOSYS) {
		/* make sure we do not travel to user land */
		error = -EINVAL;
	}
	return error;
}

#define SCHED_CHECK_SAME_OWNER        0x01
#define SCHED_CHECK_ROOT              0x02

int __do_in_kernel_syscall(ihk_os_t os, struct mcctrl_channel *c, struct syscall_request *sc)
{
	int error;
	long ret = -1;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	dprintk("__do_in_kernel_syscall(%p,%p,%ld %lx)\n", os, c, sc->number, sc->args[0]);
	switch (sc->number) {
	case __NR_mmap:
		ret = pager_call(os, sc);
		break;

	case __NR_munmap:
		/* Set new remote page table if not zero */
		if (sc->args[2]) {
			unsigned long flags;
			struct mcctrl_per_proc_data *ppd = NULL;

			ppd = kmalloc(sizeof(*ppd), GFP_ATOMIC);
			if (!ppd) {
				printk("ERROR: allocating per process data\n");
				error = -ENOMEM;
				goto out;
			}

			ppd->pid = current->tgid;
			ppd->rpgtable = sc->args[2];

			flags = ihk_ikc_spinlock_lock(&usrdata->per_proc_list_lock);
			list_add_tail(&ppd->list, &usrdata->per_proc_list);
			ihk_ikc_spinlock_unlock(&usrdata->per_proc_list_lock, flags);

			dprintk("pid: %d, rpgtable: 0x%lx added\n", 
				ppd->pid, ppd->rpgtable);
		}

		error = clear_pte_range(sc->args[0], sc->args[1]);
		if (error) {
			error = -ENOSYS;
			goto out;
		}
		ret = 0;
		break;

	case __NR_mprotect:
		ret = remap_user_space(sc->args[0], sc->args[1], sc->args[2]);
		break;

	case __NR_exit_group: {
		unsigned long flags;
		struct mcctrl_per_proc_data *ppd = NULL, *ppd_iter;

		ppd = NULL;
		flags = ihk_ikc_spinlock_lock(&usrdata->per_proc_list_lock);
		
		list_for_each_entry(ppd_iter, &usrdata->per_proc_list, list) {
			if (ppd_iter->pid == current->tgid) {
				ppd = ppd_iter;
				break;
			}
		}
		
		if (ppd) {	
			list_del(&ppd->list);
			
			dprintk("pid: %d, tid: %d: rpgtable for %d (0x%lx) removed\n", 
				current->tgid, current->pid, ppd->pid, ppd->rpgtable);
			
			kfree(ppd);
		}
		else {
			printk("WARNING: no per process data for pid %d ?\n", 
					current->tgid);
		}

		ihk_ikc_spinlock_unlock(&usrdata->per_proc_list_lock, flags);
	
		/* Make sure the user space handler will be called as well */
		error = -ENOSYS;
		goto out;
		}

	case __NR_coredump:
		error = writecore(os, sc->args[1], sc->args[0]);
		ret = 0;
		break;
	
	case __NR_sched_setparam: {

		switch (sc->args[0]) {
			
			case SCHED_CHECK_SAME_OWNER: {
				const struct cred *cred = current_cred();
				const struct cred *pcred;
				bool match;
				struct task_struct *p;
				int pid = sc->args[1];
				
				rcu_read_lock();
				p = pid_task(find_get_pid(pid), PIDTYPE_PID);
				if (!p) {
					rcu_read_unlock();
					ret = -ESRCH;
					goto sched_setparam_out;
				}
				rcu_read_unlock();

				rcu_read_lock();
				pcred = __task_cred(p);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,4,0)
				match = (uid_eq(cred->euid, pcred->euid) ||
					 uid_eq(cred->euid, pcred->uid));
#else
				match = ((cred->euid == pcred->euid) ||
						(cred->euid == pcred->uid));
#endif
				rcu_read_unlock();
				
				if (match) {
					ret = 0;
				}
				else {
					ret = -EPERM;
				}
				
				break;
			}

			case SCHED_CHECK_ROOT: {
				const struct cred *cred = current_cred();
				bool match;
				
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,4,0)
				match = uid_eq(cred->euid, GLOBAL_ROOT_UID);
#else
				match = (cred->euid == 0);
#endif
				if (match) {
					ret = 0;
				}
				else {
					ret = -EPERM;
				}
				
				break;
			}
		}
			
sched_setparam_out:
		break;
	}

	default:
		error = -ENOSYS;
		goto out;
		break;
	}

	__return_syscall(c, ret);

	error = 0;
out:
	dprintk("__do_in_kernel_syscall(%p,%p,%ld %lx): %d %ld\n", os, c, sc->number, sc->args[0], error, ret);
	return error;
}
