/* syscall.c COPYRIGHT FUJITSU LIMITED 2016-2017 */
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
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2014  RIKEN AICS
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
#include <linux/spinlock.h>
#include <linux/mount.h>
#include <asm/uaccess.h>
#include <asm/delay.h>
#include <asm/io.h>
#include "../../../config.h"
#include "mcctrl.h"
#include <linux/version.h>
#ifdef POSTK_DEBUG_ARCH_DEP_83 /* arch depend translate_rva_to_rpa() move */
#include <archdeps.h>
#endif /* POSTK_DEBUG_ARCH_DEP_83 */

#define ALIGN_WAIT_BUF(z)   (((z + 63) >> 6) << 6)

//#define SC_DEBUG

#ifdef SC_DEBUG
#define	dprintk(...)	printk(__VA_ARGS__)
#else
#define	dprintk(...)
#endif

//#define DEBUG_PTD
#ifdef DEBUG_PTD
#define pr_ptd(msg, tid, ptd) do { printk("%s: " msg ",tid=%d,refc=%d\n", __FUNCTION__, tid, atomic_read(&ptd->refcount)); } while(0)
#else
#define pr_ptd(msg, tid, ptd) do { } while(0)
#endif

//#define DEBUG_PPD
#ifdef DEBUG_PPD
#define pr_ppd(msg, tid, ppd) do { printk("%s: " msg ",tid=%d,refc=%d\n", __FUNCTION__, tid, atomic_read(&ppd->refcount)); } while(0)
#else
#define pr_ppd(msg, tid, ppd) do { } while(0)
#endif

static long pager_call_irq(ihk_os_t os, struct syscall_request *req);
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

void mcctrl_put_per_thread_data_unsafe(struct mcctrl_per_thread_data *ptd)
{
	if (!atomic_dec_and_test(&ptd->refcount)) {
		int ret = atomic_read(&ptd->refcount);
		if (ret < 0) {
			printk("%s: ERROR: invalid refcount=%d\n", __FUNCTION__, ret);
		}
		return;
	}

	list_del(&ptd->hash);
	kfree(ptd);
}

void mcctrl_put_per_thread_data(struct mcctrl_per_thread_data* _ptd)
{
	struct mcctrl_per_proc_data *ppd = _ptd->ppd;
	struct mcctrl_per_thread_data *ptd_iter, *ptd = NULL;
	int hash = (((uint64_t)_ptd->task >> 4) & MCCTRL_PER_THREAD_DATA_HASH_MASK);
	unsigned long flags;

	/* Check if data for this thread exists and delete it */
	write_lock_irqsave(&ppd->per_thread_data_hash_lock[hash], flags);
	list_for_each_entry(ptd_iter, &ppd->per_thread_data_hash[hash], hash) {
		if (ptd_iter->task == _ptd->task) {
			ptd = ptd_iter;
			break;
		}
	}

	if (!ptd) {
		printk("%s: ERROR: ptd not found\n", __FUNCTION__);
		goto out;
	}

	mcctrl_put_per_thread_data_unsafe(ptd);
	
out:
	write_unlock_irqrestore(&ppd->per_thread_data_hash_lock[hash], flags);
}

int mcctrl_add_per_thread_data(struct mcctrl_per_proc_data *ppd, void *data)
{
	struct mcctrl_per_thread_data *ptd_iter, *ptd = NULL;
	struct mcctrl_per_thread_data *ptd_alloc = NULL;
	int hash = (((uint64_t)current >> 4) & MCCTRL_PER_THREAD_DATA_HASH_MASK);
	int ret = 0;
	unsigned long flags;

	ptd_alloc = kmalloc(sizeof(struct mcctrl_per_thread_data), GFP_ATOMIC);
	if (!ptd_alloc) {
		kprintf("%s: error allocate per thread data\n", __FUNCTION__);
		ret = -ENOMEM;
		goto out_noalloc;
	}
	memset(ptd_alloc, 0, sizeof(struct mcctrl_per_thread_data));
	
	/* Check if data for this thread exists and add if not */
	write_lock_irqsave(&ppd->per_thread_data_hash_lock[hash], flags);
	list_for_each_entry(ptd_iter, &ppd->per_thread_data_hash[hash], hash) {
		if (ptd_iter->task == current) {
			ptd = ptd_iter;
			break;
		}
	}

	if (unlikely(ptd)) {
		kprintf("%s: WARNING: ptd of tid: %d exists\n", __FUNCTION__, task_pid_vnr(current));
		ret = -EBUSY;
		kfree(ptd_alloc);
		goto out;
	}

	ptd = ptd_alloc;
	ptd->ppd = ppd;
	ptd->task = current;
	ptd->tid = task_pid_vnr(current);
	ptd->data = data;
	atomic_set(&ptd->refcount, 1);
	list_add_tail(&ptd->hash, &ppd->per_thread_data_hash[hash]); 

 out:
	write_unlock_irqrestore(&ppd->per_thread_data_hash_lock[hash], flags);
 out_noalloc:
	return ret;
}

#ifndef POSTK_DEBUG_ARCH_DEP_56 /* Strange how to use inline declaration fix. */
struct mcctrl_per_thread_data *mcctrl_get_per_thread_data(struct mcctrl_per_proc_data *ppd, struct task_struct *task)
{
	struct mcctrl_per_thread_data *ptd_iter, *ptd = NULL;
	int hash = (((uint64_t)task >> 4) & MCCTRL_PER_THREAD_DATA_HASH_MASK);
	unsigned long flags;

	/* Check if data for this thread exists */
	read_lock_irqsave(&ppd->per_thread_data_hash_lock[hash], flags);

	list_for_each_entry(ptd_iter, &ppd->per_thread_data_hash[hash], hash) {
		if (ptd_iter->task == task) {
			ptd = ptd_iter;
			break;
		}
	}

	if (ptd) {
		if (atomic_read(&ptd->refcount) <= 0) {
			printk("%s: ERROR: use-after-free detected (%d)", __FUNCTION__, atomic_read(&ptd->refcount));
			ptd = NULL;
			goto out;
		}
		atomic_inc(&ptd->refcount);
	}

 out:
	read_unlock_irqrestore(&ppd->per_thread_data_hash_lock[hash], flags);
	return ptd;
}
#endif /* !POSTK_DEBUG_ARCH_DEP_56 */

#ifndef POSTK_DEBUG_ARCH_DEP_83 /* arch depend translate_rva_to_rpa() move */
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

			/* For GB pages, just report regular 2MB page */
			if (offsh == 30) {
				pgsize = 1UL << 21;
				dprintk("%s: GB page translated 0x%lx -> 0x%lx, pgsize: %lu\n",
						__FUNCTION__, rva, rpa, pgsize);
			}

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
#endif /* !POSTK_DEBUG_ARCH_DEP_83 */

static int __notify_syscall_requester(ihk_os_t os, struct ikc_scd_packet *packet,
		struct syscall_response *res)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct ihk_ikc_channel_desc *c = (usrdata->channels + packet->ref)->c;
	struct ikc_scd_packet r_packet;
	int ret = 0;

	/* If spinning, no need for IKC message */
	if (__sync_bool_compare_and_swap(&res->req_thread_status,
				IHK_SCD_REQ_THREAD_SPINNING,
				IHK_SCD_REQ_THREAD_TO_BE_WOKEN)) {
		dprintk("%s: no need to send IKC message for PID %d\n",
			   __FUNCTION__, packet->pid);
		return ret;
	}

	/* Wait until the status goes back to IHK_SCD_REQ_THREAD_SPINNING or
	   IHK_SCD_REQ_THREAD_DESCHEDULED because two wake-up attempts are competing.
	   Note that mcexec_terminate_thread() and remote page fault and
	   returning EINTR would compete. */
	if (res->req_thread_status == IHK_SCD_REQ_THREAD_TO_BE_WOKEN) {
		printk("%s: INFO: someone else is waking up the McKernel thread, "
				"pid: %d, req status: %lu, syscall nr: %lu\n",
				__FUNCTION__, packet->pid,
				res->req_thread_status, packet->req.number);
	}

	/* The thread is not spinning any more, make sure it's descheduled */
	if (!__sync_bool_compare_and_swap(&res->req_thread_status,
				IHK_SCD_REQ_THREAD_DESCHEDULED,
				IHK_SCD_REQ_THREAD_TO_BE_WOKEN)) {
		printk("%s: WARNING: inconsistent requester status, "
				"pid: %d, req status: %lu, syscall nr: %lu\n",
				__FUNCTION__, packet->pid,
				res->req_thread_status, packet->req.number);
		dump_stack();

		return -EINVAL;
	}

	r_packet.msg = SCD_MSG_WAKE_UP_SYSCALL_THREAD;
	r_packet.ttid = packet->req.rtid;
	ret = ihk_ikc_send(c, &r_packet, 0);

	return ret;
}

long syscall_backward(struct mcctrl_usrdata *usrdata, int num,
                      unsigned long arg1, unsigned long arg2,
                      unsigned long arg3, unsigned long arg4,
                      unsigned long arg5, unsigned long arg6,
                      unsigned long *ret)
{
	struct ikc_scd_packet *packet;
    struct ikc_scd_packet *free_packet = NULL;
	struct syscall_request *req;
	struct syscall_response *resp;
	unsigned long syscall_ret;
	struct wait_queue_head_list_node *wqhln;
	unsigned long irqflags;
	struct mcctrl_per_proc_data *ppd;
	struct mcctrl_per_thread_data *ptd;
	unsigned long phys;
	struct syscall_request _request[2];
	struct syscall_request *request;
	int retry;

	if (((unsigned long)_request ^ (unsigned long)(_request + 1)) &
	    ~(PAGE_SIZE -1))
		request = _request + 1;
	else
		request = _request;
	request->number = num;
	request->args[0] = arg1;
	request->args[1] = arg2;
	request->args[2] = arg3;
	request->args[3] = arg4;
	request->args[4] = arg5;
	request->args[5] = arg6;


	/* Look up per-process structure */
	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));

	if (!ppd) {
		kprintf("%s: ERROR: no per-process structure for PID %d??\n", 
				__FUNCTION__, task_tgid_vnr(current));
		return -EINVAL;
	}

	ptd = mcctrl_get_per_thread_data(ppd, current);
	if (!ptd) {
		printk("%s: ERROR: mcctrl_get_per_thread_data failed\n", __FUNCTION__);
		syscall_ret = -ENOENT;
		goto no_ptd;
	}
	pr_ptd("get", task_pid_vnr(current), ptd);
	packet = (struct ikc_scd_packet *)ptd->data;
	if (!packet) {
		syscall_ret = -ENOENT;
		printk("%s: no packet registered for TID %d\n",
				__FUNCTION__, task_pid_vnr(current));
		goto out_put_ppd;
	}

	req = &packet->req;

	/* Map response structure */
	phys = ihk_device_map_memory(ihk_os_to_dev(usrdata->os), 
			packet->resp_pa, sizeof(*resp));
	resp = ihk_device_map_virtual(ihk_os_to_dev(usrdata->os), 
			phys, sizeof(*resp), NULL, 0);

retry_alloc:
	wqhln = kmalloc(sizeof(*wqhln), GFP_ATOMIC);
	if (!wqhln) {
		printk("WARNING: coudln't alloc wait queue head, retrying..\n");
		goto retry_alloc;
	}
	memset(wqhln, 0, sizeof(struct wait_queue_head_list_node));

	/* Prepare per-thread wait queue head */
	wqhln->task = current;
	/* Save the TID explicitly, because mcexec_syscall(), where the request
	 * will be matched, is in IRQ context and can't call task_pid_vnr() */
	wqhln->rtid = task_pid_vnr(current);
	wqhln->req = 0;
	init_waitqueue_head(&wqhln->wq_syscall);

	irqflags = ihk_ikc_spinlock_lock(&ppd->wq_list_lock);
	/* Add to exact list */
	list_add_tail(&wqhln->list, &ppd->wq_list_exact);
	ihk_ikc_spinlock_unlock(&ppd->wq_list_lock, irqflags);

	resp->stid = task_pid_vnr(current);
	resp->fault_address = virt_to_phys(request);

#define STATUS_IN_PROGRESS	0
#define	STATUS_SYSCALL		4
	req->valid = 0;

	if (__notify_syscall_requester(usrdata->os, packet, resp) < 0) {
		printk("%s: WARNING: failed to notify PID %d\n",
			__FUNCTION__, packet->pid);
	}

	mb();
	resp->status = STATUS_SYSCALL;

	retry = 0;
 retry_offload:
	dprintk("%s: tid: %d, syscall: %d SLEEPING\n", 
			__FUNCTION__, task_pid_vnr(current), num);
	/* wait for response */
	syscall_ret = wait_event_interruptible(wqhln->wq_syscall, wqhln->req);
	
	/* debug */
	if (syscall_ret == -ERESTARTSYS) {
		printk("%s: INFO: interrupted by signal\n", __FUNCTION__);
		retry++;
		if (retry < 5) {
			printk("%s: INFO: retry=%d\n", __FUNCTION__, retry);
			goto retry_offload;
		}
	}

	/* Remove per-thread wait queue head */
	irqflags = ihk_ikc_spinlock_lock(&ppd->wq_list_lock);
	list_del(&wqhln->list);
	ihk_ikc_spinlock_unlock(&ppd->wq_list_lock, irqflags);

	dprintk("%s: tid: %d, syscall: %d WOKEN UP\n",
		__FUNCTION__, task_pid_vnr(current), num);

	if (retry >= 5) {
		kfree(wqhln);
		kprintf("%s: INFO: mcexec is gone or retry count exceeded,pid=%d,ppd=%p,retry=%d\n", __FUNCTION__, task_tgid_vnr(current), ppd, retry);
		syscall_ret = -EINVAL;
		goto out;
	}

	if (syscall_ret) {
		kfree(wqhln);
		printk("%s: ERROR: wait_event_interruptible returned %ld\n", __FUNCTION__, syscall_ret);
		goto out;
	}
	else {
		unsigned long phys2;
		struct syscall_response *resp2;

		/* Note that wqhln->packet is a new packet */
		packet = wqhln->packet;
		free_packet = packet;
		req = &packet->req;

		phys2 = ihk_device_map_memory(ihk_os_to_dev(usrdata->os), 
				packet->resp_pa, sizeof(*resp));
		resp2 = ihk_device_map_virtual(ihk_os_to_dev(usrdata->os), 
				phys2, sizeof(*resp), NULL, 0);

		if (resp != resp2) {
			resp = resp2;
			phys = phys2;
			printk("%s: updated new remote PA for resp\n", __FUNCTION__);
		}
	}

	if (!req->valid) {
		printk("%s:not valid\n", __FUNCTION__);
	}
	req->valid = 0;

	/* check result */
	if (req->number != __NR_mmap) {
		printk("%s:unexpected response. %lx %lx\n",
		       __FUNCTION__, req->number, req->args[0]);
		syscall_ret = -EIO;
		goto out;
	}

	*ret = req->args[1];

	kfree(wqhln);
	syscall_ret = 0;
out:
	/* Release packet sent from McKernel */
	if (free_packet) {
		ihk_ikc_release_packet((struct ihk_ikc_free_packet *)free_packet,
							   (usrdata->ikc2linux[smp_processor_id()] ?
								usrdata->ikc2linux[smp_processor_id()] :
								usrdata->ikc2linux[0]));
	}
	ihk_device_unmap_virtual(ihk_os_to_dev(usrdata->os), resp, sizeof(*resp));
	ihk_device_unmap_memory(ihk_os_to_dev(usrdata->os), phys, sizeof(*resp));

out_put_ppd:
	mcctrl_put_per_thread_data(ptd);
	pr_ptd("put", task_pid_vnr(current), ptd);
 no_ptd:
	dprintk("%s: tid: %d, syscall: %d, syscall_ret: %lx\n",
		__FUNCTION__, task_pid_vnr(current), num, syscall_ret);

	mcctrl_put_per_proc_data(ppd);
	return syscall_ret;
}

#if 0 /* debug */
/* Info of Linux counterpart of migrated-to-Linux thread */
struct host_thread {
	struct host_thread *next;
	struct mcos_handler_info *handler;
	int     pid;
	int     tid;
	unsigned long usp;
	unsigned long lfs;
	unsigned long rfs;
	struct task_struct *task;
};

extern struct host_thread *host_threads;
extern rwlock_t host_thread_lock;
#endif

int remote_page_fault(struct mcctrl_usrdata *usrdata, void *fault_addr, uint64_t reason)
{
	struct ikc_scd_packet *packet;
	struct ikc_scd_packet *free_packet = NULL;
	struct syscall_request *req;
	struct syscall_response *resp;
	int error;
	struct wait_queue_head_list_node *wqhln;
	unsigned long irqflags;
	struct mcctrl_per_proc_data *ppd;
	struct mcctrl_per_thread_data *ptd;
	unsigned long phys;
	int retry;
	
	dprintk("%s: tid: %d, fault_addr: %p, reason: %lu\n",
			__FUNCTION__, task_pid_vnr(current), fault_addr, (unsigned long)reason);
	
	/* Look up per-process structure */
	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));

	if (!ppd) {
		kprintf("%s: ERROR: no per-process structure for PID %d??\n", 
				__FUNCTION__, task_tgid_vnr(current));
		return -EINVAL;
	}

	ptd = mcctrl_get_per_thread_data(ppd, current);
	if (!ptd) {
		printk("%s: ERROR: mcctrl_get_per_thread_data failed\n", __FUNCTION__);		
		error = -ENOENT;
		goto no_ptd;
	}
	pr_ptd("get", task_pid_vnr(current), ptd);
	packet = (struct ikc_scd_packet *)ptd->data;
	if (!packet) {
		printk("%s: no packet registered for TID %d\n",
				__FUNCTION__, task_pid_vnr(current));
		error = -ENOENT;
		goto out_put_ppd;
	}

	req = &packet->req;

	/* Map response structure */
	phys = ihk_device_map_memory(ihk_os_to_dev(usrdata->os), 
			packet->resp_pa, sizeof(*resp));
	resp = ihk_device_map_virtual(ihk_os_to_dev(usrdata->os), 
			phys, sizeof(*resp), NULL, 0);
	if (!resp) {
		printk("%s: ERROR: invalid response structure address\n",
			__FUNCTION__);
		error = -EINVAL;
		goto out;
	}

retry_alloc:
	wqhln = kmalloc(sizeof(*wqhln), GFP_ATOMIC);
	if (!wqhln) {
		printk("WARNING: coudln't alloc wait queue head, retrying..\n");
		goto retry_alloc;
	}
	memset(wqhln, 0, sizeof(struct wait_queue_head_list_node));

	/* Prepare per-thread wait queue head */
	wqhln->task = current;
	/* Save the TID explicitly, because mcexec_syscall(), where the request
	 * will be matched, is in IRQ context and can't call task_pid_vnr() */
	wqhln->rtid = task_pid_vnr(current);
	wqhln->req = 0;
	init_waitqueue_head(&wqhln->wq_syscall);

	irqflags = ihk_ikc_spinlock_lock(&ppd->wq_list_lock);
	/* Add to exact list */
	list_add_tail(&wqhln->list, &ppd->wq_list_exact);
	ihk_ikc_spinlock_unlock(&ppd->wq_list_lock, irqflags);

	/* Request page fault */
	resp->ret = -EFAULT;
	resp->fault_address = (unsigned long)fault_addr;
	resp->fault_reason = reason;
	resp->stid = task_pid_vnr(current);

#define STATUS_PAGER_COMPLETED	1
#define	STATUS_PAGE_FAULT	3
	req->valid = 0;

	if (__notify_syscall_requester(usrdata->os, packet, resp) < 0) {
		printk("%s: WARNING: failed to notify PID %d\n",
			__FUNCTION__, packet->pid);
	}

	mb();
	resp->status = STATUS_PAGE_FAULT;

	retry = 0;
	for (;;) {
		dprintk("%s: tid: %d, fault_addr: %p SLEEPING\n", 
				__FUNCTION__, task_pid_vnr(current), fault_addr);
		/* wait for response */
		error = wait_event_interruptible(wqhln->wq_syscall, wqhln->req);

		/* Delay signal handling */
		if (error == -ERESTARTSYS) {
			printk("%s: INFO: interrupted by signal\n", __FUNCTION__);
			retry++;
			if (retry < 5) { /* mcexec is alive */
				printk("%s: INFO: retry=%d\n", __FUNCTION__, retry);
				continue;
			}
		}

		/* Remove per-thread wait queue head */
		irqflags = ihk_ikc_spinlock_lock(&ppd->wq_list_lock);
		list_del(&wqhln->list);
		ihk_ikc_spinlock_unlock(&ppd->wq_list_lock, irqflags);

		dprintk("%s: tid: %d, fault_addr: %p WOKEN UP\n", 
				__FUNCTION__, task_pid_vnr(current), fault_addr);

		if (retry >= 5) {
			kfree(wqhln);
			kprintf("%s: INFO: mcexec is gone or retry count exceeded,pid=%d,retry=%d\n", __FUNCTION__, task_tgid_vnr(current), retry);
			error = -EINVAL;
			goto out;
		}

		if (error) {
			kfree(wqhln);
			printk("remote_page_fault:interrupted. %d\n", error);
			goto out;
		}
		else {
			/* Update packet reference */
			packet = wqhln->packet;
			free_packet = packet;
			req = &packet->req;
			{
				unsigned long phys2;
				struct syscall_response *resp2;
				phys2 = ihk_device_map_memory(ihk_os_to_dev(usrdata->os), 
						packet->resp_pa, sizeof(*resp));
				resp2 = ihk_device_map_virtual(ihk_os_to_dev(usrdata->os), 
						phys2, sizeof(*resp), NULL, 0);

				if (resp != resp2) {
					resp = resp2;
					phys = phys2;
					printk("%s: updated new remote PA for resp\n", __FUNCTION__);
				}
			}
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

			if (__notify_syscall_requester(usrdata->os, packet, resp) < 0) {
				printk("%s: WARNING: failed to notify PID %d\n",
						__FUNCTION__, packet->pid);
			}

			mb();
			resp->status = STATUS_PAGER_COMPLETED;
			break;
			//continue;
		}
		else {
			error = req->args[1];
			if (error) {
				printk("remote_page_fault:response %d\n", error);
				kfree(wqhln);
				goto out;
			}
		}
		break;
	}

	kfree(wqhln);
	error = 0;
out:
	/* Release remote page-fault response packet */
	if (free_packet) {
		ihk_ikc_release_packet((struct ihk_ikc_free_packet *)free_packet,
							   (usrdata->ikc2linux[smp_processor_id()] ?
								usrdata->ikc2linux[smp_processor_id()] :
								usrdata->ikc2linux[0]));
	}

	ihk_device_unmap_virtual(ihk_os_to_dev(usrdata->os), resp, sizeof(*resp));
	ihk_device_unmap_memory(ihk_os_to_dev(usrdata->os), phys, sizeof(*resp));

out_put_ppd:
	mcctrl_put_per_thread_data(ptd);
	pr_ptd("put", task_pid_vnr(current), ptd);
 no_ptd:
	dprintk("%s: tid: %d, fault_addr: %p, reason: %lu, error: %d\n",
			__FUNCTION__, task_pid_vnr(current), fault_addr, (unsigned long)reason, error);

	mcctrl_put_per_proc_data(ppd);
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

#define	USE_VM_INSERT_PFN	1

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
static int rus_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
#else
static int rus_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
#endif
	struct mcctrl_usrdata  *usrdata	= vma->vm_file->private_data;
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
	struct mcctrl_per_proc_data *ppd;
	struct mcctrl_per_thread_data *ptd;
	struct ikc_scd_packet *packet;
	int ret = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	dprintk("mcctrl:page fault:flags %#x pgoff %#lx va %#lx page %p\n",
			vmf->flags, vmf->pgoff, vmf->address, vmf->page);
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
	dprintk("mcctrl:page fault:flags %#x pgoff %#lx va %p page %p\n",
			vmf->flags, vmf->pgoff, vmf->virtual_address, vmf->page);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */

	/* Look up per-process structure */
	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));
	if (!ppd) {
		kprintf("%s: INFO: no per-process structure for pid %d (tid %d), try to use pid %d\n", 
				__FUNCTION__, task_tgid_vnr(current), task_pid_vnr(current), vma->vm_mm->owner->pid);
		ppd = mcctrl_get_per_proc_data(usrdata, vma->vm_mm->owner->pid);
	}

	if (!ppd) {
		kprintf("%s: ERROR: no per-process structure for PID %d??\n", 
				__FUNCTION__, task_tgid_vnr(current));
		ret = VM_FAULT_SIGBUS;
		goto no_ppd;
	}

	ptd = mcctrl_get_per_thread_data(ppd, current);
	if (!ptd) {
		printk("%s: ERROR: mcctrl_get_per_thread_data failed\n", __FUNCTION__);
		ret = VM_FAULT_SIGBUS;
		goto no_ptd;
	}
	pr_ptd("get", task_pid_vnr(current), ptd);
	packet = (struct ikc_scd_packet *)ptd->data;
	if (!packet) {
		ret = VM_FAULT_SIGBUS;
		printk("%s: no packet registered for TID %d\n",
				__FUNCTION__, task_pid_vnr(current));
		goto put_and_out;
	}

	for (try = 1; ; ++try) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
		error = translate_rva_to_rpa(usrdata->os, ppd->rpgtable,
				vmf->address, &rpa, &pgsize);
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
		error = translate_rva_to_rpa(usrdata->os, ppd->rpgtable,
				(unsigned long)vmf->virtual_address,
				&rpa, &pgsize);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
#define	NTRIES 2
		if (!error || (try >= NTRIES)) {
			if (error) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
				printk("%s: error translating 0x%#lx "
						"(req: TID: %u, syscall: %lu)\n",
						__FUNCTION__, vmf->address,
						packet->req.rtid, packet->req.number);
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
				printk("%s: error translating 0x%p "
						"(req: TID: %u, syscall: %lu)\n",
						__FUNCTION__, vmf->virtual_address,
						packet->req.rtid, packet->req.number);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
			}

			break;
		}

		reason = 0;
		if (vmf->flags & FAULT_FLAG_WRITE) {
#define	PF_WRITE	0x02
			reason |= PF_WRITE;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
		error = remote_page_fault(usrdata, (void *)vmf->address, reason);
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
		error = remote_page_fault(usrdata, vmf->virtual_address, reason);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
		if (error) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
				printk("%s: error forwarding PF for 0x%#lx "
						"(req: TID: %d, syscall: %lu)\n",
						__FUNCTION__, vmf->address,
						packet->req.rtid, packet->req.number);
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
				printk("%s: error forwarding PF for 0x%p "
						"(req: TID: %d, syscall: %lu)\n",
						__FUNCTION__, vmf->virtual_address,
						packet->req.rtid, packet->req.number);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
			break;
		}
	}
	if (error) {
		ret = VM_FAULT_SIGBUS;
		goto put_and_out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	rva = vmf->address & ~(pgsize - 1);
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
	rva = (unsigned long)vmf->virtual_address & ~(pgsize - 1);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
	rpa = rpa & ~(pgsize - 1);

	phys = ihk_device_map_memory(dev, rpa, pgsize);
	pfn = phys >> PAGE_SHIFT;
#if USE_VM_INSERT_PFN
	for (pix = 0; pix < (pgsize / PAGE_SIZE); ++pix) {
		struct page *page;

		/* LWK may hold large page based mappings that align rva outside
		 * Linux' VMA, make sure we don't try to map to those pages */
		if (rva + (pix * PAGE_SIZE) < vma->vm_start) {
			continue;
		}

		if (pfn_valid(pfn+pix)) {
			page = pfn_to_page(pfn+pix);

			error = vm_insert_page(vma, rva+(pix*PAGE_SIZE), page);
			if (error) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
				printk("%s: error inserting mapping for 0x%#lx "
						"(req: TID: %d, syscall: %lu) error: %d, " 
						"vm_start: 0x%lx, vm_end: 0x%lx\n",
						__FUNCTION__, vmf->address,
						packet->req.rtid, packet->req.number, error,
						vma->vm_start, vma->vm_end);
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
				printk("%s: error inserting mapping for 0x%p "
						"(req: TID: %d, syscall: %lu) error: %d, " 
						"vm_start: 0x%lx, vm_end: 0x%lx\n",
						__FUNCTION__, vmf->virtual_address,
						packet->req.rtid, packet->req.number, error,
						vma->vm_start, vma->vm_end);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
			}
		}
		else
		error = vm_insert_pfn(vma, rva+(pix*PAGE_SIZE), pfn+pix);
		if (error) {
#if 1 /* POSTK_DEBUG_TEMP_FIX_11 */ /* rus_vm_fault() multi-thread fix */
			printk("%s: vm_insert_pfn returned %d\n", __FUNCTION__, error);
			if (error == -EBUSY) {
				error = 0;
			} else {
				break;
			}
#else /* POSTK_DEBUG_TEMP_FIX_11 */
			break;
#endif /* POSTK_DEBUG_TEMP_FIX_11 */
		}
	}
#else
	error = remap_pfn_range(vma, rva, pfn, pgsize, vma->vm_page_prot);
#endif
	ihk_device_unmap_memory(dev, phys, pgsize);
	if (error) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
		printk("%s: remote PF failed for 0x%#lx, pgoff: %lu "
				"(req: TID: %d, syscall: %lu)\n",
				__FUNCTION__, vmf->address, vmf->pgoff,
				packet->req.rtid, packet->req.number);
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
		printk("%s: remote PF failed for 0x%p, pgoff: %lu "
				"(req: TID: %d, syscall: %lu)\n",
				__FUNCTION__, vmf->virtual_address, vmf->pgoff,
				packet->req.rtid, packet->req.number);
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0) */
		ret = VM_FAULT_SIGBUS;
		goto put_and_out;
	}

	ret = VM_FAULT_NOPAGE;

put_and_out:
	mcctrl_put_per_thread_data(ptd);
	pr_ptd("put", task_pid_vnr(current), ptd);
 no_ptd:
	mcctrl_put_per_proc_data(ppd);
 no_ppd:
	return ret;
}

static struct vm_operations_struct rus_vmops = {
	.fault = &rus_vm_fault,
};

static int rus_mmap(struct file *file, struct vm_area_struct *vma)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
//	vma->vm_flags |= VM_RESERVED | VM_DONTEXPAND | VM_MIXEDMAP;
	vma->vm_flags |= VM_RESERVED | VM_MIXEDMAP;
#else
//	vma->vm_flags |= VM_DONTDUMP | VM_DONTEXPAND | VM_MIXEDMAP;
	vma->vm_flags |= VM_DONTDUMP | VM_MIXEDMAP;
#endif
	vma->vm_ops = &rus_vmops;
	return 0;
}

static struct file_operations rus_fops = {
	.mmap = &rus_mmap,
};

unsigned long
reserve_user_space_common(struct mcctrl_usrdata *usrdata, unsigned long start, unsigned long end)
{
	struct file *file;
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
	start = vm_mmap_pgoff(file, start, end, PROT_READ|PROT_WRITE|PROT_EXEC,
	                      MAP_FIXED|MAP_SHARED, 0);
#else
	start = vm_mmap(file, start, end, PROT_READ|PROT_WRITE|PROT_EXEC,
	                MAP_FIXED|MAP_SHARED, 0);
#endif
#if 0
	{ /* debug */
        struct vm_area_struct *vma;
		down_write(&current->mm->mmap_sem);
		vma = find_vma(current->mm, start);
		vma->vm_flags |= VM_DONTCOPY;
		up_write(&current->mm->mmap_sem);
	}
#endif
	revert_creds(original);
	put_cred(promoted);
	fput(file);
	if (IS_ERR_VALUE(start)) {
		printk("mcctrl:user space reservation failed.\n");
	}

	return start;
}

struct pager {
	struct list_head	list;
	struct inode *		inode;
	uint64_t		ref; /* needs same type as fileobj->sref */
	struct file *		rofile;
	struct file *		rwfile;
	uintptr_t		map_uaddr;
	size_t			map_len;
	off_t			map_off;
};


static DEFINE_SPINLOCK(pager_lock);
static struct list_head pager_list = LIST_HEAD_INIT(pager_list);

int pager_nr_processes = 0;

void pager_add_process(void)
{
	unsigned long flags;

	spin_lock_irqsave(&pager_lock, flags);

	++pager_nr_processes;

	spin_unlock_irqrestore(&pager_lock, flags);
}

void pager_remove_process(struct mcctrl_per_proc_data *ppd)
{
	int error;
	struct pager *pager_next, *pager;
	unsigned long flags;

	if (in_atomic() || in_interrupt()) {
		printk("%s: WARNING: shouldn't be called in IRQ context..\n",
			__FUNCTION__);
		return;
	}

	/* Clean up device file mappings of this process */
	error = down_interruptible(&ppd->devobj_pager_lock);
	if (error) {
		return;
	}

	list_for_each_entry_safe(pager, pager_next,
			&ppd->devobj_pager_list, list) {

		dprintk("%s: devobj pager 0x%p removed\n", __FUNCTION__, pager);
		list_del(&pager->list);
		kfree(pager);
	}
	up(&ppd->devobj_pager_lock);

	/* Clean up global pagers for regular file mappings if this
	 * was the last process */
	spin_lock_irqsave(&pager_lock, flags);
	--pager_nr_processes;
	spin_unlock_irqrestore(&pager_lock, flags);
}

void pager_cleanup(void)
{
	unsigned long flags;
	struct pager *pager_next, *pager;

	spin_lock_irqsave(&pager_lock, flags);

	list_for_each_entry_safe(pager, pager_next, &pager_list, list) {
		list_del(&pager->list);

		if (pager->rofile) {
			fput(pager->rofile);
		}

		if (pager->rwfile) {
			fput(pager->rwfile);
		}

		dprintk("%s: pager 0x%p removed\n", __FUNCTION__, pager);
		kfree(pager);
	}

	spin_unlock_irqrestore(&pager_lock, flags);
}

struct pager_create_result {
	uintptr_t	handle;
	int		maxprot;
	uint32_t flags;
	size_t size;
	char path[PATH_MAX];
};

enum {
	/* for memobj.flags */
	MF_HAS_PAGER	= 0x0001,
	MF_SHMDT_OK	= 0x0002,
	MF_IS_REMOVABLE	= 0x0004,
	MF_PREFETCH = 0x0008,
	MF_ZEROFILL = 0x0010,
	MF_REG_FILE = 0x1000,
	MF_DEV_FILE = 0x2000,
	MF_PREMAP   = 0x8000,
	MF_XPMEM   = 0x10000, /* To identify XPMEM attachment pages for rusage accounting */
	MF_ZEROOBJ = 0x20000, /* To identify pages of anonymous, on-demand paging ranges for rusage accounting */
	MF_SHM =     0x40000,
	MF_HUGETLBFS = 0x100000,
};

static int pager_get_path(struct file *file, char *path) {
	int error = 0;
	char *pathbuf, *fullpath;

	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathbuf) {
		printk("%s: ERROR: allocating path\n", __FUNCTION__);
		error = -ENOMEM;
		goto out;
	}

	fullpath = d_path(&file->f_path, pathbuf, PATH_MAX);
	if (!IS_ERR(fullpath)) {
		memcpy(path, fullpath, strlen(fullpath) + 1);
	}
	else {
		path[0] = 0;
	}

out:
	if (pathbuf) {
		kfree(pathbuf);
	}
	return error;
}


static int pager_req_create(ihk_os_t os, int fd, uintptr_t result_pa)
{
	ihk_device_t dev = ihk_os_to_dev(os);
	int error;
	struct pager_create_result *resp;
	int maxprot = 0;
	struct file *file = NULL;
	struct inode *inode;
	struct pager *pager = NULL;
	struct pager *newpager = NULL;
	uintptr_t phys;
	struct kstat st;
	int mf_flags = 0;
	unsigned long irqflags;

	dprintk("pager_req_create(%d,%lx)\n", fd, (long)result_pa);

	error = vfs_fstat(fd, &st);
	if (error) {
		printk("pager_req_create(%d,%lx):vfs_stat failed. %d\n", fd, (long)result_pa, error);
		goto out;
	}
	if (S_ISCHR(st.mode) && (MAJOR(st.rdev) == 1)) {
		/* treat memory devices as regular files */
	}
	else if (!S_ISREG(st.mode)) {
		error = -ESRCH;
		dprintk("pager_req_create(%d,%lx):not VREG. %x\n", fd, (long)result_pa, st.mode);
		goto out;
	}

	file = fget(fd);
	if (!file) {
		error = -EBADF;
		printk("pager_req_create(%d,%lx):file not found. %d\n", fd, (long)result_pa, error);
		goto out;
	}

	inode = file->f_path.dentry->d_inode;
	if (!inode) {
		error = -EBADF;
		printk("pager_req_create(%d,%lx):inode not found. %d\n", fd, (long)result_pa, error);
		goto out;
	}

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
		printk("pager_req_create(%d,%lx):cannot read file. %d\n", fd, (long)result_pa, error);
		goto out;
	}

	if (inode->i_op == mcctrl_hugetlbfs_inode_operations) {
		mf_flags = MF_HUGETLBFS;
		/* pager is used as handle id on mckernel side, use inode */
		pager = (void *)st.ino;
		/* retrofit blksize in resp as well through st.size field;
		 * the actual file size is not used
		 */
		st.size = st.blksize;
		goto out_reply;
	}

	for (;;) {
		spin_lock_irqsave(&pager_lock, irqflags);

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

			/* Intel MPI library and shared memory "prefetch" */
			{
				char *pathbuf, *fullpath;

				pathbuf = kmalloc(PATH_MAX, GFP_ATOMIC);
				if (pathbuf) {
					fullpath = d_path(&file->f_path, pathbuf, PATH_MAX);
					if (!IS_ERR(fullpath)) {
						if (!strncmp("/dev/shm/Intel_MPI", fullpath, 18)) {
							mf_flags = (MF_PREMAP | MF_ZEROFILL);
							dprintk("%s: filename: %s, premap & zerofill\n",
									__FUNCTION__, fullpath);
						}
						else if (strstr(fullpath, "libmpi") ||
								strstr(fullpath, "libiomp") ||
								strstr(fullpath, "libpthread") ||
								strstr(fullpath, "libc.so")) {
							mf_flags = MF_PREFETCH;
							dprintk("%s: filename: %s, prefetch\n",
									__FUNCTION__, fullpath);
						}
					}

					kfree(pathbuf);
				}
			}

			break;
		}

		spin_unlock_irqrestore(&pager_lock, irqflags);

		newpager = kzalloc(sizeof(*newpager), GFP_ATOMIC);
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
	spin_unlock_irqrestore(&pager_lock, irqflags);

out_reply:
	phys = ihk_device_map_memory(dev, result_pa, sizeof(*resp));
	resp = ihk_device_map_virtual(dev, phys, sizeof(*resp), NULL, 0);
	if (!resp) {
		ihk_device_unmap_memory(dev, phys, sizeof(*resp));
		printk("%s: ERROR: invalid response structure address\n",
			__FUNCTION__);
		error = -EINVAL;
		goto out;
	}

	resp->handle = (uintptr_t)pager;
	resp->maxprot = maxprot;
	resp->flags = mf_flags;
	resp->size = st.size;

	error = pager_get_path(file, resp->path);

	ihk_device_unmap_virtual(dev, resp, sizeof(*resp));
	ihk_device_unmap_memory(dev, phys, sizeof(*resp));

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

static int pager_req_release(ihk_os_t os, uintptr_t handle, uint64_t sref)
{
	int error;
	struct pager *p;
	struct pager *free_pager = NULL;
	unsigned long flags;

	dprintk("%s(%p,%lx)\n", __func__, os, handle);

	spin_lock_irqsave(&pager_lock, flags);

	error = -EBADF;
	list_for_each_entry(p, &pager_list, list) {
		if ((uintptr_t)p == handle) {
			error = 0;
			p->ref -= sref;
			if (p->ref > 0)
				break;
			list_del(&p->list);
			free_pager = p;
			break;
		}
	}

	spin_unlock_irqrestore(&pager_lock, flags);

	if (error) {
		pr_err("%s(%p,%lx):pager not found. %d\n",
		       __func__, os, handle, error);
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
	dprintk("%s(%p,%lx): %d\n", __func__, os, handle, error);
	return error;
}

static int pager_req_read(ihk_os_t os, uintptr_t handle, off_t off, size_t size, uintptr_t rpa)
{
	ssize_t ss, n;
	struct pager *pager;
	struct file *file = NULL;
	uintptr_t phys = -1;
	ihk_device_t dev = ihk_os_to_dev(os);
	void *buf = NULL;
	loff_t pos;
	unsigned long flags;

	dprintk("pager_req_read(%lx,%lx,%lx,%lx)\n", handle, off, size, rpa);

	spin_lock_irqsave(&pager_lock, flags);

	list_for_each_entry(pager, &pager_list, list) {
		if ((uintptr_t)pager == handle) {
			file = (pager->rofile)? pager->rofile: pager->rwfile;
			get_file(file);
			break;
		}
	}
	spin_unlock_irqrestore(&pager_lock, flags);

	if (!file) {
		ss = -EBADF;
		pr_warn("%s(%lx,%lx,%lx,%lx):pager not found. %ld\n",
			__func__, handle, off, size, rpa, ss);
		goto out;
	}

	phys = ihk_device_map_memory(dev, rpa, size);
	buf = ihk_device_map_virtual(dev, phys, size, NULL, 0);
	if (!buf) {
		pr_warn("%s: ERROR: invalid buffer address\n",
			__func__);
		ss = -EINVAL;
		goto out;
	}

	pos = off;
	n = 0;
	while (n < size) {
		if (pos != off + n) {
			pr_warn("%s: pos wrong? got %lld, expected %ld\n",
				__func__, pos, off+n);
			pos = off + n;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
		ss = kernel_read(file, buf + n, size - n, &pos);
#else
		ss = kernel_read(file, pos, buf + n, size - n);
		pos += ss;
#endif
		if (ss < 0) {
			break;
		}
		if (ss == 0) {
			memset(buf + n, 0, size - n);
			n = size;
			break;
		}
		n += ss;
	}
	if (ss < 0) {
		pr_warn("%s(%lx,%lx,%lx,%lx):pread failed. %ld\n",
			__func__, handle, off, size, rpa, ss);
		goto out;
	}
	ss = n;

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
	loff_t pos;
	loff_t fsize;
	size_t len;
	unsigned long flags;

	dprintk("pager_req_write(%lx,%lx,%lx,%lx)\n", handle, off, size, rpa);

	spin_lock_irqsave(&pager_lock, flags);

	list_for_each_entry(pager, &pager_list, list) {
		if ((uintptr_t)pager == handle) {
			file = pager->rwfile;
			break;
		}
	}
	if (file) {
		get_file(file);
	}
	spin_unlock_irqrestore(&pager_lock, flags);

	if (!file) {
		ss = -EBADF;
		printk("pager_req_write(%lx,%lx,%lx,%lx):pager not found. %ld\n", handle, off, size, rpa, ss);
		goto out;
	}

	/*
	 * XXX: Find a way to avoid changing the file size
	 * by using a function in the same abstraction level as kernel_write().
	 */
	fsize = i_size_read(file->f_mapping->host);
	if (off >= fsize) {
		ss = 0;
		goto out;
	}

	phys = ihk_device_map_memory(dev, rpa, size);
	buf = ihk_device_map_virtual(dev, phys, size, NULL, 0);
	if (!buf) {
		printk("%s: ERROR: invalid buffer address\n",
			__FUNCTION__);
		ss = -EINVAL;
		goto out;
	}

	pos = off;
	len = size;
	if ((off + size) > fsize) {
		len = fsize - off;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
	ss = kernel_write(file, buf, len, &pos);
#else
	ss = kernel_write(file, buf, len, pos);
#endif
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
    char path[PATH_MAX];
};

static int pager_req_map(ihk_os_t os, int fd, size_t len, off_t off,
		uintptr_t result_rpa, int prot_and_flags)
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
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd = NULL;

	dprintk("pager_req_map(%p,%d,%lx,%lx,%lx)\n", os, fd, len, off, result_rpa);

	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));
	if (unlikely(!ppd)) {
		kprintf("%s: ERROR: no per-process structure for PID %d??\n",
				__FUNCTION__, task_tgid_vnr(current));
		return -1;
	}

	pager = kzalloc(sizeof(*pager), GFP_ATOMIC);
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
	if ((file->f_mode & FMODE_READ) && 
			(prot_and_flags ? (prot_and_flags & PROT_READ) : 1)) {
		maxprot |= PROT_READ;
	}
	if ((file->f_mode & FMODE_WRITE) && 
			(prot_and_flags ? (prot_and_flags & PROT_WRITE) : 1)) {
		maxprot |= PROT_WRITE;
	}
	if (!(file->f_path.mnt->mnt_flags & MNT_NOEXEC) &&
			(prot_and_flags ? (prot_and_flags & PROT_EXEC) : 1)) {
		maxprot |= PROT_EXEC;
	}

	prot_and_flags = MAP_SHARED |
		(prot_and_flags & (MAP_POPULATE | MAP_LOCKED));

#define	ANY_WHERE 0
	if (prot_and_flags & MAP_LOCKED) prot_and_flags |= MAP_POPULATE;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
	down_write(&current->mm->mmap_sem);

	va = do_mmap_pgoff(file, ANY_WHERE, len, maxprot, 
			prot_and_flags, pgoff);

	up_write(&current->mm->mmap_sem);
#else
	va = vm_mmap(file, ANY_WHERE, len, maxprot,
			prot_and_flags, pgoff << PAGE_SHIFT);
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
	
	dprintk("pager_req_map(%s): 0x%lx - 0x%lx (len: %lu), map_off: %lu\n", 
			file->f_dentry->d_name.name, va, va + len, len, off);

	phys = ihk_device_map_memory(dev, result_rpa, sizeof(*resp));
	resp = ihk_device_map_virtual(dev, phys, sizeof(*resp), NULL, 0);
	if (!resp) {
		ihk_device_unmap_memory(dev, phys, sizeof(*resp));
		printk("%s: ERROR: invalid response structure address\n",
			__FUNCTION__);
		error = -EINVAL;
		goto out;
	}

	resp->handle = (uintptr_t)pager;
	resp->maxprot = maxprot;

	error = pager_get_path(file, resp->path);
	if (error) {
		goto out_unmap;
	}

	error = down_interruptible(&ppd->devobj_pager_lock);
	if (error) {
		error = -EINTR;
		goto out_unmap;
	}

	list_add_tail(&pager->list, &ppd->devobj_pager_list);
	up(&ppd->devobj_pager_lock);

	pager = 0;
	error = 0;

out_unmap:
	ihk_device_unmap_virtual(dev, resp, sizeof(*resp));
	ihk_device_unmap_memory(dev, phys, sizeof(*resp));

out:
	if (file) {
		fput(file);
	}
	if (pager) {
		kfree(pager);
	}
	mcctrl_put_per_proc_data(ppd);
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
	int page_fault_attempted = 0;

	dprintk("pager_req_pfn(%p,%lx,%lx)\n", os, handle, off);

	if ((off < pager->map_off) || ((pager->map_off+pager->map_len) < (off + PAGE_SIZE))) {
		error = -ERANGE;
		pfn = 0;
		printk("pager_req_pfn(%p,%lx,%lx):out of range. %d [%lx..%lx)\n", os, handle, off, error, pager->map_off, pager->map_off+pager->map_len);
		goto out;
	}

	va = pager->map_uaddr + (off - pager->map_off);
#define	PFN_VALID	((uintptr_t)1 << 63)
	pfn = PFN_VALID;	/* Use "not present" as the default setting */

	down_read(&current->mm->mmap_sem);
retry:	
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
#ifdef POSTK_DEBUG_ARCH_DEP_12
					if (pte_is_write_combined(*pte)) {
						pfn |= PFN_WRITE_COMBINED;
					}
#else /* POSTK_DEBUG_ARCH_DEP_12 */
					if ((pte_flags(*pte) & _PAGE_PWT) && 
						!(pte_flags(*pte) & _PAGE_PCD)) {
						pfn |= _PAGE_PWT;
					}
#endif /* POSTK_DEBUG_ARCH_DEP_12 */
				}
				pte_unmap(pte);
			}
		}
	}

	/* If not present, try to fault it */
	if (!(pfn & PFN_PRESENT) && !page_fault_attempted) {
		unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;
		struct vm_area_struct *vma;
		int fault;

#if defined(FAULT_FLAG_USER)
		flags |= FAULT_FLAG_USER;
#endif

		vma = find_vma(current->mm, va);
		if (!vma || (va < vma->vm_start)) {
			printk("%s: couldn't find VMA for va %lx\n", __FUNCTION__, va); 
			error = -EINVAL;
			goto out_release;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0) || \
	(defined(RHEL_RELEASE_CODE) && RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 5))
		fault = handle_mm_fault(vma, va, flags);
#else
		fault = handle_mm_fault(current->mm, vma, va, flags);
#endif
		if (fault != 0) {
			printk("%s: error: faulting %lx at off: %lu\n", 
					__FUNCTION__, va, off);
		}

		page_fault_attempted = 1;
		goto retry;
	}

out_release:
	up_read(&current->mm->mmap_sem);

	phys = ihk_device_map_memory(dev, ppfn_rpa, sizeof(*ppfn));
	ppfn = ihk_device_map_virtual(dev, phys, sizeof(*ppfn), NULL, 0);
	if (!ppfn) {
		printk("%s: ERROR: invalid PFN address\n",
			__FUNCTION__);
		error = -EINVAL;
		goto out;
	}

	*ppfn = pfn;
	ihk_device_unmap_virtual(dev, ppfn, sizeof(*ppfn));
	ihk_device_unmap_memory(dev, phys, sizeof(*ppfn));

	error = 0;
out:
	dprintk("pager_req_pfn(%p,%lx,%lx): %d %lx\n", os, handle, off, error, pfn);
	return error;
}

static int __pager_unmap(struct pager *pager)
{
	int error;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
	down_write(&current->mm->mmap_sem);
	error = do_munmap(current->mm, pager->map_uaddr, pager->map_len);
	up_write(&current->mm->mmap_sem);
#else
	error = vm_munmap(pager->map_uaddr, pager->map_len);
#endif

	if (error) {
		printk("%s: WARNING: munmap failed for pager 0x%lx: %d\n",
			__FUNCTION__, (uintptr_t)pager, error);
	}

	return error;
}

static int pager_req_unmap(ihk_os_t os, uintptr_t handle)
{
	struct pager * const pager = (void *)handle;
	int error;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd = NULL;

	dprintk("pager_req_unmap(%p,%lx)\n", os, handle);

	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));
	if (unlikely(!ppd)) {
		kprintf("%s: ERROR: no per-process structure for PID %d??\n",
				__FUNCTION__, task_tgid_vnr(current));
		return -1;
	}

	error = down_interruptible(&ppd->devobj_pager_lock);
	if (error) {
		error = -EINTR;
		goto out;
	}

	list_del(&pager->list);
	up(&ppd->devobj_pager_lock);

	error = __pager_unmap(pager);
	kfree(pager);

out:
	mcctrl_put_per_proc_data(ppd);
	return error;
}

static long pager_req_mlock_list(ihk_os_t os, unsigned long start,
				 unsigned long end, void *addr, int nent)
{
	struct addrpair {
		unsigned long	start;
		unsigned long	end;
		unsigned long	flag;
	} *addrpair = (struct addrpair *) addr;
	int			cnt = 0;
	struct mm_struct	*mm = current->mm;
	struct vm_area_struct	*vma;

	kprintf("pager_req_mlock_list: addr(%p)\n", addr);
	vma = find_vma(current->mm, 0x7010a0);
	for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
		if (vma->vm_start < start || vma->vm_start > end) continue;
		kprintf("\t%p: %p -- %p\t%lx\n", vma,
			(void*)vma->vm_start, (void*)vma->vm_end,
			vma->vm_flags & VM_LOCKED);
		if (vma->vm_flags & VM_LOCKED) {
			kprintf("\t locked\n");
			if (++cnt >= nent) { /* last entry is a marker */
				addrpair->start = (unsigned long) -1;
				goto full;
			}
			addrpair->start = vma->vm_start;
			addrpair->end = vma->vm_end;
			addrpair->flag = vma->vm_flags;
			addrpair++;
		}
	}
full:
	return cnt;
}

#define	PAGER_REQ_CREATE	0x0001
#define	PAGER_REQ_RELEASE	0x0002
#define	PAGER_REQ_READ		0x0003
#define	PAGER_REQ_WRITE		0x0004
#define	PAGER_REQ_MAP		0x0005
#define	PAGER_REQ_PFN		0x0006
#define	PAGER_REQ_UNMAP		0x0007
#define PAGER_REQ_MLOCK_LIST	0x0008
static long pager_call_irq(ihk_os_t os, struct syscall_request *req)
{
	long ret = -ENOSYS;

	switch (req->args[0]) {
	case PAGER_REQ_RELEASE:
		ret = pager_req_release(os, req->args[1], req->args[2]);
		break;
	}

	return ret;
}

static long pager_call(ihk_os_t os, struct syscall_request *req)
{
	long ret;

	dprintk("pager_call(%#lx)\n", req->args[0]);
	switch (req->args[0]) {
	case PAGER_REQ_CREATE:
		ret = pager_req_create(os, req->args[1], req->args[2]);
		break;

	case PAGER_REQ_READ:
		ret = pager_req_read(os, req->args[1], req->args[2], req->args[3], req->args[4]);
		break;

	case PAGER_REQ_WRITE:
		ret = pager_req_write(os, req->args[1], req->args[2], req->args[3], req->args[4]);
		break;

	case PAGER_REQ_MAP:
		ret = pager_req_map(os, req->args[1], req->args[2], req->args[3], req->args[4],
				req->args[5]);
		break;

	case PAGER_REQ_PFN:
		ret = pager_req_pfn(os, req->args[1], req->args[2], req->args[3]);
		break;

	case PAGER_REQ_UNMAP:
		ret = pager_req_unmap(os, req->args[1]);
		break;

	case PAGER_REQ_MLOCK_LIST:
		ret = pager_req_mlock_list(os, (unsigned long) req->args[1],
					   (unsigned long) req->args[2],
					   (void*) req->args[3], (int) req->args[4]);
		break;
	default:
		ret = -ENOSYS;
		printk("pager_call(%#lx):unknown req %ld\n", req->args[0], ret);
		break;
	}

	dprintk("pager_call(%#lx): %ld\n", req->args[0], ret);
	return ret;
}

void __return_syscall(ihk_os_t os, struct ikc_scd_packet *packet,
		long ret, int stid)
{
	unsigned long phys;
	struct syscall_response *res;

	phys = ihk_device_map_memory(ihk_os_to_dev(os),
			packet->resp_pa, sizeof(*res));
	res = ihk_device_map_virtual(ihk_os_to_dev(os),
			phys, sizeof(*res), NULL, 0);

	if (!res) {
		printk("%s: ERROR: invalid response structure address\n",
			__FUNCTION__);
		return;
	}

	/* Map response structure and notify offloading thread */
	res->ret = ret;
	res->stid = stid;

	if (__notify_syscall_requester(os, packet, res) < 0) {
		printk("%s: WARNING: failed to notify PID %d\n",
			__FUNCTION__, packet->pid);
	}

	mb();
	res->status = 1;

	ihk_device_unmap_virtual(ihk_os_to_dev(os), res, sizeof(*res));
	ihk_device_unmap_memory(ihk_os_to_dev(os), phys, sizeof(*res));
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

int mcctrl_clear_pte_range(uintptr_t start, uintptr_t len)
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
			if (error) {
				mcctrl_zap_page_range(vma, addr, end-addr, NULL);
				error = 0;
			}
			if (ret == 0) {
				ret = error;
			}
		}
		addr = end;
	}
	up_read(&mm->mmap_sem);
	return ret;
}

int release_user_space(uintptr_t start, uintptr_t len)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	uintptr_t addr;
	uintptr_t end;
	int error;
	int ret;

	ret = 0;
	//down_read(&mm->mmap_sem);
	addr = start;
	while (addr < (start + len)) {
		vma = find_vma(mm, addr);
		if (!vma) {
			break;
		}

		if (addr < vma->vm_start) {
			addr = vma->vm_start;
		}

		end = vma->vm_end;
		if (addr < end) {
			if ((error = vm_munmap(addr, end - addr))) {
				printk("%s: ERROR: vm_munmap failed (%d)\n", __func__, error);
			}
			if (ret == 0) {
				ret = error;
			}
		}
		addr = vma->vm_end;
	}
	//up_read(&mm->mmap_sem);
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
	int i, tablesize, error = 0;
	loff_t size;
	ssize_t ret;
	unsigned long phys, tablephys, rphys;
	ihk_device_t dev = ihk_os_to_dev(os);
	char *pt;

	dprintk("coredump called as a pseudo syscall\n");

	if (chunks <= 0) {
		dprintk("no core data found!(%d)\n", chunks);
		error = -EINVAL;
		goto fail;
	}

	/* Every Linux documentation insists we should not 
	 * open a file in the kernel module, but our karma 
	 * leads us here. Precisely, Here we emulate the core 
	 * dump routine of the Linux kernel in linux/fs/exec.c. 
	 * So we have a legitimate reason to do this.
	 */
	file = filp_open("core", O_CREAT | O_RDWR | O_LARGEFILE | O_TRUNC, 0600);
	if (IS_ERR(file) || !file->f_op) {
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
			if (pt == NULL) {
				pt = phys_to_virt(phys);
			}
			dprintk("virtual %p\n", pt);
			if (pt != NULL) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
				ret = kernel_write(file, pt, size,
						   &file->f_pos);
#else
				ret = kernel_write(file, pt, size, file->f_pos);
				file->f_pos += ret;
#endif
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
				dprintk("core file write failed(%ld).\n", ret);
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
				dprintk("core file seek failed(%ld).\n", ret);
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
	if (error == -ENOSYS) {
		/* make sure we do not travel to user land */
		error = -EINVAL;
	}
	return error;
}

#define SCHED_CHECK_SAME_OWNER        0x01
#define SCHED_CHECK_ROOT              0x02

int __do_in_kernel_irq_syscall(ihk_os_t os, struct ikc_scd_packet *packet)
{
	struct syscall_request *sc = &packet->req;
	int ret;

	switch (sc->number) {
	case __NR_mmap:
		ret = pager_call_irq(os, sc);
		break;
	default:
		ret = -ENOSYS;
	}

	if (ret == -ENOSYS)
		return -ENOSYS;

	__return_syscall(os, packet, ret, 0);

	return 0;
}

int __do_in_kernel_syscall(ihk_os_t os, struct ikc_scd_packet *packet)
{
	struct syscall_request *sc = &packet->req;
	int error;
	long ret = -1;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	dprintk("%s: system call: %lx\n", __FUNCTION__, sc->args[0]);
	switch (sc->number) {
	case __NR_mmap:
		ret = pager_call(os, sc);
		break;

	case __NR_munmap:
		ret = mcctrl_clear_pte_range(sc->args[0], sc->args[1]);
		break;

	case __NR_mprotect:
		ret = remap_user_space(sc->args[0], sc->args[1], sc->args[2]);
		break;

	case __NR_exit_group: {
	
		/* Make sure the user space handler will be called as well */
		error = -ENOSYS;
		goto out;
		}

	case __NR_coredump:
		ret = writecore(os, sc->args[1], sc->args[0]);
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

	__return_syscall(os, packet, ret, 0);
	ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet,
			       (usrdata->ikc2linux[smp_processor_id()] ?
				usrdata->ikc2linux[smp_processor_id()] :
				usrdata->ikc2linux[0]));

	error = 0;
out:
	dprintk("%s: system call: %ld, args[0]: %lx, error: %d, ret: %ld\n", 
		__FUNCTION__, sc->number, sc->args[0], error, ret);
	return error;
}
