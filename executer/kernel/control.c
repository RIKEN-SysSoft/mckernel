/**
 * \file executer/kernel/control.c
 *  License details are found in the file LICENSE.
 * \brief
 *  kernel module control
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
 *  2013/09/02 shirasawa add terminate thread
 *  2013/08/19 shirasawa mcexec forward signal to MIC process
 *  2013/08/07 nakamura add page fault forwarding
 *  2013/07/05 shirasawa propagate error code for prepare image
 *  2013/07/02 shirasawa add error handling for prepare_process
 *  2013/04/17 nakamura add generic system call forwarding
 */
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <asm/delay.h>
#include <asm/msr.h>
#include <asm/io.h>
#include "mcctrl.h"

//#define DEBUG

#ifdef DEBUG
#define dprintk printk
#else
#define dprintk(...)
#endif

//static DECLARE_WAIT_QUEUE_HEAD(wq_prepare);
//extern struct mcctrl_channel *channels;
int mcctrl_ikc_set_recv_cpu(ihk_os_t os, int cpu);

static long mcexec_prepare_image(ihk_os_t os,
                                 struct program_load_desc * __user udesc)
{
	struct program_load_desc desc, *pdesc;
	struct ikc_scd_packet isp;
	void *args, *envs;
	long ret = 0;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	unsigned long flags;
	struct mcctrl_per_proc_data *ppd = NULL;

	if (copy_from_user(&desc, udesc,
	                    sizeof(struct program_load_desc))) {
		return -EFAULT;
	}
	if (desc.num_sections <= 0 || desc.num_sections > 16) {
		printk("# of sections: %d\n", desc.num_sections);
		return -EINVAL;
	}
	pdesc = kmalloc(sizeof(struct program_load_desc) + 
	                sizeof(struct program_image_section)
	                * desc.num_sections, GFP_KERNEL);
	memcpy(pdesc, &desc, sizeof(struct program_load_desc));
	if (copy_from_user(pdesc->sections, udesc->sections,
	                   sizeof(struct program_image_section)
	                   * desc.num_sections)) {
		kfree(pdesc);
		return -EFAULT;
	}

	pdesc->pid = task_tgid_vnr(current);

	if (reserve_user_space(usrdata, &pdesc->user_start, &pdesc->user_end)) {
		kfree(pdesc);
		return -ENOMEM;
	}

	args = kmalloc(pdesc->args_len, GFP_KERNEL);
	if (copy_from_user(args, pdesc->args, pdesc->args_len)) {
		kfree(args);
		kfree(pdesc);
		return -EFAULT;
	}
	
	envs = kmalloc(pdesc->envs_len, GFP_KERNEL);
	if (copy_from_user(envs, pdesc->envs, pdesc->envs_len)) {
		ret = -EFAULT;	
		goto free_out;
	}

	pdesc->args = (void*)virt_to_phys(args);
	printk("args: 0x%lX\n", (unsigned long)pdesc->args);
	printk("argc: %d\n", *(int*)args);
	pdesc->envs = (void*)virt_to_phys(envs);
	printk("envs: 0x%lX\n", (unsigned long)pdesc->envs);
	printk("envc: %d\n", *(int*)envs);

	isp.msg = SCD_MSG_PREPARE_PROCESS;
	isp.ref = pdesc->cpu;
	isp.arg = virt_to_phys(pdesc);

	printk("# of sections: %d\n", pdesc->num_sections);
	printk("%p (%lx)\n", pdesc, isp.arg);
	
	pdesc->status = 0;
	mcctrl_ikc_send(os, pdesc->cpu, &isp);

	wait_event_interruptible(usrdata->wq_prepare, pdesc->status);

	if(pdesc->err < 0){
		ret = pdesc->err;	
		goto free_out;
	}

	ppd = kmalloc(sizeof(*ppd), GFP_ATOMIC);
	if (!ppd) {
		printk("ERROR: allocating per process data\n");
		ret = -ENOMEM;
		goto free_out;
	}

	ppd->pid = pdesc->pid;
	ppd->rpgtable = pdesc->rpgtable;

	flags = ihk_ikc_spinlock_lock(&usrdata->per_proc_list_lock);
	list_add_tail(&ppd->list, &usrdata->per_proc_list);
	ihk_ikc_spinlock_unlock(&usrdata->per_proc_list_lock, flags);
	
	dprintk("pid %d, rpgtable: 0x%lx added\n", 
		ppd->pid, ppd->rpgtable);

	if (copy_to_user(udesc, pdesc, sizeof(struct program_load_desc) + 
	             sizeof(struct program_image_section) * desc.num_sections)) {
		ret = -EFAULT;	
		goto free_out;
	}

	ret = 0;

free_out:
	kfree(args);
	kfree(pdesc);
	kfree(envs);

	return ret;
}

int mcexec_transfer_image(ihk_os_t os, struct remote_transfer *__user upt)
{
	struct remote_transfer pt;
	unsigned long phys, ret = 0;
	void *rpm;
#if 0	
	unsigned long dma_status = 0;
	ihk_dma_channel_t channel;
	struct ihk_dma_request request;
	void *p;

	channel = ihk_device_get_dma_channel(ihk_os_to_dev(os), 0);
	if (!channel) {
		return -EINVAL;
	}
#endif	

	if (copy_from_user(&pt, upt, sizeof(pt))) {
		return -EFAULT;
	}

	if (pt.size > PAGE_SIZE) {
		printk("mcexec_transfer_image(): ERROR: size exceeds PAGE_SIZE\n");
		return -EFAULT;
	}
	
	phys = ihk_device_map_memory(ihk_os_to_dev(os), pt.rphys, PAGE_SIZE);
#ifdef CONFIG_MIC
	rpm = ioremap_wc(phys, PAGE_SIZE);
#else
	rpm = ihk_device_map_virtual(ihk_os_to_dev(os), phys, PAGE_SIZE, NULL, 0);
#endif
	
	if (pt.direction == MCEXEC_UP_TRANSFER_TO_REMOTE) {
		if (copy_from_user(rpm, pt.userp, pt.size)) {
			ret = -EFAULT;
		}
	}
	else if (pt.direction == MCEXEC_UP_TRANSFER_FROM_REMOTE) {
		if (copy_to_user(pt.userp, rpm, pt.size)) {
			ret = -EFAULT;
		}
	}
	else {
		printk("mcexec_transfer_image(): ERROR: invalid direction\n");
		ret = -EINVAL;
	}

#ifdef CONFIG_MIC
	iounmap(rpm);
#else
	ihk_device_unmap_virtual(ihk_os_to_dev(os), rpm, PAGE_SIZE);
#endif
	ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);	

	return ret;

#if 0	
	p = (void *)__get_free_page(GFP_KERNEL);

	if (copy_from_user(p, pt.src, PAGE_SIZE)) {
		return -EFAULT;
	}

	memset(&request, 0, sizeof(request));
	request.src_os = NULL;
	request.src_phys = virt_to_phys(p);
	request.dest_os = os;
	request.dest_phys = pt.dest;
	request.size = PAGE_SIZE;
	request.notify = (void *)virt_to_phys(&dma_status);
	request.priv = (void *)1;

	ihk_dma_request(channel, &request);

	while (!dma_status) {
		mb();
		udelay(1);
	}

	free_page((unsigned long)p);

	return 0;
#endif
}

//extern unsigned long last_thread_exec;

struct handlerinfo {
	int	pid;
};

static long mcexec_debug_log(ihk_os_t os, unsigned long arg)
{
	struct ikc_scd_packet isp;

	memset(&isp, '\0', sizeof isp);
	isp.msg = SCD_MSG_DEBUG_LOG;
	isp.arg = arg;
	mcctrl_ikc_send(os, 0, &isp);
	return 0;
}

static void release_handler(ihk_os_t os, void *param)
{
	struct handlerinfo *info = param;
	struct ikc_scd_packet isp;

	memset(&isp, '\0', sizeof isp);
	isp.msg = SCD_MSG_CLEANUP_PROCESS;
	isp.pid = info->pid;

	mcctrl_ikc_send(os, 0, &isp);
	kfree(param);
}

static long mcexec_newprocess(ihk_os_t os,
                              struct newprocess_desc *__user udesc,
                              struct file *file)
{
	struct newprocess_desc desc;
	struct handlerinfo *info;

	if (copy_from_user(&desc, udesc, sizeof(struct newprocess_desc))) {
		return -EFAULT;
	}
	info = kmalloc(sizeof(struct handlerinfo), GFP_KERNEL);
	info->pid = desc.pid;
	ihk_os_register_release_handler(file, release_handler, info);
	return 0;
}

static long mcexec_start_image(ihk_os_t os,
                               struct program_load_desc * __user udesc,
                               struct file *file)
{
	struct program_load_desc desc;
	struct ikc_scd_packet isp;
	struct mcctrl_channel *c;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct handlerinfo *info;

	if (copy_from_user(&desc, udesc,
	                   sizeof(struct program_load_desc))) {
		return -EFAULT;
	}

	info = kmalloc(sizeof(struct handlerinfo), GFP_KERNEL);
	info->pid = desc.pid;
	ihk_os_register_release_handler(file, release_handler, info);

	c = usrdata->channels + desc.cpu;

	mcctrl_ikc_set_recv_cpu(os, desc.cpu);

	usrdata->last_thread_exec = desc.cpu;
	
	isp.msg = SCD_MSG_SCHEDULE_PROCESS;
	isp.ref = desc.cpu;
	isp.arg = desc.rprocess;

	mcctrl_ikc_send(os, desc.cpu, &isp);

	return 0;
}

static DECLARE_WAIT_QUEUE_HEAD(signalq);

static long mcexec_send_signal(ihk_os_t os, struct signal_desc *sigparam)
{
	struct ikc_scd_packet isp;
	struct mcctrl_channel *c;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct signal_desc sig;
	struct mcctrl_signal msig[2];
	struct mcctrl_signal *msigp;
	int rc;

	if (copy_from_user(&sig, sigparam, sizeof(struct signal_desc))) {
		return -EFAULT;
	}

	msigp = msig;
	if(((unsigned long)msig & 0xfffffffffffff000L) !=
	   ((unsigned long)(msig + 1) & 0xfffffffffffff000L))
		msigp++;
	memset(msigp, '\0', sizeof msig);
	msigp->sig = sig.sig;
	msigp->pid = sig.pid;
	msigp->tid = sig.tid;
	memcpy(&msigp->info, &sig.info, 128);

	c = usrdata->channels;
	isp.msg = SCD_MSG_SEND_SIGNAL;
	isp.ref = sig.cpu;
	isp.pid = sig.pid;
	isp.arg = virt_to_phys(msigp);

	if((rc = mcctrl_ikc_send(os, sig.cpu, &isp)) < 0){
		printk("mcexec_send_signal: mcctrl_ikc_send ret=%d\n", rc);
		return rc;
	}
	wait_event_interruptible(signalq, msigp->cond != 0);

	return 0;
}

void
sig_done(unsigned long arg, int err)
{
	struct mcctrl_signal *msigp;

	msigp = phys_to_virt(arg);
	msigp->cond = 1;
	wake_up_interruptible(&signalq);
}

static long mcexec_get_cpu(ihk_os_t os)
{
	struct ihk_cpu_info *info;

	info = ihk_os_get_cpu_info(os);
	if (!info) {
		printk("Error: cannot retrieve CPU info.\n");
		return -EINVAL;
	}
	if (info->n_cpus < 1) {
		printk("Error: # of cpu is invalid.\n");
		return -EINVAL;
	}

	return info->n_cpus;
}

int mcexec_syscall(struct mcctrl_channel *c, int pid, unsigned long arg)
{
	struct wait_queue_head_list_node *wqhln = NULL;
	struct wait_queue_head_list_node *wqhln_iter;
	unsigned long flags;

	/* Look up per-process wait queue head with pid */
	flags = ihk_ikc_spinlock_lock(&c->wq_list_lock);
	list_for_each_entry(wqhln_iter, &c->wq_list, list) {
		if (wqhln_iter->pid == pid) {
			wqhln = wqhln_iter;
			break;
		}
	}

	if (!wqhln) {
retry_alloc:
		wqhln = kmalloc(sizeof(*wqhln), GFP_ATOMIC);
		if (!wqhln) {
			printk("WARNING: coudln't alloc wait queue head, retrying..\n");
			goto retry_alloc;
		}

		wqhln->pid = pid;
		wqhln->req = 0;
		init_waitqueue_head(&wqhln->wq_syscall);
		list_add_tail(&wqhln->list, &c->wq_list);
	}
	ihk_ikc_spinlock_unlock(&c->wq_list_lock, flags);

	wqhln->req = 1;
	wake_up(&wqhln->wq_syscall);

	return 0;
}

#ifndef DO_USER_MODE
// static int remaining_job, base_cpu, job_pos;
#endif

// extern int num_channels;
// extern int mcctrl_dma_abort;

int mcexec_wait_syscall(ihk_os_t os, struct syscall_wait_desc *__user req)
{
	struct syscall_wait_desc swd;
	struct mcctrl_channel *c;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct wait_queue_head_list_node *wqhln;
	struct wait_queue_head_list_node *wqhln_iter;
	int ret = 0;
	unsigned long irqflags;
#ifndef DO_USER_MODE
	unsigned long s, w, d;
#endif
	
//printk("mcexec_wait_syscall swd=%p req=%p size=%d\n", &swd, req, sizeof(swd.cpu));
	if (copy_from_user(&swd, req, sizeof(swd))) {
		return -EFAULT;
	}

	if (swd.cpu >= usrdata->num_channels)
		return -EINVAL;

	c = get_peer_channel(usrdata, current);
	if (c) {
		printk("mcexec_wait_syscall:already registered. task %p ch %p\n",
				current, c);
		return -EBUSY;
	}
	c = usrdata->channels + swd.cpu;

#ifdef DO_USER_MODE
retry:
	/* Prepare per-process wait queue head */
retry_alloc:
	wqhln = kmalloc(sizeof(*wqhln), GFP_KERNEL);
	if (!wqhln) {
		printk("WARNING: coudln't alloc wait queue head, retrying..\n");
		goto retry_alloc;
	}

	wqhln->pid = swd.pid;	
	wqhln->req = 0;
	init_waitqueue_head(&wqhln->wq_syscall);
	
	irqflags = ihk_ikc_spinlock_lock(&c->wq_list_lock);
	/* First see if there is one wait queue already */
	list_for_each_entry(wqhln_iter, &c->wq_list, list) {
		if (wqhln_iter->pid == current->tgid) {
			kfree(wqhln);
			wqhln = wqhln_iter;
			list_del(&wqhln->list);
			break;
		}
	}
	list_add_tail(&wqhln->list, &c->wq_list);
	ihk_ikc_spinlock_unlock(&c->wq_list_lock, irqflags);

	ret = wait_event_interruptible(wqhln->wq_syscall, wqhln->req);
	
	if (ret) {
		return -EINTR;
	}

	/* Remove per-process wait queue head */
	irqflags = ihk_ikc_spinlock_lock(&c->wq_list_lock);
	list_del(&wqhln->list);
	ihk_ikc_spinlock_unlock(&c->wq_list_lock, irqflags);
	kfree(wqhln);

	if (c->param.request_va->number == 61 &&
			c->param.request_va->args[0] == swd.pid) {

		dprintk("pid: %d, tid: %d: SC %d, swd.cpu: %d, WARNING: wait4() for self?\n",
				current->tgid,
				current->pid,
				c->param.request_va->number,
				swd.cpu);

		return -EINTR;
	}

#if 1
	mb();
	if (!c->param.request_va->valid) {
printk("mcexec_wait_syscall:stray wakeup\n");
		goto retry;
	}
#endif
#else
	while (1) {
		c = usrdata->channels + swd.cpu;
		rdtscll(s);
		if (!usrdata->remaining_job) {
			while (!(*c->param.doorbell_va)) {
				mb();
				cpu_relax();
				rdtscll(w);
				if (w > s + 1024UL * 1024 * 1024 * 10) {
					return -EINTR;
				}
			}
			d = (*c->param.doorbell_va) - 1;
			*c->param.doorbell_va = 0;

			if (d < 0 || d >= usrdata->num_channels) {
				d = 0;
			}
			usrdata->base_cpu = d;
			usrdata->job_pos = 0;
			usrdata->remaining_job = 1;
		} else { 
			usrdata->job_pos++;
		}
		
		for (; usrdata->job_pos < usrdata->num_channels; usrdata->job_pos++) {
			if (base_cpu + job_pos >= num_channels) {
				c = usrdata->channels + 
					(usrdata->base_cpu + usrdata->job_pos - usrdata->num_channels);
			} else {
				c = usrdata->channels + usrdata->base_cpu + usrdata->job_pos;
			}
			if (!c) {
				continue;
			}
			if (c->param.request_va &&
			    c->param.request_va->valid) {
#endif
				c->param.request_va->valid = 0; /* ack */
				dprintk("SC #%lx, %lx\n",
				        c->param.request_va->number,
				        c->param.request_va->args[0]);
				register_peer_channel(usrdata, current, c);
				if (__do_in_kernel_syscall(os, c, c->param.request_va)) {
					if (copy_to_user(&req->sr, c->param.request_va,
							 sizeof(struct syscall_request))) {
						deregister_peer_channel(usrdata, current, c);
						return -EFAULT;
					}
					return 0;
				}
				deregister_peer_channel(usrdata, current, c);
#ifdef	DO_USER_MODE
				goto retry;
#endif
#ifndef DO_USER_MODE
				if (usrdata->mcctrl_dma_abort) {
					return -2;
				}
			}
		}
		usrdata->remaining_job = 0;
	}
#endif
	return 0;
}

long mcexec_pin_region(ihk_os_t os, unsigned long *__user arg)
{
	struct prepare_dma_desc desc;
	int pin_shift = 16;
	int order;
	unsigned long a;

	if (copy_from_user(&desc, arg, sizeof(struct prepare_dma_desc))) {
		return -EFAULT;
	}

	order =  pin_shift - PAGE_SHIFT;
	if(desc.size > 0){
		order = get_order (desc.size);
	}

	a = __get_free_pages(GFP_KERNEL, order);
	if (!a) {
		return -ENOMEM;
	}

	a = virt_to_phys((void *)a);

	if (copy_to_user((void*)desc.pa, &a, sizeof(unsigned long))) {
		return -EFAULT;
	}
	return 0;
}

long mcexec_free_region(ihk_os_t os, unsigned long *__user arg)
{
	struct free_dma_desc desc;
	int pin_shift = 16;
	int order;

	if (copy_from_user(&desc, arg, sizeof(struct free_dma_desc))) {
		return -EFAULT;
	}

	order =  pin_shift - PAGE_SHIFT;
	if(desc.size > 0){
		order = get_order (desc.size);
	}

	if(desc.pa > 0){
		free_pages((unsigned long)phys_to_virt(desc.pa), order);
	}
	return 0;
}

long mcexec_load_syscall(ihk_os_t os, struct syscall_load_desc *__user arg)
{
	struct syscall_load_desc desc;
	unsigned long phys;
	void *rpm;
	
	if (copy_from_user(&desc, arg, sizeof(struct syscall_load_desc))) {
		return -EFAULT;
	}
	
	phys = ihk_device_map_memory(ihk_os_to_dev(os), desc.src, desc.size);
#ifdef CONFIG_MIC
	rpm = ioremap_wc(phys, desc.size);
#else
	rpm = ihk_device_map_virtual(ihk_os_to_dev(os), phys, desc.size, NULL, 0);
#endif

	dprintk("mcexec_load_syscall: %s (desc.size: %d)\n", rpm, desc.size);

	if (copy_to_user((void *__user)desc.dest, rpm, desc.size)) {
		return -EFAULT;
	}

#ifdef CONFIG_MIC
	iounmap(rpm);
#else
	ihk_device_unmap_virtual(ihk_os_to_dev(os), rpm, desc.size);
#endif
	
	ihk_device_unmap_memory(ihk_os_to_dev(os), phys, desc.size);	
	
/*
	ihk_dma_channel_t channel;
	struct ihk_dma_request request;
	unsigned long dma_status = 0;

	channel = ihk_device_get_dma_channel(ihk_os_to_dev(os), 0);
	if (!channel) {
		return -EINVAL;
	}

	memset(&request, 0, sizeof(request));
	request.src_os = os;
	request.src_phys = desc.src;
	request.dest_os = NULL;
	request.dest_phys = desc.dest;
	request.size = desc.size;
	request.notify = (void *)virt_to_phys(&dma_status);
	request.priv = (void *)1;

	ihk_dma_request(channel, &request);

	while (!dma_status) {
		mb();
		udelay(1);
	}
*/

	return 0;
}

long mcexec_ret_syscall(ihk_os_t os, struct syscall_ret_desc *__user arg)
{
	struct syscall_ret_desc ret;
	struct mcctrl_channel *mc;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
#if 0	
	ihk_dma_channel_t channel;
	struct ihk_dma_request request;

	channel = ihk_device_get_dma_channel(ihk_os_to_dev(os), 0);
	if (!channel) {
		return -EINVAL;
	}
#endif	

	if (copy_from_user(&ret, arg, sizeof(struct syscall_ret_desc))) {
		return -EFAULT;
	}
	mc = usrdata->channels + ret.cpu;
	if (!mc) {
		return -EINVAL;
	}
	deregister_peer_channel(usrdata, current, mc);

	mc->param.response_va->ret = ret.ret;

	if (ret.size > 0) {
		/* Host => Accel. Write is fast. */
		unsigned long phys;
		void *rpm;

		phys = ihk_device_map_memory(ihk_os_to_dev(os), ret.dest,
		                             ret.size);
#ifdef CONFIG_MIC
		rpm = ioremap_wc(phys, ret.size);
#else
		rpm = ihk_device_map_virtual(ihk_os_to_dev(os), phys, 
		                             ret.size, NULL, 0);
#endif
		
		if (copy_from_user(rpm, (void *__user)ret.src, ret.size)) {
			return -EFAULT;
		}

		mb();
		mc->param.response_va->status = 1;

#ifdef CONFIG_MIC
		iounmap(rpm);
#else
		ihk_device_unmap_virtual(ihk_os_to_dev(os), rpm, ret.size);
#endif
		ihk_device_unmap_memory(ihk_os_to_dev(os), phys, ret.size);

/*
		memset(&request, 0, sizeof(request));
		request.src_os = NULL;
		request.src_phys = ret.src;
		request.dest_os = os;
		request.dest_phys = ret.dest;
		request.size = ret.size;
		request.notify_os = os;
		request.notify = (void *)mc->param.response_rpa;
		request.priv = (void *)1;
		
		ihk_dma_request(channel, &request);
*/
	} else {
		mb();
		mc->param.response_va->status = 1;
	}

	return 0;
}

LIST_HEAD(mckernel_exec_files);
DEFINE_SPINLOCK(mckernel_exec_file_lock);
 

struct mckernel_exec_file {
	ihk_os_t os;
	pid_t pid;
	struct file *fp;
	struct list_head list;
};

int mcexec_open_exec(ihk_os_t os, char * __user filename)
{
	struct file *file;
	struct mckernel_exec_file *mcef;
	struct mckernel_exec_file *mcef_iter;
	int retval;

	file = open_exec(filename);
	retval = PTR_ERR(file);
	if (IS_ERR(file)) {
		goto out_return;
	}

	mcef = kmalloc(sizeof(*mcef), GFP_KERNEL);
	if (!mcef) {
		retval = ENOMEM;
		goto out_put_file;
	}

	spin_lock_irq(&mckernel_exec_file_lock);
	/* Find previous file (if exists) and drop it */
	list_for_each_entry(mcef_iter, &mckernel_exec_files, list) {
		if (mcef_iter->os == os && mcef_iter->pid == current->tgid) {
			allow_write_access(mcef_iter->fp);
			fput(mcef_iter->fp);
			list_del(&mcef_iter->list);
			kfree(mcef_iter);
			dprintk("%d open_exec dropped previous executable \n", (int)current->tgid);
			break;
		}
	}
	
	/* Add new exec file to the list */
	mcef->os = os;
	mcef->pid = current->tgid;
	mcef->fp = file;
	list_add_tail(&mcef->list, &mckernel_exec_files);
	spin_unlock(&mckernel_exec_file_lock);

	dprintk("%d open_exec and holding file: %s\n", (int)current->tgid, filename);
	return 0;
	
out_put_file:
	fput(file);

out_return:
	return -retval;
}


int mcexec_close_exec(ihk_os_t os)
{
	struct mckernel_exec_file *mcef = NULL;
	int found = 0;
		
	spin_lock_irq(&mckernel_exec_file_lock);
	list_for_each_entry(mcef, &mckernel_exec_files, list) {
		if (mcef->os == os && mcef->pid == current->tgid) {
			allow_write_access(mcef->fp);
			fput(mcef->fp);
			list_del(&mcef->list);
			kfree(mcef);
			found = 1;
			dprintk("%d close_exec dropped executable \n", (int)current->tgid);
			break;
		}
	}
	spin_unlock(&mckernel_exec_file_lock);

	return (found ? 0 : EINVAL);
}

long mcexec_strncpy_from_user(ihk_os_t os, struct strncpy_from_user_desc * __user arg)
{
	struct strncpy_from_user_desc desc;
	void *buf;
	void *dest;
	void *src;
	unsigned long remain;
	long want;
	long copied;

	if (copy_from_user(&desc, arg, sizeof(desc))) {
		return -EFAULT;
	}

	buf = (void *)__get_free_page(GFP_KERNEL);
	if (!buf) {
		return -ENOMEM;
	}

	dest = desc.dest;
	src = desc.src;
	remain = desc.n;
	want = 0;
	copied = 0;

	while ((remain > 0) && (want == copied)) {
		want = (remain > PAGE_SIZE)? PAGE_SIZE: remain;
		copied = strncpy_from_user(buf, src, want);
		if (copied == want) {
			if (copy_to_user(dest, buf, copied)) {
				copied = -EFAULT;
			}
		}
		else if (copied >= 0) {
			if (copy_to_user(dest, buf, copied+1)) {
				copied = -EFAULT;
			}
		}
		dest += copied;
		src += copied;
		remain -= copied;
	}

	desc.result = (copied >= 0)? (desc.n - remain): copied;
	free_page((unsigned long)buf);

	if (copy_to_user(arg, &desc, sizeof(*arg))) {
		return -EFAULT;
	}
	return 0;
}

long __mcctrl_control(ihk_os_t os, unsigned int req, unsigned long arg,
                      struct file *file)
{
	switch (req) {
	case MCEXEC_UP_PREPARE_IMAGE:
		return mcexec_prepare_image(os,
		                            (struct program_load_desc *)arg);
	case MCEXEC_UP_TRANSFER:
		return mcexec_transfer_image(os, (struct remote_transfer *)arg);

	case MCEXEC_UP_START_IMAGE:
		return mcexec_start_image(os, (struct program_load_desc *)arg, file);

	case MCEXEC_UP_WAIT_SYSCALL:
		return mcexec_wait_syscall(os, (struct syscall_wait_desc *)arg);

	case MCEXEC_UP_RET_SYSCALL:
		return mcexec_ret_syscall(os, (struct syscall_ret_desc *)arg);

	case MCEXEC_UP_LOAD_SYSCALL:
		return mcexec_load_syscall(os, (struct syscall_load_desc *)arg);

	case MCEXEC_UP_SEND_SIGNAL:
		return mcexec_send_signal(os, (struct signal_desc *)arg);

	case MCEXEC_UP_GET_CPU:
		return mcexec_get_cpu(os);

	case MCEXEC_UP_STRNCPY_FROM_USER:
		return mcexec_strncpy_from_user(os, 
				(struct strncpy_from_user_desc *)arg);

	case MCEXEC_UP_NEW_PROCESS:
		return mcexec_newprocess(os, (struct newprocess_desc *)arg,
		                         file);

	case MCEXEC_UP_OPEN_EXEC:
		return mcexec_open_exec(os, (char *)arg);

	case MCEXEC_UP_CLOSE_EXEC:
		return mcexec_close_exec(os);

	case MCEXEC_UP_PREPARE_DMA:
		return mcexec_pin_region(os, (unsigned long *)arg);

	case MCEXEC_UP_FREE_DMA:
		return mcexec_free_region(os, (unsigned long *)arg);
	case MCEXEC_UP_DEBUG_LOG:
		return mcexec_debug_log(os, arg);
	}
	return -EINVAL;
}

void mcexec_prepare_ack(ihk_os_t os, unsigned long arg, int err)
{
	struct program_load_desc *desc = phys_to_virt(arg);
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	desc->err = err;
	desc->status = 1;
	
	wake_up_all(&usrdata->wq_prepare);
}

