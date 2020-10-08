/* control.c COPYRIGHT FUJITSU LIMITED 2016-2017 */
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
#include <linux/version.h>
#include <linux/semaphore.h>
#include <linux/interrupt.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <asm/uaccess.h>
#include <asm/delay.h>
#include <asm/io.h>
#include <linux/syscalls.h>
#include <trace/events/sched.h>
#include <config.h>
#include "mcctrl.h"
#include <ihk/ihk_host_user.h>
#include <rusage.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <uapi/linux/sched/types.h>
#endif
#include <archdeps.h>

//#define DEBUG

#ifdef DEBUG
#define dprintk printk
#else
#define dprintk(...)
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
#define BITMAP_SCNLISTPRINTF(buf, buflen, maskp, nmaskbits) \
        bitmap_scnlistprintf(buf, buflen, maskp, nmaskbits)
#else
#define BITMAP_SCNLISTPRINTF(buf, buflen, maskp, nmaskbits) \
        scnprintf(buf, buflen, "%*pbl", nmaskbits, maskp)
#endif

//extern struct mcctrl_channel *channels;
int mcctrl_ikc_set_recv_cpu(ihk_os_t os, int cpu);
int syscall_backward(struct mcctrl_usrdata *, int, unsigned long, unsigned long,
                     unsigned long, unsigned long, unsigned long,
                     unsigned long, unsigned long *);

struct mcos_handler_info {
	int pid;
	int cpu;
	struct mcctrl_usrdata *ud;
	struct file *file;
	unsigned long user_start;
	unsigned long user_end;
	unsigned long prepare_thread;
};

static long mcexec_prepare_image(ihk_os_t os,
				struct program_load_desc * __user udesc,
				struct file *file)
{
	struct program_load_desc *desc = NULL;
	struct program_load_desc *pdesc = NULL;
	struct ikc_scd_packet isp;
	void *args = NULL;
	void *envs = NULL;
	int ret = 0;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd = NULL;
	int num_sections;
	int free_ikc_pointers = 1;
	struct mcos_handler_info *info;

	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		ret = -EINVAL;
		goto free_out;
	}

	desc = kmalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc) {
		printk("%s: error: allocating program_load_desc\n",
			__FUNCTION__);
		return -ENOMEM;
	}

	if (copy_from_user(desc, udesc,
	                    sizeof(struct program_load_desc))) {
		printk("%s: error: copying program_load_desc\n",
			__FUNCTION__);
		ret = -EFAULT;
		goto free_out;
	}

	info = ihk_os_get_mcos_private_data(file);
	if (!info) {
		ret = -EFAULT;
		goto free_out;
	}
	/* To serialize SCD_MSG_SCHEDULE_PROCESS and SCD_MSG_CLEANUP_PROCESS */
	info->cpu = desc->cpu;

	ppd = mcctrl_get_per_proc_data(usrdata, desc->pid);
	if (!ppd) {
		printk("%s: ERROR: no per process data for PID %d\n",
			__FUNCTION__, desc->pid);
		ret = -EINVAL;
		goto free_out;
	}

	num_sections = desc->num_sections;

	if (num_sections <= 0 || num_sections > 16) {
		printk("%s: ERROR: # of sections: %d\n",
			__FUNCTION__, num_sections);
		ret = -EINVAL;
		goto put_and_free_out;
	}

	pdesc = kmalloc(sizeof(struct program_load_desc) +
			sizeof(struct program_image_section) * num_sections,
			GFP_KERNEL);
	memcpy(pdesc, desc, sizeof(struct program_load_desc));

	if (copy_from_user(pdesc->sections, udesc->sections,
	                   sizeof(struct program_image_section)
	                   * num_sections)) {
		ret = -EFAULT;
		goto put_and_free_out;
	}

	kfree(desc);
	desc = NULL;

	pdesc->pid = task_tgid_vnr(current);

	if ((ret = reserve_user_space(usrdata, &pdesc->user_start,
				      &pdesc->user_end))) {
		goto put_and_free_out;
	}

	args = kmalloc(pdesc->args_len, GFP_KERNEL);
	if (copy_from_user(args, pdesc->args, pdesc->args_len)) {
		ret = -EFAULT;
		goto put_and_free_out;
	}

	envs = kmalloc(pdesc->envs_len, GFP_KERNEL);
	if (copy_from_user(envs, pdesc->envs, pdesc->envs_len)) {
		ret = -EFAULT;
		goto put_and_free_out;
	}

	pdesc->args = (void*)virt_to_phys(args);
	dprintk("args: 0x%lX\n", (unsigned long)pdesc->args);
	dprintk("argc: %ld\n", *(long *)args);
	pdesc->envs = (void*)virt_to_phys(envs);
	dprintk("envs: 0x%lX\n", (unsigned long)pdesc->envs);
	dprintk("envc: %ld\n", *(long *)envs);

	isp.msg = SCD_MSG_PREPARE_PROCESS;
	isp.ref = pdesc->cpu;
	isp.arg = virt_to_phys(pdesc);

	dprintk("# of sections: %d\n", pdesc->num_sections);
	dprintk("%p (%lx)\n", pdesc, isp.arg);

	ret = mcctrl_ikc_send_wait(os, pdesc->cpu, &isp, 0, NULL,
				   &free_ikc_pointers, 3, pdesc, args, envs);
	if (ret < 0) {
		/* either send or remote prepare_process failed */
		goto put_and_free_out;
	}
	/*
	 * Used as SCD_MSG_CLEANUP_PROCESS target which isn't scheduled
	 * with SCD_MSG_SCHEDULE_PROCESS
	 */
	info->prepare_thread = pdesc->rprocess;

	/* Update rpgtable */
	ppd->rpgtable = pdesc->rpgtable;

	if (copy_to_user(udesc, pdesc, sizeof(struct program_load_desc) +
	             sizeof(struct program_image_section) * num_sections)) {
		ret = -EFAULT;
		goto put_and_free_out;
	}

	dprintk("%s: pid %d, rpgtable: 0x%lx added\n",
		__FUNCTION__, ppd->pid, ppd->rpgtable);

	ret = 0;

put_and_free_out:
	mcctrl_put_per_proc_data(ppd);
free_out:
	if (free_ikc_pointers) {
		kfree(args);
		kfree(pdesc);
		kfree(envs);
		kfree(desc);
	}

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

struct mcos_handler_info;
static LIST_HEAD(host_threads); /* Used for FS switch */
DEFINE_RWLOCK(host_thread_lock);

struct mcos_handler_info *new_mcos_handler_info(ihk_os_t os, struct file *file)
{
	struct mcos_handler_info *info;

	info = kmalloc(sizeof(struct mcos_handler_info), GFP_KERNEL);
	if (info == NULL) {
		return NULL;
	}
	memset(info, '\0', sizeof(struct mcos_handler_info));

	info->ud = ihk_host_os_get_usrdata(os);
	if (!info->ud) {
		pr_err("%s: error: mcctrl_usrdata not found\n",
		       __func__);
		kfree(info);
		return NULL;
	}

	info->file = file;
	return info;
}

static long mcexec_debug_log(ihk_os_t os, unsigned long arg)
{
	struct ikc_scd_packet isp;

	memset(&isp, '\0', sizeof isp);
	isp.msg = SCD_MSG_DEBUG_LOG;
	isp.arg = arg;
	mcctrl_ikc_send(os, 0, &isp);
	return 0;
}

int mcexec_close_exec(ihk_os_t os, int pid);
int mcexec_destroy_per_process_data(ihk_os_t os, int pid);

static void release_handler(ihk_os_t os, void *param)
{
	struct mcos_handler_info *info = param;
	struct ikc_scd_packet isp;
	int os_ind = ihk_host_os_get_index(os);
	unsigned long flags;
	struct host_thread *thread;
	int ret;

	/* Finalize FS switch for uti threads */ 
	write_lock_irqsave(&host_thread_lock, flags);
	list_for_each_entry(thread, &host_threads, list) {
		if (thread->handler == info) {
			thread->handler = NULL;
		}
	}
	write_unlock_irqrestore(&host_thread_lock, flags);

	mcexec_close_exec(os, info->pid);

	mcexec_destroy_per_process_data(os, info->pid);

	memset(&isp, '\0', sizeof isp);
	isp.msg = SCD_MSG_CLEANUP_PROCESS;
	isp.pid = info->pid;
	isp.arg = info->prepare_thread;

	dprintk("%s: SCD_MSG_CLEANUP_PROCESS, info: %p, cpu: %d\n",
			__FUNCTION__, info, info->cpu);
	ret = mcctrl_ikc_send_wait(os, info->cpu,
			&isp, -20, NULL, NULL, 0);
	if (ret != 0) {
		printk("%s: WARNING: failed to send IKC msg: %d\n",
				__func__, ret);
	}

	if (os_ind >= 0) {
		delete_pid_entry(os_ind, info->pid);
	}
	kfree(param);
	dprintk("%s: SCD_MSG_CLEANUP_PROCESS, info: %p OK\n",
			__FUNCTION__, info);
}

static long mcexec_newprocess(ihk_os_t os, struct file *file)
{
	struct mcos_handler_info *info;

	info = new_mcos_handler_info(os, file);
	if (info == NULL) {
		return -ENOMEM;
	}
	info->pid = task_tgid_vnr(current);
	ihk_os_register_release_handler(file, release_handler, info);
	ihk_os_set_mcos_private_data(file, info);
	return 0;
}

static long mcexec_start_image(ihk_os_t os,
                               struct program_load_desc * __user udesc,
                               struct file *file)
{
	struct program_load_desc *desc;
	struct ikc_scd_packet isp;
	struct mcctrl_channel *c;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcos_handler_info *info;
	struct mcos_handler_info *prev_info;
	int ret = 0;

	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		return -EINVAL;
	}

	desc = kmalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc) {
		printk("%s: error: allocating program_load_desc\n",
			__FUNCTION__);
		return -ENOMEM;
	}

	if (copy_from_user(desc, udesc,
	                   sizeof(struct program_load_desc))) {
		ret = -EFAULT;
		goto out;
	}

	prev_info = ihk_os_get_mcos_private_data(file);
	info = new_mcos_handler_info(os, file);
	if (info == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	info->pid = desc->pid;
	info->cpu = desc->cpu;
	info->user_start = desc->user_start;
	info->user_end = desc->user_end;
	info->prepare_thread = prev_info->prepare_thread;
	ihk_os_register_release_handler(file, release_handler, info);
	ihk_os_set_mcos_private_data(file, info);

	c = usrdata->channels + desc->cpu;

	mcctrl_ikc_set_recv_cpu(os, desc->cpu);

	usrdata->last_thread_exec = desc->cpu;
	
	isp.msg = SCD_MSG_SCHEDULE_PROCESS;
	isp.ref = desc->cpu;
	isp.arg = desc->rprocess;

	ret = mcctrl_ikc_send(os, desc->cpu, &isp);
	if (ret < 0) {
		printk("%s: error: sending IKC msg\n", __FUNCTION__);
		goto out;
	}
	/* clear prepared thread struct */
	info->prepare_thread = 0;
out:
	kfree(desc);
	return ret;
}

static DECLARE_WAIT_QUEUE_HEAD(signalq);

struct mcctrl_signal_desc {
	struct mcctrl_signal msig;
	struct mcctrl_wakeup_desc wakeup;
	void *addrs[1];
};

static long mcexec_send_signal(ihk_os_t os, struct signal_desc *sigparam)
{
	struct ikc_scd_packet isp;
	struct mcctrl_channel *c;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct signal_desc sig;
	struct mcctrl_signal_desc *desc;
	struct mcctrl_signal *msigp;
	int rc, do_free;

	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		return -EINVAL;
	}

	if (copy_from_user(&sig, sigparam, sizeof(struct signal_desc))) {
		return -EFAULT;
	}

	desc = kmalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc) {
		return -ENOMEM;
	}

	msigp = &desc->msig;
	memset(msigp, '\0', sizeof(*msigp));
	msigp->sig = sig.sig;
	msigp->pid = sig.pid;
	msigp->tid = sig.tid;
	memcpy(&msigp->info, &sig.info, 128);

	c = usrdata->channels;
	isp.msg = SCD_MSG_SEND_SIGNAL;
	isp.ref = sig.cpu;
	isp.pid = sig.pid;
	isp.arg = virt_to_phys(msigp);

	rc = mcctrl_ikc_send_wait(os, sig.cpu, &isp, 0, &desc->wakeup,
				  &do_free, 1, desc);
	if (rc < 0) {
		printk("mcexec_send_signal: mcctrl_ikc_send ret=%d\n", rc);
		if (do_free)
			kfree(desc);
		return rc;
	}

	kfree(desc);
	return 0;
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

static long mcexec_get_nodes(ihk_os_t os)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		return -EINVAL;
	}

	if (!usrdata->mem_info) {
		pr_err("%s: error: mem_info not found\n", __func__);
		return -EINVAL;
	}

	return usrdata->mem_info->n_numa_nodes;
}

extern int linux_numa_2_mckernel_numa(struct mcctrl_usrdata *udp, int numa_id);
extern int mckernel_cpu_2_linux_cpu(struct mcctrl_usrdata *udp, int cpu_id);

static long mcexec_get_cpuset(ihk_os_t os, unsigned long arg)
{
	struct mcctrl_usrdata *udp = ihk_host_os_get_usrdata(os);
	struct mcctrl_part_exec *pe = NULL, *pe_itr;
	struct get_cpu_set_arg req;
	struct mcctrl_cpu_topology *cpu_top, *cpu_top_i;
	struct cache_topology *cache_top;
	int cpu, cpus_assigned, cpus_to_assign, cpu_prev;
	int ret = 0;
	int mcexec_linux_numa;
	int pe_list_len = 0;
	cpumask_t *mcexec_cpu_set = NULL;
	cpumask_t *cpus_used = NULL;
	cpumask_t *cpus_to_use = NULL;
	struct mcctrl_per_proc_data *ppd;
	struct process_list_item *pli;
	struct process_list_item *pli_next = NULL;
	struct process_list_item *pli_iter;

	if (!udp) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		return -EINVAL;
	}

	/* Look up per-process structure */
	ppd = mcctrl_get_per_proc_data(udp, task_tgid_vnr(current));
	if (!ppd) {
		return -EINVAL;
	}

	if (copy_from_user(&req, (void *)arg, sizeof(req))) {
		pr_err("%s: error copying user request\n", __func__);
		ret = -EINVAL;
		goto put_out;
	}

	/* User requested CPU mask? */
	if (req.req_cpu_list && req.req_cpu_list_len) {
		char *cpu_list = NULL;

		cpu_list = kmalloc(req.req_cpu_list_len, GFP_KERNEL);
		if (!cpu_list) {
			printk("%s: error: allocating CPU list\n", __FUNCTION__);
			ret = -ENOMEM;
			goto put_out;
		}

		if (copy_from_user(cpu_list,
					req.req_cpu_list, req.req_cpu_list_len)) {
			printk("%s: error copying CPU list request\n", __FUNCTION__);
			kfree(cpu_list);
			ret = -EINVAL;
			goto put_out;
		}

		cpus_used = kmalloc(sizeof(cpumask_t), GFP_KERNEL);
		cpus_to_use = kmalloc(sizeof(cpumask_t), GFP_KERNEL);
		if (!cpus_to_use || !cpus_used) {
			printk("%s: error: allocating CPU mask\n", __FUNCTION__);
			ret = -ENOMEM;
			kfree(cpu_list);
			goto put_out;
		}
		memset(cpus_used, 0, sizeof(cpumask_t));
		memset(cpus_to_use, 0, sizeof(cpumask_t));

		/* Parse CPU list */
		if (cpulist_parse(cpu_list, cpus_to_use) < 0) {
			printk("%s: invalid CPUs requested: %s\n",
				__FUNCTION__, cpu_list);
			ret = -EINVAL;
			kfree(cpu_list);
			goto put_out;
		}

		memcpy(cpus_used, cpus_to_use, sizeof(cpumask_t));

		/* Copy mask to user-space */
		if (copy_to_user(req.cpu_set, cpus_used,
					(req.cpu_set_size < sizeof(cpumask_t) ?
					 req.cpu_set_size : sizeof(cpumask_t)))) {
			printk("%s: error copying mask to user\n", __FUNCTION__);
			ret = -EINVAL;
			kfree(cpu_list);
			goto put_out;
		}

		/* Copy IKC target core */
		cpu = cpumask_next(-1, cpus_used);
		if (copy_to_user(req.target_core, &cpu, sizeof(cpu))) {
			printk("%s: error copying target core to user\n",
					__FUNCTION__);
			ret = -EINVAL;
			kfree(cpu_list);
			goto put_out;
		}

		/* Save in per-process structure */
		memcpy(&ppd->cpu_set, cpus_used, sizeof(cpumask_t));
		ppd->ikc_target_cpu = cpu;
		printk("%s: %s -> target McKernel CPU: %d\n",
			__func__, cpu_list, cpu);

		ret = 0;
		kfree(cpu_list);
		goto put_out;
	}

	mutex_lock(&udp->part_exec_lock);
	/* Find part_exec having same node_proxy */
	list_for_each_entry_reverse(pe_itr, &udp->part_exec_list, chain) {
		pe_list_len++;
		if (pe_itr->node_proxy_pid == req.ppid) {
			pe = pe_itr;
			break;
		}
	}

	if (!pe) {
		/* First process to enter CPU partitioning */
		pr_debug("%s: pe_list_len:%d\n", __func__, pe_list_len);
		if (pe_list_len >= PE_LIST_MAXLEN) {
			/* delete head entry of pe_list */
			pe_itr = list_first_entry(&udp->part_exec_list,
					struct mcctrl_part_exec, chain);
			list_del(&pe_itr->chain);
			kfree(pe_itr);
		}

		pe = kzalloc(sizeof(struct mcctrl_part_exec), GFP_KERNEL);
		if (!pe) {
			mutex_unlock(&udp->part_exec_lock);
			ret = -ENOMEM;
			goto put_out;
		}
		/* Init part_exec */
		mutex_init(&pe->lock);
		INIT_LIST_HEAD(&pe->pli_list);
		pe->nr_processes = req.nr_processes;
		pe->nr_processes_left = req.nr_processes;
		pe->nr_processes_joined = 0;
		pe->node_proxy_pid = req.ppid;

		list_add_tail(&pe->chain, &udp->part_exec_list);
		dprintk("%s: nr_processes: %d (partitioned exec starts)\n",
				__func__, pe->nr_processes);
	}
	mutex_unlock(&udp->part_exec_lock);

	mutex_lock(&pe->lock);

	if (pe->nr_processes != req.nr_processes) {
		printk("%s: error: requested number of processes"
				" doesn't match current partitioned execution\n",
				__FUNCTION__);
		ret = -EINVAL;
		goto put_and_unlock_out;
	}

	if (pe->nr_processes_joined >= pe->nr_processes) {
		printk("%s: too many processes have joined to the group of %d\n",
				__func__, req.ppid);
		ret = -EINVAL;
		goto put_and_unlock_out;
	}

	--pe->nr_processes_left;
	++pe->nr_processes_joined;
	dprintk("%s: nr_processes: %d, nr_processes_left: %d\n",
			__FUNCTION__,
			pe->nr_processes,
			pe->nr_processes_left);

	/* Wait for all processes */
	pli = kmalloc(sizeof(*pli), GFP_KERNEL);
	if (!pli) {
		printk("%s: error: allocating pli\n", __FUNCTION__);
		goto put_and_unlock_out;
	}

	pli->task = current;
	pli->ready = 0;
	pli->timeout = 0;
	init_waitqueue_head(&pli->pli_wq);

	pli_next = NULL;
	/* Add ourself to the list in order of start time */
	list_for_each_entry(pli_iter, &pe->pli_list, list) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
		if (pli_iter->task->start_time > current->start_time) {
			pli_next = pli_iter;
			break;
		}
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0) */
		if ((pli_iter->task->start_time.tv_sec >
					current->start_time.tv_sec) ||
				((pli_iter->task->start_time.tv_sec ==
				  current->start_time.tv_sec) &&
				 ((pli_iter->task->start_time.tv_nsec >
				   current->start_time.tv_nsec)))) {
			pli_next = pli_iter;
			break;
		}
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0) */
	}

	/* Add in front of next */
	if (pli_next) {
		list_add_tail(&pli->list, &pli_next->list);
	}
	else {
		list_add_tail(&pli->list, &pe->pli_list);
	}
	pli_next = NULL;

	/* Last process? Wake up first in list */
	if (pe->nr_processes_left == 0) {
		pli_next = list_first_entry(&pe->pli_list,
			struct process_list_item, list);
		list_del(&pli_next->list);
		pli_next->ready = 1;
		wake_up_interruptible(&pli_next->pli_wq);
		/* Reset process counter */
		pe->nr_processes_left = pe->nr_processes;
		pe->process_rank = 0;
	}

	/* Wait for the rest if not the last or if the last but
	 * the woken process is different than the last */
	if (pe->nr_processes_left || (pli_next && pli_next != pli)) {
		dprintk("%s: pid: %d, waiting in list\n",
				__FUNCTION__, task_tgid_vnr(current));
		mutex_unlock(&pe->lock);
		/* Timeout period: 10 secs + (#procs * 0.1sec) */
		ret = wait_event_interruptible_timeout(pli->pli_wq,
				pli->ready,
				msecs_to_jiffies(10000 + req.nr_processes * 100));
		mutex_lock(&pe->lock);

		/* First timeout task? Wake up everyone else,
		 * but tell them we timed out */
		if (ret == 0) {
			printk("%s: error: pid: %d, timed out, waking everyone\n",
					__FUNCTION__, task_tgid_vnr(current));
			while (!list_empty(&pe->pli_list)) {
				pli_next = list_first_entry(&pe->pli_list,
						struct process_list_item, list);
				list_del(&pli_next->list);
				pli_next->ready = 1;
				pli_next->timeout = 1;
				wake_up_interruptible(&pli_next->pli_wq);
			}

			ret = -ETIMEDOUT;
			goto put_and_unlock_out;
		}

		/* Interrupted or woken up by someone else due to time out? */
		if (ret < 0 || pli->timeout) {
			if (ret > 0) {
				printk("%s: error: pid: %d, job startup timed out\n",
						__FUNCTION__, task_tgid_vnr(current));
				ret = -ETIMEDOUT;
			}
			goto put_and_unlock_out;
		}

		/* Incorrect wakeup state? */
		if (!pli->ready) {
			printk("%s: error: pid: %d, not ready but woken?\n",
					__FUNCTION__, task_tgid_vnr(current));
			ret = -EINVAL;
			goto put_and_unlock_out;
		}

		dprintk("%s: pid: %d, woken up\n",
				__FUNCTION__, task_tgid_vnr(current));
	}

	--pe->nr_processes_left;
	kfree(pli);

	cpus_to_assign = udp->cpu_info->n_cpus / req.nr_processes;
	cpus_used = kmalloc(sizeof(cpumask_t), GFP_KERNEL);
	cpus_to_use = kmalloc(sizeof(cpumask_t), GFP_KERNEL);
	mcexec_cpu_set = kmalloc(sizeof(cpumask_t), GFP_KERNEL);
	if (!cpus_used || !cpus_to_use || !mcexec_cpu_set) {
		printk("%s: error: allocating cpu masks\n", __FUNCTION__);
		ret = -ENOMEM;
		goto put_and_unlock_out;
	}
	memcpy(cpus_used, &pe->cpus_used, sizeof(cpumask_t));
	memset(cpus_to_use, 0, sizeof(cpumask_t));
	memset(mcexec_cpu_set, 0, sizeof(cpumask_t));

	/* Find the first unused CPU */
	cpu = cpumask_next_zero(-1, cpus_used);
	if (cpu >= udp->cpu_info->n_cpus) {
		printk("%s: error: no more CPUs available\n",
				__FUNCTION__);
		ret = -EINVAL;
		goto put_and_unlock_out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
	cpumask_set_cpu(cpu, cpus_used);
	cpumask_set_cpu(cpu, cpus_to_use);
	if (udp->cpu_info->ikc_mapped) {
		cpumask_set_cpu(udp->cpu_info->ikc_map[cpu], mcexec_cpu_set);
	}
#else
	cpu_set(cpu, *cpus_used);
	cpu_set(cpu, *cpus_to_use);
	if (udp->cpu_info->ikc_mapped) {
		cpu_set(udp->cpu_info->ikc_map[cpu], *mcexec_cpu_set);
	}
#endif
	cpu_prev = cpu;
	dprintk("%s: CPU %d assigned (first)\n", __FUNCTION__, cpu);

	for (cpus_assigned = 1; cpus_assigned < cpus_to_assign;
			++cpus_assigned) {
		int node;

		cpu_top = NULL;
		/* Find the topology object of the last core assigned */
		list_for_each_entry(cpu_top_i, &udp->cpu_topology_list, chain) {
			if (cpu_top_i->mckernel_cpu_id == cpu_prev) {
				cpu_top = cpu_top_i;
				break;
			}
		}

		if (!cpu_top) {
			printk("%s: error: couldn't find CPU topology info\n",
					__FUNCTION__);
			ret = -EINVAL;
			goto put_and_unlock_out;
		}

		/* Find a core sharing the same cache iterating caches from
		 * the most inner one outwards */
		list_for_each_entry(cache_top, &cpu_top->cache_list, chain) {
			for_each_cpu(cpu, &cache_top->shared_cpu_map) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
				if (!cpumask_test_cpu(cpu, cpus_used)) {
#else
				if (!cpu_isset(cpu, *cpus_used)) {
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
					cpumask_set_cpu(cpu, cpus_used);
					cpumask_set_cpu(cpu, cpus_to_use);
					if (udp->cpu_info->ikc_mapped) {
						cpumask_set_cpu(udp->cpu_info->ikc_map[cpu],
								mcexec_cpu_set);
					}
#else
					cpu_set(cpu, *cpus_used);
					cpu_set(cpu, *cpus_to_use);
					if (udp->cpu_info->ikc_mapped) {
						cpu_set(udp->cpu_info->ikc_map[cpu],
								*mcexec_cpu_set);
					}
#endif
					cpu_prev = cpu;
					dprintk("%s: CPU %d assigned (same cache L%lu)\n",
						__FUNCTION__, cpu, cache_top->saved->level);
					goto next_cpu;
				}
			}
		}

		/* No CPU? Find a core from the same NUMA node */
		node = linux_numa_2_mckernel_numa(udp,
				cpu_to_node(mckernel_cpu_2_linux_cpu(udp, cpu_prev)));

		for_each_cpu_not(cpu, cpus_used) {
			/* Invalid CPU? */
			if (cpu >= udp->cpu_info->n_cpus)
				break;

			/* Found one */
			if (node == linux_numa_2_mckernel_numa(udp,
						cpu_to_node(mckernel_cpu_2_linux_cpu(udp, cpu)))) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
				cpumask_set_cpu(cpu, cpus_used);
				cpumask_set_cpu(cpu, cpus_to_use);
				if (udp->cpu_info->ikc_mapped) {
					cpumask_set_cpu(udp->cpu_info->ikc_map[cpu],
							mcexec_cpu_set);
				}
#else
				cpu_set(cpu, *cpus_used);
				cpu_set(cpu, *cpus_to_use);
				if (udp->cpu_info->ikc_mapped) {
					cpu_set(udp->cpu_info->ikc_map[cpu],
							*mcexec_cpu_set);
				}
#endif
				cpu_prev = cpu;
				dprintk("%s: CPU %d assigned (same NUMA)\n",
						__FUNCTION__, cpu);
				goto next_cpu;
			}
		}

		/* No CPU? Simply find the next unused one */
		cpu = cpumask_next_zero(-1, cpus_used);
		if (cpu >= udp->cpu_info->n_cpus) {
			printk("%s: error: no more CPUs available\n",
					__FUNCTION__);
			ret = -EINVAL;
			goto put_and_unlock_out;
		}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
		cpumask_set_cpu(cpu, cpus_used);
		cpumask_set_cpu(cpu, cpus_to_use);
		if (udp->cpu_info->ikc_mapped) {
			cpumask_set_cpu(udp->cpu_info->ikc_map[cpu], mcexec_cpu_set);
		}
#else
		cpu_set(cpu, *cpus_used);
		cpu_set(cpu, *cpus_to_use);
		if (udp->cpu_info->ikc_mapped) {
			cpu_set(udp->cpu_info->ikc_map[cpu], *mcexec_cpu_set);
		}
#endif
		cpu_prev = cpu;
		dprintk("%s: CPU %d assigned (unused)\n",
				__FUNCTION__, cpu);

next_cpu:
		continue;
	}

	/* Found all cores, let user know */
	if (copy_to_user(req.cpu_set, cpus_to_use,
				(req.cpu_set_size < sizeof(cpumask_t) ?
				 req.cpu_set_size : sizeof(cpumask_t)))) {
		printk("%s: error copying mask to user\n", __FUNCTION__);
		ret = -EINVAL;
		goto put_and_unlock_out;
	}

	/* Copy IKC target core */
	cpu = cpumask_next(-1, cpus_to_use);
	if (copy_to_user(req.target_core, &cpu, sizeof(cpu))) {
		printk("%s: error copying target core to user\n",
				__FUNCTION__);
		ret = -EINVAL;
		goto put_and_unlock_out;
	}

	/* Copy rank */
	if (copy_to_user(req.process_rank, &pe->process_rank,
				sizeof(int))) {
		printk("%s: error copying process rank to user\n",
				__FUNCTION__);
		ret = -EINVAL;
		goto put_and_unlock_out;
	}

	/* mcexec NUMA to bind to */
	mcexec_linux_numa = cpu_to_node(mckernel_cpu_2_linux_cpu(udp, cpu));
	if (copy_to_user(req.mcexec_linux_numa, &mcexec_linux_numa,
				sizeof(mcexec_linux_numa))) {
		printk("%s: error copying mcexec Linux NUMA id\n",
				__FUNCTION__);
		ret = -EINVAL;
		goto put_and_unlock_out;
	}

	/* mcexec cpu_set to bind to if user requested */
	if (req.mcexec_cpu_set && udp->cpu_info->ikc_mapped) {
		int ikc_mapped = 1;

		if (copy_to_user(req.mcexec_cpu_set, mcexec_cpu_set,
					(req.mcexec_cpu_set_size < sizeof(cpumask_t) ?
					 req.mcexec_cpu_set_size : sizeof(cpumask_t)))) {
			printk("%s: error copying mcexec CPU set to user\n", __FUNCTION__);
			ret = -EINVAL;
			goto put_and_unlock_out;
		}

		if (copy_to_user(req.ikc_mapped, &ikc_mapped,
					sizeof(ikc_mapped))) {
			printk("%s: error copying ikc_mapped\n", __FUNCTION__);
			ret = -EINVAL;
			goto put_and_unlock_out;
		}
	}

	/* Save in per-process structure */
	memcpy(&ppd->cpu_set, cpus_to_use, sizeof(cpumask_t));
	ppd->ikc_target_cpu = cpu;

	/* Commit used cores to OS structure */
	memcpy(&pe->cpus_used, cpus_used, sizeof(*cpus_used));

	/* If not last process, wake up next process in list */
	if (pe->nr_processes_left != 0) {
		++pe->process_rank;
		pli_next = list_first_entry(&pe->pli_list,
			struct process_list_item, list);
		list_del(&pli_next->list);
		pli_next->ready = 1;
		wake_up_interruptible(&pli_next->pli_wq);
	}

	dprintk("%s: pid: %d, ret: 0\n", __FUNCTION__, task_tgid_vnr(current));
	ret = 0;

put_and_unlock_out:
	mutex_unlock(&pe->lock);

put_out:
	mcctrl_put_per_proc_data(ppd);

	kfree(cpus_to_use);
	kfree(cpus_used);
	kfree(mcexec_cpu_set);

	return ret;
}

#define THREAD_POOL_PER_CPU_THRESHOLD	(128)

int mcctrl_get_num_pool_threads(ihk_os_t os)
{
	struct mcctrl_usrdata *ud = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd = NULL;
	int hash;
	unsigned long flags;
	int nr_threads = 0;

	if (!ud) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		return -EINVAL;
	}

	for (hash = 0; hash < MCCTRL_PER_PROC_DATA_HASH_SIZE; ++hash) {

		read_lock_irqsave(&ud->per_proc_data_hash_lock[hash], flags);

		list_for_each_entry(ppd, &ud->per_proc_data_hash[hash], hash) {
			struct pid *vpid;
			struct task_struct *ppd_task;

			vpid = find_vpid(ppd->pid);
			if (!vpid) {
				printk("%s: WARNING: couldn't find vpid with PID number %d?\n",
					__FUNCTION__, ppd->pid);
				continue;
			}

			ppd_task = get_pid_task(vpid, PIDTYPE_PID);
			if (!ppd_task) {
				printk("%s: WARNING: couldn't find task with PID %d?\n",
					__FUNCTION__, ppd->pid);
				continue;
			}

			nr_threads += get_nr_threads(ppd_task);
			put_task_struct(ppd_task);
		}

		read_unlock_irqrestore(&ud->per_proc_data_hash_lock[hash], flags);
	}

	dprintk("%s: nr_threads: %d, num_online_cpus: %d\n",
		__FUNCTION__, nr_threads, num_online_cpus());
	return (nr_threads > (num_online_cpus() * THREAD_POOL_PER_CPU_THRESHOLD));
}

int mcctrl_add_per_proc_data(struct mcctrl_usrdata *ud, int pid, 
	struct mcctrl_per_proc_data *ppd)
{
	struct mcctrl_per_proc_data *ppd_iter;
	int hash = (pid & MCCTRL_PER_PROC_DATA_HASH_MASK);
	int ret = 0;
	unsigned long flags;

	/* Check if data for this thread exists and add if not */
	write_lock_irqsave(&ud->per_proc_data_hash_lock[hash], flags);
	list_for_each_entry(ppd_iter, &ud->per_proc_data_hash[hash], hash) {
		if (ppd_iter->pid == pid) {
			ret = -EBUSY;
			goto out;
		}
	}

	list_add_tail(&ppd->hash, &ud->per_proc_data_hash[hash]);

out:
	write_unlock_irqrestore(&ud->per_proc_data_hash_lock[hash], flags);
	return ret;
}


/* NOTE: per-process data is refcounted.
 * For every get call the user should call put. */
struct mcctrl_per_proc_data *mcctrl_get_per_proc_data(
		struct mcctrl_usrdata *ud, int pid)
{
	struct mcctrl_per_proc_data *ppd_iter, *ppd = NULL;
	int hash = (pid & MCCTRL_PER_PROC_DATA_HASH_MASK);
	unsigned long flags;

	/* Check if data for this process exists and return it */
	read_lock_irqsave(&ud->per_proc_data_hash_lock[hash], flags);
	list_for_each_entry(ppd_iter, &ud->per_proc_data_hash[hash], hash) {
		if (ppd_iter->pid == pid) {
			ppd = ppd_iter;
			break;
		}
	}

	if (ppd) {
		atomic_inc(&ppd->refcount);
	}

	read_unlock_irqrestore(&ud->per_proc_data_hash_lock[hash], flags);

	return ppd;
}

/* Drop reference. If zero, remove and deallocate */
void mcctrl_put_per_proc_data(struct mcctrl_per_proc_data *ppd)
{
	int hash;
	unsigned long flags;
	int i;
	struct wait_queue_head_list_node *wqhln;
	struct wait_queue_head_list_node *wqhln_next;
	struct ikc_scd_packet *packet;
	struct mcctrl_per_thread_data *ptd;
	struct mcctrl_per_thread_data *next;

	if (!ppd)
		return;

	hash = (ppd->pid & MCCTRL_PER_PROC_DATA_HASH_MASK);

	/* Removal from hash table and the refcount reaching zero
	 * have to happen atomically */
	write_lock_irqsave(&ppd->ud->per_proc_data_hash_lock[hash], flags);
	if (!atomic_dec_and_test(&ppd->refcount)) {
		write_unlock_irqrestore(&ppd->ud->per_proc_data_hash_lock[hash], flags);
		return;
	}

	list_del(&ppd->hash);
	write_unlock_irqrestore(&ppd->ud->per_proc_data_hash_lock[hash], flags);

	dprintk("%s: deallocating PPD for pid %d\n", __FUNCTION__, ppd->pid);

	for (i = 0; i < MCCTRL_PER_THREAD_DATA_HASH_SIZE; i++) {
		write_lock_irqsave(&ppd->per_thread_data_hash_lock[i], flags);
		list_for_each_entry_safe(ptd, next,
		                         ppd->per_thread_data_hash + i, hash) {

			/* We use ERESTARTSYS to tell the LWK that the proxy
			   process is gone and the application should be terminated. */
			packet = (struct ikc_scd_packet *)ptd->data;
			dprintk("%s: calling __return_syscall (hash),target pid=%d,tid=%d\n", __FUNCTION__, ppd->pid, packet->req.rtid);
			__return_syscall(ppd->ud->os, packet, -ERESTARTSYS,
					 packet->req.rtid);
			ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet);

			/* Note that uti ptd needs another put by mcexec_terminate_thread()
			   (see mcexec_syscall_wait()).
			   TODO: Detect tracer has died before calling mcexec_terminate_thread() and put uti ptd */
			if (atomic_read(&ptd->refcount) != 1) {
				printk("%s: WARNING: ptd->refcount != 1 but %d\n", __FUNCTION__, atomic_read(&ptd->refcount));
			}
			mcctrl_put_per_thread_data_unsafe(ptd);
			pr_ptd("put", ptd->tid, ptd);
		}
		write_unlock_irqrestore(&ppd->per_thread_data_hash_lock[i], flags);
	}

	flags = ihk_ikc_spinlock_lock(&ppd->wq_list_lock);
	list_for_each_entry_safe(wqhln, wqhln_next, &ppd->wq_req_list, list) {
		list_del(&wqhln->list);
		packet = wqhln->packet;
		kfree(wqhln);

		/* We use ERESTARTSYS to tell the LWK that the proxy
		 * process is gone and the application should be terminated */
		__return_syscall(ppd->ud->os, packet, -ERESTARTSYS,
				packet->req.rtid);
		ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet);
	}
	ihk_ikc_spinlock_unlock(&ppd->wq_list_lock, flags);

	pager_remove_process(ppd);
	kfree(ppd);
}


/*
 * Called indirectly from the IKC message handler.
 */
int mcexec_syscall(struct mcctrl_usrdata *ud, struct ikc_scd_packet *packet)
{
	struct wait_queue_head_list_node *wqhln = NULL;
	struct wait_queue_head_list_node *wqhln_iter;
	struct wait_queue_head_list_node *wqhln_alloc = NULL;
	int pid = packet->pid;
	unsigned long flags;
	struct mcctrl_per_proc_data *ppd;
	int ret;

	/* Handle requests that do not need the proxy process right now */
	ret = __do_in_kernel_irq_syscall(ud->os, packet);
	if (ret != -ENOSYS) {
		ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet);
		return ret;
	}

	/* Get a reference to per-process structure */
	ppd = mcctrl_get_per_proc_data(ud, pid);

	if (unlikely(!ppd)) {
		dprintk("%s: ERROR: no per-process structure for PID %d, "
				"syscall nr: %lu\n",
				__FUNCTION__, pid, packet->req.number);

		/* We use ERESTARTSYS to tell the LWK that the proxy
		 * process is gone and the application should be terminated */
		__return_syscall(ud->os, packet, -ERESTARTSYS,
				packet->req.rtid);
		ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet);

		return -1;
	}

	dprintk("%s: (packet_handler) rtid: %d, ttid: %d, sys nr: %d\n",
			__FUNCTION__,
			packet->req.rtid,
			packet->req.ttid,
			packet->req.number);
	/*
	 * Three scenarios are possible:
	 * - Find the designated thread if req->ttid is specified.
	 * - Find any available thread if req->ttid is zero.
	 * - Add a request element if no threads are available.
	 */
	flags = ihk_ikc_spinlock_lock(&ppd->wq_list_lock);

	/* Is this a request for a specific thread? See if it's waiting */
	if (unlikely(packet->req.ttid)) {
		list_for_each_entry(wqhln_iter, &ppd->wq_list_exact, list) {
			if (packet->req.ttid != wqhln_iter->rtid)
				continue;

			wqhln = wqhln_iter;
			break;
		}
		/* Find the mcexec thread with the same tid as the requesting McKernel thread 
		   and let it handle the migrate-to-Linux request */
		if (packet->req.number == __NR_sched_setaffinity && packet->req.args[0] == 0) {
			list_for_each_entry(wqhln_iter, &ppd->wq_list, list) {
				if (packet->req.ttid == wqhln_iter->rtid) {
					if (!wqhln_iter->task) {
						printk("%s: ERROR: wqhln_iter->task=%p,rtid=%d,&ppd->wq_list_lock=%p\n", __FUNCTION__, wqhln_iter->task, wqhln_iter->rtid, &ppd->wq_list_lock);
					} else if(wqhln_iter->req) {
						/* list_del() is called after woken-up */
						dprintk("%s: INFO: target thread is busy, wqhln_iter->req=%d,rtid=%d,&ppd->wq_list_lock=%p\n", __FUNCTION__, wqhln_iter->req, wqhln_iter->rtid, &ppd->wq_list_lock);
					} else {
						wqhln = wqhln_iter;
						dprintk("%s: uti, worker with tid of %d found in wq_list\n", __FUNCTION__, packet->req.ttid);
					}
					break;
				}
			}
			if (!wqhln) {
				dprintk("%s: uti: INFO: target worker (tid=%d) not found in wq_list\n", __FUNCTION__, packet->req.ttid);
			}
		} else {
			if (!wqhln) {
				printk("%s: WARNING: no target thread (tid=%d) found for exact request??\n",
					   __FUNCTION__, packet->req.ttid);
			}
		}
	}
	/* Is there any thread available? */
	else {
		list_for_each_entry(wqhln_iter, &ppd->wq_list, list) {
			if (wqhln_iter->task && !wqhln_iter->req) {
				wqhln = wqhln_iter;
				break;
			}
		}
	}

	/* If no match found, add request to pending request list */
	if (unlikely(!wqhln)) {
retry_alloc:
		wqhln_alloc = kmalloc(sizeof(*wqhln), GFP_ATOMIC);
		if (!wqhln_alloc) {
			printk("WARNING: coudln't alloc wait queue head, retrying..\n");
			goto retry_alloc;
		}

		wqhln = wqhln_alloc;
		wqhln->req = 0;
		wqhln->task = NULL;
		/* Let the mcexec thread to handle migrate-to-Linux request in mcexec_wait_syscall() after finishing the current task */
		if (packet->req.number == __NR_sched_setaffinity && packet->req.args[0] == 0) {
			wqhln->rtid = packet->req.ttid;
		} else {
			wqhln->rtid = 0;
		}
		init_waitqueue_head(&wqhln->wq_syscall);
		list_add_tail(&wqhln->list, &ppd->wq_req_list);
	}

	wqhln->packet = packet;
	wqhln->req = 1;
	wake_up(&wqhln->wq_syscall);
	ihk_ikc_spinlock_unlock(&ppd->wq_list_lock, flags);

	mcctrl_put_per_proc_data(ppd);

	return 0;
}

/*
 * Called from an mcexec thread via ioctl().
 */
int mcexec_wait_syscall(ihk_os_t os, struct syscall_wait_desc *__user req)
{
	struct ikc_scd_packet *packet;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct wait_queue_head_list_node *wqhln = NULL;
	struct wait_queue_head_list_node *wqhln_iter;
	int ret = 0;
	unsigned long irqflags;
	struct mcctrl_per_proc_data *ppd;
	struct mcctrl_per_thread_data *ptd = NULL;

	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		return -EINVAL;
	}

	/* Get a reference to per-process structure */
	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));

	if (unlikely(!ppd)) {
		kprintf("%s: ERROR: no per-process structure for PID %d??\n",
			__FUNCTION__, task_tgid_vnr(current));
			return -EINVAL;
	}

	ptd = mcctrl_get_per_thread_data(ppd, current);
	if (ptd) {
		printk("%s: ERROR: packet %p is already registered for thread %d\n",
				__FUNCTION__, ptd->data, task_pid_vnr(current));
		mcctrl_put_per_thread_data(ptd);
		ret = -EBUSY;
		goto no_ptd;
	}

retry:
	/* Prepare per-thread wait queue head or find a valid request */
	irqflags = ihk_ikc_spinlock_lock(&ppd->wq_list_lock);

	/* Handle migrate-to-Linux request if any */
	list_for_each_entry(wqhln_iter, &ppd->wq_req_list, list) {
		if (wqhln_iter->rtid == task_pid_vnr(current)) {
			wqhln = wqhln_iter;
			wqhln->task = current;
			list_del(&wqhln->list);
			goto found;
		}
	}

	/* First see if there is a valid request already that is not yet taken */
	list_for_each_entry(wqhln_iter, &ppd->wq_req_list, list) {
		if (!wqhln_iter->rtid && wqhln_iter->task == NULL && wqhln_iter->req) {
			wqhln = wqhln_iter;
			wqhln->task = current;
			list_del(&wqhln->list);
			break;
		}
	}
 found:
	if (!wqhln) {
retry_alloc:
		wqhln = kmalloc(sizeof(*wqhln), GFP_ATOMIC);
		if (!wqhln) {
			printk("WARNING: coudln't alloc wait queue head, retrying..\n");
			goto retry_alloc;
		}

		wqhln->task = current;
		wqhln->req = 0;
		wqhln->packet = NULL;
		/* Let mcexec_syscall() find the mcexec thread to handle migrate-to-Linux request */
		wqhln->rtid = task_pid_vnr(current);
		init_waitqueue_head(&wqhln->wq_syscall);

		list_add(&wqhln->list, &ppd->wq_list);
		ihk_ikc_spinlock_unlock(&ppd->wq_list_lock, irqflags);

		/* Wait for a request.. */
		ret = wait_event_interruptible(wqhln->wq_syscall, wqhln->req);

		/* Remove per-thread wait queue head */
		irqflags = ihk_ikc_spinlock_lock(&ppd->wq_list_lock);
		list_del(&wqhln->list);
	}
	ihk_ikc_spinlock_unlock(&ppd->wq_list_lock, irqflags);

	if (ret == -ERESTARTSYS) {
		/* Requeue valid requests */
		if (wqhln->req) {
			irqflags = ihk_ikc_spinlock_lock(&ppd->wq_list_lock);
			list_add_tail(&wqhln->list, &ppd->wq_req_list);
			ihk_ikc_spinlock_unlock(&ppd->wq_list_lock, irqflags);
		}
		else {
			kfree(wqhln);
		}
		wqhln = NULL;
		ret = -EINTR;
		goto no_ptd;
	}

	packet = wqhln->packet;
	kfree(wqhln);
	wqhln = NULL;

	dprintk("%s: tid: %d request from CPU %d\n",
			__FUNCTION__, task_pid_vnr(current), packet->ref);

	mb();
	if (!smp_load_acquire(&packet->req.valid)) {
		printk("%s: ERROR: stray wakeup pid: %d, tid: %d: SC %lu\n",
				__FUNCTION__,
				task_tgid_vnr(current),
				task_pid_vnr(current),
				packet->req.number);
		ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet);
		goto retry;
	}

	smp_store_release(&packet->req.valid,  0); /* ack */
	dprintk("%s: system call: %d, args[0]: %lu, args[1]: %lu, args[2]: %lu, "
			"args[3]: %lu, args[4]: %lu, args[5]: %lu\n",
			__FUNCTION__,
			packet->req.number,
			packet->req.args[0],
			packet->req.args[1],
			packet->req.args[2],
			packet->req.args[3],
			packet->req.args[4],
			packet->req.args[5]);
	
	/* Create ptd */
	if ((ret = mcctrl_add_per_thread_data(ppd, packet))) {
		kprintf("%s: error adding per-thread data (%d)\n", __FUNCTION__, ret);
		ret = -EINVAL;
		goto no_ptd;
	}
	
	/* Get a reference valid until offload is done */
	ptd = mcctrl_get_per_thread_data(ppd, current);
	if (!ptd) {
		kprintf("%s: ERROR: ptd not found\n", __FUNCTION__);
		ret = -EINVAL;
		goto no_ptd;
	}
	pr_ptd("get", task_pid_vnr(current), ptd);

	if (packet->req.number == __NR_sched_setaffinity  && packet->req.args[0] == 0) {
		dprintk("%s: uti,packet=%p,tid=%d\n", __FUNCTION__, packet, task_pid_vnr(current));

		/* Get a reference valid until thread-offload is done */
		ptd = mcctrl_get_per_thread_data(ppd, current);
		if (!ptd) {
			kprintf("%s: ptd not found\n", __FUNCTION__);
			ret = -EINVAL;
			goto no_ptd;
		}
		pr_ptd("get", task_pid_vnr(current), ptd);
	}

	if (__do_in_kernel_syscall(os, packet)) {
		if (copy_to_user(&req->sr, &packet->req,
					sizeof(struct syscall_request))) {
			ret = -EINVAL;
			goto put_ppd_out;
		}

		if (copy_to_user(&req->cpu, &packet->ref, sizeof(req->cpu))) {
			ret = -EINVAL;
			goto put_ppd_out;
		}

		ret = 0;
		goto put_ppd_out;
	}

	/* Drop reference to zero and restart from add */
	mcctrl_put_per_thread_data(ptd);
	pr_ptd("put,in_kernel", task_pid_vnr(current), ptd);

	mcctrl_put_per_thread_data(ptd);
	pr_ptd("put,in_kernel", task_pid_vnr(current), ptd);
	goto retry;

put_ppd_out:
	mcctrl_put_per_thread_data(ptd);
	pr_ptd("put,in_mcexec", task_pid_vnr(current), ptd);
 no_ptd:
	mcctrl_put_per_proc_data(ppd);
	return ret;
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

	return 0;
}

long mcexec_ret_syscall(ihk_os_t os, struct syscall_ret_desc *__user arg)
{
	struct syscall_ret_desc ret;
	struct ikc_scd_packet *packet;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd;
	struct mcctrl_per_thread_data *ptd;
	int error = 0;

	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		return -EINVAL;
	}

	if (copy_from_user(&ret, arg, sizeof(struct syscall_ret_desc))) {
		return -EFAULT;
	}

	/* Look up per-process structure */
	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));
	if (!ppd) {
		kprintf("%s: ERROR: no per-process structure for PID %d??\n", 
				__FUNCTION__, task_tgid_vnr(current));
		return -EINVAL;
	}

	/* Get a reference for this function */
	ptd = mcctrl_get_per_thread_data(ppd, current);
	if (!ptd) {
		printk("%s: ERROR: mcctrl_get_per_thread_data failed\n", __FUNCTION__);
		error = -EINVAL;
		goto no_ptd;
	}
	pr_ptd("get", task_pid_vnr(current), ptd);
	packet = (struct ikc_scd_packet *)ptd->data;
	if (!packet) {
		kprintf("%s: ERROR: no packet registered for TID %d\n", 
			__FUNCTION__, task_pid_vnr(current));
		error = -EINVAL;
		goto put_ppd_out;
	}

	if (ret.size > 0) {
		/* Host => Accel. Write is fast. */
		unsigned long phys;
		void *rpm;

		phys = ihk_device_map_memory(ihk_os_to_dev(os), ret.dest, ret.size);
#ifdef CONFIG_MIC
		rpm = ioremap_wc(phys, ret.size);
#else
		rpm = ihk_device_map_virtual(ihk_os_to_dev(os), phys, 
		                             ret.size, NULL, 0);
#endif
		if (copy_from_user(rpm, (void *__user)ret.src, ret.size)) {
			error = -EFAULT;
			goto out;
		}

#ifdef CONFIG_MIC
		iounmap(rpm);
#else
		ihk_device_unmap_virtual(ihk_os_to_dev(os), rpm, ret.size);
#endif
		ihk_device_unmap_memory(ihk_os_to_dev(os), phys, ret.size);
	} 

	__return_syscall(os, packet, ret.ret, task_pid_vnr(current));

	error = 0;
out:
	/* Free packet */
	ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet);
 put_ppd_out:
	/* Drop a reference for this function */
	mcctrl_put_per_thread_data(ptd);
	pr_ptd("put", task_pid_vnr(current), ptd);
	
	/* Final drop of the reference for non-uti syscall offloading */
	mcctrl_put_per_thread_data(ptd);
	pr_ptd("put", task_pid_vnr(current), ptd);
 no_ptd:
	mcctrl_put_per_proc_data(ppd);
	return error;
}

LIST_HEAD(mckernel_exec_files);
DEFINE_SEMAPHORE(mckernel_exec_file_lock);
 

struct mckernel_exec_file {
	ihk_os_t os;
	pid_t pid;
	struct file *fp;
	struct list_head list;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
#define GUIDVAL(x) (x)
#else
#define GUIDVAL(x) ((x).val)
#endif


int
mcexec_getcred(unsigned long phys)
{
	int	*virt = phys_to_virt(phys);

	virt[0] = GUIDVAL(current_uid());
	virt[1] = GUIDVAL(current_euid());
	virt[2] = GUIDVAL(current_suid());
	virt[3] = GUIDVAL(current_fsuid());
	virt[4] = GUIDVAL(current_gid());
	virt[5] = GUIDVAL(current_egid());
	virt[6] = GUIDVAL(current_sgid());
	virt[7] = GUIDVAL(current_fsgid());
	return 0;
}

int
mcexec_getcredv(int __user *virt)
{
	int	wk[8];

	wk[0] = GUIDVAL(current_uid());
	wk[1] = GUIDVAL(current_euid());
	wk[2] = GUIDVAL(current_suid());
	wk[3] = GUIDVAL(current_fsuid());
	wk[4] = GUIDVAL(current_gid());
	wk[5] = GUIDVAL(current_egid());
	wk[6] = GUIDVAL(current_sgid());
	wk[7] = GUIDVAL(current_fsgid());
	if(copy_to_user(virt, wk, sizeof(int) * 8))
		return -EFAULT;
	return 0;
}

int mcexec_create_per_process_data(ihk_os_t os,
				   struct rpgtable_desc * __user rpt,
				   struct file *file)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd = NULL;
	int i;
	struct rpgtable_desc krpt;
	long ret;

	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		return -EINVAL;
	}

	if (rpt &&
	    copy_from_user(&krpt, rpt, sizeof(krpt))) {
		return -EFAULT;
	}

	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));
	if (ppd) {
		printk("%s: WARNING: per-process data for pid %d already exists\n",
				__FUNCTION__, task_tgid_vnr(current));
		mcctrl_put_per_proc_data(ppd);
		return -EINVAL;
	}

	ppd = kmalloc(sizeof(*ppd), GFP_KERNEL);
	if (!ppd) {
		printk("%s: ERROR: allocating per-process data\n", __FUNCTION__);
		return -ENOMEM;
	}
	if ((ret = mcexec_newprocess(os, file))) {
		kfree(ppd);
		return ret;
	}
	memset(ppd, 0, sizeof(struct mcctrl_per_proc_data)); /* debug */

	ppd->ud = usrdata;
	ppd->pid = task_tgid_vnr(current);
	/*
	 * XXX: rpgtable will be updated in __do_in_kernel_syscall()
	 * under case __NR_munmap
	 */
	INIT_LIST_HEAD(&ppd->wq_list);
	INIT_LIST_HEAD(&ppd->wq_req_list);
	INIT_LIST_HEAD(&ppd->wq_list_exact);
	init_waitqueue_head(&ppd->wq_procfs);
	spin_lock_init(&ppd->wq_list_lock);
	memset(&ppd->cpu_set, 0, sizeof(cpumask_t));
	ppd->ikc_target_cpu = 0;
	/* Final ref will be dropped in release_handler() through
	 * mcexec_destroy_per_process_data() */
	atomic_set(&ppd->refcount, 1);

	for (i = 0; i < MCCTRL_PER_THREAD_DATA_HASH_SIZE; ++i) {
		INIT_LIST_HEAD(&ppd->per_thread_data_hash[i]);
		rwlock_init(&ppd->per_thread_data_hash_lock[i]);
	}

	INIT_LIST_HEAD(&ppd->devobj_pager_list);
	sema_init(&ppd->devobj_pager_lock, 1);

	if (mcctrl_add_per_proc_data(usrdata, ppd->pid, ppd) < 0) {
		printk("%s: error adding per process data\n", __FUNCTION__);
		kfree(ppd);
		return -EINVAL;
	}

	pager_add_process();

	dprintk("%s: PID: %d, counter: %d\n",
		__FUNCTION__, ppd->pid, atomic_read(&ppd->refcount));

	if (rpt) {
		ppd->rpgtable = krpt.rpgtable;
		return mcctrl_clear_pte_range(krpt.start, krpt.len);
	}

	return 0;
}

int mcexec_destroy_per_process_data(ihk_os_t os, int pid)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd = NULL;

	/* destroy_ikc_channels could have destroyed usrdata */
	if (!usrdata) {
		pr_warn("%s: warning: mcctrl_usrdata not found\n", __func__);
		return 0;
	}

	ppd = mcctrl_get_per_proc_data(usrdata, pid);

	if (ppd) {
		/* One for the reference and one for deallocation.
		 * XXX: actual deallocation may not happen here */
		mcctrl_put_per_proc_data(ppd);
		pr_ppd("put", task_pid_vnr(current), ppd);

		/* Note that it will call return_syscall() */
		mcctrl_put_per_proc_data(ppd);
		pr_ppd("put", task_pid_vnr(current), ppd);
	}
	else {
		printk("WARNING: no per process data for PID %d ?\n",
				task_tgid_vnr(current));
	}

	return 0;
}


int mcexec_open_exec(ihk_os_t os, char * __user filename)
{
	struct file *file;
	struct mckernel_exec_file *mcef;
	struct mckernel_exec_file *mcef_iter;
	int retval;
	int os_ind = ihk_host_os_get_index(os);
	char *pathbuf = NULL;
	char *fullpath = NULL;
	char *kfilename = NULL;
	int len;

	if (os_ind < 0) {
		return -EINVAL;
	}

	pathbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!pathbuf) {
		retval = -ENOMEM;
		goto out;
	}

	kfilename = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!kfilename) {
		retval = -ENOMEM;
		kfree(pathbuf);
		goto out;
	}

	len = strncpy_from_user(kfilename, filename, PATH_MAX);
	if (unlikely(len < 0)) {
		retval = -EINVAL;
		goto out_free;
	}

	file = open_exec(kfilename);
	retval = PTR_ERR(file);
	if (IS_ERR(file)) {
		goto out_free;
	}

	fullpath = d_path(&file->f_path, pathbuf, PATH_MAX);
	if (IS_ERR(fullpath)) {
		retval = PTR_ERR(fullpath);
		goto out_free;
	}

	mcef = kmalloc(sizeof(*mcef), GFP_KERNEL);
	if (!mcef) {
		retval = -ENOMEM;
		goto out_put_file;
	}
	memset(mcef, 0, sizeof(struct mckernel_exec_file)); /* debug */

	down(&mckernel_exec_file_lock);
	/* Find previous file (if exists) and drop it */
	list_for_each_entry(mcef_iter, &mckernel_exec_files, list) {
		if (mcef_iter->os == os && mcef_iter->pid == task_tgid_vnr(current)) {
			allow_write_access(mcef_iter->fp);
			fput(mcef_iter->fp);
			list_del(&mcef_iter->list);
			kfree(mcef_iter);
			break;
		}
	}

	/* Add new exec file to the list */
	mcef->os = os;
	mcef->pid = task_tgid_vnr(current);
	mcef->fp = file;
	list_add_tail(&mcef->list, &mckernel_exec_files);

	/* Create /proc/self/exe entry */
	add_pid_entry(os_ind, task_tgid_vnr(current));
	proc_exe_link(os_ind, task_tgid_vnr(current), fullpath);
	up(&mckernel_exec_file_lock);

	dprintk("%d open_exec and holding file: %s\n", (int)task_tgid_vnr(current),
			kfilename);

	kfree(kfilename);
	kfree(pathbuf);

	return 0;

out_put_file:
	fput(file);
out_free:
	kfree(pathbuf);
	kfree(kfilename);
out:
	return retval;
}

int mcexec_close_exec(ihk_os_t os, int pid)
{
	struct mckernel_exec_file *mcef = NULL;
	int found = 0;
	int os_ind = ihk_host_os_get_index(os);	

	if (os_ind < 0) {
		return EINVAL;
	}
		
	down(&mckernel_exec_file_lock);
	list_for_each_entry(mcef, &mckernel_exec_files, list) {
		if (mcef->os == os && mcef->pid == pid) {
			allow_write_access(mcef->fp);
			fput(mcef->fp);
			list_del(&mcef->list);
			kfree(mcef);
			found = 1;
			dprintk("%d close_exec dropped executable \n", (int)task_tgid_vnr(current));
			break;
		}
	}

	up(&mckernel_exec_file_lock);

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

long mcexec_sys_mount(struct sys_mount_desc *__user arg)
{
	struct sys_mount_desc desc;
	struct cred *promoted;
	const struct cred *original;
	int ret;

	if (copy_from_user(&desc, arg, sizeof(desc))) {
		return -EFAULT;
	}

	promoted = prepare_creds();
	if (!promoted) {
		return -ENOMEM;
	}
	cap_raise(promoted->cap_effective, CAP_SYS_ADMIN);
	original = override_creds(promoted);

	ret = mcctrl_sys_mount(desc.dev_name, desc.dir_name, desc.type,
		desc.flags, desc.data);

	revert_creds(original);
	put_cred(promoted);

	return ret;
}

long mcexec_sys_umount(struct sys_mount_desc *__user arg)
{
	struct sys_umount_desc desc;
	struct cred *promoted;
	const struct cred *original;
	int ret;

	if (copy_from_user(&desc, arg, sizeof(desc))) {
		return -EFAULT;
	}

	promoted = prepare_creds();
	if (!promoted) {
		return -ENOMEM;
	}
	cap_raise(promoted->cap_effective, CAP_SYS_ADMIN);
	original = override_creds(promoted);

	ret = mcctrl_sys_umount(desc.dir_name, MNT_FORCE);

	revert_creds(original);
	put_cred(promoted);

	return ret;
}

long mcexec_sys_unshare(struct sys_unshare_desc *__user arg)
{
	struct sys_unshare_desc desc;
	struct cred *promoted;
	const struct cred *original;
	int ret;

	if (copy_from_user(&desc, arg, sizeof(desc))) {
		return -EFAULT;
	}

	promoted = prepare_creds();
	if (!promoted) {
		return -ENOMEM;
	}
	cap_raise(promoted->cap_effective, CAP_SYS_ADMIN);
	original = override_creds(promoted);

	ret = mcctrl_sys_unshare(desc.unshare_flags);

	revert_creds(original);
	put_cred(promoted);

	return ret;
}

static DECLARE_WAIT_QUEUE_HEAD(perfctrlq);

long mcctrl_perf_num(ihk_os_t os, unsigned long arg)
{
	struct mcctrl_usrdata *usrdata;

	if (!os || ihk_host_validate_os(os)) {
		return -EINVAL;
	}

	usrdata = ihk_host_os_get_usrdata(os);

	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		return -EINVAL;
	}

	usrdata->perf_event_num = arg;

	return 0;
}

struct mcctrl_perf_ctrl_desc {
	struct perf_ctrl_desc desc;
	struct mcctrl_wakeup_desc wakeup;
	void *addrs[1];
};
#define wakeup_desc_of_perf_desc(_desc) \
	(&container_of((_desc), struct mcctrl_perf_ctrl_desc, desc)->wakeup)

/* Note that usrdata->perf_event_num is updated with # of registered
 * events
 */
long mcctrl_perf_set(ihk_os_t os, struct ihk_perf_event_attr *__user arg)
{
	struct mcctrl_usrdata *usrdata = NULL;
	struct ikc_scd_packet isp;
	struct perf_ctrl_desc *perf_desc;
	struct ihk_perf_event_attr attr;
	struct ihk_cpu_info *info = NULL;
	int ret = 0;
	int i = 0, j = 0;
	int need_free;
	int num_registered = 0;
	int err = 0;

	if (!os || ihk_host_validate_os(os)) {
		return -EINVAL;
	}

	usrdata = ihk_host_os_get_usrdata(os);

	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		return -EINVAL;
	}

	info = ihk_os_get_cpu_info(os);
	if (!info) {
		pr_err("%s: error: cannot get cpu info\n", __func__);
		return -EINVAL;
	}

	for (i = 0; i < usrdata->perf_event_num; i++) {
		ret = copy_from_user(&attr, &arg[i],
				     sizeof(struct ihk_perf_event_attr));
		if (ret) {
			pr_err("%s: error: copying ihk_perf_event_attr from user\n",
			       __func__);
			return -EINVAL;
		}

		perf_desc = kmalloc(sizeof(struct mcctrl_perf_ctrl_desc),
				    GFP_KERNEL);
		if (!perf_desc) {
			return -ENOMEM;
		}
		memset(perf_desc, '\0', sizeof(struct perf_ctrl_desc));

		perf_desc->ctrl_type = PERF_CTRL_SET;
		perf_desc->err = 0;
		perf_desc->target_cntr = i + ARCH_PERF_COUNTER_START;
		perf_desc->config = attr.config;
		perf_desc->exclude_kernel = attr.exclude_kernel;
		perf_desc->exclude_user = attr.exclude_user;

		memset(&isp, '\0', sizeof(struct ikc_scd_packet));
		isp.msg = SCD_MSG_PERF_CTRL;
		isp.arg = virt_to_phys(perf_desc);

		for (j = 0; j < info->n_cpus; j++) {
			ret = mcctrl_ikc_send_wait(os, j, &isp,
					msecs_to_jiffies(10000),
					wakeup_desc_of_perf_desc(perf_desc),
					&need_free, 1, perf_desc);
			if (ret < 0) {
				pr_warn("%s: mcctrl_ikc_send_wait ret=%d\n",
					__func__, ret);
				if (need_free)
					kfree(perf_desc);
				return ret;
			}

			err = perf_desc->err;
			if (err != 0) {
				break;
			}
		}

		if (err == 0) {
			num_registered++;
		}
		kfree(perf_desc);
	}

	usrdata->perf_event_num = num_registered;

	return num_registered;
}

long mcctrl_perf_get(ihk_os_t os, unsigned long *__user arg)
{
	struct mcctrl_usrdata *usrdata = NULL;
	struct ikc_scd_packet isp;
	struct perf_ctrl_desc *perf_desc;
	struct ihk_cpu_info *info = NULL;
	unsigned long value_sum = 0;
	int ret = 0;
	int i = 0, j = 0;
	int need_free;

	if (!os || ihk_host_validate_os(os)) {
		return -EINVAL;
	}

	usrdata = ihk_host_os_get_usrdata(os);
	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		return -EINVAL;
	}

	info = ihk_os_get_cpu_info(os);
	if (!info || info->n_cpus < 1) {
		return -EINVAL;
	}

	for (i = 0; i < usrdata->perf_event_num; i++) {
		perf_desc = kmalloc(sizeof(struct mcctrl_perf_ctrl_desc),
				    GFP_KERNEL);
		if (!perf_desc) {
			return -ENOMEM;
		}
		memset(perf_desc, '\0', sizeof(struct perf_ctrl_desc));

		perf_desc->ctrl_type = PERF_CTRL_GET;
		perf_desc->err = 0;
		perf_desc->target_cntr = i + ARCH_PERF_COUNTER_START;

		memset(&isp, '\0', sizeof(struct ikc_scd_packet));
		isp.msg = SCD_MSG_PERF_CTRL;
		isp.arg = virt_to_phys(perf_desc);

		for (j = 0; j < info->n_cpus; j++) {
			ret = mcctrl_ikc_send_wait(os, j, &isp,
					msecs_to_jiffies(10000),
					wakeup_desc_of_perf_desc(perf_desc),
					&need_free, 1, perf_desc);
			if (ret < 0) {
				pr_warn("%s: mcctrl_ikc_send_wait ret=%d\n",
					__func__, ret);
				if (need_free)
					kfree(perf_desc);
				return ret;
			}

			if (perf_desc->err == 0) {
				value_sum += perf_desc->read_value;
			}
		}
		kfree(perf_desc);
		if (copy_to_user(&arg[i], &value_sum, sizeof(unsigned long))) {
			printk("%s: error: copying read_value to user\n",
			       __func__);
			return -EINVAL;
		}
		value_sum = 0;
	}

	return 0;
}

long mcctrl_perf_enable(ihk_os_t os)
{
	struct mcctrl_usrdata *usrdata = NULL;
	struct ikc_scd_packet isp;
	struct perf_ctrl_desc *perf_desc;
	struct ihk_cpu_info *info = NULL;
	unsigned long cntr_mask = 0;
	int ret = 0;
	int i = 0, j = 0;
	int need_free;

	if (!os || ihk_host_validate_os(os)) {
		return -EINVAL;
	}

	usrdata = ihk_host_os_get_usrdata(os);
	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		return -EINVAL;
	}

	for (i = 0; i < usrdata->perf_event_num; i++) {
		cntr_mask |= 1UL << (i + ARCH_PERF_COUNTER_START);
	}
	perf_desc = kmalloc(sizeof(struct mcctrl_perf_ctrl_desc), GFP_KERNEL);
	if (!perf_desc) {
		return -ENOMEM;
	}
	memset(perf_desc, '\0', sizeof(struct perf_ctrl_desc));

	perf_desc->ctrl_type = PERF_CTRL_ENABLE;
	perf_desc->err = 0;
	perf_desc->target_cntr_mask = cntr_mask;

	memset(&isp, '\0', sizeof(struct ikc_scd_packet));
	isp.msg = SCD_MSG_PERF_CTRL;
	isp.arg = virt_to_phys(perf_desc);

	info = ihk_os_get_cpu_info(os);
	if (!info || info->n_cpus < 1) {
		kfree(perf_desc);
		return -EINVAL;
	}
	for (j = 0; j < info->n_cpus; j++) {
		ret = mcctrl_ikc_send_wait(os, j, &isp, 0,
					   wakeup_desc_of_perf_desc(perf_desc),
					   &need_free, 1, perf_desc);

		if (ret < 0) {
			pr_warn("%s: mcctrl_ikc_send_wait ret=%d\n",
				__func__, ret);
			if (need_free)
				kfree(perf_desc);
			return -EINVAL;
		}

		if (perf_desc->err < 0) {
			ret = perf_desc->err;
			kfree(perf_desc);
			return ret;
		}

	}
	kfree(perf_desc);

	return 0;
}

long mcctrl_perf_disable(ihk_os_t os)
{
	struct mcctrl_usrdata *usrdata = NULL;
	struct ikc_scd_packet isp;
	struct perf_ctrl_desc *perf_desc;
	struct ihk_cpu_info *info = NULL;
	unsigned long cntr_mask = 0;
	int ret = 0;
	int i = 0, j = 0;
	int need_free;

	if (!os || ihk_host_validate_os(os)) {
		return -EINVAL;
	}

	usrdata = ihk_host_os_get_usrdata(os);
	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		return -EINVAL;
	}

	for (i = 0; i < usrdata->perf_event_num; i++) {
		cntr_mask |= 1UL << (i + ARCH_PERF_COUNTER_START);
	}
	perf_desc = kmalloc(sizeof(struct mcctrl_perf_ctrl_desc), GFP_KERNEL);
	if (!perf_desc) {
		return -ENOMEM;
	}
	memset(perf_desc, '\0', sizeof(struct perf_ctrl_desc));

	perf_desc->ctrl_type = PERF_CTRL_DISABLE;
	perf_desc->err = 0;
	perf_desc->target_cntr_mask = cntr_mask;

	memset(&isp, '\0', sizeof(struct ikc_scd_packet));
	isp.msg = SCD_MSG_PERF_CTRL;
	isp.arg = virt_to_phys(perf_desc);

	info = ihk_os_get_cpu_info(os);
	if (!info || info->n_cpus < 1) {
		kfree(perf_desc);
		return -EINVAL;
	}
	for (j = 0; j < info->n_cpus; j++) {
		ret = mcctrl_ikc_send_wait(os, j, &isp, 0,
				wakeup_desc_of_perf_desc(perf_desc),
				&need_free, 1, perf_desc);
		if (ret < 0) {
			pr_warn("%s: mcctrl_ikc_send_wait ret=%d\n",
				__func__, ret);
			if (need_free)
				kfree(perf_desc);
			return -EINVAL;
		}

		if (perf_desc->err < 0) {
			ret = perf_desc->err;
			kfree(perf_desc);
			return ret;
		}
	}
	kfree(perf_desc);

	return 0;
}

long mcctrl_perf_destroy(ihk_os_t os)
{
	mcctrl_perf_disable(os);
	mcctrl_perf_num(os, 0);
	return 0;
}

/* Compose LWK-specific rusage structure */
long mcctrl_getrusage(ihk_os_t ihk_os, struct mcctrl_ioctl_getrusage_desc *__user _desc)
{
	struct mcctrl_ioctl_getrusage_desc desc;
	struct rusage_global *rusage_global = ihk_os_get_rusage(ihk_os);
	struct ihk_os_rusage *rusage = NULL;
	int ret = 0;
	int i;
	unsigned long ut;
	unsigned long st;

	if (!ihk_os || ihk_host_validate_os(ihk_os)) {
		return -EINVAL;
	}

	ret = copy_from_user(&desc, _desc, sizeof(struct mcctrl_ioctl_getrusage_desc));
	if (ret != 0) {
		printk("%s: copy_from_user failed\n", __FUNCTION__);
		goto out;
	}

	rusage = kmalloc(sizeof(struct ihk_os_rusage), GFP_KERNEL);
	if (!rusage) {
		printk("%s: kmalloc failed\n", __FUNCTION__);
		ret = -ENOMEM;
		goto out;
	}
	memset(rusage, 0, sizeof(struct ihk_os_rusage));

	/* Compile statistics */
	for (i = 0; i < IHK_MAX_NUM_PGSIZES; i++) {
		rusage->memory_stat_rss[i] = rusage_global->memory_stat_rss[i];
		rusage->memory_stat_mapped_file[i] = rusage_global->memory_stat_mapped_file[i];
	}
	rusage->memory_max_usage = rusage_global->memory_max_usage;
	rusage->memory_kmem_usage = rusage_global->memory_kmem_usage;
	rusage->memory_kmem_max_usage = rusage_global->memory_kmem_max_usage;
	for (i = 0; i < rusage_global->num_numa_nodes; i++) {
		rusage->memory_numa_stat[i] = rusage_global->memory_numa_stat[i];
	}
	for (ut = 0, st = 0, i = 0; i < rusage_global->num_processors; i++) {
		unsigned long wt;

		wt = rusage_global->cpu[i].user_tsc * rusage_global->ns_per_tsc / 1000;
		ut += wt;
		st += rusage_global->cpu[i].system_tsc * rusage_global->ns_per_tsc / 1000;
		rusage->cpuacct_usage_percpu[i] = wt;
	}
	rusage->cpuacct_stat_system = (st + 10000000 - 1) / 10000000;
	rusage->cpuacct_stat_user = (ut + 10000000 - 1) / 10000000;
	rusage->cpuacct_usage = ut;

	rusage->num_threads = rusage_global->num_threads;
	rusage->max_num_threads = rusage_global->max_num_threads;

	if (desc.size_rusage > sizeof(struct ihk_os_rusage)) {
		printk("%s: desc.size_rusage=%ld > sizeof(struct mckernel_rusage)=%ld\n",
		       __func__, desc.size_rusage,
		       sizeof(struct ihk_os_rusage));
		ret = -EINVAL;
		goto out;
	}

	ret = copy_to_user(desc.rusage, rusage, desc.size_rusage);
	if (ret != 0) {
		printk("%s: copy_to_user failed\n", __FUNCTION__);
		goto out;
	}

 out:
	if (rusage) {
		kfree(rusage);
	}

	return ret;
}

extern void *get_user_sp(void);
extern void set_user_sp(unsigned long);
extern void restore_tls(unsigned long addr);
extern void save_tls_ctx(void __user *ctx);
extern unsigned long get_tls_ctx(void __user *ctx);
extern unsigned long get_rsp_ctx(void *ctx);

long mcexec_uti_get_ctx(ihk_os_t os, struct uti_get_ctx_desc __user *udesc)
{
	struct uti_get_ctx_desc desc;
	unsigned long phys;
	struct uti_ctx *rctx;
	int rc = 0;
	unsigned long icurrent = (unsigned long)current;

	if(copy_from_user(&desc, udesc, sizeof(struct uti_get_ctx_desc))) {
		rc = -EFAULT;
		goto out;
	}

	phys = ihk_device_map_memory(ihk_os_to_dev(os), desc.rp_rctx, sizeof(struct uti_ctx));
#ifdef CONFIG_MIC
	rctx = ioremap_wc(phys, sizeof(struct uti_ctx));
#else
	rctx = ihk_device_map_virtual(ihk_os_to_dev(os), phys, sizeof(struct uti_ctx), NULL, 0);
#endif
	if (copy_to_user(desc.rctx, rctx->ctx, sizeof(struct uti_ctx))) {
		rc = -EFAULT;
		goto unmap_and_out;
	}

	if (copy_to_user(&udesc->key, &icurrent, sizeof(unsigned long))) {
		rc = -EFAULT;
		goto unmap_and_out;
	}
	
	rctx->uti_refill_tid = desc.uti_refill_tid;

 unmap_and_out:
#ifdef CONFIG_MIC
	iounmap(rctx);
#else
	ihk_device_unmap_virtual(ihk_os_to_dev(os), rctx, sizeof(struct uti_ctx));
#endif
	ihk_device_unmap_memory(ihk_os_to_dev(os), phys, sizeof(struct uti_ctx));
 out:
	return rc;
}

long mcctrl_switch_ctx(ihk_os_t os, struct uti_switch_ctx_desc __user *udesc,
		       struct file *file)
{
	int rc = 0;
	void *usp = get_user_sp();
	struct mcos_handler_info *info;
	struct host_thread *thread;
	unsigned long flags;
	struct uti_switch_ctx_desc desc;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd;

	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		rc = -EINVAL;
		goto out;
	}

	if (copy_from_user(&desc, udesc, sizeof(struct uti_switch_ctx_desc))) {
		printk("%s: Error: copy_from_user failed\n", __FUNCTION__);
		rc = -EFAULT;
		goto out;
	}

	rc = arch_switch_ctx(&desc);
	if (rc < 0) {
		goto out;
	}

	save_tls_ctx(desc.lctx);
	info = ihk_os_get_mcos_private_data(file);
	thread = kmalloc(sizeof(struct host_thread), GFP_KERNEL);
	memset(thread, '\0', sizeof(struct host_thread));
	thread->pid = task_tgid_vnr(current);
	thread->tid = task_pid_vnr(current);
	thread->usp = (unsigned long)usp;
	thread->ltls = get_tls_ctx(desc.lctx);
	thread->rtls = get_tls_ctx(desc.rctx);
	thread->handler = info;

	write_lock_irqsave(&host_thread_lock, flags);
	list_add_tail(&thread->list, &host_threads);
	write_unlock_irqrestore(&host_thread_lock, flags);

	/* How ppd refcount reaches zero depends on how utility-thread exits:
	   (1) MCEXEC_UP_CREATE_PPD sets to 1
	   (2) mcexec_util_thread2() increments to 2
	   (3) Tracer detects exit/exit_group/killed by signal of tracee
               and decrements to 1 via mcexec_terminate_thread()
	   (4) Tracer calls exit_fd(), it calls release_handler(),
	       it decrements to 0

	   KNOWN ISSUE: 
               mcexec_terminate_thread() isn't called when tracer is
	       unexpectedly killed so the refcount remains 1 when 
	       exiting release_handler()
	*/
	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));
	pr_ppd("get", task_pid_vnr(current), ppd);
 out:
	return rc;
}

/* Return value: 0 if target is uti thread, -EINVAL if not */
long
mcexec_sig_thread(ihk_os_t os, unsigned long arg, struct file *file)
{
	int tid = task_pid_vnr(current);
	int pid = task_tgid_vnr(current);
	unsigned long flags;
	struct host_thread *thread_iter, *thread = NULL;
	long ret = 0;

	read_lock_irqsave(&host_thread_lock, flags);
	list_for_each_entry(thread_iter, &host_threads, list) {
		if(thread_iter->pid == pid && thread_iter->tid == tid) {
			thread = thread_iter;
			break;
		}
	}
	read_unlock_irqrestore(&host_thread_lock, flags);
	if (thread) {
		if (arg)
			restore_tls(thread->ltls);
		else
			restore_tls(thread->rtls);
		goto out;
	}
	ret = -EINVAL;
 out:
	return ret;
}

static long mcexec_terminate_thread_unsafe(ihk_os_t os, int pid, int tid, long code, struct task_struct *tsk)
{
	struct ikc_scd_packet *packet;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd;
	struct mcctrl_per_thread_data *ptd;

	dprintk("%s: target pid=%d,tid=%d,code=%lx,task=%p\n", __FUNCTION__, pid, tid, code, tsk);

	if (!usrdata) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		goto no_ppd;
	}

	ppd = mcctrl_get_per_proc_data(usrdata, pid);
	if (!ppd) {
		kprintf("%s: ERROR: no per-process structure for PID %d??\n",
				__FUNCTION__, pid);
		goto no_ppd;
	}

	ptd = mcctrl_get_per_thread_data(ppd, tsk);
	if (!ptd) {
		printk("%s: ERROR: mcctrl_get_per_thread_data failed\n", __FUNCTION__);
		goto no_ptd;
	}
	if (ptd->tid != tid) {
		printk("%s: ERROR: ptd->tid(%d) != tid(%d)\n", __FUNCTION__, ptd->tid, tid);
		goto no_ptd;
	}
	pr_ptd("get", tid, ptd);

	packet = (struct ikc_scd_packet *)ptd->data;
	if (!packet) {
		kprintf("%s: ERROR: no packet registered for TID %d\n",
				__FUNCTION__, tid);
		goto no_ptd;
	}
	__return_syscall(usrdata->os, packet, code, tid);
	ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet);

	/* Drop reference for this function */
	mcctrl_put_per_thread_data(ptd);
	pr_ptd("put", tid, ptd);

	/* Final drop of reference for uti ptd */
	mcctrl_put_per_thread_data(ptd);
	pr_ptd("put", tid, ptd);

	if (atomic_read(&ptd->refcount) != 1) {
		printk("%s: WARNING: ptd->refcount != 1 but %d\n", __FUNCTION__, atomic_read(&ptd->refcount));
	}
	mcctrl_put_per_thread_data(ptd);
	pr_ptd("put", tid, ptd);
 no_ptd:
	mcctrl_put_per_proc_data(ppd);
	pr_ppd("put", task_pid_vnr(current), ppd);

	/* This is the final drop of uti-ppd */
	mcctrl_put_per_proc_data(ppd);
	pr_ppd("put", task_pid_vnr(current), ppd);
 no_ppd:
	return 0;
}

static long
mcexec_terminate_thread(ihk_os_t os, struct terminate_thread_desc * __user arg)
{
	long rc;
	unsigned long flags;
	struct terminate_thread_desc desc;
	struct host_thread *thread_iter, *thread = NULL;

    if (copy_from_user(&desc, arg, sizeof(struct terminate_thread_desc))) {
		rc = -EFAULT;
		goto out;
    }

	dprintk("%s: target pid=%d,tid=%d\n", __FUNCTION__, desc.pid, desc.tid);

	/* Stop switching FS registers for uti thread */
	write_lock_irqsave(&host_thread_lock, flags);
	list_for_each_entry(thread_iter, &host_threads, list) {
		if(thread_iter->tid == desc.tid) {
			thread = thread_iter;
			break;
		}
	}
	if (!thread) {
		printk("%s: ERROR: thread (pid=%d,tid=%d) not found in host_threads\n", __FUNCTION__, desc.pid, desc.tid);
		rc = -ESRCH;
		goto unlock_out;
	}

	list_del(&thread->list);
	kfree(thread);

	write_unlock_irqrestore(&host_thread_lock, flags);

	rc = mcexec_terminate_thread_unsafe(os, desc.pid, desc.tid, desc.code, (struct task_struct *)desc.tsk);

 out:
	return rc;

 unlock_out:
	write_unlock_irqrestore(&host_thread_lock, flags);
	goto out;
}

static long mcexec_release_user_space(struct release_user_space_desc *__user arg)
{
	struct release_user_space_desc desc;

	if (copy_from_user(&desc, arg, sizeof(desc))) {
		return -EFAULT;
	}

#if 1
	return mcctrl_clear_pte_range(desc.user_start,
				      desc.user_end - desc.user_start);
#else
	return release_user_space(desc.user_start, desc.user_end - desc.user_start);
#endif
}

 static long (*mckernel_do_futex)(int n, unsigned long arg0, unsigned long arg1,
			  unsigned long arg2, unsigned long arg3,
			  unsigned long arg4, unsigned long arg5,
				   unsigned long _uti_clv,
				   void *uti_futex_resp,
				   void *_linux_wait_event,
							  void *_linux_printk,
							  void *_linux_clock_gettime);

 long uti_wait_event(void *_resp, unsigned long nsec_timeout) {
	 struct uti_futex_resp *resp = _resp;
	 if (nsec_timeout) {
		 return wait_event_interruptible_timeout(resp->wq, resp->done, nsecs_to_jiffies(nsec_timeout));
	 } else {
		 return wait_event_interruptible(resp->wq, resp->done);
	 }
 }

 int uti_printk(const char *fmt, ...) {
	 int sum = 0, nwritten;
	 va_list args;
	 va_start(args, fmt);
	 nwritten = vprintk(fmt, args);
	 sum += nwritten;
	 va_end(args);
	 return sum;
 }

int uti_clock_gettime(clockid_t clk_id, struct timespec *tp) {
	int ret = 0;
	struct timespec64 ts64;
	dprintk("%s: clk_id=%x,REALTIME=%x,MONOTONIC=%x\n", __FUNCTION__, clk_id, CLOCK_REALTIME, CLOCK_MONOTONIC);
	switch(clk_id) {
	case CLOCK_REALTIME:
		getnstimeofday64(&ts64);
		tp->tv_sec = ts64.tv_sec;
		tp->tv_nsec = ts64.tv_nsec;
		dprintk("%s: CLOCK_REALTIME,%ld.%09ld\n", __FUNCTION__, tp->tv_sec, tp->tv_nsec);
		break;
	case CLOCK_MONOTONIC: {
		/* Do not use getrawmonotonic() because it returns different value than clock_gettime() */
		ktime_get_ts64(&ts64);
		tp->tv_sec = ts64.tv_sec;
		tp->tv_nsec = ts64.tv_nsec;
		dprintk("%s: CLOCK_MONOTONIC,%ld.%09ld\n", __FUNCTION__, tp->tv_sec, tp->tv_nsec);
		break; }
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

long mcexec_syscall_thread(ihk_os_t os, unsigned long arg, struct file *file)
{
	struct syscall_struct {
		int number;
		unsigned long args[6];
		unsigned long ret;
		unsigned long uti_clv; /* copy of a clv in McKernel */
	};
	struct syscall_struct param;
	struct syscall_struct __user *uparam =
	                              (struct syscall_struct __user *)arg;
	long rc;


	if (copy_from_user(&param, uparam, sizeof param)) {
		return -EFAULT;
	}

	if (param.number == __NR_futex) {
		struct uti_futex_resp resp = {
			.done = 0
		};
		init_waitqueue_head(&resp.wq);
		
 		if (!mckernel_do_futex) {
			if (ihk_os_get_special_address(os, IHK_SPADDR_MCKERNEL_DO_FUTEX,
										   (unsigned long *)&mckernel_do_futex,
										   NULL)) {
				kprintf("%s: ihk_os_get_special_address failed\n", __FUNCTION__);
				return -EINVAL;
			}
			dprintk("%s: mckernel_do_futex=%p\n", __FUNCTION__, mckernel_do_futex);
		}

		rc = (*mckernel_do_futex)(param.number, param.args[0], param.args[1], param.args[2],
							  param.args[3], param.args[4], param.args[5], param.uti_clv, (void *)&resp, (void *)uti_wait_event, (void *)uti_printk, (void *)uti_clock_gettime);
		param.ret = rc;
	} else {
		struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

		if (!usrdata) {
			pr_err("%s: error: mcctrl_usrdata not found\n",
			       __func__);
			return -EINVAL;
		}

		dprintk("%s: syscall_backward, SC %d, tid %d\n",
			__func__, param.number, task_tgid_vnr(current));
		rc = syscall_backward(usrdata, param.number,
				      param.args[0], param.args[1],
				      param.args[2], param.args[3],
				      param.args[4], param.args[5],
				      &param.ret);
		switch (param.number) {
		case __NR_munmap:
			dprintk("%s: syscall_backward, munmap,addr=%lx,len=%lx,tid=%d\n",
			__func__, param.args[0], param.args[1],
			       task_tgid_vnr(current));
			break;
		case __NR_mmap:
			dprintk("%s: syscall_backward, mmap,ret=%lx,tid=%d\n",
			       __func__, param.ret, task_tgid_vnr(current));
			break;
		default:
			break;
		}
	}
	if (copy_to_user(&uparam->ret, &param.ret, sizeof(unsigned long))) {
		return -EFAULT;
	}
	return rc;
}

void mcctrl_futex_wake(struct ikc_scd_packet *pisp)
{
	struct uti_futex_resp *resp;

	/* Guard the access to pisp->futex.resp, which is dead out of mcexec_syscall_thread() */
	if (*pisp->futex.spin_sleep == 0) {
		dprintk("%s: DEBUG: woken up by someone else\n", __FUNCTION__);
		return;
	}

	resp = pisp->futex.resp;
	if (!resp) {
		kprintf("%s: ERROR: pisp->futex.resp is NULL\n", __FUNCTION__);
		return;
	}

	if (*pisp->futex.spin_sleep == 0) {
		kprintf("%s: ERROR: resp is dead\n", __FUNCTION__);
		return;
	}

	resp->done = 1;
	wake_up_interruptible(&resp->wq);
}


static struct ihk_cache_topology *
cache_topo_search(struct ihk_cpu_topology *cpu_topo, int level)
{
	struct ihk_cache_topology *lcache_topo;

	list_for_each_entry(lcache_topo, &cpu_topo->cache_topology_list,
	                    chain) {
		if (lcache_topo->level == level)
			return lcache_topo;
	}
	return NULL;
}

static unsigned int *uti_rr;
static int max_cpu;

static int
uti_attr_init(void)
{
	int i;
	unsigned int *rr;
	unsigned int *retval;

	if (uti_rr)
		return 0;

	for_each_possible_cpu(i) {
		max_cpu = i;
	}
	max_cpu++;
	rr = (unsigned int *)kmalloc(sizeof(unsigned int) * max_cpu,
	                             GFP_KERNEL);
	if (!rr)
		return -ENOMEM;
	memset(rr, '\0', sizeof(unsigned int) * max_cpu);

	retval = __sync_val_compare_and_swap(&uti_rr, NULL, rr);
	if (retval != NULL) {
		kfree(rr);
	}

	return 0;
}

void
uti_attr_finalize(void)
{
	if (uti_rr)
		kfree(uti_rr);
}

static cpumask_t *
uti_cpu_select(cpumask_t *cpumask)
{
	int i;
	int mincpu;
	unsigned int minrr;
	unsigned int newval;
	unsigned int retval;

retry:
	minrr = (unsigned int)-1;
	mincpu = -1;
	for_each_cpu(i, cpumask) {
		int rr = uti_rr[i];
		if (rr < minrr) {
			mincpu = i;
			minrr = rr;
		}
	}
	newval = minrr + 1;
	retval = __sync_val_compare_and_swap(uti_rr + mincpu, minrr, newval);
	if (retval != minrr)
		goto retry;

	for_each_cpu(i, cpumask) {
		if (i != mincpu) {
			cpumask_clear_cpu(i, cpumask);
		}
	}
	
	return cpumask;
}

int pr_cpumask(const char *msg, cpumask_t* cpumask) {
	int ret;
	char *buf;
	
	if (!(buf = kmalloc(PAGE_SIZE * 2, GFP_KERNEL))) {
		kprintf("%s: error: allocating buf\n",
			__func__);
		ret = -ENOMEM;
		goto out;
	}
	
	BITMAP_SCNLISTPRINTF(buf, PAGE_SIZE * 2,
			     cpumask_bits(cpumask),
			     nr_cpumask_bits);
	buf[PAGE_SIZE * 2 - 1] = 0;

	pr_info("%s: info: cpuset: %s\n", msg, buf);
	ret = 0;
 out:
	return ret;
}

static long
mcexec_uti_attr(ihk_os_t os, struct uti_attr_desc __user *_desc)
{
	struct uti_attr_desc desc;
	char *uti_cpu_set_str;
	struct kuti_attr *kattr;
	cpumask_t *cpuset = NULL, *env_cpuset = NULL;
	struct mcctrl_usrdata *ud = ihk_host_os_get_usrdata(os);
	ihk_device_t dev = ihk_os_to_dev(os);
	struct mcctrl_cpu_topology *cpu_topo;
	struct mcctrl_cpu_topology *target_cpu = NULL;
	struct node_topology *node_topo;
	struct ihk_cache_topology *lcache_topo;
	struct ihk_node_topology *lnode_topo;
	cpumask_t *wkmask;
	int i;
	int rc = 0;
	int mask_size = cpumask_size();

	if (!ud) {
		pr_err("%s: error: mcctrl_usrdata not found\n",
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if ((rc = uti_attr_init())) {
		pr_err("%s: error: uti_attr_init (%d)\n",
		       __func__, rc);
		goto out;
	}

	if ((rc = copy_from_user(&desc, _desc, sizeof(desc)))) {
		pr_err("%s: error: copy_from_user\n",
		       __func__);
		rc = -EFAULT;
		goto out;
	}

	if (!(uti_cpu_set_str = kmalloc(desc.uti_cpu_set_len, GFP_KERNEL))) {
		pr_err("%s: error: allocating uti_cpu_set_str\n",
		       __func__);
		rc = -ENOMEM;
		goto out;
	}

	if ((rc = copy_from_user(uti_cpu_set_str, desc.uti_cpu_set_str, desc.uti_cpu_set_len))) {
		pr_err("%s: error: copy_from_user\n",
		       __func__);
		rc = -EFAULT;
		goto out;
	}

	kattr = phys_to_virt(desc.phys_attr);

	/* Find caller cpu for later resolution of subgroups */
	list_for_each_entry(cpu_topo, &ud->cpu_topology_list, chain) {
		if (cpu_topo->mckernel_cpu_id == kattr->parent_cpuid) {
			target_cpu = cpu_topo;
		}
	}

	if (!target_cpu) {
		printk("%s: errror: caller cpu not found\n",
		       __func__);
		return -EINVAL;
	}

	if (!(cpuset = kmalloc(mask_size * 2, GFP_KERNEL))) {
		return -ENOMEM;
	}
	wkmask = (cpumask_t *)(((char *)cpuset) + mask_size);

	/* Initial cpuset */
	memcpy(cpuset, cpu_active_mask, mask_size);

	if (kattr->attr.flags & UTI_FLAG_NUMA_SET) {
		nodemask_t *numaset = (nodemask_t *)&kattr->attr.numa_set[0];
		memset(wkmask, '\0', mask_size);
		for_each_node_mask(i, *numaset) {
			list_for_each_entry(node_topo, &ud->node_topology_list,
			                    chain) {
				if (node_topo->mckernel_numa_id == i) {
					cpumask_or(wkmask, wkmask,
					           &node_topo->saved->cpumap);
					break;
				}
			}
		}
		cpumask_and(cpuset, cpuset, wkmask);
	}

	if ((kattr->attr.flags & UTI_FLAG_SAME_NUMA_DOMAIN) ||
	    (kattr->attr.flags & UTI_FLAG_DIFFERENT_NUMA_DOMAIN)) {
		memset(wkmask, '\0', mask_size);
		for (i = 0; i < UTI_MAX_NUMA_DOMAINS; i++) {
			lnode_topo = ihk_device_get_node_topology(dev, i);
			if(!lnode_topo)
				continue;
			if(IS_ERR(lnode_topo))
				continue;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
			if (cpumask_test_cpu(target_cpu->saved->cpu_number,
			              &lnode_topo->cpumap)) {
#else
			if (cpu_isset(target_cpu->saved->cpu_number,
			              lnode_topo->cpumap)) {
#endif
				if (kattr->attr.flags &
				    UTI_FLAG_SAME_NUMA_DOMAIN) {
					cpumask_or(wkmask, wkmask,
					           &lnode_topo->cpumap);
				}
			}
			else {
				if (kattr->attr.flags &
				    UTI_FLAG_DIFFERENT_NUMA_DOMAIN) {
					cpumask_or(wkmask, wkmask,
					           &lnode_topo->cpumap);
				}
			}
		}
		cpumask_and(cpuset, cpuset, wkmask);
	}

	if (((kattr->attr.flags & UTI_FLAG_SAME_L1) ||
	     (kattr->attr.flags & UTI_FLAG_DIFFERENT_L1)) &&
	    (lcache_topo = cache_topo_search(target_cpu->saved, 1))) {
		if (kattr->attr.flags & UTI_FLAG_SAME_L1) {
			cpumask_and(cpuset, cpuset,
			            &lcache_topo->shared_cpu_map);
		}
		else {
			cpumask_complement(wkmask,
			                   &lcache_topo->shared_cpu_map);
			cpumask_and(cpuset, cpuset, wkmask);
		}
	}

	if (((kattr->attr.flags & UTI_FLAG_SAME_L2) ||
	     (kattr->attr.flags & UTI_FLAG_DIFFERENT_L2)) &&
	    (lcache_topo = cache_topo_search(target_cpu->saved, 2))) {
		if (kattr->attr.flags & UTI_FLAG_SAME_L2) {
			cpumask_and(cpuset, cpuset,
			            &lcache_topo->shared_cpu_map);
		}
		else {
			cpumask_complement(wkmask,
			                   &lcache_topo->shared_cpu_map);
			cpumask_and(cpuset, cpuset, wkmask);
		}
	}

	if (((kattr->attr.flags & UTI_FLAG_SAME_L3) ||
	     (kattr->attr.flags & UTI_FLAG_DIFFERENT_L3)) &&
	    (lcache_topo = cache_topo_search(target_cpu->saved, 3))) {
		if (kattr->attr.flags & UTI_FLAG_SAME_L3) {
			cpumask_and(cpuset, cpuset,
			            &lcache_topo->shared_cpu_map);
		}
		else {
			cpumask_complement(wkmask,
			                   &lcache_topo->shared_cpu_map);
			cpumask_and(cpuset, cpuset, wkmask);
		}
	}
	
	/* UTI_CPU_SET, PREFER_FWK, PREFER_LWK */

	if (uti_cpu_set_str) {
		if (!(env_cpuset = kmalloc(mask_size, GFP_KERNEL))) {
			pr_err("%s: error: allocating env_cpuset\n",
			       __func__);
			rc = -ENOMEM;
			goto out;
		}
		
		if (cpulist_parse(uti_cpu_set_str, env_cpuset) < 0) {
			pr_err("%s: error: cpulist_parse: %s\n",
			       __func__, uti_cpu_set_str);
			rc = -EINVAL;
			goto out;
		}

		//pr_cpumask("cpuset", cpuset);
		//pr_cpumask("env_cpuset", env_cpuset);
		
		if ((kattr->attr.flags & UTI_FLAG_PREFER_LWK)) {
			cpumask_andnot(cpuset, cpuset, env_cpuset);
		} else { /* Including PREFER_FWK and !PREFER_FWK */
			cpumask_and(cpuset, cpuset, env_cpuset);
		}
	}

	if (kattr->attr.flags &
	    (UTI_FLAG_EXCLUSIVE_CPU | UTI_FLAG_CPU_INTENSIVE)) {
		uti_cpu_select(cpuset);
	}

	//pr_cpumask("final cpuset", cpuset);

	/* Setaffinity cpuset */
	rc = cpumask_weight(cpuset);
	if (rc > 0) {
		if ((rc = mcctrl_sched_setaffinity(0, cpuset))) {
			pr_err("%s: error: setaffinity (%d)\n",
			       __func__, rc);
			goto out;
		}
	} else {
		pr_warn("%s: warning: cpuset is empty\n", __func__);
	}

	
	/* Assign real-time scheduler */
	if (kattr->attr.flags & UTI_FLAG_HIGH_PRIORITY) {
		struct sched_param sp;

		sp.sched_priority = 1;
		if ((rc = mcctrl_sched_setscheduler_nocheck(current, SCHED_FIFO, &sp))) {
			pr_err("%s: error: setscheduler_nocheck (%d)\n",
			       __func__, rc);
			goto out;
		}
	}

	rc = 0;
out:
	kfree(cpuset);
	kfree(env_cpuset);
	return rc;
}

static int __mcctrl_control_perm(unsigned int request)
{
	int ret = 0;
	kuid_t euid;

	/* black list */
	switch (request) {
	case IHK_OS_AUX_PERF_NUM:
	case IHK_OS_AUX_PERF_SET:
	case IHK_OS_AUX_PERF_GET:
	case IHK_OS_AUX_PERF_ENABLE:
	case IHK_OS_AUX_PERF_DISABLE:
	case IHK_OS_AUX_PERF_DESTROY:
		euid = current_euid();
		pr_debug("%s: request=0x%x, euid=%u\n",
			 __func__, request, euid.val);
		if (euid.val) {
			ret = -EPERM;
		}
		break;
	default:
		break;
	}
	pr_debug("%s: request=0x%x, ret=%d\n", __func__, request, ret);

	return ret;
}

long __mcctrl_control(ihk_os_t os, unsigned int req, unsigned long arg,
                      struct file *file)
{
	int ret;

	ret = __mcctrl_control_perm(req);
	if (ret) {
		pr_err("%s: error: permission denied, req: %x\n",
		       __func__, req);
		return ret;
	}

	switch (req) {
	case MCEXEC_UP_PREPARE_IMAGE:
		return mcexec_prepare_image(os,
					(struct program_load_desc *)arg,
					file);
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

	case MCEXEC_UP_CREATE_PPD:
		return mcexec_create_per_process_data(os,
				      (struct rpgtable_desc * __user)arg, file);

	case MCEXEC_UP_GET_NODES:
		return mcexec_get_nodes(os);

	case MCEXEC_UP_GET_CPUSET:
		return mcexec_get_cpuset(os, arg);

	case MCEXEC_UP_STRNCPY_FROM_USER:
		return mcexec_strncpy_from_user(os, 
				(struct strncpy_from_user_desc *)arg);

	case MCEXEC_UP_OPEN_EXEC:
		return mcexec_open_exec(os, (char *)arg);

	case MCEXEC_UP_CLOSE_EXEC:
		return mcexec_close_exec(os, task_tgid_vnr(current));

	case MCEXEC_UP_PREPARE_DMA:
		return mcexec_pin_region(os, (unsigned long *)arg);

	case MCEXEC_UP_FREE_DMA:
		return mcexec_free_region(os, (unsigned long *)arg);

	case MCEXEC_UP_GET_CRED:
		return mcexec_getcred((unsigned long)arg);

	case MCEXEC_UP_GET_CREDV:
		return mcexec_getcredv((int *)arg);

	case MCEXEC_UP_SYS_MOUNT:
		return mcexec_sys_mount((struct sys_mount_desc *)arg);

	case MCEXEC_UP_SYS_UMOUNT:
		return mcexec_sys_umount((struct sys_mount_desc *)arg);

	case MCEXEC_UP_SYS_UNSHARE:
		return mcexec_sys_unshare((struct sys_unshare_desc *)arg);

	case MCEXEC_UP_UTI_GET_CTX:
		return mcexec_uti_get_ctx(os, (struct uti_get_ctx_desc *)arg);

	case MCEXEC_UP_UTI_SWITCH_CTX:
		return mcctrl_switch_ctx(os, (struct uti_switch_ctx_desc *)arg,
					 file);

	case MCEXEC_UP_SIG_THREAD:
		return mcexec_sig_thread(os, arg, file);

	case MCEXEC_UP_SYSCALL_THREAD:
		return mcexec_syscall_thread(os, arg, file);

	case MCEXEC_UP_TERMINATE_THREAD:
		return mcexec_terminate_thread(os, (struct terminate_thread_desc *)arg);

	case MCEXEC_UP_RELEASE_USER_SPACE:
		return mcexec_release_user_space((struct release_user_space_desc *)arg);

	case MCEXEC_UP_GET_NUM_POOL_THREADS:
		return mcctrl_get_num_pool_threads(os);

	case MCEXEC_UP_UTI_ATTR:
		return mcexec_uti_attr(os, (struct uti_attr_desc __user *)arg);

	case MCEXEC_UP_DEBUG_LOG:
		return mcexec_debug_log(os, arg);

	case IHK_OS_AUX_PERF_NUM:
		return mcctrl_perf_num(os, arg);

	case IHK_OS_AUX_PERF_SET:
		return mcctrl_perf_set(os, (struct ihk_perf_event_attr *)arg);

	case IHK_OS_AUX_PERF_GET:
		return mcctrl_perf_get(os, (unsigned long *)arg);

	case IHK_OS_AUX_PERF_ENABLE:
		return mcctrl_perf_enable(os);

	case IHK_OS_AUX_PERF_DISABLE:
		return mcctrl_perf_disable(os);

	case IHK_OS_AUX_PERF_DESTROY:
		return mcctrl_perf_destroy(os);

	case IHK_OS_GETRUSAGE:
		return mcctrl_getrusage(os, (struct mcctrl_ioctl_getrusage_desc *)arg);
	}
	return -EINVAL;
}

int mcctrl_get_request_os_cpu(ihk_os_t os, int *ret_cpu)
{
	struct mcctrl_usrdata *usrdata;
	struct mcctrl_per_proc_data *ppd;
	struct mcctrl_per_thread_data *ptd;
	struct ikc_scd_packet *packet;
	struct ihk_ikc_channel_desc *ch;
	int ret = 0;

	if (!os || ihk_host_validate_os(os) || !ret_cpu) {
		return -EINVAL;
	}

	/* Look up per-OS mcctrl structure */
	usrdata = ihk_host_os_get_usrdata(os);
	if (!usrdata) {
		pr_err("%s: ERROR: mcctrl_usrdata not found for OS %p\n",
		       __func__, os);
		return -EINVAL;
	}

	/* Look up per-process structure */
	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));
	if (!ppd) {
		kprintf("%s: ERROR: no per-process structure for PID %d??\n",
				__FUNCTION__, task_tgid_vnr(current));
		return -EINVAL;
	}

	/* Look up per-thread structure */
	ptd = mcctrl_get_per_thread_data(ppd, current);
	if (!ptd) {
		printk("%s: ERROR: mcctrl_get_per_thread_data failed\n", __FUNCTION__);
		ret = -EINVAL;
		goto no_ptd;
	}
	pr_ptd("get", task_pid_vnr(current), ptd);
	packet = (struct ikc_scd_packet *)ptd->data;
	if (!packet) {
		printk("%s: ERROR: no packet registered for TID %d\n",
				__FUNCTION__, task_pid_vnr(current));
		ret = -EINVAL;
		goto out_put_ppd;
	}

	/* TODO: define a new IHK query function instead of
	 * accessing internals directly */
	ch = (usrdata->channels + packet->ref)->c;
	*ret_cpu = ch->send.queue->read_cpu;
	ret = 0;

	dprintk("%s: OS: %lx, CPU: %d\n",
		__func__, (unsigned long)os, *ret_cpu);

out_put_ppd:
	mcctrl_put_per_thread_data(ptd);
	pr_ptd("put", task_pid_vnr(current), ptd);
 no_ptd:
	mcctrl_put_per_proc_data(ppd);

	return ret;
}

int __mcctrl_os_read_write_cpu_register(ihk_os_t os, int cpu,
		struct ihk_os_cpu_register *desc,
		enum mcctrl_os_cpu_operation op)
{
	struct mcctrl_usrdata *udp = ihk_host_os_get_usrdata(os);
	struct ikc_scd_packet isp;
	struct ihk_os_cpu_register *ldesc = NULL;
	int do_free = 0;
	int ret = -EINVAL;

	if (!udp) {
		pr_err("%s: error: mcctrl_usrdata not found\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	if (cpu < 0 || cpu >= udp->cpu_info->n_cpus) {
		pr_err("%s: error: cpu (%d) is out of range\n",
		       __func__, cpu);
		ret = -EINVAL;
		goto out;

	}

	/* Keep a dynamic structure around that can
	 * survive an early return due to a signal */
	ldesc = kmalloc(sizeof(*ldesc), GFP_KERNEL);
	if (!ldesc) {
		printk("%s: ERROR: allocating cpu register desc\n", __FUNCTION__);
		return -ENOMEM;
	}
	*ldesc = *desc;

	memset(&isp, '\0', sizeof(struct ikc_scd_packet));
	isp.msg = SCD_MSG_CPU_RW_REG;
	isp.op = op;
	isp.pdesc = virt_to_phys(ldesc);

	ret = mcctrl_ikc_send_wait(os, cpu, &isp, 0, NULL, &do_free, 1, ldesc);
	if (ret != 0) {
		printk("%s: ERROR sending IKC msg: %d\n", __FUNCTION__, ret);
		goto out;
	}

	/* Update if read */
	if (op == MCCTRL_OS_CPU_READ_REGISTER) {
		desc->val = ldesc->val;
	}

	/* Notify caller (for future async implementation) */
	atomic_set(&desc->sync, 1);

	printk("%s: MCCTRL_OS_CPU_%s_REGISTER: CPU: %d, addr_ext: 0x%lx, val: 0x%lx\n",
		__FUNCTION__,
		(op == MCCTRL_OS_CPU_READ_REGISTER ? "READ" : "WRITE"), cpu,
		desc->addr_ext, desc->val);

out:
	if (do_free) {
		kfree(ldesc);
	}
	return ret;
}

int mcctrl_os_read_cpu_register(ihk_os_t os, int cpu,
		struct ihk_os_cpu_register *desc)
{
	return __mcctrl_os_read_write_cpu_register(os, cpu,
			desc, MCCTRL_OS_CPU_READ_REGISTER);
}

int mcctrl_os_write_cpu_register(ihk_os_t os, int cpu,
		struct ihk_os_cpu_register *desc)
{
	return __mcctrl_os_read_write_cpu_register(os, cpu,
			desc, MCCTRL_OS_CPU_WRITE_REGISTER);
}

