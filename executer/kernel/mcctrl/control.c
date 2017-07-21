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
#include <asm/uaccess.h>
#include <asm/delay.h>
#include <asm/io.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <trace/events/sched.h>
#include "../../../config.h"
#include "mcctrl.h"
#include <ihk/ihk_host_user.h>

//#define DEBUG

#ifdef DEBUG
#define dprintk printk
#else
#define dprintk(...)
#endif

#ifdef MCCTRL_KSYM_sys_unshare
#if MCCTRL_KSYM_sys_unshare
typedef int (*int_star_fn_ulong_t)(unsigned long);
int (*mcctrl_sys_unshare)(unsigned long unshare_flags) =
        (int_star_fn_ulong_t)
        MCCTRL_KSYM_sys_unshare;
#else // exported
int (*mcctrl_sys_unshare)(unsigned long unshare_flags) = NULL;
#endif
#endif

#ifdef MCCTRL_KSYM_sys_mount
#if MCCTRL_KSYM_sys_mount
typedef int (*int_star_fn_char_char_char_ulong_void_t)(char *, char *, char *, unsigned long, void *);
int (*mcctrl_sys_mount)(char *dev_name,char *dir_name, char *type, unsigned long flags, void *data) =
        (int_star_fn_char_char_char_ulong_void_t)
        MCCTRL_KSYM_sys_mount;
#else // exported
int (*mcctrl_sys_mount)(char *dev_name,char *dir_name, char *type, unsigned long flags, void *data) = sys_mount;
#endif
#endif

#ifdef MCCTRL_KSYM_sys_umount
#if MCCTRL_KSYM_sys_umount
typedef int (*int_fn_char_star_int_t)(char *, int);
int (*mcctrl_sys_umount)(char *dir_name, int flags) =
        (int_fn_char_star_int_t)
        MCCTRL_KSYM_sys_umount;
#else // exported
int (*mcctrl_sys_umount)(char *dir_name, int flags) = sys_umount;
#endif
#endif

//extern struct mcctrl_channel *channels;
int mcctrl_ikc_set_recv_cpu(ihk_os_t os, int cpu);
int syscall_backward(struct mcctrl_usrdata *, int, unsigned long, unsigned long,
                     unsigned long, unsigned long, unsigned long,
                     unsigned long, unsigned long *);

static long mcexec_prepare_image(ihk_os_t os,
                                 struct program_load_desc * __user udesc)
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
	                sizeof(struct program_image_section)
	                * num_sections, GFP_KERNEL);
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

	if (reserve_user_space(usrdata, &pdesc->user_start, &pdesc->user_end)) {
		ret = -ENOMEM;
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
	
	pdesc->status = 0;
	mb();
	mcctrl_ikc_send(os, pdesc->cpu, &isp);

	ret = wait_event_interruptible(ppd->wq_prepare, pdesc->status);
	if (ret < 0) {
		printk("%s: ERROR after wait: %d\n", __FUNCTION__, ret);
		goto put_and_free_out;
	}

	if (pdesc->err < 0) {
		ret = pdesc->err;	
		goto put_and_free_out;
	}

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
	kfree(args);
	kfree(pdesc);
	kfree(envs);
	kfree(desc);

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

struct mcos_handler_info {
	int pid;
	int cpu;
	struct mcctrl_usrdata *ud;
	struct file *file;
};

struct mcos_handler_info;
static struct host_thread *host_threads;
DEFINE_RWLOCK(host_thread_lock);

struct host_thread {
	struct host_thread *next;
	struct mcos_handler_info *handler;
	int     pid;
	int     tid;
	unsigned long usp;
	unsigned long lfs;
	unsigned long rfs;
};

struct mcos_handler_info *new_mcos_handler_info(ihk_os_t os, struct file *file)
{
	struct mcos_handler_info *info;

	info = kmalloc(sizeof(struct mcos_handler_info), GFP_KERNEL);
	memset(info, '\0', sizeof(struct mcos_handler_info));
	info->ud = ihk_host_os_get_usrdata(os);
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

int mcexec_close_exec(ihk_os_t os);
int mcexec_destroy_per_process_data(ihk_os_t os);

static void release_handler(ihk_os_t os, void *param)
{
	struct mcos_handler_info *info = param;
	struct ikc_scd_packet isp;
	int os_ind = ihk_host_os_get_index(os);
	unsigned long flags;
	struct host_thread *thread;

	write_lock_irqsave(&host_thread_lock, flags);
	for (thread = host_threads; thread; thread = thread->next) {
		if (thread->handler == info) {
			thread->handler = NULL;
		}
	}
	write_unlock_irqrestore(&host_thread_lock, flags);

	mcexec_close_exec(os);

	mcexec_destroy_per_process_data(os);

	memset(&isp, '\0', sizeof isp);
	isp.msg = SCD_MSG_CLEANUP_PROCESS;
	isp.pid = info->pid;

	dprintk("%s: SCD_MSG_CLEANUP_PROCESS, info: %p, cpu: %d\n",
			__FUNCTION__, info, info->cpu);
	mcctrl_ikc_send(os, info->cpu, &isp);
	if (os_ind >= 0) {
		delete_pid_entry(os_ind, info->pid);
	}
	kfree(param);
	dprintk("%s: SCD_MSG_CLEANUP_PROCESS, info: %p OK\n",
			__FUNCTION__, info);
}

static long mcexec_newprocess(ihk_os_t os,
                              struct newprocess_desc *__user udesc,
                              struct file *file)
{
	struct newprocess_desc desc;
	struct mcos_handler_info *info;

	if (copy_from_user(&desc, udesc, sizeof(struct newprocess_desc))) { 
		return -EFAULT;
	}
	info = new_mcos_handler_info(os, file);
	info->pid = desc.pid;
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

	desc = kmalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc) {
		printk("%s: error: allocating program_load_desc\n",
			__FUNCTION__);
		return -ENOMEM;
	}

	if (copy_from_user(desc, udesc,
	                   sizeof(struct program_load_desc))) {
		kfree(desc);
		return -EFAULT;
	}

	info = new_mcos_handler_info(os, file);
	info->pid = desc->pid;
	info->cpu = desc->cpu;
	ihk_os_register_release_handler(file, release_handler, info);
	ihk_os_set_mcos_private_data(file, info);

	c = usrdata->channels + desc->cpu;

	mcctrl_ikc_set_recv_cpu(os, desc->cpu);

	usrdata->last_thread_exec = desc->cpu;
	
	isp.msg = SCD_MSG_SCHEDULE_PROCESS;
	isp.ref = desc->cpu;
	isp.arg = desc->rprocess;

	mcctrl_ikc_send(os, desc->cpu, &isp);

	kfree(desc);
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

	if ((rc = mcctrl_ikc_send(os, sig.cpu, &isp)) < 0) {
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

static long mcexec_get_nodes(ihk_os_t os)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	if (!usrdata || !usrdata->mem_info)
		return -EINVAL;

	return usrdata->mem_info->n_numa_nodes;
}

extern int linux_numa_2_mckernel_numa(struct mcctrl_usrdata *udp, int numa_id);
extern int mckernel_cpu_2_linux_cpu(struct mcctrl_usrdata *udp, int cpu_id);

static long mcexec_get_cpuset(ihk_os_t os, unsigned long arg)
{
	struct mcctrl_usrdata *udp = ihk_host_os_get_usrdata(os);
	struct mcctrl_part_exec *pe;
	struct get_cpu_set_arg req;
	struct cpu_topology *cpu_top, *cpu_top_i;
	struct cache_topology *cache_top;
	int cpu, cpus_assigned, cpus_to_assign, cpu_prev;
	int ret = 0;
	int mcexec_linux_numa;
	cpumask_t *mcexec_cpu_set = NULL;
	cpumask_t *cpus_used = NULL;
	cpumask_t *cpus_to_use = NULL;
	struct mcctrl_per_proc_data *ppd;
	struct process_list_item *pli;
	struct process_list_item *pli_next = NULL;
	struct process_list_item *pli_iter;

	if (!udp) {
		return -EINVAL;
	}

	/* Look up per-process structure */
	ppd = mcctrl_get_per_proc_data(udp, task_tgid_vnr(current));
	if (!ppd) {
		return -EINVAL;
	}

	pe = &udp->part_exec;

	mutex_lock(&pe->lock);

	if (copy_from_user(&req, (void *)arg, sizeof(req))) {
		printk("%s: error copying user request\n", __FUNCTION__);
		ret = -EINVAL;
		goto put_and_unlock_out;
	}

	/* First process to enter CPU partitioning */
	if (pe->nr_processes == -1) {
		pe->nr_processes = req.nr_processes;
		pe->nr_processes_left = req.nr_processes;
		dprintk("%s: nr_processes: %d (partitioned exec starts)\n",
				__FUNCTION__,
				pe->nr_processes);
	}

	if (pe->nr_processes != req.nr_processes) {
		printk("%s: error: requested number of processes"
				" doesn't match current partitioned execution\n",
				__FUNCTION__);
		ret = -EINVAL;
		goto put_and_unlock_out;
	}

	--pe->nr_processes_left;
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
	init_waitqueue_head(&pli->pli_wq);

	pli_next = NULL;
	/* Add ourself to the list in order of start time */
	list_for_each_entry(pli_iter, &pe->pli_list, list) {
		if ((pli_iter->task->start_time.tv_sec >
					current->start_time.tv_sec) ||
				((pli_iter->task->start_time.tv_sec ==
				  current->start_time.tv_sec) &&
				 ((pli_iter->task->start_time.tv_nsec >
				   current->start_time.tv_nsec)))) {
			pli_next = pli_iter;
			break;
		}
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
	}

	/* Wait for the rest if not the last or if the last but
	 * the woken process is different than the last */
	if (pe->nr_processes_left || (pli_next && pli_next != pli)) {
		dprintk("%s: pid: %d, waiting in list\n",
				__FUNCTION__, task_tgid_vnr(current));
		mutex_unlock(&pe->lock);
		ret = wait_event_interruptible(pli->pli_wq, pli->ready);
		mutex_lock(&pe->lock);
		if (ret != 0) {
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

	/* Reset if last process */
	if (pe->nr_processes_left == 0) {
		dprintk("%s: nr_processes: %d (partitioned exec ends)\n",
				__FUNCTION__,
				pe->nr_processes);
		pe->nr_processes = -1;
		memset(&pe->cpus_used, 0, sizeof(pe->cpus_used));
	}
	/* Otherwise wake up next process in list */
	else {
		pli_next = list_first_entry(&pe->pli_list,
			struct process_list_item, list);
		list_del(&pli_next->list);
		pli_next->ready = 1;
		wake_up_interruptible(&pli_next->pli_wq);
	}

	dprintk("%s: pid: %d, ret: 0\n", __FUNCTION__, task_tgid_vnr(current));
	ret = 0;

put_and_unlock_out:
	kfree(cpus_to_use);
	kfree(cpus_used);
	kfree(mcexec_cpu_set);
	mcctrl_put_per_proc_data(ppd);
	mutex_unlock(&pe->lock);

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
		struct mcctrl_per_thread_data *ptd;
		struct mcctrl_per_thread_data *next;

		list_for_each_entry_safe(ptd, next,
		                         ppd->per_thread_data_hash + i, hash) {
			packet = ptd->data;
			list_del(&ptd->hash);
			kfree(ptd);
			/* We use ERESTARTSYS to tell the LWK that the proxy
			 * process is gone and the application should be terminated */
			__return_syscall(ppd->ud->os, packet, -ERESTARTSYS,
					packet->req.rtid);
			ihk_ikc_release_packet(
					(struct ihk_ikc_free_packet *)packet,
					(ppd->ud->ikc2linux[smp_processor_id()] ?
					 ppd->ud->ikc2linux[smp_processor_id()] :
					 ppd->ud->ikc2linux[0]));
		}
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
		ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet,
				(ppd->ud->ikc2linux[smp_processor_id()] ?
				 ppd->ud->ikc2linux[smp_processor_id()] :
				 ppd->ud->ikc2linux[0]));
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

	/* Get a reference to per-process structure */
	ppd = mcctrl_get_per_proc_data(ud, pid);

	if (unlikely(!ppd)) {
		kprintf("%s: ERROR: no per-process structure for PID %d, "
				"syscall nr: %lu\n",
				__FUNCTION__, pid, packet->req.number);

		/* We use ERESTARTSYS to tell the LWK that the proxy
		 * process is gone and the application should be terminated */
		__return_syscall(ud->os, packet, -ERESTARTSYS,
				packet->req.rtid);
		ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet,
				(ud->ikc2linux[smp_processor_id()] ?
				 ud->ikc2linux[smp_processor_id()] :
				 ud->ikc2linux[0]));

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
		if (!wqhln) {
			printk("%s: WARNING: no target thread found for exact request??\n",
				__FUNCTION__);
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
		init_waitqueue_head(&wqhln->wq_syscall);
		list_add_tail(&wqhln->list, &ppd->wq_req_list);
	}

	wqhln->packet = packet;
	wqhln->req = 1;
	ihk_ikc_spinlock_unlock(&ppd->wq_list_lock, flags);
	wake_up(&wqhln->wq_syscall);

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

	/* Get a reference to per-process structure */
	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));

	if (unlikely(!ppd)) {
		kprintf("%s: ERROR: no per-process structure for PID %d??\n",
			__FUNCTION__, task_tgid_vnr(current));
			return -EINVAL;
	}

	packet = (struct ikc_scd_packet *)mcctrl_get_per_thread_data(ppd, current);
	if (packet) {
		printk("%s: ERROR: packet %p is already registered for thread %d\n",
				__FUNCTION__, packet, task_pid_vnr(current));
		ret = -EBUSY;
		goto put_ppd_out;
	}

retry:
	/* Prepare per-thread wait queue head or find a valid request */
	irqflags = ihk_ikc_spinlock_lock(&ppd->wq_list_lock);
	/* First see if there is a valid request already that is not yet taken */
	list_for_each_entry(wqhln_iter, &ppd->wq_req_list, list) {
		if (wqhln_iter->task == NULL && wqhln_iter->req) {
			wqhln = wqhln_iter;
			wqhln->task = current;
			list_del(&wqhln->list);
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

		wqhln->task = current;
		wqhln->req = 0;
		wqhln->packet = NULL;
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
		/* Is the request valid? */
		if (wqhln->req) {
			packet = wqhln->packet;
			kfree(wqhln);
			wqhln = NULL;
			ret = -EINTR;
			goto put_ppd_out;
		}
		else {
			kfree(wqhln);
			wqhln = NULL;
			ret = -EINTR;
			goto put_ppd_out;
		}
	}

	packet = wqhln->packet;
	kfree(wqhln);
	wqhln = NULL;

	dprintk("%s: tid: %d request from CPU %d\n",
			__FUNCTION__, task_pid_vnr(current), packet->ref);

	mb();
	if (!packet->req.valid) {
		printk("%s: ERROR: stray wakeup pid: %d, tid: %d: SC %lu\n",
				__FUNCTION__,
				task_tgid_vnr(current),
				task_pid_vnr(current),
				packet->req.number);
		ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet,
				(usrdata->ikc2linux[smp_processor_id()] ?
				 usrdata->ikc2linux[smp_processor_id()] :
				 usrdata->ikc2linux[0]));
		goto retry;
	}

	packet->req.valid = 0; /* ack */
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
	
	if (mcctrl_add_per_thread_data(ppd, current, packet) < 0) {
		kprintf("%s: error adding per-thread data\n", __FUNCTION__);
		ret = -EINVAL;;
		goto put_ppd_out;
	}

	if (__do_in_kernel_syscall(os, packet)) {
		if (copy_to_user(&req->sr, &packet->req,
					sizeof(struct syscall_request))) {

			if (mcctrl_delete_per_thread_data(ppd, current) < 0) {
				kprintf("%s: error deleting per-thread data\n", __FUNCTION__);
			}
			ret = -EINVAL;;
			goto put_ppd_out;
		}
		req->cpu = packet->ref;

		ret = 0;
		goto put_ppd_out;
	}

	ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet,
			(usrdata->ikc2linux[smp_processor_id()] ?
			 usrdata->ikc2linux[smp_processor_id()] :
			 usrdata->ikc2linux[0]));

	if (mcctrl_delete_per_thread_data(ppd, current) < 0) {
		kprintf("%s: error deleting per-thread data\n", __FUNCTION__);
		ret = -EINVAL;;
		goto put_ppd_out;
	}

	goto retry;

put_ppd_out:
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
	int error = 0;

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

	packet = (struct ikc_scd_packet *)mcctrl_get_per_thread_data(ppd, current);
	if (!packet) {
		kprintf("%s: ERROR: no packet registered for TID %d\n", 
			__FUNCTION__, task_pid_vnr(current));
		error = -EINVAL;
		goto out;
	}

	mcctrl_delete_per_thread_data(ppd, current);

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
	ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet,
			(usrdata->ikc2linux[smp_processor_id()] ?
			 usrdata->ikc2linux[smp_processor_id()] :
			 usrdata->ikc2linux[0]));

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

int mcexec_create_per_process_data(ihk_os_t os)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd = NULL;
	int i;

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

	ppd->ud = usrdata;
	ppd->pid = task_tgid_vnr(current);
	/*
	 * XXX: rpgtable will be updated in __do_in_kernel_syscall()
	 * under case __NR_munmap
	 */
	INIT_LIST_HEAD(&ppd->wq_list);
	INIT_LIST_HEAD(&ppd->wq_req_list);
	INIT_LIST_HEAD(&ppd->wq_list_exact);
	init_waitqueue_head(&ppd->wq_prepare);
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

	return 0;
}

int mcexec_destroy_per_process_data(ihk_os_t os)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd = NULL;

	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));

	if (ppd) {
		/* One for the reference and one for deallocation.
		 * XXX: actual deallocation may not happen here */
		mcctrl_put_per_proc_data(ppd);
		mcctrl_put_per_proc_data(ppd);
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

	pathbuf = kmalloc(PATH_MAX, GFP_TEMPORARY);
	if (!pathbuf) {
		retval = -ENOMEM;
		goto out;
	}

	kfilename = kmalloc(PATH_MAX, GFP_TEMPORARY);
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

int mcexec_close_exec(ihk_os_t os)
{
	struct mckernel_exec_file *mcef = NULL;
	int found = 0;
	int os_ind = ihk_host_os_get_index(os);	

	if (os_ind < 0) {
		return EINVAL;
	}
		
	down(&mckernel_exec_file_lock);
	list_for_each_entry(mcef, &mckernel_exec_files, list) {
		if (mcef->os == os && mcef->pid == task_tgid_vnr(current)) {
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

#ifdef MCCTRL_KSYM_sys_mount
	ret = mcctrl_sys_mount(desc.dev_name, desc.dir_name, desc.type,
		desc.flags, desc.data);
#else
	ret = -EFAULT;
#endif

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

#ifdef MCCTRL_KSYM_sys_umount
	ret = mcctrl_sys_umount(desc.dir_name, MNT_FORCE);
#else
	ret = -EFAULT;
#endif

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

#if MCCTRL_KSYM_sys_unshare
	ret = mcctrl_sys_unshare(desc.unshare_flags);
#else
	ret = -EFAULT;
#endif

	revert_creds(original);
	put_cred(promoted);

	return ret;
}

static DECLARE_WAIT_QUEUE_HEAD(perfctrlq);

long mcctrl_perf_num(ihk_os_t os, unsigned long arg)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	usrdata->perf_event_num = arg;

	return 0;
}

long mcctrl_perf_set(ihk_os_t os, struct ihk_perf_event_attr *__user arg)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct ikc_scd_packet isp;
	struct perf_ctrl_desc *perf_desc = NULL;
	struct ihk_perf_event_attr attr;
	struct ihk_cpu_info *info = ihk_os_get_cpu_info(os);
	int ret = 0;
	int i = 0, j = 0;

	for (i = 0; i < usrdata->perf_event_num; i++) {
		if (copy_from_user(&attr, &arg[i], sizeof(struct ihk_perf_event_attr))) {
			printk("%s: error: copying ihk_perf_event_attr from user\n",
			       __FUNCTION__);
			return -EINVAL;
		}

		for (j = 0; j < info->n_cpus; j++) {
			perf_desc = kmalloc(sizeof(struct perf_ctrl_desc), GFP_KERNEL);
			if (!perf_desc) {
				printk("%s: error: allocating perf_ctrl_desc\n",
				       __FUNCTION__);
				return -ENOMEM;
			}
			memset(perf_desc, '\0', sizeof(struct perf_ctrl_desc));

			perf_desc->ctrl_type = PERF_CTRL_SET;
			perf_desc->status = 0;
			perf_desc->target_cntr = i;
			perf_desc->config = attr.config;
			perf_desc->exclude_kernel = attr.exclude_kernel;
			perf_desc->exclude_user = attr.exclude_user;

			memset(&isp, '\0', sizeof(struct ikc_scd_packet));
			isp.msg = SCD_MSG_PERF_CTRL;
			isp.arg = virt_to_phys(perf_desc);

			if ((ret = mcctrl_ikc_send(os, j, &isp)) < 0) {
				printk("%s: mcctrl_ikc_send ret=%d\n", __FUNCTION__, ret);
				kfree(perf_desc);
				return -EINVAL;
			}

			ret = wait_event_interruptible(perfctrlq, perf_desc->status);
			if (ret < 0) {
				printk("%s: ERROR after wait: %d\n", __FUNCTION__, ret);
				kfree(perf_desc);
				return -EINVAL;
			}
				
			kfree(perf_desc);
		}
	}

	return usrdata->perf_event_num;
}

long mcctrl_perf_get(ihk_os_t os, unsigned long *__user arg)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct ikc_scd_packet isp;
	struct perf_ctrl_desc *perf_desc = NULL;
	struct ihk_cpu_info *info = ihk_os_get_cpu_info(os);
	unsigned long value_sum = 0;
	int ret = 0;
	int i = 0, j = 0;

	for (i = 0; i < usrdata->perf_event_num; i++) {
		for (j = 0; j < info->n_cpus; j++) {
			perf_desc = kmalloc(sizeof(struct perf_ctrl_desc), GFP_KERNEL);
			if (!perf_desc) {
				printk("%s: error: allocating perf_ctrl_desc\n",
				       __FUNCTION__);
				return -ENOMEM;
			}
			memset(perf_desc, '\0', sizeof(struct perf_ctrl_desc));

			perf_desc->ctrl_type = PERF_CTRL_GET;
			perf_desc->status = 0;
			perf_desc->target_cntr = i;

			memset(&isp, '\0', sizeof(struct ikc_scd_packet));
			isp.msg = SCD_MSG_PERF_CTRL;
			isp.arg = virt_to_phys(perf_desc);

			if ((ret = mcctrl_ikc_send(os, j, &isp)) < 0) {
				printk("%s: mcctrl_ikc_send ret=%d\n", __FUNCTION__, ret);
				kfree(perf_desc);
				return -EINVAL;
			}

			ret = wait_event_interruptible(perfctrlq, perf_desc->status);
			if (ret < 0) {
				printk("%s: ERROR after wait: %d\n", __FUNCTION__, ret);
				kfree(perf_desc);
				return -EINVAL;
			}
			value_sum += perf_desc->read_value;
			kfree(perf_desc);
		}
		if (copy_to_user(&arg[i], &value_sum, sizeof(unsigned long))) {
			printk("%s: error: copying read_value to user\n",
			       __FUNCTION__);
			return -EINVAL;
		}
		value_sum = 0;
	}

	return 0;
}

long mcctrl_perf_enable(ihk_os_t os)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct ikc_scd_packet isp;
	struct perf_ctrl_desc *perf_desc = NULL;
	struct ihk_cpu_info *info = ihk_os_get_cpu_info(os);
	unsigned int cntr_mask = 0;
	int ret = 0;
	int i = 0, j = 0;

	for (i = 0; i < usrdata->perf_event_num; i++) {
		cntr_mask |= 1 << i;
	}
	for (j = 0; j < info->n_cpus; j++) {
		perf_desc = kmalloc(sizeof(struct perf_ctrl_desc), GFP_KERNEL);
		if (!perf_desc) {
			printk("%s: error: allocating perf_ctrl_desc\n",
			       __FUNCTION__);
			return -ENOMEM;
		}
		memset(perf_desc, '\0', sizeof(struct perf_ctrl_desc));

		perf_desc->ctrl_type = PERF_CTRL_ENABLE;
		perf_desc->status = 0;
		perf_desc->target_cntr_mask = cntr_mask;

		memset(&isp, '\0', sizeof(struct ikc_scd_packet));
		isp.msg = SCD_MSG_PERF_CTRL;
		isp.arg = virt_to_phys(perf_desc);

		if ((ret = mcctrl_ikc_send(os, j, &isp)) < 0) {
			printk("%s: mcctrl_ikc_send ret=%d\n", __FUNCTION__, ret);
			kfree(perf_desc);
			return -EINVAL;
		}

		ret = wait_event_interruptible(perfctrlq, perf_desc->status);
		if (ret < 0) {
			printk("%s: ERROR after wait: %d\n", __FUNCTION__, ret);
			kfree(perf_desc);
			return -EINVAL;
		}
		kfree(perf_desc);
	}

	return 0;
}

long mcctrl_perf_disable(ihk_os_t os)
{
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct ikc_scd_packet isp;
	struct perf_ctrl_desc *perf_desc = NULL;
	struct ihk_cpu_info *info = ihk_os_get_cpu_info(os);
	unsigned int cntr_mask = 0;
	int ret = 0;
	int i = 0, j = 0;

	for (i = 0; i < usrdata->perf_event_num; i++) {
		cntr_mask |= 1 << i;
	}
	for (j = 0; j < info->n_cpus; j++) {
		perf_desc = kmalloc(sizeof(struct perf_ctrl_desc), GFP_KERNEL);
		if (!perf_desc) {
			printk("%s: error: allocating perf_ctrl_desc\n",
			       __FUNCTION__);
			return -ENOMEM;
		}
		memset(perf_desc, '\0', sizeof(struct perf_ctrl_desc));

		perf_desc->ctrl_type = PERF_CTRL_DISABLE;
		perf_desc->status = 0;
		perf_desc->target_cntr_mask = cntr_mask;

		memset(&isp, '\0', sizeof(struct ikc_scd_packet));
		isp.msg = SCD_MSG_PERF_CTRL;
		isp.arg = virt_to_phys(perf_desc);

		if ((ret = mcctrl_ikc_send(os, j, &isp)) < 0) {
			printk("%s: mcctrl_ikc_send ret=%d\n", __FUNCTION__, ret);
			kfree(perf_desc);
			return -EINVAL;
		}

		ret = wait_event_interruptible(perfctrlq, perf_desc->status);
		if (ret < 0) {
			printk("%s: ERROR after wait: %d\n", __FUNCTION__, ret);
			kfree(perf_desc);
			return -EINVAL;
		}
		kfree(perf_desc);
	}

	return 0;
}

long mcctrl_perf_destroy(ihk_os_t os)
{
	mcctrl_perf_disable(os);
	mcctrl_perf_num(os, 0);
	return 0;
}

void mcctrl_perf_ack(ihk_os_t os, struct ikc_scd_packet *packet)
{
	struct perf_ctrl_desc *perf_desc = phys_to_virt(packet->arg);

	perf_desc->status = 1;
	wake_up_interruptible(&perfctrlq);

}

extern void *get_user_sp(void);
extern void set_user_sp(unsigned long);
extern void restore_fs(unsigned long fs);
extern void save_fs_ctx(void *);
extern unsigned long get_fs_ctx(void *);

long
mcexec_util_thread1(ihk_os_t os, unsigned long arg, struct file *file)
{
	void **__user uparam = (void ** __user)arg;
	void *param[6];
	unsigned long p_rctx;
	unsigned long phys;
	void *__user u_rctx;
	void *rctx;
	int rc = 0;
	unsigned long free_address;
	unsigned long free_size;
	unsigned long icurrent = (unsigned long)current;

	if(copy_from_user(param, uparam, sizeof(void *) * 6)) {
		return -EFAULT;
	}
	p_rctx = (unsigned long)param[0];
	u_rctx = (void *__user)param[1];
	free_address = (unsigned long)param[4];
	free_size = (unsigned long)param[5];

	phys = ihk_device_map_memory(ihk_os_to_dev(os), p_rctx, PAGE_SIZE);
#ifdef CONFIG_MIC
	rctx = ioremap_wc(phys, PAGE_SIZE);
#else
	rctx = ihk_device_map_virtual(ihk_os_to_dev(os), phys, PAGE_SIZE, NULL, 0);
#endif
	if(copy_to_user(u_rctx, rctx, PAGE_SIZE) ||
	   copy_to_user((unsigned long *)(uparam + 3), &icurrent,
	                sizeof(unsigned long)))
		rc = -EFAULT;

	((unsigned long *)rctx)[0] = free_address;
	((unsigned long *)rctx)[1] = free_size;

#ifdef CONFIG_MIC
	iounmap(rctx);
#else
	ihk_device_unmap_virtual(ihk_os_to_dev(os), rctx, PAGE_SIZE);
#endif
	ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);

	return rc;
}

static inline struct host_thread *get_host_thread(void)
{
	int pid = task_tgid_vnr(current);
	int tid = task_pid_vnr(current);
	unsigned long flags;
	struct host_thread *thread;
	
	read_lock_irqsave(&host_thread_lock, flags);
	for (thread = host_threads; thread; thread = thread->next)
		if(thread->pid == pid && thread->tid == tid)
			break;
	read_unlock_irqrestore(&host_thread_lock, flags);

	return thread;
}

long
mcexec_util_thread2(ihk_os_t os, unsigned long arg, struct file *file)
{
	void *usp = get_user_sp();
	struct mcos_handler_info *info;
	struct host_thread *thread;
	unsigned long flags;
	void **__user param = (void **__user )arg;
	void *__user rctx = (void *__user)param[1];
	void *__user lctx = (void *__user)param[2];

	save_fs_ctx(lctx);
	info = ihk_os_get_mcos_private_data(file);
	thread = kmalloc(sizeof(struct host_thread), GFP_KERNEL);
	memset(thread, '\0', sizeof(struct host_thread));
	thread->pid = task_tgid_vnr(current);
	thread->tid = task_pid_vnr(current);
	thread->usp = (unsigned long)usp;
	thread->lfs = get_fs_ctx(lctx);
	thread->rfs = get_fs_ctx(rctx);
	thread->handler = info;

	write_lock_irqsave(&host_thread_lock, flags);
	thread->next = host_threads;
	host_threads = thread;
	write_unlock_irqrestore(&host_thread_lock, flags);

	return 0;
}

long
mcexec_sig_thread(ihk_os_t os, unsigned long arg, struct file *file)
{
	int tid = task_pid_vnr(current);
	int pid = task_tgid_vnr(current);
	unsigned long flags;
	struct host_thread *thread;

	read_lock_irqsave(&host_thread_lock, flags);
	for (thread = host_threads; thread; thread = thread->next)
		if(thread->pid == pid && thread->tid == tid)
			break;
	read_unlock_irqrestore(&host_thread_lock, flags);
	if (thread) {
		if (arg)
			restore_fs(thread->lfs);
		else
			restore_fs(thread->rfs);
		return 0;
	}
	return -EINVAL;
}

long
mcexec_terminate_thread(ihk_os_t os, unsigned long *param, struct file *file)
{
	int pid = param[0];
	int tid = param[1];
	struct task_struct *tsk = (struct task_struct *)param[3];
	unsigned long flags;
	struct host_thread *thread;
	struct host_thread *prev;
	struct ikc_scd_packet *packet;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd;

	write_lock_irqsave(&host_thread_lock, flags);
	for (prev = NULL, thread = host_threads; thread;
	     prev = thread, thread = thread->next) {
		if(thread->tid == tid)
			break;
	}
	if (!thread) {
		write_unlock_irqrestore(&host_thread_lock, flags);
		return -EINVAL;
	}

	ppd = mcctrl_get_per_proc_data(usrdata, pid);
	if (!ppd) {
		kprintf("%s: ERROR: no per-process structure for PID %d??\n",
		        __FUNCTION__, pid);
		goto err;
	}
	packet = (struct ikc_scd_packet *)mcctrl_get_per_thread_data(ppd, tsk);
	if (!packet) {
		kprintf("%s: ERROR: no packet registered for TID %d\n",
		       __FUNCTION__, tid);
		goto err;
	}
	mcctrl_delete_per_thread_data(ppd, tsk);
	__return_syscall(usrdata->os, packet, param[2], tid);
	ihk_ikc_release_packet((struct ihk_ikc_free_packet *)packet,
	                       (usrdata->channels + packet->ref)->c);
err:
	if(ppd)
		mcctrl_put_per_proc_data(ppd);

	if (prev)
		prev->next = thread->next;
	else
		host_threads = thread->next;
	write_unlock_irqrestore(&host_thread_lock, flags);
	kfree(thread);
	return 0;
}

long
mcexec_syscall_thread(ihk_os_t os, unsigned long arg, struct file *file)
{
	struct syscall_struct {
		int number;
		unsigned long args[6];
		unsigned long ret;
	};
	struct syscall_struct param;
	struct syscall_struct __user *uparam =
	                              (struct syscall_struct __user *)arg;
	int rc;

	if (copy_from_user(&param, uparam, sizeof param)) {
		return -EFAULT;
	}
	rc = syscall_backward(ihk_host_os_get_usrdata(os), param.number,
	                      param.args[0], param.args[1], param.args[2],
	                      param.args[3], param.args[4], param.args[5],
	                      &param.ret);

	if (copy_to_user(&uparam->ret, &param.ret, sizeof(unsigned long))) {
		return -EFAULT;
	}
	return rc;
}

long
mcexec_copy_from_mck(ihk_os_t os, unsigned long *arg)
{
	void __user *to = (void *)arg[0];
	void *from = phys_to_virt(arg[1]);
	long len = arg[2];

	if (copy_to_user(to, from, len)) {
		return -EFAULT;
	}
	return 0;
}

long
mcexec_copy_to_mck(ihk_os_t os, unsigned long *arg)
{
	void *to = phys_to_virt(arg[0]);
	void __user *from = (void *)arg[1];
	long len = arg[2];

	if (copy_from_user(to, from, len)) {
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

	case MCEXEC_UP_CREATE_PPD:
		return mcexec_create_per_process_data(os);

	case MCEXEC_UP_GET_NODES:
		return mcexec_get_nodes(os);

	case MCEXEC_UP_GET_CPUSET:
		return mcexec_get_cpuset(os, arg);

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

	case MCEXEC_UP_UTIL_THREAD1:
		return mcexec_util_thread1(os, arg, file);

	case MCEXEC_UP_UTIL_THREAD2:
		return mcexec_util_thread2(os, arg, file);

	case MCEXEC_UP_SIG_THREAD:
		return mcexec_sig_thread(os, arg, file);

	case MCEXEC_UP_SYSCALL_THREAD:
		return mcexec_syscall_thread(os, arg, file);

	case MCEXEC_UP_TERMINATE_THREAD:
		return mcexec_terminate_thread(os, (unsigned long *)arg, file);

	case MCEXEC_UP_GET_NUM_POOL_THREADS:
		return mcctrl_get_num_pool_threads(os);

	case MCEXEC_UP_COPY_FROM_MCK:
		return mcexec_copy_from_mck(os, (unsigned long *)arg);

	case MCEXEC_UP_COPY_TO_MCK:
		return mcexec_copy_to_mck(os, (unsigned long *)arg);

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
	}
	return -EINVAL;
}

void mcexec_prepare_ack(ihk_os_t os, unsigned long arg, int err)
{
	struct program_load_desc *desc = phys_to_virt(arg);
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd = NULL;

	ppd = mcctrl_get_per_proc_data(usrdata, desc->pid);
	if (!ppd) {
		printk("%s: ERROR: no per process data for PID %d\n",
			__FUNCTION__, desc->pid);
		return;
	}

	desc->err = err;
	desc->status = 1;
	mb();
	
	wake_up_all(&ppd->wq_prepare);
	mcctrl_put_per_proc_data(ppd);
}


/* Per-CPU register manipulation functions */
struct mcctrl_os_cpu_response {
	int done;
	unsigned long val;
	wait_queue_head_t wq;
};

int mcctrl_get_request_os_cpu(ihk_os_t os, int *ret_cpu)
{
	struct mcctrl_usrdata *usrdata;
	struct mcctrl_per_proc_data *ppd;
	struct ikc_scd_packet *packet;
	struct ihk_ikc_channel_desc *ch;
	int ret = 0;

	if (!os) {
		return -EINVAL;
	}

	/* Look up per-OS mcctrl structure */
	usrdata = ihk_host_os_get_usrdata(os);
	if (!usrdata) {
		printk("%s: ERROR: no usrdata found for OS %p\n", __FUNCTION__, os);
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
	packet = (struct ikc_scd_packet *)mcctrl_get_per_thread_data(ppd, current);
	if (!packet) {
		ret = -EINVAL;
		printk("%s: ERROR: no packet registered for TID %d\n",
				__FUNCTION__, task_pid_vnr(current));
		goto out_put_ppd;
	}

	/* TODO: define a new IHK query function instead of
	 * accessing internals directly */
	ch = (usrdata->channels + packet->ref)->c;
	*ret_cpu = ch->send.queue->read_cpu;
	ret = 0;

	printk("%s: OS: %p, CPU: %d\n", __FUNCTION__, os, *ret_cpu);

out_put_ppd:
	mcctrl_put_per_proc_data(ppd);

	return ret;
}

void mcctrl_os_read_write_cpu_response(ihk_os_t os,
		struct ikc_scd_packet *pisp)
{
	struct mcctrl_os_cpu_response *resp;

	/* XXX: What if caller thread is unblocked by a signal
	 * before this message arrives? */
	resp = pisp->resp;
	if (!resp) {
		return;
	}

	resp->val = pisp->desc.val;
	resp->done = 1;
	wake_up_interruptible(&resp->wq);
}

int __mcctrl_os_read_write_cpu_register(ihk_os_t os, int cpu,
		struct ihk_os_cpu_register *desc,
		enum mcctrl_os_cpu_operation op)
{
	struct ikc_scd_packet isp;
	struct mcctrl_os_cpu_response resp;
	int ret = -EINVAL;

	memset(&isp, '\0', sizeof(struct ikc_scd_packet));
	isp.msg = SCD_MSG_CPU_RW_REG;
	isp.op = op;
	isp.desc = *desc;
	isp.resp = &resp;

	resp.done = 0;
	init_waitqueue_head(&resp.wq);

	mb();
	ret = mcctrl_ikc_send(os, cpu, &isp);
	if (ret < 0) {
		printk("%s: ERROR sending IKC msg: %d\n", __FUNCTION__, ret);
		goto out;
	}

	/* Wait for response */
	ret = wait_event_interruptible(resp.wq, resp.done);
	if (ret < 0) {
		printk("%s: ERROR after wait: %d\n", __FUNCTION__, ret);
		goto out;
	}

	/* Update if read */
	if (ret == 0 && op == MCCTRL_OS_CPU_READ_REGISTER) {
		desc->val = resp.val;
	}

	dprintk("%s: MCCTRL_OS_CPU_%s_REGISTER: reg: 0x%lx, val: 0x%lx\n",
		__FUNCTION__,
		(op == MCCTRL_OS_CPU_READ_REGISTER ? "READ" : "WRITE"),
		desc->addr, desc->val);

out:
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

