/**
 * \file syscall.c
 *  License details are found in the file LICENSE.
 * \brief
 *  archtecture depended system call handlers
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 * \author Masamichi Takagi  <m-takagi@ab.jp.nec.com> \par
 * 	Copyright (C) 2013  NEC Corporation
 * \author Tomoki Shirasawa  <tomoki.shirasawa.kk@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 */
/*
 * HISTORY:
 */

#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <cls.h>
#include <syscall.h>
#include <process.h>
#include <string.h>
#include <errno.h>
#include <kmalloc.h>

void terminate(int, int, ihk_mc_user_context_t *);

//#define DEBUG_PRINT_SC

#ifdef DEBUG_PRINT_SC
#define dkprintf kprintf
#else
#define dkprintf(...)
#endif

/*
See dkprintf("BSP HW ID = %d, ", bsp_hw_id); (in ./mcos/kernel/ap.c)

Core with BSP HW ID 224 is 1st logical core of last physical core.
It                      boots first and is given SW-ID of 0

Core with BSP HW ID 0 is 1st logical core of 1st physical core. 
It                      boots next and is given  SW-ID of 1.
Core with BSP HW ID 1   boots next and is given  SW-ID of 2.
Core with BSP HW ID 2   boots next and is given  SW-ID of 3.
Core with BSP HW ID 3   boots next and is given  SW-ID of 4.
...
Core with BSP HW ID 220 is 1st logical core of 56-th physical core.
It                      boots next and is given  SW-ID of 221.
Core with BSP HW ID 221 boots next and is given  SW-ID of 222.
Core with BSP HW ID 222 boots next and is given  SW-ID of 223.
Core with BSP HW ID 223 boots next and is given  SW-ID of 224.

Core with BSP HW ID 225 is 2nd logical core of last physical core.
It                      boots next and is given  SW-ID of 225.
Core with BSP HW ID 226 boots next and is given  SW-ID of 226.
Core with BSP HW ID 227 boots next and is given  SW-ID of 227.
*/
static ihk_spinlock_t cpuid_head_lock = 0;
static int cpuid_head = 1;

/* archtecture-depended syscall handlers */
int obtain_clone_cpuid() {
    /* see above on BSP HW ID */
	struct ihk_mc_cpu_info *cpu_info = ihk_mc_get_cpu_info();
    int cpuid, nretry = 0;
    ihk_mc_spinlock_lock_noirq(&cpuid_head_lock);
 retry:
    /* Try to obtain next physical core */
    cpuid = cpuid_head;
    cpuid_head += 4;
    if(cpuid_head >= cpu_info->ncpus) {
        cpuid_head = ((cpuid_head % 4) + 1) % 4;
    }
    /* Don't use a physical core with a system process (e.g. MPI)
       because using it degrades performance */
    if((cpu_info->ncpus - 3 <= cpuid && cpuid <= cpu_info->ncpus - 1) ||
       get_cpu_local_var(cpuid)->status != CPU_STATUS_IDLE) {
        nretry++;
        if(nretry >= cpu_info->ncpus) {
            panic("there is no cpu with empty runq\n");
        }
        goto retry; 
    }
    ihk_mc_spinlock_unlock_noirq(&cpuid_head_lock);
    return cpuid;
}

SYSCALL_DECLARE(rt_sigreturn)
{
        struct process *proc = cpu_local_var(current);
	unsigned long *regs;

	asm volatile ("movq %%gs:132,%0" : "=r" (regs));
	regs -= 16;
        memcpy(regs, proc->sigstack, 128);

	proc->sigmask.__val[0] = proc->supmask.__val[0];

        return proc->sigrc;
}

extern struct cpu_local_var *clv;
extern unsigned long do_kill(int pid, int tid, int sig);
extern void interrupt_syscall(int all);
extern int num_processors;

void
do_signal(unsigned long rc, void *regs0, struct process *proc, struct sig_pending *pending)
{
	unsigned long *regs = regs0;
	struct k_sigaction *k;
	int	sig;
	__sigset_t w;
	int	irqstate;

	for(w = pending->sigmask.__val[0], sig = 0; w; sig++, w >>= 1);

	if(sig == SIGKILL || sig == SIGTERM)
		terminate(0, sig, (ihk_mc_user_context_t *)regs[14]);

	irqstate = ihk_mc_spinlock_lock(&proc->sighandler->lock);
	if(regs == NULL){ /* call from syscall */
		asm volatile ("movq %%gs:132,%0" : "=r" (regs));
		regs -= 16;
	}
	else{
		rc = regs[9]; /* rax */
	}
	k = proc->sighandler->action + sig - 1;

	if(k->sa.sa_handler == (void *)1){
		kfree(pending);
		ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
		return;
	}
	else if(k->sa.sa_handler){
		unsigned long *usp; /* user stack */

		usp = (void *)regs[14];
		memcpy(proc->sigstack, regs, 128);
		proc->sigrc = rc;
		usp--;
		*usp = (unsigned long)k->sa.sa_restorer;

		regs[4] = (unsigned long)sig;
		regs[11] = (unsigned long)k->sa.sa_handler;
		regs[14] = (unsigned long)usp;
		kfree(pending);
		proc->sigmask.__val[0] |= pending->sigmask.__val[0];
		ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
	}
	else{
		kfree(pending);
		ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
		if(sig == SIGCHLD || sig == SIGURG)
			return;
		terminate(0, sig, (ihk_mc_user_context_t *)regs[14]);
	}
}

void
check_signal(unsigned long rc, void *regs0)
{
	unsigned long *regs = regs0;
	struct process *proc;
	struct sig_pending *pending;
	struct sig_pending *next;
	struct list_head *head;
	ihk_spinlock_t *lock;
	__sigset_t w;
	int	irqstate;

	if(clv == NULL)
		return;
	proc = cpu_local_var(current);
	if(proc == NULL || proc->pid == 0)
		return;

	if(regs != NULL && (regs[14] & 0x8000000000000000))
		return;

	for(;;){
		w = proc->sigmask.__val[0];
		lock = &proc->sigshared->lock;
		head = &proc->sigshared->sigpending;
		pending = NULL;
		irqstate = ihk_mc_spinlock_lock(lock);
		list_for_each_entry_safe(pending, next, head, list){
			if(!(pending->sigmask.__val[0] & w)){
				list_del(&pending->list);
				break;
			}
		}
		if(&pending->list == head)
			pending = NULL;
		ihk_mc_spinlock_unlock(lock, irqstate);

		if(!pending){
			lock = &proc->sigpendinglock;
			head = &proc->sigpending;
			irqstate = ihk_mc_spinlock_lock(lock);
			list_for_each_entry_safe(pending, next, head, list){
				if(!(pending->sigmask.__val[0] & w)){
					list_del(&pending->list);
					break;
				}
			}
			if(&pending->list == head)
				pending = NULL;
			ihk_mc_spinlock_unlock(lock, irqstate);
		}
		if(!pending)
			return;

		do_signal(rc, regs, proc, pending);
	}
}

unsigned long
do_kill(int pid, int tid, int sig)
{
	struct process *proc = cpu_local_var(current);
	struct process *tproc = NULL;
	int i;
	__sigset_t mask;
	struct sig_pending *pending;
	struct list_head *head;
	int irqstate;
	int rc;

	if(proc == NULL || proc->pid == 0){
		return -ESRCH;
	}

	if(sig > 64 || sig < 0)
		return -EINVAL;

	if(tid == -1){
		if(pid == -1)
			return -EPERM;
		if(proc->pid == -pid)
			pid = -pid;
		if(pid == proc->pid || pid == 0){
			tproc = proc;
		}
	}
	else if(pid == -1){
		for(i = 0; i < num_processors; i++)
			if(get_cpu_local_var(i)->current &&
			   get_cpu_local_var(i)->current->pid > 0 &&
			   get_cpu_local_var(i)->current->tid == tid){
				tproc = get_cpu_local_var(i)->current;
				break;
			}
	}
	else{
		if(pid == 0)
			return -ESRCH;
		for(i = 0; i < num_processors; i++)
			if(get_cpu_local_var(i)->current &&
			   get_cpu_local_var(i)->current->pid == pid &&
			   get_cpu_local_var(i)->current->tid == tid){
				tproc = get_cpu_local_var(i)->current;
				break;
			}
	}

	if(!tproc)
		return -ESRCH;
	if(sig == 0)
		return 0;

	if(tid == -1){
		irqstate = ihk_mc_spinlock_lock(&tproc->sigshared->lock);
		head = &tproc->sigshared->sigpending;
	}
	else{
		irqstate = ihk_mc_spinlock_lock(&tproc->sigpendinglock);
		head = &tproc->sigpending;
	}
	mask = __sigmask(sig);
	pending = NULL;
	rc = 0;
	if(sig < 34){
		list_for_each_entry(pending, head, list){
			if(pending->sigmask.__val[0] == mask)
				break;
		}
		if(&pending->list == head)
			pending = NULL;
	}
	if(pending == NULL){
		pending = kmalloc(sizeof(struct sig_pending), IHK_MC_AP_NOWAIT);
		pending->sigmask.__val[0] = mask;
		if(!pending){
			rc = -ENOMEM;
		}
		else{
			list_add_tail(&pending->list, head);
			proc->sigevent = 1;
		}
	}
	if(tid == -1){
		ihk_mc_spinlock_unlock(&tproc->sigshared->lock, irqstate);
	}
	else{
		ihk_mc_spinlock_unlock(&tproc->sigpendinglock, irqstate);
	}
	interrupt_syscall(1);
	return rc;
}

void
set_signal(int sig, void *regs0)
{
	unsigned long *regs = regs0;
	struct process *proc = cpu_local_var(current);

	if(proc == NULL || proc->pid == 0)
		return;

	if((__sigmask(sig) & proc->sigmask.__val[0]) ||
	   (regs[14] & 0x8000000000000000))
		terminate(0, sig, (ihk_mc_user_context_t *)regs[14]);
	else
		do_kill(proc->pid, proc->tid, sig);
}
