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
#include <cpulocal.h>
#include <syscall.h>
#include <process.h>
#include <string.h>
#include <errno.h>
#include <kmalloc.h>

void terminate(int, int, ihk_mc_user_context_t *);
int copy_from_user(struct process *proc, void *dst, const void *src, size_t siz);
int copy_to_user(struct process *proc, void *dst, const void *src, size_t siz);
long do_sigaction(int sig, struct k_sigaction *act, struct k_sigaction *oact);

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

    /* A hyper-threading core on the same physical core as
       the parent process might be chosen. Use sched_setaffinity
       if you want to skip that kind of busy physical core for
       performance reason. */
    cpuid_head += 1;
    if(cpuid_head >= cpu_info->ncpus) {
        cpuid_head = 0;
    }

    /* A hyper-threading core whose parent physical core has a
       process on one of its hyper-threading core might
       be chosen. Use sched_setaffinity if you want to skip that
       kind of busy physical core for performance reason. */
    if(get_cpu_local_var(cpuid)->status != CPU_STATUS_IDLE) {
        nretry++;
        if(nretry >= cpu_info->ncpus) {
            cpuid = -1;
            ihk_mc_spinlock_unlock_noirq(&cpuid_head_lock);
            goto out;
        }
        goto retry; 
    }
    ihk_mc_spinlock_unlock_noirq(&cpuid_head_lock);
 out:
    return cpuid;
}

SYSCALL_DECLARE(rt_sigaction)
{
	struct process *proc = cpu_local_var(current);
	int sig = ihk_mc_syscall_arg0(ctx);
	const struct sigaction *act = (const struct sigaction *)ihk_mc_syscall_arg1(ctx);
	struct sigaction *oact = (struct sigaction *)ihk_mc_syscall_arg2(ctx);
	size_t sigsetsize = ihk_mc_syscall_arg3(ctx);
	struct k_sigaction new_sa, old_sa;
	int rc;

	if(sig == SIGKILL || sig == SIGSTOP)
		return -EINVAL;
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if(act)
		if(copy_from_user(proc, &new_sa.sa, act, sizeof new_sa.sa)){
			goto fault;
		}
	rc = do_sigaction(sig, act? &new_sa: NULL, oact? &old_sa: NULL);
	if(rc == 0 && oact)
		if(copy_to_user(proc, oact, &old_sa.sa, sizeof old_sa.sa)){
			goto fault;
		}

	return rc;
fault:
	return -EFAULT;
}

struct sigsp {
	struct x86_regs regs;
	unsigned long sigrc;
	unsigned long sigmask;
	int ssflags;
	siginfo_t info;
};

SYSCALL_DECLARE(rt_sigreturn)
{
	struct process *proc = cpu_local_var(current);
	struct x86_regs *regs;
	struct sigsp *sigsp;
	long rc = -EFAULT;

	asm("movq %%gs:132, %0" : "=r" (regs));
	--regs;

	sigsp = (struct sigsp *)regs->rsp;
	proc->sigmask.__val[0] = sigsp->sigmask;
	proc->sigstack.ss_flags = sigsp->ssflags;
	if(copy_from_user(proc, regs, &sigsp->regs, sizeof(struct x86_regs)))
		return rc;
	copy_from_user(proc, &rc, &sigsp->sigrc, sizeof(long));
	return rc;
}

extern struct cpu_local_var *clv;
extern unsigned long do_kill(int pid, int tid, int sig, struct siginfo *info);
extern void interrupt_syscall(int all, int pid);
extern int num_processors;

void
do_setpgid(int pid, int pgid)
{
	struct cpu_local_var *v;
	struct process *p;
	struct process *proc = cpu_local_var(current);
	int i;
	unsigned long irqstate;

	if(pid == 0)
		pid = proc->pid;
	if(pgid == 0)
		pgid = pid;

	for(i = 0; i < num_processors; i++){
		v = get_cpu_local_var(i);
		irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
		list_for_each_entry(p, &(v->runq), sched_list){
			if(p->pid <= 0)
				continue;
			if(p->pid == pid){
				p->pgid = pgid;

                /* Update pgid in fork_tree because it's used in wait4 */
                ihk_mc_spinlock_lock_noirq(&p->ftn->lock);
                p->ftn->pgid = pgid;
                ihk_mc_spinlock_unlock_noirq(&p->ftn->lock);
			}
		}
		ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
	}
}

extern void coredump(struct process *proc, void *regs);

void
do_signal(unsigned long rc, void *regs0, struct process *proc, struct sig_pending *pending)
{
	struct x86_regs *regs = regs0;
	struct k_sigaction *k;
	int	sig;
	__sigset_t w;
	int	irqstate;

	for(w = pending->sigmask.__val[0], sig = 0; w; sig++, w >>= 1);

	if(regs == NULL){ /* call from syscall */
		asm("movq %%gs:132, %0" : "=r" (regs));
		--regs;
	}
	else{
		rc = regs->rax;
	}

	if(sig == SIGKILL)
		terminate(0, sig, (ihk_mc_user_context_t *)regs->rsp);

	irqstate = ihk_mc_spinlock_lock(&proc->sighandler->lock);
	k = proc->sighandler->action + sig - 1;

	if(k->sa.sa_handler == (void *)1){
		kfree(pending);
		ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
		return;
	}
	else if(k->sa.sa_handler){
		unsigned long *usp; /* user stack */
		struct sigsp *sigsp;
		int	ssflags = proc->sigstack.ss_flags;
		unsigned long	mask = (unsigned long)proc->sigmask.__val[0];

		if((k->sa.sa_flags & SA_ONSTACK) &&
		   !(proc->sigstack.ss_flags & SS_DISABLE) &&
		   !(proc->sigstack.ss_flags & SS_ONSTACK)){
			unsigned long lsp;
			lsp = ((unsigned long)(((char *)proc->sigstack.ss_sp) + proc->sigstack.ss_size)) & 0xfffffffffffffff8UL;
			usp = (unsigned long *)lsp;
			proc->sigstack.ss_flags |= SS_ONSTACK;
		}
		else{
			usp = (unsigned long *)regs->rsp;
		}
		sigsp = ((struct sigsp *)usp) - 1;
		if(copy_to_user(proc, &sigsp->regs, regs, sizeof(struct x86_regs)) ||
		   copy_to_user(proc, &sigsp->sigrc, &rc, sizeof(long))){
			kfree(pending);
			ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
			terminate(0, sig, (ihk_mc_user_context_t *)regs->rsp);
			return;
		}
		sigsp->sigmask = mask;
		sigsp->ssflags = ssflags;
		memcpy(&sigsp->info, &pending->info, sizeof(siginfo_t));

		usp = (unsigned long *)sigsp;
		usp--;
		*usp = (unsigned long)k->sa.sa_restorer;

		regs->rdi = (unsigned long)sig;
		if(k->sa.sa_flags & SA_SIGINFO){
			regs->rsi = (unsigned long)&sigsp->info;
			regs->rdx = 0;
		}
		regs->rip = (unsigned long)k->sa.sa_handler;
		regs->rsp = (unsigned long)usp;

		proc->sigmask.__val[0] |= pending->sigmask.__val[0];
		kfree(pending);
		ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
	}
	else{
		int	coredumped = 0;
		kfree(pending);
		ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
		switch(sig){
		    case SIGCHLD:
		    case SIGURG:
			return;
        case SIGSTOP: {
            dkprintf("do_signal,SIGSTOP,changing state\n");
            struct process *proc = cpu_local_var(current);
            struct fork_tree_node *ftn = proc->ftn;
            int exit_code = SIGSTOP;

            /* Update process state in fork tree */
            ihk_mc_spinlock_lock_noirq(&ftn->lock);	
            ftn->exit_status = (exit_code << 8) | 0x7f;
            ftn->status = PS_STOPPED;
            ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);	

            /* Wake up the parent who tried wait4 and sleeping */
            waitq_wakeup(&proc->ftn->parent->waitpid_q);

            dkprintf("do_signal,SIGSTOP,sleeping\n");
            /* Sleep */
            proc->status = PS_STOPPED;
            schedule();
            dkprintf("SIGSTOP(): woken up\n");
            goto out; }
        case SIGCONT:
            dkprintf("do_signal,SIGCONT,do nothing\n");
            goto out;
		    case SIGQUIT:
		    case SIGILL:
		    case SIGTRAP:
		    case SIGABRT:
		    case SIGBUS:
		    case SIGFPE:
		    case SIGUSR1:
		    case SIGSEGV:
		    case SIGUSR2:
			coredump(proc, regs);
			coredumped = 0x80;
		}
		terminate(0, sig | coredumped, (ihk_mc_user_context_t *)regs->rsp);
	}
 out:;
}

void
check_signal(unsigned long rc, void *regs0)
{
	struct x86_regs *regs = regs0;
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

	if(regs != NULL && (regs->rsp & 0x8000000000000000))
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
do_kill(int pid, int tid, int sig, siginfo_t *info)
{
	struct cpu_local_var *v;
	struct process *p;
	struct process *proc = cpu_local_var(current);
	struct process *tproc = NULL;
	int i;
	__sigset_t mask;
	struct sig_pending *pending;
	struct list_head *head;
	int rc;
	unsigned long irqstate = 0;
	struct k_sigaction *k;
	int doint;
	ihk_spinlock_t *savelock = NULL;
	int found = 0;

	if(sig > 64 || sig < 0)
		return -EINVAL;

	if(tid == -1 && pid <= 0){
		int	pgid = -pid;
		int	rc = -ESRCH;
		int	*pids;
		int	i;
		int	n = 0;
		int	sendme = 0;

		if(pid == 0){
			if(proc == NULL || proc->pid <= 0)
				return -ESRCH;
			pgid = proc->pgid;
		}
		pids = kmalloc(sizeof(int) * num_processors, IHK_MC_AP_NOWAIT);
		if(!pids)
			return -ENOMEM;
		for(i = 0; i < num_processors; i++){
			v = get_cpu_local_var(i);
			irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
			list_for_each_entry(p, &(v->runq), sched_list){
				if(p->pid <= 0)
					continue;
				if(proc && p->pid == proc->pid){
					sendme = 1;
					continue;
				}
				if(pgid == 1 || p->pgid == pgid){
					int	j;

					for(j = 0; j < n; j++)
						if(pids[j] == p->pid)
							break;
					if(j == n){
						pids[n] = p->pid;
						n++;
					}
				}
			}
			ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
		}
		for(i = 0; i < n; i++)
			rc = do_kill(pids[i], -1, sig, info);
		if(sendme)
			rc = do_kill(proc->pid, -1, sig, info);

		kfree(pids);
		return rc;
	}

	irqstate = cpu_disable_interrupt_save();
	mask = __sigmask(sig);
	if(tid == -1){
		struct process *tproc0 = NULL;
		ihk_spinlock_t *savelock0 = NULL;

		for(i = 0; i < num_processors; i++){
			v = get_cpu_local_var(i);
			found = 0;
			ihk_mc_spinlock_lock_noirq(&(v->runq_lock));
			list_for_each_entry(p, &(v->runq), sched_list){
				if(p->pid == pid){
					if(p->tid == pid || tproc == NULL){
						if(!(mask & p->sigmask.__val[0])){
							tproc = p;
							if(!found && savelock)
								ihk_mc_spinlock_unlock_noirq(savelock);
							found = 1;
							savelock =  &(v->runq_lock);
							if(savelock0 && savelock0 != savelock){
								ihk_mc_spinlock_unlock_noirq(savelock0);
								savelock0 = NULL;
							}
						}
						else if(tproc == NULL && tproc0 == NULL){
							tproc0 = p;
							found = 1;
							savelock0 = &(v->runq_lock);
						}
					}
					if(!(mask & p->sigmask.__val[0])){
						if(p->tid == pid || tproc == NULL){

						}
					}
				}
			}
			if(!found)
				ihk_mc_spinlock_unlock_noirq(&(v->runq_lock));
		}
		if(tproc == NULL){
			tproc = tproc0;
			savelock = savelock0;
		}
	}
	else if(pid == -1){
		for(i = 0; i < num_processors; i++){
			v = get_cpu_local_var(i);
			found = 0;
			ihk_mc_spinlock_lock_noirq(&(v->runq_lock));
			list_for_each_entry(p, &(v->runq), sched_list){
				if(p->pid > 0 &&
				   p->tid == tid){
					savelock = &(v->runq_lock);
					found = 1;
					tproc = p;
					break;
				}
			}
			if(!found)
				ihk_mc_spinlock_unlock_noirq(&(v->runq_lock));
		}
	}
	else{
		for(i = 0; i < num_processors; i++){
			v = get_cpu_local_var(i);
			found = 0;
			ihk_mc_spinlock_lock_noirq(&(v->runq_lock));
			list_for_each_entry(p, &(v->runq), sched_list){
				if(p->pid == pid &&
				   p->tid == tid){
					savelock = &(v->runq_lock);
					found = 1;
					tproc = p;
					break;
				}
			}
			if(found)
				break;
			ihk_mc_spinlock_unlock_noirq(&(v->runq_lock));
		}
	}

	if(!tproc){
		cpu_restore_interrupt(irqstate);
		return -ESRCH;
	}
	if(sig == 0){
		ihk_mc_spinlock_unlock_noirq(savelock);
		cpu_restore_interrupt(irqstate);
		return 0;
	}

	doint = 0;
	if(tid == -1){
		ihk_mc_spinlock_lock_noirq(&tproc->sigshared->lock);
		head = &tproc->sigshared->sigpending;
	}
	else{
		ihk_mc_spinlock_lock_noirq(&tproc->sigpendinglock);
		head = &tproc->sigpending;
	}

	rc = 0;
	k = tproc->sighandler->action + sig - 1;
	if(k->sa.sa_handler != (void *)1 &&
	   (k->sa.sa_handler != NULL ||
	    (sig != SIGCHLD && sig != SIGURG))){
		pending = NULL;
		if(sig < 33){ // SIGRTMIN - SIGRTMAX
			list_for_each_entry(pending, head, list){
				if(pending->sigmask.__val[0] == mask)
					break;
			}
			if(&pending->list == head)
				pending = NULL;
		}
		if(pending == NULL){
			doint = 1;
			pending = kmalloc(sizeof(struct sig_pending), IHK_MC_AP_NOWAIT);
			if(!pending){
				rc = -ENOMEM;
			}
			else{
				pending->sigmask.__val[0] = mask;
				memcpy(&pending->info, info, sizeof(siginfo_t));
				list_add_tail(&pending->list, head);
				tproc->sigevent = 1;
			}
		}
	}

	if(tid == -1){
		ihk_mc_spinlock_unlock_noirq(&tproc->sigshared->lock);
	}
	else{
		ihk_mc_spinlock_unlock_noirq(&tproc->sigpendinglock);
	}
	dkprintf("do_kill,pid=%d,sig=%d\n", pid, sig);
	if(doint && !(mask & tproc->sigmask.__val[0])){
        dkprintf("do_kill,proc=%p,tproc=%p\n", proc, tproc);
        switch(sig) {
        case SIGCONT:
            break;
        case SIGSTOP:
        default:
            if(proc != tproc){
                dkprintf("do_kill,ipi,pid=%d,cpu_id=%d\n",
                         tproc->pid, tproc->cpu_id);
                ihk_mc_interrupt_cpu(get_x86_cpu_local_variable(tproc->cpu_id)->apic_id, 0xd0);
            }
            break;
        }
        ihk_mc_spinlock_unlock_noirq(savelock);
        cpu_restore_interrupt(irqstate);
        switch(sig) {
        case SIGSTOP:
            break;
        case SIGCONT:
            dkprintf("do_kill,SIGCONT\n");
            /* Wake up the target only when stopped by SIGSTOP */
            sched_wakeup_process(tproc, PS_STOPPED);
            if (tproc->ftn->status & PS_STOPPED) {
                ihk_mc_spinlock_lock_noirq(&tproc->ftn->lock);	
                xchg4((int *)(&tproc->ftn->status), PS_RUNNING);
                ihk_mc_spinlock_unlock_noirq(&tproc->ftn->lock);	
            } 
            break;
        default:
            dkprintf("do_kill,sending kill to mcexec,pid=%d,cpuid=%d\n",
                     tproc->pid, tproc->cpu_id);
            interrupt_syscall(tproc->pid, tproc->cpu_id);
            break;
        }
	}
	else{
		ihk_mc_spinlock_unlock_noirq(savelock);
		cpu_restore_interrupt(irqstate);
	}
	return rc;
}

void
set_signal(int sig, void *regs0, siginfo_t *info)
{
	struct x86_regs *regs = regs0;
	struct process *proc = cpu_local_var(current);

	if(proc == NULL || proc->pid == 0)
		return;

	if((__sigmask(sig) & proc->sigmask.__val[0]) ||
	   (regs->rsp & 0x8000000000000000)){
		coredump(proc, regs0);
		terminate(0, sig | 0x80, (ihk_mc_user_context_t *)regs->rsp);
	}
	else
		do_kill(proc->pid, proc->tid, sig, info);
}
