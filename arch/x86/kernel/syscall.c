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

        return proc->sigrc;
}

extern struct cpu_local_var *clv;
extern unsigned long do_kill(int pid, int tid, int sig);
extern void interrupt_syscall(int all);
extern int num_processors;

void
check_signal(unsigned long rc, unsigned long *regs)
{
	struct process *proc;
	struct k_sigaction *k;
	int	sig;

	if(clv == NULL)
		return;
	proc = cpu_local_var(current);
	if(proc == NULL || proc->pid == 0)
		return;
	sig = proc->signal;

	proc->signal = 0;
	if(sig){
		int irqstate = ihk_mc_spinlock_lock(&proc->sighandler->lock);
		if(regs == NULL){ /* call from syscall */
			asm volatile ("movq %%gs:132,%0" : "=r" (regs));
			regs -= 16;
		}
		else{
			rc = regs[9]; /* rax */
		}
		k = proc->sighandler->action + sig - 1;

		if(k->sa.sa_handler == (void *)1){
			ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
			return;
		}
		else if(k->sa.sa_handler){
			unsigned long *usp; /* user stack */

			if(regs[14] & 0x8000000000000000){ // kernel addr
				proc->signal = sig;
				ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
				return;
			}

			usp = (void *)regs[14];
			memcpy(proc->sigstack, regs, 128);
			proc->sigrc = rc;
			usp--;
			*usp = (unsigned long)k->sa.sa_restorer;

			regs[4] = (unsigned long)sig;
			regs[11] = (unsigned long)k->sa.sa_handler;
			regs[14] = (unsigned long)usp;
			ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
		}
		else{
			ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
			if(sig == SIGCHLD || sig == SIGURG)
				return;
			terminate(0, sig, (ihk_mc_user_context_t *)regs[14]);
		}
	}
}

unsigned long
do_kill(int pid, int tid, int sig)
{
	struct process *proc = cpu_local_var(current);
	struct process *tproc = NULL;
	int	i;

	if(proc == NULL || proc->pid == 0){
		return -ESRCH;
	}

	if(sig > 64 || sig < 0)
		return -EINVAL;

	if(tid == -1){
		if(pid == proc->pid || pid <= 0){
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

	if(__sigmask(sig) & proc->sigmask.__val[0]){
		// TODO: masked signal: ignore -> pending
		return 0;
	}
	proc->signal = sig;
	interrupt_syscall(1);
	return 0;
}

void
set_signal(int sig, unsigned long *regs, int nonmaskable)
{
	struct process *proc = cpu_local_var(current);

	if(proc == NULL || proc->pid == 0)
		return;

	if(__sigmask(sig) & proc->sigmask.__val[0]){
		if(nonmaskable){
			terminate(0, sig, (ihk_mc_user_context_t *)regs[14]);
		}
		else{
			// TODO: masked signal: ignore -> pending
			return;
		}
	}
	proc->signal = sig;
	interrupt_syscall(1);
}
