/*
 * [x86] syscall.c
 */

#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <cls.h>
#include <syscall.h>
#include <process.h>
#include <string.h>

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

void
check_signal(unsigned long rc, unsigned long *regs)
{
	struct process *proc = cpu_local_var(current);
	struct k_sigaction *k;
	int	sig = proc->signal;

	proc->signal = 0;
	if(sig){
		if(regs == NULL){ /* call from syscall */
			asm volatile ("movq %%gs:132,%0" : "=r" (regs));
			regs -= 16;
		}
		else{
			rc = regs[9]; /* rax */
		}

		k = proc->sighandler->action + sig - 1;

		if(k->sa.sa_handler == (void *)1){
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
		}
		else{
			if(sig == SIGCHLD || sig == SIGURG)
				return;
			terminate(0, sig, (ihk_mc_user_context_t *)regs[14]);
		}
	}
}

void
sigsegv(unsigned long *regs)
{
	struct process *proc = cpu_local_var(current);

	proc->signal = SIGSEGV;
	check_signal(0, regs);
}

void
sigill(unsigned long *regs)
{
	struct process *proc = cpu_local_var(current);

	proc->signal = SIGILL;
	check_signal(0, regs);
}
