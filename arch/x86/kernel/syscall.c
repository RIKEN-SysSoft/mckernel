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
#include <uio.h>

void terminate(int, int, ihk_mc_user_context_t *);
int copy_from_user(void *dst, const void *src, size_t siz);
int copy_to_user(void *dst, const void *src, size_t siz);
int write_process_vm(struct process_vm *vm, void *dst, const void *src, size_t siz);
long do_sigaction(int sig, struct k_sigaction *act, struct k_sigaction *oact);
extern void save_fp_regs(struct process *proc);

//#define DEBUG_PRINT_SC

#ifdef DEBUG_PRINT_SC
#define dkprintf kprintf
#else
#define dkprintf(...) do { if (0) kprintf(__VA_ARGS__); } while (0)
#endif

uintptr_t debug_constants[] = {
	sizeof(struct cpu_local_var),
	offsetof(struct cpu_local_var, current),
	offsetof(struct cpu_local_var, runq),
	offsetof(struct cpu_local_var, status),
	offsetof(struct process, ctx),
	offsetof(struct process, sched_list),
	offsetof(struct process, ftn),
	offsetof(struct fork_tree_node, status),
	offsetof(struct fork_tree_node, pid),
	offsetof(struct fork_tree_node, tid),
	-1,
};

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
	get_cpu_local_var(cpuid)->status = CPU_STATUS_RESERVED;
    ihk_mc_spinlock_unlock_noirq(&cpuid_head_lock);
 out:
    return cpuid;
}

SYSCALL_DECLARE(rt_sigaction)
{
	int sig = ihk_mc_syscall_arg0(ctx);
	const struct sigaction *act = (const struct sigaction *)ihk_mc_syscall_arg1(ctx);
	struct sigaction *oact = (struct sigaction *)ihk_mc_syscall_arg2(ctx);
	size_t sigsetsize = ihk_mc_syscall_arg3(ctx);
	struct k_sigaction new_sa, old_sa;
	int rc;

	if(sig == SIGKILL || sig == SIGSTOP || sig <= 0 || sig > 64)
		return -EINVAL;
	if (sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if(act)
		if(copy_from_user(&new_sa.sa, act, sizeof new_sa.sa)){
			goto fault;
		}
	rc = do_sigaction(sig, act? &new_sa: NULL, oact? &old_sa: NULL);
	if(rc == 0 && oact)
		if(copy_to_user(oact, &old_sa.sa, sizeof old_sa.sa)){
			goto fault;
		}

	return rc;
fault:
	return -EFAULT;
}

struct sigsp {
	struct x86_user_context regs;
	unsigned long sigrc;
	unsigned long sigmask;
	int ssflags;
	siginfo_t info;
};

SYSCALL_DECLARE(rt_sigreturn)
{
	struct process *proc = cpu_local_var(current);
	struct x86_user_context *regs;
	struct sigsp *sigsp;
	long rc = -EFAULT;

	asm("movq %%gs:132, %0" : "=r" (regs));
	--regs;

	sigsp = (struct sigsp *)regs->gpr.rsp;
	proc->sigmask.__val[0] = sigsp->sigmask;
	proc->sigstack.ss_flags = sigsp->ssflags;
	if(copy_from_user(regs, &sigsp->regs, sizeof(struct x86_user_context)))
		return rc;
	copy_from_user(&rc, &sigsp->sigrc, sizeof(long));
	return rc;
}

extern struct cpu_local_var *clv;
extern unsigned long do_kill(int pid, int tid, int sig, struct siginfo *info, int ptracecont);
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
		pid = proc->ftn->pid;
	if(pgid == 0)
		pgid = pid;

	for(i = 0; i < num_processors; i++){
		v = get_cpu_local_var(i);
		irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
		list_for_each_entry(p, &(v->runq), sched_list){
			if(p->ftn->pid <= 0)
				continue;
			if(p->ftn->pid == pid){
				p->ftn->pgid = pgid;
			}
		}
		ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
	}
}

#define RFLAGS_MASK (RFLAGS_CF | RFLAGS_PF | RFLAGS_AF | RFLAGS_ZF | \
		RFLAGS_SF | RFLAGS_TF | RFLAGS_DF | RFLAGS_OF |  \
		RFLAGS_NT | RFLAGS_RF | RFLAGS_AC)
#define DB6_RESERVED_MASK (0xffffffffffff1ff0UL)
#define DB6_RESERVED_SET (0xffff0ff0UL)
#define DB7_RESERVED_MASK (0xffffffff0000dc00UL)
#define DB7_RESERVED_SET (0x400UL)

extern ihk_mc_user_context_t *lookup_user_context(struct process *proc);

long
ptrace_read_user(struct process *proc, long addr, unsigned long *value)
{
	unsigned long *p;
	struct x86_user_context *uctx;
	size_t off;

	if ((addr < 0) || (addr & (sizeof(*value) - 1))) {
		return -EIO;
	}
	else if (addr < sizeof(struct user_regs_struct)) {
		uctx = lookup_user_context(proc);
		if (!uctx) {
			return -EIO;
		}
		if (addr < offsetof(struct user_regs_struct, fs_base)) {
			*value = *(unsigned long *)(
					(uintptr_t)(&uctx->gpr) + addr);
		}
		else {
			off = addr - offsetof(struct user_regs_struct, fs_base);
			*value = *(unsigned long *)(
					(uintptr_t)(&uctx->sr) + off);
		}
		return 0;
	}
	if (offsetof(struct user, u_debugreg[0]) <= addr &&
			addr < offsetof(struct user, u_debugreg[8])) {
		if (addr & (sizeof(*value) - 1)) return -EIO;
		if (proc->ptrace_debugreg == NULL) {
			kprintf("ptrace_read_user: missing ptrace_debugreg\n");
			return -EFAULT;
		}
		p = &proc->ptrace_debugreg[(addr - offsetof(struct user, u_debugreg[0])) / sizeof(*value)];
		*value = *p;
		return 0;
	}

	/* SUCCESS others */
	dkprintf("ptrace_read_user,addr=%d\n", addr);
	*value = 0;
	return 0;
}

long
ptrace_write_user(struct process *proc, long addr, unsigned long value)
{
	unsigned long *p;
	struct x86_user_context *uctx;
	size_t off;

	if ((addr < 0) || (addr & (sizeof(value) - 1))) {
		return -EIO;
	}
	else if (addr < sizeof(struct user_regs_struct)) {
		uctx = lookup_user_context(proc);
		if (!uctx) {
			return -EIO;
		}
		if (addr == offsetof(struct user_regs_struct, eflags)) {
			uctx->gpr.rflags &= ~RFLAGS_MASK;
			uctx->gpr.rflags |= (value & RFLAGS_MASK);
		}
		else if (addr < offsetof(struct user_regs_struct, fs_base)) {
			*(unsigned long *)((uintptr_t)(&uctx->gpr) + addr)
				= value;
		}
		else {
			off = addr - offsetof(struct user_regs_struct,
					fs_base);
			*(unsigned long *)((uintptr_t)(&uctx->sr) + off)
				= value;
		}
		return 0;
	}
	if (offsetof(struct user, u_debugreg[0]) <= addr &&
			addr < offsetof(struct user, u_debugreg[8])) {
		if (addr & (sizeof(value) - 1)) return -EIO;
		if (proc->ptrace_debugreg == NULL) {
			kprintf("ptrace_write_user: missing ptrace_debugreg\n");
			return -EFAULT;
		}
		p = &proc->ptrace_debugreg[(addr - offsetof(struct user, u_debugreg[0])) / sizeof(value)];
		if (addr == offsetof(struct user, u_debugreg[6])) {
			value &= ~DB6_RESERVED_MASK;
			value |= DB6_RESERVED_SET;
		}
		if (addr == offsetof(struct user, u_debugreg[7])) {
			value &= ~DB7_RESERVED_MASK;
			value |= DB7_RESERVED_SET;
		}
		*p = value;
		return 0;
	}

	/* SUCCESS others */
	dkprintf("ptrace_write_user,addr=%d\n", addr);
	return 0;
}

long
alloc_debugreg(struct process *proc)
{
	proc->ptrace_debugreg = kmalloc(sizeof(*proc->ptrace_debugreg) * 8, IHK_MC_AP_NOWAIT);
	if (proc->ptrace_debugreg == NULL) {
		kprintf("alloc_debugreg: no memory.\n");
		return -ENOMEM;
	}
	memset(proc->ptrace_debugreg, '\0', sizeof(*proc->ptrace_debugreg) * 8);
	proc->ptrace_debugreg[6] = DB6_RESERVED_SET;
	proc->ptrace_debugreg[7] = DB7_RESERVED_SET;
	return 0;
}

void
save_debugreg(unsigned long *debugreg)
{
	asm("mov %%db0, %0" :"=r" (debugreg[0]));
	asm("mov %%db1, %0" :"=r" (debugreg[1]));
	asm("mov %%db2, %0" :"=r" (debugreg[2]));
	asm("mov %%db3, %0" :"=r" (debugreg[3]));
//	asm("mov %%db4, %0" :"=r" (debugreg[4]));
//	asm("mov %%db5, %0" :"=r" (debugreg[5]));
	debugreg[4] = debugreg[5] = 0;
	asm("mov %%db6, %0" :"=r" (debugreg[6]));
	asm("mov %%db7, %0" :"=r" (debugreg[7]));
}

void
restore_debugreg(unsigned long *debugreg)
{
	asm("mov %0, %%db0" ::"r" (debugreg[0]));
	asm("mov %0, %%db1" ::"r" (debugreg[1]));
	asm("mov %0, %%db2" ::"r" (debugreg[2]));
	asm("mov %0, %%db3" ::"r" (debugreg[3]));
//	asm("mov %0, %%db4" ::"r" (debugreg[4]));
//	asm("mov %0, %%db5" ::"r" (debugreg[5]));
	asm("mov %0, %%db6" ::"r" (debugreg[6]));
	asm("mov %0, %%db7" ::"r" (debugreg[7]));
}

void
clear_debugreg(void)
{
	unsigned long r = 0;
	asm("mov %0, %%db0" ::"r" (r));
	asm("mov %0, %%db1" ::"r" (r));
	asm("mov %0, %%db2" ::"r" (r));
	asm("mov %0, %%db3" ::"r" (r));
//	asm("mov %0, %%db4" ::"r" (r));
//	asm("mov %0, %%db5" ::"r" (r));
	r = DB6_RESERVED_SET;
	asm("mov %0, %%db6" ::"r" (r));
	r = DB7_RESERVED_SET;
	asm("mov %0, %%db7" ::"r" (r));
}

void clear_single_step(struct process *proc)
{
	proc->uctx->gpr.rflags &= ~RFLAGS_TF;
}

void set_single_step(struct process *proc)
{
	proc->uctx->gpr.rflags |= RFLAGS_TF;
}

long ptrace_read_fpregs(struct process *proc, void *fpregs)
{
	save_fp_regs(proc);
	if (proc->fp_regs == NULL) {
		return -ENOMEM;
	}
	return copy_to_user(fpregs, &proc->fp_regs->i387,
			sizeof(struct i387_fxsave_struct));
}

long ptrace_write_fpregs(struct process *proc, void *fpregs)
{
	save_fp_regs(proc);
	if (proc->fp_regs == NULL) {
		return -ENOMEM;
	}
	return copy_from_user(&proc->fp_regs->i387, fpregs, 
			sizeof(struct i387_fxsave_struct));
}

long ptrace_read_regset(struct process *proc, long type, struct iovec *iov)
{
	long rc = -EINVAL;

	switch (type) {
	case NT_X86_XSTATE:
		save_fp_regs(proc);
		if (proc->fp_regs == NULL) {
			return -ENOMEM;
		}
		if (iov->iov_len > sizeof(fp_regs_struct)) {
			iov->iov_len = sizeof(fp_regs_struct);
		}
		rc = copy_to_user(iov->iov_base, proc->fp_regs, iov->iov_len);
		break;
	default:
		kprintf("ptrace_read_regset: not supported type 0x%x\n", type);
		break;
	}
	return rc;
}

long ptrace_write_regset(struct process *proc, long type, struct iovec *iov)
{
	long rc = -EINVAL;

	switch (type) {
	case NT_X86_XSTATE:
		save_fp_regs(proc);
		if (proc->fp_regs == NULL) {
			return -ENOMEM;
		}
		if (iov->iov_len > sizeof(fp_regs_struct)) {
			iov->iov_len = sizeof(fp_regs_struct);
		}
		rc = copy_from_user(proc->fp_regs, iov->iov_base, iov->iov_len);
		break;
	default:
		kprintf("ptrace_write_regset: not supported type 0x%x\n", type);
		break;
	}
	return rc;
}

extern void coredump(struct process *proc, void *regs);

void ptrace_report_signal(struct process *proc, int sig)
{
	long rc;

	dkprintf("ptrace_report_signal,pid=%d\n", proc->ftn->pid);

	ihk_mc_spinlock_lock_noirq(&proc->ftn->lock);	
	proc->ftn->exit_status = sig;
	/* Transition process state */
	proc->ftn->status = PS_TRACED;
	proc->ftn->ptrace &= ~PT_TRACE_SYSCALL_MASK;
	if (sig == SIGSTOP || sig == SIGTSTP ||
			sig == SIGTTIN || sig == SIGTTOU) {
		proc->ftn->signal_flags |= SIGNAL_STOP_STOPPED;
	} else {
		proc->ftn->signal_flags &= ~SIGNAL_STOP_STOPPED;
	}
	ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);	
	if (proc->ftn->parent) {
		/* kill SIGCHLD */
		ihk_mc_spinlock_lock_noirq(&proc->ftn->parent->lock);
		if (proc->ftn->parent->owner) {
			struct siginfo info;

			memset(&info, '\0', sizeof info);
			info.si_signo = SIGCHLD;
			info.si_code = CLD_TRAPPED;
			info._sifields._sigchld.si_pid = proc->ftn->pid;
			info._sifields._sigchld.si_status = proc->ftn->exit_status;
			rc = do_kill(proc->ftn->parent->pid, -1, SIGCHLD, &info, 0);
			if (rc < 0) {
				kprintf("ptrace_report_signal,do_kill failed\n");
			}
		}
		ihk_mc_spinlock_unlock_noirq(&proc->ftn->parent->lock);	

		/* Wake parent (if sleeping in wait4()) */
		waitq_wakeup(&proc->ftn->parent->waitpid_q);
	}

	dkprintf("ptrace_report_signal,sleeping\n");
	/* Sleep */
	schedule();
	dkprintf("ptrace_report_signal,wake up\n");
}

void
do_signal(unsigned long rc, void *regs0, struct process *proc, struct sig_pending *pending)
{
	struct x86_user_context *regs = regs0;
	struct k_sigaction *k;
	int	sig;
	__sigset_t w;
	int	irqstate;
	struct fork_tree_node *ftn = proc->ftn;
	int	orgsig;
	int	ptraceflag = 0;

	for(w = pending->sigmask.__val[0], sig = 0; w; sig++, w >>= 1);
	dkprintf("do_signal,pid=%d,sig=%d\n", proc->ftn->pid, sig);
	orgsig = sig;

	if((ftn->ptrace & PT_TRACED) &&
	   pending->ptracecont == 0 &&
	   sig != SIGKILL) {
		ptraceflag = 1;
		sig = SIGSTOP;
	}

	if(regs == NULL){ /* call from syscall */
		asm("movq %%gs:132, %0" : "=r" (regs));
		--regs;
	}
	else{
		rc = regs->gpr.rax;
	}

	irqstate = ihk_mc_spinlock_lock(&proc->sighandler->lock);
	k = proc->sighandler->action + sig - 1;

	if(k->sa.sa_handler == SIG_IGN){
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
			usp = (unsigned long *)regs->gpr.rsp;
		}
		sigsp = ((struct sigsp *)usp) - 1;
		sigsp = (struct sigsp *)((unsigned long)sigsp & 0xfffffffffffffff0UL);
		if(write_process_vm(proc->vm, &sigsp->regs, regs, sizeof(struct x86_user_context)) ||
		   write_process_vm(proc->vm, &sigsp->sigrc, &rc, sizeof(long))){
			kfree(pending);
			ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
			kprintf("do_signal,write_process_vm failed\n");
			terminate(0, sig, (ihk_mc_user_context_t *)regs->gpr.rsp);
			return;
		}
		sigsp->sigmask = mask;
		sigsp->ssflags = ssflags;
		memcpy(&sigsp->info, &pending->info, sizeof(siginfo_t));

		usp = (unsigned long *)sigsp;
		usp--;
		*usp = (unsigned long)k->sa.sa_restorer;

		regs->gpr.rdi = (unsigned long)sig;
		if(k->sa.sa_flags & SA_SIGINFO){
			regs->gpr.rsi = (unsigned long)&sigsp->info;
			regs->gpr.rdx = 0;
		}
		regs->gpr.rip = (unsigned long)k->sa.sa_handler;
		regs->gpr.rsp = (unsigned long)usp;

		proc->sigmask.__val[0] |= pending->sigmask.__val[0];
		kfree(pending);
		ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
	}
	else {
		int	coredumped = 0;
		siginfo_t info;

		if(ptraceflag){
			if(proc->ptrace_recvsig)
				kfree(proc->ptrace_recvsig);
			proc->ptrace_recvsig = pending;
			if(proc->ptrace_sendsig)
				kfree(proc->ptrace_sendsig);
			proc->ptrace_sendsig = NULL;
		}
		else
			kfree(pending);
		ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
		switch (sig) {
		case SIGSTOP:
		case SIGTSTP:
		case SIGTTIN:
		case SIGTTOU:
			memset(&info, '\0', sizeof info);
			info.si_signo = SIGCHLD;
			info.si_code = CLD_STOPPED;
			info._sifields._sigchld.si_pid = proc->ftn->pid;
			info._sifields._sigchld.si_status = (sig << 8) | 0x7f;
			do_kill(proc->ftn->parent->pid, -1, SIGCHLD, &info, 0);
			if(ptraceflag){
				ptrace_report_signal(proc, orgsig);
			}
			else{
				dkprintf("do_signal,SIGSTOP,changing state\n");

				/* Update process state in fork tree */
				ihk_mc_spinlock_lock_noirq(&ftn->lock);	
				ftn->group_exit_status = SIGSTOP;

				/* Reap and set new signal_flags */
				ftn->signal_flags = SIGNAL_STOP_STOPPED;

				ftn->status = PS_STOPPED;
				ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);	

				/* Wake up the parent who tried wait4 and sleeping */
				waitq_wakeup(&proc->ftn->parent->waitpid_q);

				dkprintf("do_signal,SIGSTOP,sleeping\n");
				/* Sleep */
				proc->ftn->status = PS_STOPPED;
				schedule();
				dkprintf("SIGSTOP(): woken up\n");
			}
			break;
		case SIGTRAP:
			dkprintf("do_signal,SIGTRAP\n");
			if(!(ftn->ptrace & PT_TRACED)) {
				goto core;
			}

			/* Update process state in fork tree */
			ihk_mc_spinlock_lock_noirq(&ftn->lock);	
			ftn->exit_status = SIGTRAP;
			ftn->status = PS_TRACED;
			ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);	

			/* Wake up the parent who tried wait4 and sleeping */
			waitq_wakeup(&proc->ftn->parent->waitpid_q);

			/* Sleep */
			dkprintf("do_signal,SIGTRAP,sleeping\n");

			schedule();
			dkprintf("SIGTRAP(): woken up\n");
			break;
		case SIGCONT:
			memset(&info, '\0', sizeof info);
			info.si_signo = SIGCHLD;
			info.si_code = CLD_CONTINUED;
			info._sifields._sigchld.si_pid = proc->ftn->pid;
			info._sifields._sigchld.si_status = 0x0000ffff;
			do_kill(proc->ftn->parent->pid, -1, SIGCHLD, &info, 0);
			ftn->signal_flags = SIGNAL_STOP_CONTINUED;
			dkprintf("do_signal,SIGCONT,do nothing\n");
			break;
		case SIGQUIT:
		case SIGILL:
		case SIGABRT:
		case SIGFPE:
		case SIGSEGV:
		case SIGBUS:
		case SIGSYS:
		core:
			dkprintf("do_signal,default,core,sig=%d\n", sig);
			coredump(proc, regs);
			coredumped = 0x80;
			terminate(0, sig | coredumped, (ihk_mc_user_context_t *)regs->gpr.rsp);
			break;
		case SIGCHLD:
		case SIGURG:
			break;
		default:
			dkprintf("do_signal,default,terminate,sig=%d\n", sig);
			terminate(0, sig, (ihk_mc_user_context_t *)regs->gpr.rsp);
			break;
		}
	}
}

static struct sig_pending *
getsigpending(struct process *proc, int delflag){
	struct list_head *head;
	ihk_spinlock_t *lock;
	struct sig_pending *next;
	struct sig_pending *pending;
	__sigset_t w;
	int	irqstate;

	w = proc->sigmask.__val[0];

	lock = &proc->sigshared->lock;
	head = &proc->sigshared->sigpending;
	for(;;){
		irqstate = ihk_mc_spinlock_lock(lock);
		list_for_each_entry_safe(pending, next, head, list){
			if(!(pending->sigmask.__val[0] & w)){
				if(delflag)
					list_del(&pending->list);
				ihk_mc_spinlock_unlock(lock, irqstate);
				return pending;
			}
		}
		ihk_mc_spinlock_unlock(lock, irqstate);

		if(lock == &proc->sigpendinglock)
			return NULL;
		lock = &proc->sigpendinglock;
		head = &proc->sigpending;
	}

	return NULL;
}

struct sig_pending *
hassigpending(struct process *proc)
{
	return getsigpending(proc, 0);
}

void
check_signal(unsigned long rc, void *regs0)
{
	struct x86_user_context *regs = regs0;
	struct process *proc;
	struct sig_pending *pending;
	int	irqstate;

	if(clv == NULL)
		return;
	proc = cpu_local_var(current);
	if(proc == NULL || proc->ftn->pid == 0){
		struct process *p;

		irqstate = ihk_mc_spinlock_lock(&(cpu_local_var(runq_lock)));
		list_for_each_entry(p, &(cpu_local_var(runq)), sched_list){
			if(p->ftn->pid <= 0)
				continue;
			if(p->ftn->status == PS_INTERRUPTIBLE &&
			   hassigpending(p)){
				p->ftn->status = PS_RUNNING;
				ihk_mc_spinlock_unlock(&(cpu_local_var(runq_lock)), irqstate);
			//	schedule();
				return;
			}
		}
		ihk_mc_spinlock_unlock(&(cpu_local_var(runq_lock)), irqstate);
		return;
	}

	if(regs != NULL && (regs->gpr.rsp & 0x8000000000000000)) {
		return;
	}

	for(;;){
		pending = getsigpending(proc, 1);
		if(!pending) {
			dkprintf("check_signal,queue is empty\n");
			return;
		}

		do_signal(rc, regs, proc, pending);
	}
}

unsigned long
do_kill(int pid, int tid, int sig, siginfo_t *info, int ptracecont)
{
	dkprintf("do_kill,pid=%d,tid=%d,sig=%d\n", pid, tid, sig);
	struct cpu_local_var *v;
	struct process *p;
	struct process *proc = cpu_local_var(current);
	struct process *tproc = NULL;
	int i;
	__sigset_t mask;
	struct list_head *head;
	int rc;
	unsigned long irqstate = 0;
	struct k_sigaction *k;
	int doint;
	ihk_spinlock_t *savelock = NULL;
	int found = 0;
	siginfo_t info0;

	if(sig > 64 || sig < 0)
		return -EINVAL;

	if(info == NULL){
		memset(&info0, '\0', sizeof info0);
		info = &info0;
		info0.si_signo = sig;
	}

	if(tid == -1 && pid <= 0){
		int	pgid = -pid;
		int	rc = -ESRCH;
		int	*pids;
		int	i;
		int	n = 0;
		int	sendme = 0;

		if(pid == 0){
			if(proc == NULL || proc->ftn->pid <= 0)
				return -ESRCH;
			pgid = proc->ftn->pgid;
		}
		pids = kmalloc(sizeof(int) * num_processors, IHK_MC_AP_NOWAIT);
		if(!pids)
			return -ENOMEM;
		for(i = 0; i < num_processors; i++){
			v = get_cpu_local_var(i);
			irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
			list_for_each_entry(p, &(v->runq), sched_list){
				int	j;

				if(p->ftn->pid <= 0)
					continue;
				if(pgid != 1 && p->ftn->pgid != pgid)
					continue;
				if(proc && p->ftn->pid == proc->ftn->pid){
					sendme = 1;
					continue;
				}

				for(j = 0; j < n; j++)
					if(pids[j] == p->ftn->pid)
						break;
				if(j == n){
					pids[n] = p->ftn->pid;
					n++;
				}
			}
			ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
		}
		for(i = 0; i < n; i++)
			rc = do_kill(pids[i], -1, sig, info, ptracecont);
		if(sendme)
			rc = do_kill(proc->ftn->pid, -1, sig, info, ptracecont);

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
				if(p->ftn->pid == pid){
					if(p->ftn->tid == pid || tproc == NULL){
						if(!(mask & p->sigmask.__val[0])){
							tproc = p;
							if(!found && savelock) {
								ihk_mc_spinlock_unlock_noirq(savelock);
							}
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
						if(p->ftn->tid == pid || tproc == NULL){

						}
					}
				}
			}
			if(!found) {
				ihk_mc_spinlock_unlock_noirq(&(v->runq_lock));
			}
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
				if(p->ftn->pid > 0 &&
				   p->ftn->tid == tid){
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
				if(p->ftn->pid == pid &&
				   p->ftn->tid == tid){
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

	if(sig != SIGCONT &&
	   proc->ftn->euid != 0 &&
	   proc->ftn->ruid != tproc->ftn->ruid &&
	   proc->ftn->euid != tproc->ftn->ruid &&
	   proc->ftn->ruid != tproc->ftn->suid &&
	   proc->ftn->euid != tproc->ftn->suid){
		ihk_mc_spinlock_unlock_noirq(savelock);
		cpu_restore_interrupt(irqstate);
		return -EPERM;
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

	/* Put signal event even when handler is SIG_IGN or SIG_DFL
	   because target ptraced process must call ptrace_report_signal 
	   in check_signal */
	rc = 0;
	k = tproc->sighandler->action + sig - 1;
	if((sig != SIGKILL && (tproc->ftn->ptrace & PT_TRACED)) ||
			(k->sa.sa_handler != (void *)1 &&
			 (k->sa.sa_handler != NULL ||
			  (sig != SIGCHLD && sig != SIGURG)))){
		struct sig_pending *pending = NULL;
		if (sig < 33) { // SIGRTMIN - SIGRTMAX
			list_for_each_entry(pending, head, list){
				if(pending->sigmask.__val[0] == mask &&
				   pending->ptracecont == ptracecont)
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
				pending->ptracecont = ptracecont;
				if(sig == SIGKILL || sig == SIGSTOP)
					list_add(&pending->list, head);
				else
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

	if (doint && !(mask & tproc->sigmask.__val[0])) {
		int cpuid = tproc->cpu_id;
		int pid = tproc->ftn->pid;
		int status = tproc->ftn->status;

		if (proc != tproc) {
			dkprintf("do_kill,ipi,pid=%d,cpu_id=%d\n",
				 tproc->ftn->pid, tproc->cpu_id);
			ihk_mc_interrupt_cpu(get_x86_cpu_local_variable(tproc->cpu_id)->apic_id, 0xd0);
		}

		ihk_mc_spinlock_unlock_noirq(savelock);
		cpu_restore_interrupt(irqstate);
		if(!tproc->nohost)
			interrupt_syscall(pid, cpuid);

		if (status != PS_RUNNING) {
			if(sig == SIGKILL){
				/* Wake up the target only when stopped by ptrace-reporting */
				sched_wakeup_process(tproc, PS_TRACED | PS_STOPPED);
			}
			else if(sig == SIGCONT || ptracecont){
				/* Wake up the target only when stopped by SIGSTOP */
				sched_wakeup_process(tproc, PS_STOPPED);
			}
		}
	}
	else {
		ihk_mc_spinlock_unlock_noirq(savelock);
		cpu_restore_interrupt(irqstate);
	}
	return rc;
}

void
set_signal(int sig, void *regs0, siginfo_t *info)
{
	struct x86_user_context *regs = regs0;
	struct process *proc = cpu_local_var(current);

	if(proc == NULL || proc->ftn->pid == 0)
		return;

	if((__sigmask(sig) & proc->sigmask.__val[0]) ||
	   (regs->gpr.rsp & 0x8000000000000000)){
		coredump(proc, regs0);
		terminate(0, sig | 0x80, (ihk_mc_user_context_t *)regs->gpr.rsp);
	}
		do_kill(proc->ftn->pid, proc->ftn->tid, sig, info, 0);
}
