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

void terminate(int, int);
int copy_from_user(void *dst, const void *src, size_t siz);
int copy_to_user(void *dst, const void *src, size_t siz);
int write_process_vm(struct process_vm *vm, void *dst, const void *src, size_t siz);
long do_sigaction(int sig, struct k_sigaction *act, struct k_sigaction *oact);
long syscall(int num, ihk_mc_user_context_t *ctx);
extern void save_fp_regs(struct thread *proc);
void set_signal(int sig, void *regs0, siginfo_t *info);
void check_signal(unsigned long rc, void *regs0, int num);

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
	offsetof(struct thread, ctx),
	offsetof(struct thread, sched_list),
	offsetof(struct thread, proc),
	offsetof(struct thread, status),
	offsetof(struct process, pid),
	offsetof(struct thread, tid),
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
ihk_spinlock_t cpuid_head_lock = 0;
static int cpuid_head = 0;

/* archtecture-depended syscall handlers */
int obtain_clone_cpuid() {
    /* see above on BSP HW ID */
	struct ihk_mc_cpu_info *cpu_info = ihk_mc_get_cpu_info();
    int cpuid, nretry = 0;
    ihk_mc_spinlock_lock_noirq(&cpuid_head_lock);
	
	/* Always start from 0 to fill in LWK cores linearily */
	cpuid_head = 0;
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
	int num;
	int restart;
	siginfo_t info;
};

SYSCALL_DECLARE(rt_sigreturn)
{
	struct thread *thread = cpu_local_var(current);
	struct x86_user_context *regs;
	struct sigsp *sigsp;

	asm("movq %%gs:132, %0" : "=r" (regs));
	--regs;

	sigsp = (struct sigsp *)regs->gpr.rsp;
	if(copy_from_user(regs, &sigsp->regs, sizeof(struct x86_user_context)))
		return -EFAULT;
	thread->sigmask.__val[0] = sigsp->sigmask;
	thread->sigstack.ss_flags = sigsp->ssflags;
	if(sigsp->restart){
		return syscall(sigsp->num, (ihk_mc_user_context_t *)regs);
	}
	if(regs->gpr.rflags & RFLAGS_TF){
		struct siginfo info;

		regs->gpr.rax = sigsp->sigrc;
		memset(&info, '\0', sizeof info);
		regs->gpr.rflags &= ~RFLAGS_TF;
		info.si_code = TRAP_TRACE;
		set_signal(SIGTRAP, regs, &info);
		check_signal(0, regs, 0);
		check_need_resched();
	}
	return sigsp->sigrc;
}

extern struct cpu_local_var *clv;
extern unsigned long do_kill(struct thread *thread, int pid, int tid, int sig, struct siginfo *info, int ptracecont);
extern void interrupt_syscall(int all, int pid);
extern int num_processors;

#define RFLAGS_MASK (RFLAGS_CF | RFLAGS_PF | RFLAGS_AF | RFLAGS_ZF | \
		RFLAGS_SF | RFLAGS_TF | RFLAGS_DF | RFLAGS_OF |  \
		RFLAGS_NT | RFLAGS_RF | RFLAGS_AC)
#define DB6_RESERVED_MASK (0xffffffffffff1ff0UL)
#define DB6_RESERVED_SET (0xffff0ff0UL)
#define DB7_RESERVED_MASK (0xffffffff0000dc00UL)
#define DB7_RESERVED_SET (0x400UL)

extern ihk_mc_user_context_t *lookup_user_context(struct thread *thread);

long
ptrace_read_user(struct thread *thread, long addr, unsigned long *value)
{
	unsigned long *p;
	struct x86_user_context *uctx;
	size_t off;

	if ((addr < 0) || (addr & (sizeof(*value) - 1))) {
		return -EIO;
	}
	else if (addr < sizeof(struct user_regs_struct)) {
		uctx = lookup_user_context(thread);
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
		if (thread->ptrace_debugreg == NULL) {
			kprintf("ptrace_read_user: missing ptrace_debugreg\n");
			return -EFAULT;
		}
		p = &thread->ptrace_debugreg[(addr - offsetof(struct user, u_debugreg[0])) / sizeof(*value)];
		*value = *p;
		return 0;
	}

	/* SUCCESS others */
	dkprintf("ptrace_read_user,addr=%d\n", addr);
	*value = 0;
	return 0;
}

long
ptrace_write_user(struct thread *thread, long addr, unsigned long value)
{
	unsigned long *p;
	struct x86_user_context *uctx;
	size_t off;

	if ((addr < 0) || (addr & (sizeof(value) - 1))) {
		return -EIO;
	}
	else if (addr < sizeof(struct user_regs_struct)) {
		uctx = lookup_user_context(thread);
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
		if (thread->ptrace_debugreg == NULL) {
			kprintf("ptrace_write_user: missing ptrace_debugreg\n");
			return -EFAULT;
		}
		p = &thread->ptrace_debugreg[(addr - offsetof(struct user, u_debugreg[0])) / sizeof(value)];
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
alloc_debugreg(struct thread *thread)
{
	thread->ptrace_debugreg = kmalloc(sizeof(*thread->ptrace_debugreg) * 8, IHK_MC_AP_NOWAIT);
	if (thread->ptrace_debugreg == NULL) {
		kprintf("alloc_debugreg: no memory.\n");
		return -ENOMEM;
	}
	memset(thread->ptrace_debugreg, '\0', sizeof(*thread->ptrace_debugreg) * 8);
	thread->ptrace_debugreg[6] = DB6_RESERVED_SET;
	thread->ptrace_debugreg[7] = DB7_RESERVED_SET;
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

void clear_single_step(struct thread *thread)
{
	thread->uctx->gpr.rflags &= ~RFLAGS_TF;
}

void set_single_step(struct thread *thread)
{
	thread->uctx->gpr.rflags |= RFLAGS_TF;
}

long ptrace_read_fpregs(struct thread *thread, void *fpregs)
{
	save_fp_regs(thread);
	if (thread->fp_regs == NULL) {
		return -ENOMEM;
	}
	return copy_to_user(fpregs, &thread->fp_regs->i387,
			sizeof(struct i387_fxsave_struct));
}

long ptrace_write_fpregs(struct thread *thread, void *fpregs)
{
	save_fp_regs(thread);
	if (thread->fp_regs == NULL) {
		return -ENOMEM;
	}
	return copy_from_user(&thread->fp_regs->i387, fpregs, 
			sizeof(struct i387_fxsave_struct));
}

long ptrace_read_regset(struct thread *thread, long type, struct iovec *iov)
{
	long rc = -EINVAL;

	switch (type) {
	case NT_X86_XSTATE:
		if (thread->fp_regs == NULL) {
			return -ENOMEM;
		}
		if (iov->iov_len > sizeof(fp_regs_struct)) {
			iov->iov_len = sizeof(fp_regs_struct);
		}
		rc = copy_to_user(iov->iov_base, thread->fp_regs, iov->iov_len);
		break;
	default:
		kprintf("ptrace_read_regset: not supported type 0x%x\n", type);
		break;
	}
	return rc;
}

long ptrace_write_regset(struct thread *thread, long type, struct iovec *iov)
{
	long rc = -EINVAL;

	switch (type) {
	case NT_X86_XSTATE:
		if (thread->fp_regs == NULL) {
			return -ENOMEM;
		}
		if (iov->iov_len > sizeof(fp_regs_struct)) {
			iov->iov_len = sizeof(fp_regs_struct);
		}
		rc = copy_from_user(thread->fp_regs, iov->iov_base, iov->iov_len);
		break;
	default:
		kprintf("ptrace_write_regset: not supported type 0x%x\n", type);
		break;
	}
	return rc;
}

extern void coredump(struct thread *thread, void *regs);

void ptrace_report_signal(struct thread *thread, int sig)
{
	struct mcs_rwlock_node_irqsave lock;
	struct process *proc = thread->proc;
	int parent_pid;
	struct siginfo info;

	dkprintf("ptrace_report_signal,pid=%d\n", thread->proc->pid);

	mcs_rwlock_writer_lock(&proc->update_lock, &lock);	
	if(!(proc->ptrace & PT_TRACED)){
		mcs_rwlock_writer_unlock(&proc->update_lock, &lock);
		return;
	}
	proc->exit_status = sig;
	/* Transition thread state */
	proc->status = PS_TRACED;
	thread->status = PS_TRACED;
	proc->ptrace &= ~PT_TRACE_SYSCALL_MASK;
	if (sig == SIGSTOP || sig == SIGTSTP ||
			sig == SIGTTIN || sig == SIGTTOU) {
		proc->signal_flags |= SIGNAL_STOP_STOPPED;
	} else {
		proc->signal_flags &= ~SIGNAL_STOP_STOPPED;
	}
	parent_pid = proc->parent->pid;
	mcs_rwlock_writer_unlock(&proc->update_lock, &lock);

	memset(&info, '\0', sizeof info);
	info.si_signo = SIGCHLD;
	info.si_code = CLD_TRAPPED;
	info._sifields._sigchld.si_pid = thread->proc->pid;
	info._sifields._sigchld.si_status = thread->proc->exit_status;
	do_kill(cpu_local_var(current), parent_pid, -1, SIGCHLD, &info, 0);
	/* Wake parent (if sleeping in wait4()) */
	waitq_wakeup(&proc->parent->waitpid_q);

	dkprintf("ptrace_report_signal,sleeping\n");
	/* Sleep */
	schedule();
	dkprintf("ptrace_report_signal,wake up\n");
}
static int
isrestart(int num, unsigned long rc, int sig, int restart)
{
	if(sig == SIGKILL || sig == SIGSTOP)
		return 0;
	if(num == 0 || rc != -EINTR)
		return 0;
	switch(num){
	    case __NR_pause:
	    case __NR_rt_sigsuspend:
	    case __NR_rt_sigtimedwait:
//	    case __NR_rt_sigwaitinfo:
	    case __NR_epoll_wait:
	    case __NR_epoll_pwait:
	    case __NR_poll:
	    case __NR_ppoll:
	    case __NR_select:
	    case __NR_pselect6:
	    case __NR_msgrcv:
	    case __NR_msgsnd:
	    case __NR_semop:
	    case __NR_semtimedop:
	    case __NR_clock_nanosleep:
	    case __NR_nanosleep:
//	    case __NR_usleep:
	    case __NR_io_getevents:
		return 0;
	}
	if(sig == SIGCHLD)
		return 1;
	if(restart)
		return 1;
	return 0;
}

void
do_signal(unsigned long rc, void *regs0, struct thread *thread, struct sig_pending *pending, int num)
{
	struct x86_user_context *regs = regs0;
	struct k_sigaction *k;
	int	sig;
	__sigset_t w;
	struct process *proc = thread->proc;
	int	orgsig;
	int	ptraceflag = 0;
	struct mcs_rwlock_node_irqsave lock;
	unsigned long irqstate;

	for(w = pending->sigmask.__val[0], sig = 0; w; sig++, w >>= 1);
	dkprintf("do_signal,pid=%d,sig=%d\n", proc->pid, sig);
	orgsig = sig;

	if((proc->ptrace & PT_TRACED) &&
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

	irqstate = ihk_mc_spinlock_lock(&thread->sigcommon->lock);
	k = thread->sigcommon->action + sig - 1;

	if(k->sa.sa_handler == SIG_IGN){
		kfree(pending);
		ihk_mc_spinlock_unlock(&thread->sigcommon->lock, irqstate);
		return;
	}
	else if(k->sa.sa_handler){
		unsigned long *usp; /* user stack */
		struct sigsp *sigsp;
		int	ssflags = thread->sigstack.ss_flags;
		unsigned long	mask = (unsigned long)thread->sigmask.__val[0];

		if((k->sa.sa_flags & SA_ONSTACK) &&
		   !(thread->sigstack.ss_flags & SS_DISABLE) &&
		   !(thread->sigstack.ss_flags & SS_ONSTACK)){
			unsigned long lsp;
			lsp = ((unsigned long)(((char *)thread->sigstack.ss_sp) + thread->sigstack.ss_size)) & 0xfffffffffffffff8UL;
			usp = (unsigned long *)lsp;
			thread->sigstack.ss_flags |= SS_ONSTACK;
		}
		else{
			usp = (unsigned long *)regs->gpr.rsp;
		}
		sigsp = ((struct sigsp *)usp) - 1;
		sigsp = (struct sigsp *)((unsigned long)sigsp & 0xfffffffffffffff0UL);
		if(write_process_vm(thread->vm, &sigsp->regs, regs, sizeof(struct x86_user_context)) ||
		   write_process_vm(thread->vm, &sigsp->sigrc, &rc, sizeof(long))){
			kfree(pending);
			ihk_mc_spinlock_unlock(&thread->sigcommon->lock, irqstate);
			kprintf("do_signal,write_process_vm failed\n");
			terminate(0, sig);
			return;
		}
		sigsp->sigmask = mask;
		sigsp->ssflags = ssflags;
		sigsp->num = num;
		sigsp->restart = isrestart(num, rc, sig, k->sa.sa_flags & SA_RESTART);
		if(num != 0 && rc == -EINTR && sig == SIGCHLD)
			sigsp->restart = 1;
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

		if(!(k->sa.sa_flags & SA_NODEFER))
			thread->sigmask.__val[0] |= pending->sigmask.__val[0];
		kfree(pending);
		ihk_mc_spinlock_unlock(&thread->sigcommon->lock, irqstate);
		if(regs->gpr.rflags & RFLAGS_TF){
			struct siginfo info;

			memset(&info, '\0', sizeof info);
			regs->gpr.rflags &= ~RFLAGS_TF;
			info.si_code = TRAP_TRACE;
			set_signal(SIGTRAP, regs, &info);
			check_signal(0, regs, 0);
			check_need_resched();
		}
	}
	else {
		int	coredumped = 0;
		siginfo_t info;

		if(ptraceflag){
			if(thread->ptrace_recvsig)
				kfree(thread->ptrace_recvsig);
			thread->ptrace_recvsig = pending;
			if(thread->ptrace_sendsig)
				kfree(thread->ptrace_sendsig);
			thread->ptrace_sendsig = NULL;
		}
		else
			kfree(pending);
		ihk_mc_spinlock_unlock(&thread->sigcommon->lock, irqstate);
		switch (sig) {
		case SIGSTOP:
		case SIGTSTP:
		case SIGTTIN:
		case SIGTTOU:
			memset(&info, '\0', sizeof info);
			info.si_signo = SIGCHLD;
			info.si_code = CLD_STOPPED;
			info._sifields._sigchld.si_pid = thread->proc->pid;
			info._sifields._sigchld.si_status = (sig << 8) | 0x7f;
			do_kill(cpu_local_var(current), thread->proc->parent->pid, -1, SIGCHLD, &info, 0);
			if(ptraceflag){
				ptrace_report_signal(thread, orgsig);
			}
			else{
				dkprintf("do_signal,SIGSTOP,changing state\n");

				/* Update thread state in fork tree */
				mcs_rwlock_writer_lock(&proc->update_lock, &lock);	
				proc->group_exit_status = SIGSTOP;

				/* Reap and set new signal_flags */
				proc->signal_flags = SIGNAL_STOP_STOPPED;

				proc->status = PS_STOPPED;
				thread->status = PS_STOPPED;
				mcs_rwlock_writer_unlock(&proc->update_lock, &lock);	

				/* Wake up the parent who tried wait4 and sleeping */
				waitq_wakeup(&proc->parent->waitpid_q);

				dkprintf("do_signal,SIGSTOP,sleeping\n");
				/* Sleep */
				schedule();
				dkprintf("SIGSTOP(): woken up\n");
			}
			break;
		case SIGTRAP:
			dkprintf("do_signal,SIGTRAP\n");
			if(!(proc->ptrace & PT_TRACED)) {
				goto core;
			}

			/* Update thread state in fork tree */
			mcs_rwlock_writer_lock(&proc->update_lock, &lock);	
			proc->exit_status = SIGTRAP;
			proc->status = PS_TRACED;
			thread->status = PS_TRACED;
			mcs_rwlock_writer_unlock(&proc->update_lock, &lock);	

			/* Wake up the parent who tried wait4 and sleeping */
			waitq_wakeup(&thread->proc->parent->waitpid_q);

			/* Sleep */
			dkprintf("do_signal,SIGTRAP,sleeping\n");

			schedule();
			dkprintf("SIGTRAP(): woken up\n");
			break;
		case SIGCONT:
			memset(&info, '\0', sizeof info);
			info.si_signo = SIGCHLD;
			info.si_code = CLD_CONTINUED;
			info._sifields._sigchld.si_pid = proc->pid;
			info._sifields._sigchld.si_status = 0x0000ffff;
			do_kill(cpu_local_var(current), proc->parent->pid, -1, SIGCHLD, &info, 0);
			proc->signal_flags = SIGNAL_STOP_CONTINUED;
			dkprintf("do_signal,SIGCONT,do nothing\n");
			break;
		case SIGQUIT:
		case SIGILL:
		case SIGABRT:
		case SIGFPE:
		case SIGSEGV:
		case SIGBUS:
		case SIGSYS:
		case SIGXCPU:
		case SIGXFSZ:
		core:
			dkprintf("do_signal,default,core,sig=%d\n", sig);
			coredump(thread, regs);
			coredumped = 0x80;
			terminate(0, sig | coredumped);
			break;
		case SIGCHLD:
		case SIGURG:
			break;
		default:
			dkprintf("do_signal,default,terminate,sig=%d\n", sig);
			terminate(0, sig);
			break;
		}
	}
}

static struct sig_pending *
getsigpending(struct thread *thread, int delflag){
	struct list_head *head;
	ihk_spinlock_t *lock;
	struct sig_pending *next;
	struct sig_pending *pending;
	__sigset_t w;
	int	irqstate;
	__sigset_t x;
	int sig;
	struct k_sigaction *k;

	w = thread->sigmask.__val[0];

	lock = &thread->sigcommon->lock;
	head = &thread->sigcommon->sigpending;
	for(;;){
		irqstate = ihk_mc_spinlock_lock(lock);
		list_for_each_entry_safe(pending, next, head, list){
			for(x = pending->sigmask.__val[0], sig = 0; x; sig++, x >>= 1);
			k = thread->sigcommon->action + sig - 1;
			if(delflag ||
			   (sig != SIGCHLD && sig != SIGURG) ||
			   (k->sa.sa_handler != (void *)1 &&
			    k->sa.sa_handler != NULL)){
				if(!(pending->sigmask.__val[0] & w)){
					if(delflag)
						list_del(&pending->list);
					ihk_mc_spinlock_unlock(lock, irqstate);
					return pending;
				}
			}
		}
		ihk_mc_spinlock_unlock(lock, irqstate);

		if(lock == &thread->sigpendinglock)
			return NULL;
		lock = &thread->sigpendinglock;
		head = &thread->sigpending;
	}

	return NULL;
}

struct sig_pending *
hassigpending(struct thread *thread)
{
	return getsigpending(thread, 0);
}

int
interrupt_from_user(void *regs0)
{
	struct x86_user_context *regs = regs0;

	return !(regs->gpr.rsp & 0x8000000000000000);
}

void
check_signal(unsigned long rc, void *regs0, int num)
{
	struct x86_user_context *regs = regs0;
	struct thread *thread;
	struct sig_pending *pending;
	int	irqstate;

	if(clv == NULL)
		return;
	thread = cpu_local_var(current);

	if(thread == NULL || thread == &cpu_local_var(idle)){
		struct thread *t;

		irqstate = ihk_mc_spinlock_lock(&(cpu_local_var(runq_lock)));
		list_for_each_entry(t, &(cpu_local_var(runq)), sched_list){
			if(t == &cpu_local_var(idle))
				continue;
			if(t->status == PS_INTERRUPTIBLE &&
			   hassigpending(t)){
				t->status = PS_RUNNING;
				break;
			}
		}
		ihk_mc_spinlock_unlock(&(cpu_local_var(runq_lock)), irqstate);
		return;
	}

	if(regs != NULL && !interrupt_from_user(regs)) {
		return;
	}

	for(;;){
		pending = getsigpending(thread, 1);
		if(!pending) {
			dkprintf("check_signal,queue is empty\n");
			return;
		}

		do_signal(rc, regs, thread, pending, num);
	}
}

unsigned long
do_kill(struct thread *thread, int pid, int tid, int sig, siginfo_t *info,
        int ptracecont)
{
	dkprintf("do_kill,pid=%d,tid=%d,sig=%d\n", pid, tid, sig);
	struct thread *t;
	struct process *tproc;
	struct process *proc = thread? thread->proc: NULL;
	struct thread *tthread = NULL;
	int i;
	__sigset_t mask;
	ihk_spinlock_t *savelock = NULL;
	struct list_head *head = NULL;
	int rc;
	unsigned long irqstate = 0;
	struct k_sigaction *k;
	int doint;
	int found = 0;
	siginfo_t info0;
	struct resource_set *rset = cpu_local_var(resource_set);
	int hash;
	struct thread_hash *thash = rset->thread_hash;
	struct process_hash *phash = rset->process_hash;
	struct mcs_rwlock_node lock;
	struct mcs_rwlock_node updatelock;

	if(sig > 64 || sig < 0)
		return -EINVAL;

	if(info == NULL){
		memset(&info0, '\0', sizeof info0);
		info = &info0;
		info0.si_signo = sig;
		info0.si_code = SI_KERNEL;
	}

	if(tid == -1 && pid <= 0){
		struct process *p;
		struct mcs_rwlock_node_irqsave slock;
		int	pgid = -pid;
		int	rc = -ESRCH;
		int	*pids;
		int	n = 0;
		int	sendme = 0;

		if(pid == 0){
			if(thread == NULL || thread->proc->pid <= 0)
				return -ESRCH;
			pgid = thread->proc->pgid;
		}
		pids = kmalloc(sizeof(int) * num_processors, IHK_MC_AP_NOWAIT);
		if(!pids)
			return -ENOMEM;
		for(i = 0; i < HASH_SIZE; i++){
			mcs_rwlock_reader_lock(&phash->lock[i], &slock);
			list_for_each_entry(p, &phash->list[i], hash_list){
				if(pgid != 1 && p->pgid != pgid)
					continue;

				if(thread && p->pid == thread->proc->pid){
					sendme = 1;
					continue;
				}

				pids[n] = p->pid;
				n++;
			}
			mcs_rwlock_reader_unlock(&phash->lock[i], &slock);
		}
		for(i = 0; i < n; i++)
			rc = do_kill(thread, pids[i], -1, sig, info, ptracecont);
		if(sendme)
			rc = do_kill(thread, thread->proc->pid, -1, sig, info, ptracecont);

		kfree(pids);
		return rc;
	}

	irqstate = cpu_disable_interrupt_save();
	mask = __sigmask(sig);
	if(tid == -1){
		struct thread *tthread0 = NULL;
		struct mcs_rwlock_node plock;
		struct mcs_rwlock_node updatelock;

		found = 0;
		hash = process_hash(pid);
		mcs_rwlock_reader_lock_noirq(&phash->lock[hash], &plock);
		list_for_each_entry(tproc, &phash->list[hash], hash_list){
			if(tproc->pid == pid){
				found = 1;
				break;
			}
		}
		if(!found){
			mcs_rwlock_reader_unlock_noirq(&phash->lock[hash], &plock);
			cpu_restore_interrupt(irqstate);
			return -ESRCH;
		}

		mcs_rwlock_reader_lock_noirq(&tproc->update_lock, &updatelock);
		if(tproc->status == PS_EXITED || tproc->status == PS_ZOMBIE){
			goto done;
		}
		mcs_rwlock_reader_lock_noirq(&tproc->threads_lock, &lock);
		list_for_each_entry(t, &tproc->threads_list, siblings_list){
			if(t->tid == pid || tthread == NULL){
				if(t->status == PS_EXITED){
					continue;
				}
				if(!(mask & t->sigmask.__val[0])){
					tthread = t;
					found = 1;
				}
				else if(tthread == NULL && tthread0 == NULL){
					tthread0 = t;
					found = 1;
				}
			}
		}
		if(tthread == NULL){
			tthread = tthread0;
		}
		if(tthread && tthread->status != PS_EXITED){
			savelock = &tthread->sigcommon->lock;
			head = &tthread->sigcommon->sigpending;
			hold_thread(tthread);
		}
		else
			tthread = NULL;
		mcs_rwlock_reader_unlock_noirq(&tproc->threads_lock, &lock);
done:
		mcs_rwlock_reader_unlock_noirq(&tproc->update_lock, &updatelock);
		mcs_rwlock_reader_unlock_noirq(&phash->lock[hash], &plock);
	}
	else{
		found = 0;
		hash = thread_hash(tid);
		mcs_rwlock_reader_lock_noirq(&thash->lock[hash], &lock);
		list_for_each_entry(tthread, &thash->list[hash], hash_list){
			if(pid != -1 && tthread->proc->pid != pid){
				continue;
			}
			if(tthread->tid == tid){
				found = 1;
				break;
			}
		}

		if(!found){
			mcs_rwlock_reader_unlock_noirq(&thash->lock[hash], &lock);
			cpu_restore_interrupt(irqstate);
			return -ESRCH;
		}

		tproc = tthread->proc;
		mcs_rwlock_reader_lock_noirq(&tproc->update_lock, &updatelock);
		savelock = &tthread->sigpendinglock;
		head = &tthread->sigpending;
		if(sig == SIGKILL ||
		   (tproc->status != PS_EXITED &&
		    tproc->status != PS_ZOMBIE &&
		    tthread->status != PS_EXITED)){
			hold_thread(tthread);
		}
		else{
			tthread = NULL;
		}
		mcs_rwlock_reader_unlock_noirq(&tproc->update_lock, &updatelock);
		mcs_rwlock_reader_unlock_noirq(&thash->lock[hash], &lock);
	}


	if(sig != SIGCONT &&
	   proc &&
	   proc->euid != 0 &&
	   proc->ruid != tproc->ruid &&
	   proc->euid != tproc->ruid &&
	   proc->ruid != tproc->suid &&
	   proc->euid != tproc->suid){
		if(tthread)
			release_thread(tthread);
		cpu_restore_interrupt(irqstate);
		return -EPERM;
	}

	if(sig == 0 || tthread == NULL || tthread->status == PS_EXITED){
		if(tthread)
			release_thread(tthread);
		cpu_restore_interrupt(irqstate);
		return 0;
	}

	doint = 0;

	ihk_mc_spinlock_lock_noirq(savelock);

	/* Put signal event even when handler is SIG_IGN or SIG_DFL
	   because target ptraced thread must call ptrace_report_signal 
	   in check_signal */
	rc = 0;
	k = tthread->sigcommon->action + sig - 1;
	if((sig != SIGKILL && (tproc->ptrace & PT_TRACED)) ||
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
				tthread->sigevent = 1;
			}
		}
	}
	ihk_mc_spinlock_unlock_noirq(savelock);
	cpu_restore_interrupt(irqstate);

	if (doint && !(mask & tthread->sigmask.__val[0])) {
		int cpuid = tthread->cpu_id;
		int pid = tproc->pid;
		int status = tthread->status;

		if (thread != tthread) {
			dkprintf("do_kill,ipi,pid=%d,cpu_id=%d\n",
				 tproc->pid, tthread->cpu_id);
			ihk_mc_interrupt_cpu(get_x86_cpu_local_variable(tthread->cpu_id)->apic_id, 0xd0);
		}

		if(!tthread->proc->nohost)
			interrupt_syscall(pid, cpuid);

		if (status != PS_RUNNING) {
			if(sig == SIGKILL){
				/* Wake up the target only when stopped by ptrace-reporting */
				sched_wakeup_thread(tthread, PS_TRACED | PS_STOPPED);
			}
			else if(sig == SIGCONT || ptracecont){
				/* Wake up the target only when stopped by SIGSTOP */
				sched_wakeup_thread(tthread, PS_STOPPED);
			}
		}
	}
	release_thread(tthread);
	return rc;
}

void
set_signal(int sig, void *regs0, siginfo_t *info)
{
	struct x86_user_context *regs = regs0;
	struct thread *thread = cpu_local_var(current);

	if(thread == NULL || thread->proc->pid == 0)
		return;

	if((__sigmask(sig) & thread->sigmask.__val[0]) ||
	   (regs->gpr.rsp & 0x8000000000000000)){
		coredump(thread, regs0);
		terminate(0, sig | 0x80);
	}
		do_kill(thread, thread->proc->pid, thread->tid, sig, info, 0);
}
