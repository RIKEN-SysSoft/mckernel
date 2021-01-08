/* syscall.c COPYRIGHT FUJITSU LIMITED 2018 */
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
#include <cls.h>
#include <cpulocal.h>
#include <syscall.h>
#include <process.h>
#include <string.h>
#include <errno.h>
#include <kmalloc.h>
#include <uio.h>
#include <mman.h>
#include <shm.h>
#include <prctl.h>
#include <ihk/ikc.h>
#include <page.h>
#include <limits.h>
#include <syscall.h>
#include <bitops.h>
#include <rusage_private.h>
#include <memory.h>
#include <ihk/debug.h>

void terminate_mcexec(int, int);
extern long do_sigaction(int sig, struct k_sigaction *act, struct k_sigaction *oact);
long syscall(int num, ihk_mc_user_context_t *ctx);
extern unsigned long do_fork(int, unsigned long, unsigned long, unsigned long,
	unsigned long, unsigned long, unsigned long);
extern int get_xsave_size();
extern uint64_t get_xsave_mask();

//#define DEBUG_PRINT_SC

#ifdef DEBUG_PRINT_SC
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

uintptr_t debug_constants[] = {
	sizeof(struct cpu_local_var),
	offsetof(struct cpu_local_var, current),
	offsetof(struct cpu_local_var, runq),
	offsetof(struct cpu_local_var, status),
	offsetof(struct cpu_local_var, idle),
	offsetof(struct thread, ctx),
	offsetof(struct thread, sched_list),
	offsetof(struct thread, proc),
	offsetof(struct thread, status),
	offsetof(struct process, pid),
	offsetof(struct thread, tid),
	-1,
};

#define VDSO_MAXPAGES 2
struct vdso {
	long busy;
	int vdso_npages;
	char vvar_is_global;
	char hpet_is_global;
	char pvti_is_global;
	char padding;
	long vdso_physlist[VDSO_MAXPAGES];
	void *vvar_virt;
	long vvar_phys;
	void *hpet_virt;
	long hpet_phys;
	void *pvti_virt;
	long pvti_phys;
	void *vgtod_virt;
};

struct vsyscall_gtod_data {
	int seq;

	struct {
		int vclock_mode;
		unsigned long cycle_last;
		unsigned long mask;
		unsigned int mult;
		unsigned int shift;
	} clock;

	/* open coded 'struct timespec' */
	time_t wall_time_sec;
	unsigned long wall_time_snsec;
};

static struct vdso vdso;
static size_t container_size = 0;
static ptrdiff_t vdso_offset;

extern int num_processors;

int obtain_clone_cpuid(cpu_set_t *cpu_set, int use_last) {
	int min_queue_len = -1;
	int cpu, min_cpu = -1, uti_cpu = -1;
	unsigned long irqstate;
	
	irqstate = ihk_mc_spinlock_lock(&runq_reservation_lock);
	/* Find the first allowed core with the shortest run queue */
	for (cpu = 0; cpu < num_processors; ++cpu) {
		struct cpu_local_var *v;

		if (!CPU_ISSET(cpu, cpu_set)) continue;

		v = get_cpu_local_var(cpu);
		ihk_mc_spinlock_lock_noirq(&v->runq_lock);
		dkprintf("%s: cpu=%d,runq_len=%d,runq_reserved=%d\n", __FUNCTION__, cpu, v->runq_len, v->runq_reserved);
		if (min_queue_len == -1 || v->runq_len + v->runq_reserved < min_queue_len) {
			min_queue_len = v->runq_len + v->runq_reserved;
			min_cpu = cpu;
		}

		/* Record the last tie CPU */
		if (min_cpu != cpu && v->runq_len + v->runq_reserved == min_queue_len) {
			uti_cpu = cpu;
		}
		dkprintf("%s: cpu=%d,runq_len=%d,runq_reserved=%d,min_cpu=%d,uti_cpu=%d\n", __FUNCTION__, cpu, v->runq_len, v->runq_reserved, min_cpu, uti_cpu);
		ihk_mc_spinlock_unlock_noirq(&v->runq_lock);
#if 0
		if (min_queue_len == 0)
			break;
#endif
	}

	min_cpu = use_last ? uti_cpu : min_cpu;
	if (min_cpu != -1) {
		if (get_cpu_local_var(min_cpu)->status != CPU_STATUS_RESERVED)
			get_cpu_local_var(min_cpu)->status = CPU_STATUS_RESERVED;
		__sync_fetch_and_add(&get_cpu_local_var(min_cpu)->runq_reserved, 1);
	}
	ihk_mc_spinlock_unlock(&runq_reservation_lock, irqstate);

    return min_cpu;
}

SYSCALL_DECLARE(prctl)
{
	struct process *proc = cpu_local_var(current)->proc;
	int option = (int)ihk_mc_syscall_arg0(ctx);
	unsigned long arg2 = (unsigned long)ihk_mc_syscall_arg1(ctx);
	unsigned long arg3 = (unsigned long)ihk_mc_syscall_arg2(ctx);
	unsigned long arg4 = (unsigned long)ihk_mc_syscall_arg3(ctx);
	unsigned long arg5 = (unsigned long)ihk_mc_syscall_arg4(ctx);
	int ret = 0;

	switch (option) {
	case PR_SET_THP_DISABLE:
		if (arg3 || arg4 || arg5) {
			return -EINVAL;
		}
		proc->thp_disable = arg2;
		ret = 0;
		break;
	case PR_GET_THP_DISABLE:
		if (arg2 || arg3 || arg4 || arg5) {
			return -EINVAL;
		}
		ret = proc->thp_disable;
		break;
	default:
		ret = syscall_generic_forwarding(__NR_prctl, ctx);
		break;
	}

	return ret;
}

struct sigsp {
	unsigned long flags;
	void *link;
	stack_t sigstack;
	unsigned long regs[23];
#define _r8 regs[0] 
#define _r9 regs[1] 
#define _r10 regs[2] 
#define _r11 regs[3] 
#define _r12 regs[4] 
#define _r13 regs[5] 
#define _r14 regs[6] 
#define _r15 regs[7] 
#define _rdi regs[8] 
#define _rsi regs[9] 
#define _rbp regs[10] 
#define _rbx regs[11] 
#define _rdx regs[12] 
#define _rax regs[13] 
#define _rcx regs[14] 
#define _rsp regs[15] 
#define _rip regs[16] 
#define _rflags regs[17] 
#define _csgsfs regs[18] 
#define _error regs[19] 
#define _trapno regs[20] 
#define _oldmask regs[21] 
#define _cr2 regs[22] 
	void *fpregs;
	unsigned long reserve[8];

	unsigned long sigrc;
	unsigned long sigmask;
	int num;
	int restart;
	unsigned long ss;
	siginfo_t info;
};

SYSCALL_DECLARE(rt_sigreturn)
{
	struct thread *thread = cpu_local_var(current);
	struct x86_user_context *regs;
	struct sigsp ksigsp;
	struct sigsp *sigsp;
	int xsavesize = get_xsave_size();

	asm ("movq %%gs:(%1),%0"
			: "=r"(regs)
			: "r"(offsetof(struct x86_cpu_local_variables, tss.rsp0)));
	--regs;

	sigsp = (struct sigsp *)regs->gpr.rsp;
	if(copy_from_user(&ksigsp, sigsp, sizeof ksigsp))
		return -EFAULT;

	regs->gpr.r15 = ksigsp._r15;
	regs->gpr.r14 = ksigsp._r14;
	regs->gpr.r13 = ksigsp._r13;
	regs->gpr.r12 = ksigsp._r12;
	regs->gpr.rbp = ksigsp._rbp;
	regs->gpr.rbx = ksigsp._rbx;
	regs->gpr.r11 = ksigsp._r11;
	regs->gpr.r10 = ksigsp._r10;
	regs->gpr.r9 = ksigsp._r9;
	regs->gpr.r8 = ksigsp._r8;
	regs->gpr.rax = ksigsp._rax;
	regs->gpr.rcx = ksigsp._rcx;
	regs->gpr.rdx = ksigsp._rdx;
	regs->gpr.rsi = ksigsp._rsi;
	regs->gpr.rdi = ksigsp._rdi;
	regs->gpr.error = ksigsp._error;
	regs->gpr.rip = ksigsp._rip;
	regs->gpr.rflags = ksigsp._rflags;
	regs->gpr.rsp = ksigsp._rsp;
	thread->sigmask.__val[0] = ksigsp._oldmask;

	memcpy(&thread->sigstack, &ksigsp.sigstack, sizeof(stack_t));
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
		check_need_resched();
		check_signal(0, regs, -1);
	}

	if(ksigsp.fpregs && xsavesize){
		void *fpregs = kmalloc(xsavesize + 64, IHK_MC_AP_NOWAIT);

		if(fpregs){
			uint64_t xsave_mask = get_xsave_mask();
			unsigned int low = (unsigned int)xsave_mask;
			unsigned int high = (unsigned int)(xsave_mask >> 32);
			struct xsave_struct *kfpregs;

			kfpregs = (void *)((((unsigned long)fpregs) + 63) & ~63);

			if(copy_from_user(kfpregs, ksigsp.fpregs, xsavesize))
				return -EFAULT;
			asm volatile("xrstor %0" : : "m"(*kfpregs), "a"(low), "d"(high) : "memory");
			kfree(fpregs);
		}
	}

	return sigsp->sigrc;
}

extern struct cpu_local_var *clv;
extern void interrupt_syscall(struct thread *, int sig);
extern void terminate(int, int);
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
	if (thread->fp_regs == NULL) {
		return -ENOMEM;
	}
	return copy_to_user(fpregs, &thread->fp_regs->i387,
			sizeof(struct i387_fxsave_struct));
}

long ptrace_write_fpregs(struct thread *thread, void *fpregs)
{
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

extern int coredump(struct thread *thread, void *regs, int sig);

void ptrace_report_signal(struct thread *thread, int sig)
{
	struct mcs_rwlock_node_irqsave lock;
	struct process *proc = thread->proc;
	int parent_pid;
	struct siginfo info;

	dkprintf("ptrace_report_signal, tid=%d, pid=%d\n", thread->tid, thread->proc->pid);

	mcs_rwlock_writer_lock(&proc->update_lock, &lock);	
	if (!(thread->ptrace & PT_TRACED)) {
		mcs_rwlock_writer_unlock(&proc->update_lock, &lock);
		return;
	}

	/* Transition thread state */
	thread->exit_status = sig;
	thread->status = PS_TRACED;
	thread->ptrace &= ~PT_TRACE_SYSCALL;
	save_debugreg(thread->ptrace_debugreg);
	if (sig == SIGSTOP || sig == SIGTSTP ||
	    sig == SIGTTIN || sig == SIGTTOU) {
		thread->signal_flags |= SIGNAL_STOP_STOPPED;
	}
	else {
		thread->signal_flags &= ~SIGNAL_STOP_STOPPED;
	}

	if (thread == proc->main_thread) {
		proc->status = PS_DELAY_TRACED;
		parent_pid = proc->parent->pid;
	}
	else {
		parent_pid = thread->report_proc->pid;
		waitq_wakeup(&thread->report_proc->waitpid_q);
	}
	mcs_rwlock_writer_unlock(&proc->update_lock, &lock);

	memset(&info, '\0', sizeof info);
	info.si_signo = SIGCHLD;
	info.si_code = CLD_TRAPPED;
	info._sifields._sigchld.si_pid = thread->tid;
	info._sifields._sigchld.si_status = thread->exit_status;
	do_kill(cpu_local_var(current), parent_pid, -1, SIGCHLD, &info, 0);

	dkprintf("ptrace_report_signal,sleeping\n");
	/* Sleep */
	schedule();
	dkprintf("ptrace_report_signal,wake up\n");
}

static long
ptrace_arch_prctl(int pid, long code, long addr)
{
	long rc = -EIO;
	struct thread *child;

	child = find_thread(pid, pid);
	if (!child)
		return -ESRCH;
	if (child->proc->status & (PS_TRACED | PS_STOPPED)) {
		switch (code) {
		case ARCH_GET_FS: {
			unsigned long value;
			unsigned long *p = (unsigned long *)addr;
			rc = ptrace_read_user(child,
					offsetof(struct user_regs_struct, fs_base),
					&value);
			if (rc == 0) {
				rc = copy_to_user(p, (char *)&value, sizeof(value));
			}
			break;
		}
		case ARCH_GET_GS: {
			unsigned long value;
			unsigned long *p = (unsigned long *)addr;
			rc = ptrace_read_user(child,
					offsetof(struct user_regs_struct, gs_base),
					&value);
			if (rc == 0) {
				rc = copy_to_user(p, (char *)&value, sizeof(value));
			}
			break;
		}
		case ARCH_SET_FS:
			rc = ptrace_write_user(child,
					offsetof(struct user_regs_struct, fs_base),
					(unsigned long)addr);
			break;
		case ARCH_SET_GS:
			rc = ptrace_write_user(child,
					offsetof(struct user_regs_struct, gs_base),
					(unsigned long)addr);
			break;
		default:
			rc = -EINVAL;
			break;
		}
	}
	thread_unlock(child);

	return rc;
}

long
arch_ptrace(long request, int pid, long addr, long data)
{
	switch(request) {
	    case PTRACE_ARCH_PRCTL:
		return ptrace_arch_prctl(pid, data, addr);
		break;

	    default:
		break;
	}
	return -EOPNOTSUPP;
}

static int
isrestart(int num, unsigned long rc, int sig, int restart)
{
	if (sig == SIGKILL || sig == SIGSTOP)
		return 0;
	if (num < 0 || rc != -EINTR)
		return 0;
	if (sig == SIGCHLD)
		return 1;
	switch (num) {
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
	if (restart)
		return 1;
	return 0;
}

int
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
	struct mcs_rwlock_node_irqsave mcs_rw_node;
	int restart = 0;
	int ret;

	for(w = pending->sigmask.__val[0], sig = 0; w; sig++, w >>= 1);
	dkprintf("do_signal(): tid=%d, pid=%d, sig=%d\n", thread->tid, proc->pid, sig);
	orgsig = sig;

	if ((thread->ptrace & PT_TRACED) &&
	    pending->ptracecont == 0 &&
	    sig != SIGKILL) {
		ptraceflag = 1;
		sig = SIGSTOP;
	}

	if(regs == NULL){ /* call from syscall */
		asm ("movq %%gs:(%1),%0"
				: "=r"(regs)
				: "r"(offsetof(struct x86_cpu_local_variables, tss.rsp0)));
		--regs;
	}
	else{
		rc = regs->gpr.rax;
	}

	mcs_rwlock_writer_lock(&thread->sigcommon->lock, &mcs_rw_node);
	k = thread->sigcommon->action + sig - 1;

	if(k->sa.sa_handler == SIG_IGN){
		kfree(pending);
		mcs_rwlock_writer_unlock(&thread->sigcommon->lock, &mcs_rw_node);
		goto out;
	}
	else if(k->sa.sa_handler){
		unsigned long *usp; /* user stack */
		struct sigsp ksigsp;
		struct sigsp *sigsp;
		int xsavesize = get_xsave_size();
		unsigned long fpregs;

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
		fpregs = (unsigned long)usp - xsavesize;
		sigsp = ((struct sigsp *)fpregs) - 1;
		sigsp = (struct sigsp *)((unsigned long)sigsp & 0xfffffffffffffff0UL);
		memset(&ksigsp, '\0', sizeof ksigsp);

		ksigsp._r15 = regs->gpr.r15;
		ksigsp._r14 = regs->gpr.r14;
		ksigsp._r13 = regs->gpr.r13;
		ksigsp._r12 = regs->gpr.r12;
		ksigsp._rbp = regs->gpr.rbp;
		ksigsp._rbx = regs->gpr.rbx;
		ksigsp._r11 = regs->gpr.r11;
		ksigsp._r10 = regs->gpr.r10;
		ksigsp._r9 = regs->gpr.r9;
		ksigsp._r8 = regs->gpr.r8;
		ksigsp._rax = regs->gpr.rax;
		ksigsp._rcx = regs->gpr.rcx;
		ksigsp._rdx = regs->gpr.rdx;
		ksigsp._rsi = regs->gpr.rsi;
		ksigsp._rdi = regs->gpr.rdi;
		ksigsp._error = regs->gpr.error;
		ksigsp._rip = regs->gpr.rip;
		ksigsp._rflags = regs->gpr.rflags;
		ksigsp._rsp = regs->gpr.rsp;
		ksigsp._cr2 = (unsigned long)pending->info._sifields._sigfault.si_addr;
		ksigsp._oldmask = thread->sigmask.__val[0];

		memcpy(&ksigsp.sigstack, &thread->sigstack, sizeof(stack_t));
		ksigsp.sigrc = rc;
		ksigsp.num = num;
		restart = isrestart(num, rc, sig, k->sa.sa_flags & SA_RESTART);
		ksigsp.restart = restart;
		if(xsavesize){
			uint64_t xsave_mask = get_xsave_mask();
			unsigned int low = (unsigned int)xsave_mask;
			unsigned int high = (unsigned int)(xsave_mask >> 32);
			void *_kfpregs = kmalloc(xsavesize + 64, IHK_MC_AP_NOWAIT);
			struct xsave_struct *kfpregs;

			if(!_kfpregs){
				kfree(pending);
				kfree(_kfpregs);
				kprintf("do_signal,no space available\n");
				terminate(0, sig);
				goto out;
			}
			kfpregs = (void *)((((unsigned long)_kfpregs) + 63) & ~63);
			memset(kfpregs, '\0', xsavesize);
			asm volatile("xsave %0" : : "m"(*kfpregs), "a"(low), "d"(high) : "memory");
			if(copy_to_user((void *)fpregs, kfpregs, xsavesize)){
				kfree(pending);
				kfree(_kfpregs);
				kprintf("do_signal,write_process_vm failed\n");
				terminate(0, sig);
				goto out;
			}
			ksigsp.fpregs = (void *)fpregs;
			kfree(_kfpregs);
		}
		memcpy(&ksigsp.info, &pending->info, sizeof(siginfo_t));

		if(copy_to_user(sigsp, &ksigsp, sizeof ksigsp)){
			kfree(pending);
			mcs_rwlock_writer_unlock(&thread->sigcommon->lock, &mcs_rw_node);
			kprintf("do_signal,write_process_vm failed\n");
			terminate(0, sig);
			goto out;
		}

		usp = (unsigned long *)sigsp;
		usp--;
		*usp = (unsigned long)k->sa.sa_restorer;

		regs->gpr.rdi = (unsigned long)sig;
		regs->gpr.rsi = (unsigned long)&sigsp->info;
		regs->gpr.rdx = (unsigned long)sigsp;
		regs->gpr.rip = (unsigned long)k->sa.sa_handler;
		regs->gpr.rsp = (unsigned long)usp;

		// check signal handler is ONESHOT
		if (k->sa.sa_flags & SA_RESETHAND) {
			k->sa.sa_handler = SIG_DFL; 
		}

		if(!(k->sa.sa_flags & SA_NODEFER))
			thread->sigmask.__val[0] |= pending->sigmask.__val[0];
		kfree(pending);
		mcs_rwlock_writer_unlock(&thread->sigcommon->lock, &mcs_rw_node);
		if(regs->gpr.rflags & RFLAGS_TF){
			struct siginfo info;

			memset(&info, '\0', sizeof info);
			regs->gpr.rflags &= ~RFLAGS_TF;
			info.si_code = TRAP_TRACE;
			set_signal(SIGTRAP, regs, &info);
			check_need_resched();
			check_signal(0, regs, -1);
		}
	}
	else {
		int	coredumped = 0;
		siginfo_t info;
		int ptc = pending->ptracecont;

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
		mcs_rwlock_writer_unlock(&thread->sigcommon->lock, &mcs_rw_node);
		switch (sig) {
		case SIGSTOP:
		case SIGTSTP:
		case SIGTTIN:
		case SIGTTOU:
			if(ptraceflag){
				ptrace_report_signal(thread, orgsig);
			}
			else{
				memset(&info, '\0', sizeof info);
				info.si_signo = SIGCHLD;
				info.si_code = CLD_STOPPED;
				info._sifields._sigchld.si_pid = thread->proc->pid;
				info._sifields._sigchld.si_status = (sig << 8) | 0x7f;
				if (ptc == 2 &&
				    thread != thread->proc->main_thread) {
					thread->signal_flags =
							    SIGNAL_STOP_STOPPED;
					thread->status = PS_STOPPED;
					thread->exit_status = SIGSTOP;
					do_kill(thread,
						thread->report_proc->pid, -1,
						SIGCHLD, &info, 0);
					waitq_wakeup(
					       &thread->report_proc->waitpid_q);
				}
				else {
					/* Update thread state in fork tree */
					mcs_rwlock_writer_lock(
						     &proc->update_lock, &lock);
					proc->group_exit_status = SIGSTOP;

					/* Reap and set new signal_flags */
					proc->main_thread->signal_flags =
							    SIGNAL_STOP_STOPPED;

					proc->status = PS_DELAY_STOPPED;
					thread->status = PS_STOPPED;
					mcs_rwlock_writer_unlock(
						     &proc->update_lock, &lock);

					do_kill(thread,
						thread->proc->parent->pid, -1,
						SIGCHLD, &info, 0);
				}
				/* Sleep */
				schedule();
				dkprintf("SIGSTOP(): woken up\n");
			}
			break;
		case SIGTRAP:
			dkprintf("do_signal,SIGTRAP\n");
			if (!(thread->ptrace & PT_TRACED)) {
				goto core;
			}

			/* Update thread state in fork tree */
			thread->exit_status = SIGTRAP;
			thread->status = PS_TRACED;
			if (thread == proc->main_thread) {
				mcs_rwlock_writer_lock(&proc->update_lock,
						       &lock);
				proc->group_exit_status = SIGTRAP;
				proc->status = PS_DELAY_TRACED;
				mcs_rwlock_writer_unlock(&proc->update_lock,
							 &lock);
				do_kill(thread, thread->proc->parent->pid, -1,
					SIGCHLD, &info, 0);
			}
			else {
				do_kill(thread, thread->report_proc->pid, -1,
					SIGCHLD, &info, 0);
				waitq_wakeup(&thread->report_proc->waitpid_q);
			}

			/* Sleep */
			dkprintf("do_signal,SIGTRAP,sleeping\n");

			schedule();
			dkprintf("SIGTRAP(): woken up\n");
			break;
		case SIGCONT:
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
			thread->coredump_regs =
				kmalloc(sizeof(struct x86_user_context),
					IHK_MC_AP_NOWAIT);
			if (!thread->coredump_regs) {
				kprintf("%s: Out of memory\n", __func__);
				goto skip;
			}
			memcpy(thread->coredump_regs, regs,
			       sizeof(struct x86_user_context));

			ret = coredump(thread, regs, sig);
			switch (ret) {
			case -EBUSY:
				kprintf("%s: INFO: coredump not performed, try ulimit -c <non-zero>\n",
					__func__);
				break;
			case 0:
				coredumped = 0x80;
				break;
			default:
				kprintf("%s: ERROR: coredump failed (%d)\n",
					__func__, ret);
				break;
			}
skip:
			terminate(0, sig | coredumped);
			break;
		case SIGCHLD:
		case SIGURG:
		case SIGWINCH:
			break;
		default:
			dkprintf("do_signal,default,terminate,sig=%d\n", sig);
			terminate(0, sig);
			break;
		}
	}
out:
	return restart;
}

int
interrupt_from_user(void *regs0)
{
	struct x86_user_context *regs = regs0;

	return !(regs->gpr.rsp & 0x8000000000000000);
}

void save_syscall_return_value(int num, unsigned long rc)
{
	/* Empty on x86 */
	return;
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
	mcs_rwlock_lock_t *savelock = NULL;
	struct mcs_rwlock_node mcs_rw_node;
	struct list_head *head = NULL;
	int rc;
	unsigned long irqstate = 0;
	int doint;
	int found = 0;
	siginfo_t info0;
	struct resource_set *rset = cpu_local_var(resource_set);
	int hash;
	struct thread_hash *thash = rset->thread_hash;
	struct process_hash *phash = rset->process_hash;
	struct mcs_rwlock_node lock;
	struct mcs_rwlock_node updatelock;
	struct sig_pending *pending = NULL;

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
		int	*pids = NULL;
		int	n = 0, nr_pids = 0;
		int	sendme = 0;

		if(pid == 0){
			if(thread == NULL || thread->proc->pid <= 0)
				return -ESRCH;
			pgid = thread->proc->pgid;
		}

		// Count nr of pids
		for(i = 0; i < HASH_SIZE; i++){
			mcs_rwlock_reader_lock(&phash->lock[i], &slock);
			list_for_each_entry(p, &phash->list[i], hash_list){
				if(pgid != 1 && p->pgid != pgid)
					continue;

				if(thread && p->pid == thread->proc->pid){
					sendme = 1;
					continue;
				}

				++nr_pids;
			}
			mcs_rwlock_reader_unlock(&phash->lock[i], &slock);
		}

		if (nr_pids) {
			pids = kmalloc(sizeof(int) * nr_pids, IHK_MC_AP_NOWAIT);
			if(!pids)
				return -ENOMEM;
		}
		else {
			if (sendme) {
				goto sendme;
			}
			return rc;
		}

		// Collect pids and do the kill
		for(i = 0; i < HASH_SIZE; i++){
			if (n == nr_pids) {
				break;
			}
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
				if (n == nr_pids) {
					break;
				}
			}
			mcs_rwlock_reader_unlock(&phash->lock[i], &slock);
		}
		for(i = 0; i < n; i++)
			rc = do_kill(thread, pids[i], -1, sig, info, ptracecont);
sendme:
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
			if (tthread->tid == tid &&
			    tthread->status != PS_EXITED) {
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
		mcs_rwlock_reader_lock_noirq(&tproc->threads_lock, &lock);
		if (tthread->status != PS_EXITED &&
			(sig == SIGKILL ||
			 (tproc->status != PS_EXITED && tproc->status != PS_ZOMBIE))) {
			if ((rc = hold_thread(tthread))) {
				kprintf("%s: ERROR hold_thread returned %d,tid=%d\n", __FUNCTION__, rc, tthread->tid);
				tthread = NULL;
			}
		}
		else{
			tthread = NULL;
		}
		mcs_rwlock_reader_unlock_noirq(&tproc->threads_lock, &lock);
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

	/* Forward signal to Linux by interrupt_syscall mechanism */
	if (tthread->uti_state == UTI_STATE_RUNNING_IN_LINUX) {
		if (!tthread->proc->nohost) {
			interrupt_syscall(tthread, sig);
		}
		release_thread(tthread);
		return 0;
	}

	doint = 0;

	mcs_rwlock_writer_lock_noirq(savelock, &mcs_rw_node);

	rc = 0;

	if (sig < 33) { // SIGRTMIN - SIGRTMAX
		list_for_each_entry(pending, head, list) {
			if (pending->sigmask.__val[0] == mask &&
			    pending->ptracecont == ptracecont)
				break;
		}
		if (&pending->list == head)
			pending = NULL;
	}
	if (pending == NULL) {
		doint = 1;
		pending = kmalloc(sizeof(struct sig_pending), IHK_MC_AP_NOWAIT);
		if (!pending) {
			rc = -ENOMEM;
		}
		else {
			memset(pending, 0, sizeof(struct sig_pending));
			pending->sigmask.__val[0] = mask;
			memcpy(&pending->info, info, sizeof(siginfo_t));
			pending->ptracecont = ptracecont;
			if (sig == SIGKILL || sig == SIGSTOP)
				list_add(&pending->list, head);
			else
				list_add_tail(&pending->list, head);
			tthread->sigevent = 1;
		}
	}

	mcs_rwlock_writer_unlock_noirq(savelock, &mcs_rw_node);
	cpu_restore_interrupt(irqstate);

	if (sig == SIGCONT || ptracecont == 1) {
		/* Wake up the target only when stopped by SIGSTOP */
		if (sched_wakeup_thread(tthread, PS_STOPPED) == 0) {
			struct siginfo info;

			tthread->proc->main_thread->signal_flags =
							SIGNAL_STOP_CONTINUED;
			tthread->proc->status = PS_RUNNING;
			memset(&info, '\0', sizeof(info));
			info.si_signo = SIGCHLD;
			info.si_code = CLD_CONTINUED;
			info._sifields._sigchld.si_pid = tthread->proc->pid;
			info._sifields._sigchld.si_status = 0x0000ffff;
			do_kill(tthread, tthread->proc->parent->pid, -1,
							SIGCHLD, &info, 0);
			tthread->proc->status = PS_RUNNING;
			if (thread != tthread) {
				ihk_mc_interrupt_cpu(tthread->cpu_id,
						ihk_mc_get_vector(IHK_GV_IKC));
			}
			doint = 0;
		}
	}
	if (doint && !(mask & tthread->sigmask.__val[0])) {
		int status = tthread->status;

		if (thread != tthread) {
			dkprintf("do_kill,ipi,pid=%d,cpu_id=%d\n",
				 tproc->pid, tthread->cpu_id);
			ihk_mc_interrupt_cpu(tthread->cpu_id,
					ihk_mc_get_vector(IHK_GV_IKC));
		}

		if (status != PS_RUNNING) {
			if(sig == SIGKILL){
				/* Wake up the target only when stopped by ptrace-reporting */
				sched_wakeup_thread(tthread, PS_TRACED | PS_STOPPED | PS_INTERRUPTIBLE);
			}
			else {
				sched_wakeup_thread(tthread, PS_INTERRUPTIBLE);
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

	if (thread == NULL || thread->proc->pid == 0)
		return;

        if (!interrupt_from_user(regs)) {
		ihk_mc_debug_show_interrupt_context(regs);
                panic("panic: kernel mode signal");
        }

	if ((__sigmask(sig) & thread->sigmask.__val[0])) {
		coredump(thread, regs0, sig);
		terminate(0, sig | 0x80);
	}
	do_kill(thread, thread->proc->pid, thread->tid, sig, info, 0);
}

SYSCALL_DECLARE(mmap)
{
	const unsigned int supported_flags = 0
		| MAP_SHARED		// 01
		| MAP_PRIVATE		// 02
		| MAP_FIXED		// 10
		| MAP_ANONYMOUS		// 20
		| MAP_LOCKED		// 2000
		| MAP_POPULATE		// 8000
		| MAP_HUGETLB		// 00040000
		| (0x3FU << MAP_HUGE_SHIFT) // FC000000
		;
	const int ignored_flags = 0
#ifdef	USE_NOCACHE_MMAP
		| MAP_32BIT		// 40
#endif /* USE_NOCACHE_MMAP */
		| MAP_DENYWRITE		// 0800
		| MAP_NORESERVE		// 4000
		| MAP_STACK		// 00020000
		;
	const int error_flags = 0
#ifndef	USE_NOCACHE_MMAP
		| MAP_32BIT		// 40
#endif /* ndef USE_NOCACHE_MMAP */
		| MAP_GROWSDOWN		// 0100
		| MAP_EXECUTABLE	// 1000
		| MAP_NONBLOCK		// 00010000
		;

	const uintptr_t addr0 = ihk_mc_syscall_arg0(ctx);
	size_t len0 = ihk_mc_syscall_arg1(ctx);
	const int prot = ihk_mc_syscall_arg2(ctx);
	const int flags0 = ihk_mc_syscall_arg3(ctx);
	const int fd = ihk_mc_syscall_arg4(ctx);
	const off_t off0 = ihk_mc_syscall_arg5(ctx);
	struct thread *thread = cpu_local_var(current);
	struct vm_regions *region = &thread->vm->region;
	int error;
	uintptr_t addr = 0;
	size_t len;
	int flags = flags0;
	size_t pgsize;

	dkprintf("sys_mmap(%lx,%lx,%x,%x,%d,%lx)\n",
			addr0, len0, prot, flags0, fd, off0);

	/* check constants for flags */
	if (1) {
		int dup_flags;

		dup_flags = (supported_flags & ignored_flags);
		dup_flags |= (ignored_flags & error_flags);
		dup_flags |= (error_flags & supported_flags);

		if (dup_flags) {
			ekprintf("sys_mmap:duplicate flags: %lx\n", dup_flags);
			ekprintf("s-flags: %08x\n", supported_flags);
			ekprintf("i-flags: %08x\n", ignored_flags);
			ekprintf("e-flags: %08x\n", error_flags);
			panic("sys_mmap:duplicate flags\n");
			/* no return */
		}
	}

	/* check arguments */
	pgsize = PAGE_SIZE;
	if (flags & MAP_HUGETLB) {
		/* OpenMPI expects -EINVAL when trying to map
		 * /dev/shm/ file with MAP_SHARED | MAP_HUGETLB
		 */
		if (!(flags & MAP_ANONYMOUS)) {
			error = -EINVAL;
			goto out;
		}

		switch (flags & (0x3F << MAP_HUGE_SHIFT)) {
		case 0:
			/* default hugepage size */
			flags |= ihk_mc_get_linux_default_huge_page_shift() <<
				MAP_HUGE_SHIFT;
			break;

		case MAP_HUGE_2MB:
		case MAP_HUGE_1GB:
			break;

		default:
			ekprintf("sys_mmap(%lx,%lx,%x,%x,%x,%lx):"
					"not supported page size.\n",
					addr0, len0, prot, flags0, fd, off0);
			error = -EINVAL;
			goto out;
		}

		pgsize = (size_t)1 << ((flags >> MAP_HUGE_SHIFT) & 0x3F);
		/* Round-up map length by pagesize */
		len0 = ALIGN(len0, pgsize);

		if (rusage_check_overmap(len0,
				(flags >> MAP_HUGE_SHIFT) & 0x3F)) {
			error = -ENOMEM;
			goto out;
		}
	}

#define	VALID_DUMMY_ADDR	((region->user_start + PTL3_SIZE - 1) & ~(PTL3_SIZE - 1))
	addr = addr0;
	len = (len0 + pgsize - 1) & ~(pgsize - 1);
recheck:
	if ((addr & (pgsize - 1))
			|| (len == 0)
			|| !(flags & (MAP_SHARED | MAP_PRIVATE))
			|| ((flags & MAP_SHARED) && (flags & MAP_PRIVATE))
			|| (off0 & (pgsize - 1))) {
		if (!(flags & MAP_FIXED) && addr != VALID_DUMMY_ADDR) {
			addr = VALID_DUMMY_ADDR;
			goto recheck;
		}
		ekprintf("sys_mmap(%lx,%lx,%x,%x,%x,%lx):EINVAL\n",
				addr0, len0, prot, flags0, fd, off0);
		error = -EINVAL;
		goto out;
	}

	if (addr < region->user_start
			|| region->user_end <= addr
			|| len > (region->user_end - region->user_start)) {
		if (!(flags & MAP_FIXED) && addr != VALID_DUMMY_ADDR) {
			addr = VALID_DUMMY_ADDR;
			goto recheck;
		}
		ekprintf("sys_mmap(%lx,%lx,%x,%x,%x,%lx):ENOMEM\n",
				addr0, len0, prot, flags0, fd, off0);
		error = -ENOMEM;
		goto out;
	}

	/* check not supported requests */
	if ((flags & error_flags)
			|| (flags & ~(supported_flags | ignored_flags))) {
		ekprintf("sys_mmap(%lx,%lx,%x,%x,%x,%lx):unknown flags %x\n",
				addr0, len0, prot, flags0, fd, off0,
				(flags & ~(supported_flags | ignored_flags)));
		error = -EINVAL;
		goto out;
	}

	addr = do_mmap(addr, len, prot, flags, fd, off0, 0, NULL);

	error = 0;
out:
	dkprintf("sys_mmap(%lx,%lx,%x,%x,%d,%lx): %ld %lx\n",
			addr0, len0, prot, flags0, fd, off0, error, addr);
	return (!error)? addr: error;
}

SYSCALL_DECLARE(clone)
{
	struct process *proc = cpu_local_var(current)->proc;
	struct mcs_rwlock_node_irqsave lock_dump;
	unsigned long ret;

	/* mutex coredump */
	mcs_rwlock_reader_lock(&proc->coredump_lock, &lock_dump);

	ret =  do_fork((int)ihk_mc_syscall_arg0(ctx), ihk_mc_syscall_arg1(ctx),
                   ihk_mc_syscall_arg2(ctx), ihk_mc_syscall_arg3(ctx),
                   ihk_mc_syscall_arg4(ctx), ihk_mc_syscall_pc(ctx),
                   ihk_mc_syscall_sp(ctx));

	mcs_rwlock_reader_unlock(&proc->coredump_lock, &lock_dump);
	return ret;
}

SYSCALL_DECLARE(fork)
{
	return do_fork(SIGCHLD, 0, 0, 0, 0, ihk_mc_syscall_pc(ctx), ihk_mc_syscall_sp(ctx));
}

SYSCALL_DECLARE(vfork)
{
	return do_fork(CLONE_VFORK|SIGCHLD, 0, 0, 0, 0, ihk_mc_syscall_pc(ctx), ihk_mc_syscall_sp(ctx));
}

SYSCALL_DECLARE(shmget)
{
	const key_t key = ihk_mc_syscall_arg0(ctx);
	const size_t size = ihk_mc_syscall_arg1(ctx);
	const int shmflg0 = ihk_mc_syscall_arg2(ctx);
	int shmid = -EINVAL;
	int error;
	int shmflg = shmflg0;

	dkprintf("shmget(%#lx,%#lx,%#x)\n", key, size, shmflg0);

	if (shmflg & SHM_HUGETLB) {
		int hugeshift = shmflg & (0x3F << SHM_HUGE_SHIFT);

		if (hugeshift == 0) {
			/* default hugepage size */
			shmflg |= ihk_mc_get_linux_default_huge_page_shift() <<
				MAP_HUGE_SHIFT;
		} else if (hugeshift == SHM_HUGE_2MB ||
			   hugeshift == SHM_HUGE_1GB) {
			/*nop*/
		} else {
			error = -EINVAL;
			goto out;
		}
	}

	shmid = do_shmget(key, size, shmflg);

	error = 0;
out:
	dkprintf("shmget(%#lx,%#lx,%#x): %d %d\n", key, size, shmflg0, error, shmid);
	return (error)?: shmid;
} /* sys_shmget() */

long do_arch_prctl(unsigned long code, unsigned long address)
{
	int err = 0;
	enum ihk_asr_type type;

	switch (code) {
		case ARCH_SET_FS:
		case ARCH_GET_FS:
			type = IHK_ASR_X86_FS;
			break;
		case ARCH_GET_GS:
			type = IHK_ASR_X86_GS;
			break;
		case ARCH_SET_GS:
			return -ENOTSUPP;
		default:
			return -EINVAL;
	}

	switch (code) {
		case ARCH_SET_FS:
			dkprintf("[%d] arch_prctl: ARCH_SET_FS: 0x%lX\n",
			        ihk_mc_get_processor_id(), address);
			cpu_local_var(current)->tlsblock_base = address;
			err = ihk_mc_arch_set_special_register(type, address);
			break;
		case ARCH_SET_GS:
			err = ihk_mc_arch_set_special_register(type, address);
			break;
		case ARCH_GET_FS:
		case ARCH_GET_GS:
			err = ihk_mc_arch_get_special_register(type,
												   (unsigned long*)address);
			break;
		default:
			break;
	}

	return err;
}


SYSCALL_DECLARE(arch_prctl)
{
	return do_arch_prctl(ihk_mc_syscall_arg0(ctx), 
	                     ihk_mc_syscall_arg1(ctx));
}

SYSCALL_DECLARE(time)
{
	return time();
}

static int vdso_get_vdso_info(void)
{
	int error;
	struct ikc_scd_packet packet;
	struct ihk_ikc_channel_desc *ch = cpu_local_var(ikc2linux);

	dkprintf("vdso_get_vdso_info()\n");
	memset(&vdso, '\0', sizeof vdso);
	vdso.busy = 1;
	vdso.vdso_npages = 0;

	packet.msg = SCD_MSG_GET_VDSO_INFO;
	packet.arg = virt_to_phys(&vdso);

	error = ihk_ikc_send(ch, &packet, 0);
	if (error) {
		ekprintf("vdso_get_vdso_info: ihk_ikc_send failed. %d\n", error);
		goto out;
	}

	while (vdso.busy) {
		cpu_pause();
	}

	error = 0;
out:
	if (error) {
		vdso.vdso_npages = 0;
	}
	dkprintf("vdso_get_vdso_info(): %d\n", error);
	return error;
} /* vdso_get_vdso_info() */

static int vdso_map_global_pages(void)
{
	int error;
	enum ihk_mc_pt_attribute attr;
	int i;
	void *virt;
	intptr_t phys;

	dkprintf("vdso_map_global_pages()\n");
	if (vdso.vvar_virt && vdso.vvar_is_global) {
		attr = PTATTR_ACTIVE | PTATTR_USER | PTATTR_NO_EXECUTE;
		error = ihk_mc_pt_set_page(NULL, vdso.vvar_virt, vdso.vvar_phys, attr);
		if (error) {
			ekprintf("vdso_map_global_pages: mapping vvar failed. %d\n", error);
			goto out;
		}
	}

	if (vdso.hpet_virt && vdso.hpet_is_global) {
		attr = PTATTR_ACTIVE | PTATTR_USER | PTATTR_NO_EXECUTE | PTATTR_UNCACHABLE;
		error = ihk_mc_pt_set_page(NULL, vdso.hpet_virt, vdso.hpet_phys, attr);
		if (error) {
			ekprintf("vdso_map_global_pages: mapping hpet failed. %d\n", error);
			goto out;
		}
	}

	if (vdso.pvti_virt && vdso.pvti_is_global) {
		error = arch_setup_pvclock();
		if (error) {
			ekprintf("vdso_map_global_pages: arch_setup_pvclock failed. %d\n", error);
			goto out;
		}

		attr = PTATTR_ACTIVE | PTATTR_USER | PTATTR_NO_EXECUTE;
		for (i = 0; i < pvti_npages; ++i) {
			virt = vdso.pvti_virt - (i * PAGE_SIZE);
			phys = virt_to_phys(pvti + (i * PAGE_SIZE));
			error = ihk_mc_pt_set_page(NULL, virt, phys, attr);
			if (error) {
				ekprintf("vdso_map_global_pages: mapping pvti failed. %d\n", error);
				goto out;
			}
		}
	}

	error = 0;
out:
	dkprintf("vdso_map_global_pages(): %d\n", error);
	return error;
} /* vdso_map_global_pages() */

static void vdso_calc_container_size(void)
{
	intptr_t start, end;
	intptr_t s, e;

	dkprintf("vdso_calc_container_size()\n");
	start = 0;
	end = vdso.vdso_npages * PAGE_SIZE;

	if (vdso.vvar_virt && !vdso.vvar_is_global) {
		s = (intptr_t)vdso.vvar_virt;
		e = s + PAGE_SIZE;

		if (s < start) {
			start = s;
		}
		if (end < e) {
			end = e;
		}
	}
	if (vdso.hpet_virt && !vdso.hpet_is_global) {
		s = (intptr_t)vdso.hpet_virt;
		e = s + PAGE_SIZE;

		if (s < start) {
			start = s;
		}
		if (end < e) {
			end = e;
		}
	}
	if (vdso.pvti_virt && !vdso.pvti_is_global) {
		s = (intptr_t)vdso.pvti_virt;
		e = s + PAGE_SIZE;

		if (s < start) {
			start = s;
		}
		if (end < e) {
			end = e;
		}
	}

	vdso_offset = 0;
	if (start < 0) {
		vdso_offset = -start;
	}

	container_size = end - start;
	dkprintf("vdso_calc_container_size(): %#lx %#lx\n", container_size, vdso_offset);
	return;
} /* vdso_calc_container_size() */

int arch_setup_vdso()
{
	int error;

	dkprintf("arch_setup_vdso()\n");
	error = vdso_get_vdso_info();
	if (error) {
		ekprintf("arch_setup_vdso: vdso_get_vdso_info failed. %d\n", error);
		goto out;
	}

	if (vdso.vdso_npages <= 0) {
		error = 0;
		goto out;
	}

	error = vdso_map_global_pages();
	if (error) {
		ekprintf("arch_setup_vdso: vdso_map_global_pages failed. %d\n", error);
		goto out;
	}

	vdso_calc_container_size();

	error = 0;
out:
	if (container_size > 0) {
		kprintf("vdso is enabled\n");
	}
	else {
		kprintf("vdso is disabled\n");
	}
	dkprintf("arch_setup_vdso(): %d\n", error);
	return error;
} /* arch_setup_vdso() */

int arch_map_vdso(struct process_vm *vm)
{
	struct address_space *as = vm->address_space;
	page_table_t pt = as->page_table;
	void *container;
	void *s;
	void *e;
	unsigned long vrflags;
	enum ihk_mc_pt_attribute attr;
	int error;
	int i;
	struct vm_range *range;

	dkprintf("arch_map_vdso()\n");
	if (container_size <= 0) {
		/* vdso pages are not available */
		dkprintf("arch_map_vdso(): not available\n");
		error = 0;
		goto out;
	}

	container = (void *)vm->region.map_end;
	vm->region.map_end += container_size;

	s = container + vdso_offset;
	e = s + (vdso.vdso_npages * PAGE_SIZE);
	vrflags = VR_REMOTE;
	vrflags |= VR_PROT_READ | VR_PROT_EXEC;
	vrflags |= VRFLAG_PROT_TO_MAXPROT(vrflags);
	error = add_process_memory_range(vm, (intptr_t)s, (intptr_t)e,
			NOPHYS, vrflags, NULL, 0, PAGE_SHIFT, NULL, &range);
	if (error) {
		ekprintf("ERROR: adding memory range for vdso. %d\n", error);
		goto out;
	}
	vm->vdso_addr = s;

	attr = PTATTR_ACTIVE | PTATTR_USER;
	for (i = 0; i < vdso.vdso_npages; ++i) {
		s = vm->vdso_addr + (i * PAGE_SIZE);
		e = s + PAGE_SIZE;
		error = ihk_mc_pt_set_range(pt, vm, s, e,
									vdso.vdso_physlist[i], attr, 0, range, 0);
		if (error) {
			ekprintf("ihk_mc_pt_set_range failed. %d\n", error);
			goto out;
		}
	}

	if (container_size > (vdso.vdso_npages * PAGE_SIZE)) {
		if (vdso_offset) {
			s = container;
			e = container + vdso_offset;
		}
		else {
			s = container + (vdso.vdso_npages * PAGE_SIZE);
			e = container + container_size;
		}
		vrflags = VR_REMOTE;
		vrflags |= VR_PROT_READ;
		vrflags |= VRFLAG_PROT_TO_MAXPROT(vrflags);
		error = add_process_memory_range(vm, (intptr_t)s, (intptr_t)e,
				NOPHYS, vrflags, NULL, 0,
				PAGE_SHIFT, NULL, &range);
		if (error) {
			ekprintf("ERROR: adding memory range for vvar. %d\n", error);
			goto out;
		}
		vm->vvar_addr = s;

		if (vdso.vvar_virt && !vdso.vvar_is_global) {
			s = vm->vdso_addr + (intptr_t)vdso.vvar_virt;
			e = s + PAGE_SIZE;
			attr = PTATTR_ACTIVE | PTATTR_USER | PTATTR_NO_EXECUTE;
			error = ihk_mc_pt_set_range(pt, vm, s, e,
										vdso.vvar_phys, attr, 0, range, 0);
			if (error) {
				ekprintf("ihk_mc_pt_set_range failed. %d\n", error);
				goto out;
			}
		}
		if (vdso.hpet_virt && !vdso.hpet_is_global) {
			s = vm->vdso_addr + (intptr_t)vdso.hpet_virt;
			e = s + PAGE_SIZE;
			attr = PTATTR_ACTIVE | PTATTR_USER | PTATTR_NO_EXECUTE | PTATTR_UNCACHABLE;
			error = ihk_mc_pt_set_range(pt, vm, s, e,
										vdso.hpet_phys, attr, 0, range, 0);
			if (error) {
				ekprintf("ihk_mc_pt_set_range failed. %d\n", error);
				goto out;
			}
		}
		if (vdso.pvti_virt && !vdso.pvti_is_global) {
			s = vm->vdso_addr + (intptr_t)vdso.pvti_virt;
			e = s + PAGE_SIZE;
			attr = PTATTR_ACTIVE | PTATTR_USER | PTATTR_NO_EXECUTE;
			error = ihk_mc_pt_set_range(pt, vm, s, e,
										vdso.pvti_phys, attr, 0, range, 0);
			if (error) {
				ekprintf("ihk_mc_pt_set_range failed. %d\n", error);
				goto out;
			}
		}
	}

	error = 0;
out:
	dkprintf("arch_map_vdso(): %d %p\n", error, vm->vdso_addr);
	return error;
} /* arch_map_vdso() */

void
save_uctx(void *uctx, struct x86_user_context *regs)
{
	struct trans_uctx {
		volatile int cond;
		int fregsize;

		unsigned long rax;
		unsigned long rbx;
		unsigned long rcx;
		unsigned long rdx;
		unsigned long rsi;
		unsigned long rdi;
		unsigned long rbp;
		unsigned long r8;
		unsigned long r9;
		unsigned long r10;
		unsigned long r11;
		unsigned long r12;
		unsigned long r13;
		unsigned long r14;
		unsigned long r15;
		unsigned long rflags;
		unsigned long rip;
		unsigned long rsp;
		unsigned long fs;
	} *ctx = uctx;

	if (!regs) {
		asm ("movq %%gs:(%1),%0" : "=r"(regs) :
		     "r"(offsetof(struct x86_cpu_local_variables, tss.rsp0)));
		regs--;
	}

	ctx->cond = 0;
	ctx->rax = regs->gpr.rax;
	ctx->rbx = regs->gpr.rbx;
	ctx->rcx = regs->gpr.rcx;
	ctx->rdx = regs->gpr.rdx;
	ctx->rsi = regs->gpr.rsi;
	ctx->rdi = regs->gpr.rdi;
	ctx->rbp = regs->gpr.rbp;
	ctx->r8 = regs->gpr.r8;
	ctx->r9 = regs->gpr.r9;
	ctx->r10 = regs->gpr.r10;
	ctx->r11 = regs->gpr.r11;
	ctx->r12 = regs->gpr.r12;
	ctx->r13 = regs->gpr.r13;
	ctx->r14 = regs->gpr.r14;
	ctx->r15 = regs->gpr.r15;
	ctx->rflags = regs->gpr.rflags;
	ctx->rsp = regs->gpr.rsp;
	ctx->rip = regs->gpr.rip;
	ihk_mc_arch_get_special_register(IHK_ASR_X86_FS, &ctx->fs);
	ctx->fregsize = 0;
}

int do_process_vm_read_writev(int pid, 
		const struct iovec *local_iov,
		unsigned long liovcnt,
		const struct iovec *remote_iov,
		unsigned long riovcnt,
		unsigned long flags,
		int op)
{
	int ret = -EINVAL;	
	int li, ri;
	int pli, pri;
	off_t loff, roff;
	size_t llen = 0, rlen = 0;
	size_t copied = 0;
	size_t to_copy;
	struct thread *lthread = cpu_local_var(current);
	struct process *rproc;
	struct process *lproc = lthread->proc;
	struct process_vm *rvm = NULL;
	unsigned long rphys;
	unsigned long rpage_left;
	unsigned long psize;
	void *rva;
	struct vm_range *range;
	struct mcs_rwlock_node_irqsave lock;
	struct mcs_rwlock_node update_lock;

	/* Sanity checks */
	if (flags) {
		return -EINVAL;
	}
	
	if (liovcnt > IOV_MAX || riovcnt > IOV_MAX) {
		return -EINVAL;
	}

	/* Check if parameters are okay */
	ihk_rwspinlock_read_lock_noirq(&lthread->vm->memory_range_lock);

	range = lookup_process_memory_range(lthread->vm, 
			(uintptr_t)local_iov, 
			(uintptr_t)(local_iov + liovcnt));

	if (!range) {
		ret = -EFAULT; 
		goto arg_out;
	}

	range = lookup_process_memory_range(lthread->vm, 
			(uintptr_t)remote_iov, 
			(uintptr_t)(remote_iov + riovcnt));

	if (!range) {
		ret = -EFAULT; 
		goto arg_out;
	}

	ret = 0;
arg_out:
	ihk_rwspinlock_read_unlock_noirq(&lthread->vm->memory_range_lock);

	if (ret != 0) {
		goto out;
	}

	for (li = 0; li < liovcnt; ++li) {
		llen += local_iov[li].iov_len;
		dkprintf("local_iov[%d].iov_base: 0x%lx, len: %lu\n",
			li, local_iov[li].iov_base, local_iov[li].iov_len);
	}

	for (ri = 0; ri < riovcnt; ++ri) {
		rlen += remote_iov[ri].iov_len;
		dkprintf("remote_iov[%d].iov_base: 0x%lx, len: %lu\n",
			ri, remote_iov[ri].iov_base, remote_iov[ri].iov_len);
	}

	if (llen != rlen) {
		return -EINVAL;
	}
	
	/* Find remote process */
	rproc = find_process(pid, &lock);
	if (!rproc) {
		ret = -ESRCH;
		goto out;
	}

	mcs_rwlock_reader_lock_noirq(&rproc->update_lock, &update_lock);
	if(rproc->status == PS_EXITED ||
	   rproc->status == PS_ZOMBIE){
		mcs_rwlock_reader_unlock_noirq(&rproc->update_lock, &update_lock);
		process_unlock(rproc, &lock);
		ret = -ESRCH;
		goto out;
	}
	rvm = rproc->vm;
	hold_process_vm(rvm);
	mcs_rwlock_reader_unlock_noirq(&rproc->update_lock, &update_lock);
	process_unlock(rproc, &lock);

	if (lproc->euid != 0 &&
	    (lproc->ruid != rproc->ruid ||
	     lproc->ruid != rproc->euid ||
	     lproc->ruid != rproc->suid ||
	     lproc->rgid != rproc->rgid ||
	     lproc->rgid != rproc->egid ||
	     lproc->rgid != rproc->sgid)) {
		ret = -EPERM;
		goto out;
	}

	dkprintf("pid %d found, doing %s: liovcnt: %d, riovcnt: %d \n", pid,
		(op == PROCESS_VM_READ) ? "PROCESS_VM_READ" : "PROCESS_VM_WRITE",
		liovcnt, riovcnt);

	pli = pri = -1; /* Previous indeces in iovecs */
	li = ri = 0; /* Current indeces in iovecs */
	loff = roff = 0; /* Offsets in current iovec */

	/* Now iterate and do the copy */
	while (copied < llen) {
		int faulted = 0;

		/* New local vector? */
		if (pli != li) {
			struct vm_range *range;

			ihk_rwspinlock_read_lock_noirq(&lthread->vm->memory_range_lock);

			/* Is base valid? */
			range = lookup_process_memory_range(lthread->vm,
					(uintptr_t)local_iov[li].iov_base,
					(uintptr_t)(local_iov[li].iov_base + 1));

			if (!range) {
				ret = -EFAULT;
				goto pli_out;
			}

			/* Is range valid? */
			range = lookup_process_memory_range(lthread->vm,
					(uintptr_t)local_iov[li].iov_base,
					(uintptr_t)(local_iov[li].iov_base + local_iov[li].iov_len));

			if (range == NULL) {
				ret = -EINVAL;
				goto pli_out;
			}

			if (!(range->flag & ((op == PROCESS_VM_READ) ?
				VR_PROT_WRITE : VR_PROT_READ))) {
				ret = -EFAULT;
				goto pli_out;
			}

			ret = 0;
pli_out:
			ihk_rwspinlock_read_unlock_noirq(&lthread->vm->memory_range_lock);

			if (ret != 0) {
				goto out;
			}

			pli = li;
		}

		/* New remote vector? */
		if (pri != ri) {
			struct vm_range *range;

			ihk_rwspinlock_read_lock_noirq(&rvm->memory_range_lock);

			/* Is base valid? */
			range = lookup_process_memory_range(rvm,
					(uintptr_t)remote_iov[li].iov_base,
					(uintptr_t)(remote_iov[li].iov_base + 1));

			if (range == NULL) {
				ret = -EFAULT;
				goto pri_out;
			}

			/* Is range valid? */
			range = lookup_process_memory_range(rvm,
					(uintptr_t)remote_iov[li].iov_base,
					(uintptr_t)(remote_iov[li].iov_base + remote_iov[li].iov_len));

			if (range == NULL) {
				ret = -EINVAL;
				goto pri_out;
			}

			if (!(range->flag & ((op == PROCESS_VM_READ) ?
				VR_PROT_READ : VR_PROT_WRITE))) {
				ret = -EFAULT;
				goto pri_out;
			}

			ret = 0;
pri_out:
			ihk_rwspinlock_read_unlock_noirq(&rvm->memory_range_lock);

			if (ret != 0) {
				goto out;
			}

			pri = ri;
		}

		/* Figure out how much we can copy at most in this iteration */
		to_copy = (local_iov[li].iov_len - loff);	
		if ((remote_iov[ri].iov_len - roff) < to_copy) {
			to_copy = remote_iov[ri].iov_len - roff;
		}

retry_lookup:
		/* TODO: remember page and do this only if necessary */
		ret = ihk_mc_pt_virt_to_phys_size(rvm->address_space->page_table,
				remote_iov[ri].iov_base + roff, &rphys, &psize);

		if (ret) {
			uint64_t reason = PF_POPULATE | PF_WRITE | PF_USER;
			void *addr;

			if (faulted) {
				ret = -EFAULT;
				goto out;
			}

			/* Fault in pages */
			for (addr = (void *)
					(((unsigned long)remote_iov[ri].iov_base + roff)
					& PAGE_MASK);
					addr < (remote_iov[ri].iov_base + roff + to_copy);
					addr += PAGE_SIZE) {

				ret = page_fault_process_vm(rvm, addr, reason);
				if (ret) {
					ret = -EFAULT;
					goto out;
				}
			}

			faulted = 1;
			goto retry_lookup;
		}

		rpage_left = ((((unsigned long)remote_iov[ri].iov_base + roff +
			psize) & ~(psize - 1)) -
			((unsigned long)remote_iov[ri].iov_base + roff));
		if (rpage_left < to_copy) {
			to_copy = rpage_left;
		}

		rva = phys_to_virt(rphys);

		fast_memcpy(
				(op == PROCESS_VM_READ) ? local_iov[li].iov_base + loff : rva,
				(op == PROCESS_VM_READ) ? rva : local_iov[li].iov_base + loff,
				to_copy);

		copied += to_copy;
		dkprintf("local_iov[%d]: 0x%lx %s remote_iov[%d]: 0x%lx, %lu copied, psize: %lu, rpage_left: %lu\n",
			li, local_iov[li].iov_base + loff, 
			(op == PROCESS_VM_READ) ? "<-" : "->", 
			ri, remote_iov[ri].iov_base + roff, to_copy,
			psize, rpage_left);

		loff += to_copy;
		roff += to_copy;

		if (loff == local_iov[li].iov_len) {
			li++;
			loff = 0;
		}

		if (roff == remote_iov[ri].iov_len) {
			ri++;
			roff = 0;
		}
	}

	release_process_vm(rvm);

	return copied;

out:
	if(rvm)
		release_process_vm(rvm);
	return ret;
}

int move_pages_smp_handler(int cpu_index, int nr_cpus, void *arg)
{
	int i, i_s, i_e, phase = 1;
	struct move_pages_smp_req *mpsr =
		(struct move_pages_smp_req *)arg;
	struct process_vm *vm = mpsr->proc->vm;
	int count = mpsr->count;
	struct page_table *save_pt;
	extern struct page_table *get_init_page_table(void);

	i_s = (count / nr_cpus) * cpu_index;
	i_e = i_s + (count / nr_cpus);
	if (cpu_index == (nr_cpus - 1)) {
		i_e = count;
	}

	/* Load target process' PT so that we can access user-space */
	save_pt = cpu_local_var(current) == &cpu_local_var(idle) ?
		get_init_page_table() :
		cpu_local_var(current)->vm->address_space->page_table;

	if (save_pt != vm->address_space->page_table) {
		ihk_mc_load_page_table(vm->address_space->page_table);
	}
	else {
		save_pt = NULL;
	}

	if (nr_cpus == 1) {
		switch (cpu_index) {
			case 0:
				memcpy(mpsr->virt_addr, mpsr->user_virt_addr,
						sizeof(void *) * count);
				if (mpsr->user_nodes) {
					memcpy(mpsr->nodes, mpsr->user_nodes,
							sizeof(int) * count);
				}
				memset(mpsr->ptep, 0, sizeof(pte_t) * count);
				memset(mpsr->status, 0, sizeof(int) * count);
				memset(mpsr->nr_pages, 0, sizeof(int) * count);
				memset(mpsr->dst_phys, 0,
						sizeof(unsigned long) * count);
				mpsr->nodes_ready = 1;
				break;

			default:
				break;
		}
	}
	else if (nr_cpus > 1 && nr_cpus < 4) {
		switch (cpu_index) {
			case 0:
				memcpy(mpsr->virt_addr, mpsr->user_virt_addr,
						sizeof(void *) * count);
				if (mpsr->user_nodes) {
					memcpy(mpsr->nodes, mpsr->user_nodes,
							sizeof(int) * count);
				}
				mpsr->nodes_ready = 1;
				break;
			case 1:
				memset(mpsr->ptep, 0, sizeof(pte_t) * count);
				memset(mpsr->status, 0, sizeof(int) * count);
				memset(mpsr->nr_pages, 0, sizeof(int) * count);
				memset(mpsr->dst_phys, 0,
						sizeof(unsigned long) * count);
				break;

			default:
				break;
		}
	}
	else if (nr_cpus >= 4 && nr_cpus < 7) {
		switch (cpu_index) {
			case 0:
				memcpy(mpsr->virt_addr, mpsr->user_virt_addr,
						sizeof(void *) * count);
				break;
			case 1:
				if (mpsr->user_nodes) {
					memcpy(mpsr->nodes, mpsr->user_nodes,
							sizeof(int) * count);
				}
				mpsr->nodes_ready = 1;
				break;
			case 2:
				memset(mpsr->ptep, 0, sizeof(pte_t) * count);
				memset(mpsr->status, 0, sizeof(int) * count);
				break;
			case 3:
				memset(mpsr->nr_pages, 0, sizeof(int) * count);
				memset(mpsr->dst_phys, 0,
						sizeof(unsigned long) * count);
				break;

			default:
				break;
		}
	}
	else {
		switch (cpu_index) {
			case 0:
				memcpy(mpsr->virt_addr, mpsr->user_virt_addr,
						sizeof(void *) * (count / 2));
				break;
			case 1:
				memcpy(mpsr->virt_addr + (count / 2),
						mpsr->user_virt_addr + (count / 2),
						sizeof(void *) * (count / 2));
				break;
			case 2:
				if (mpsr->user_nodes) {
					memcpy(mpsr->nodes, mpsr->user_nodes,
							sizeof(int) * count);
				}
				mpsr->nodes_ready = 1;
				break;
			case 3:
				memset(mpsr->ptep, 0, sizeof(pte_t) * count);
				break;
			case 4:
				memset(mpsr->status, 0, sizeof(int) * count);
				break;
			case 5:
				memset(mpsr->nr_pages, 0, sizeof(int) * count);
				break;
			case 6:
				memset(mpsr->dst_phys, 0,
						sizeof(unsigned long) * count);
				break;
			default:
				break;
		}
	}

	while (!(volatile int)mpsr->nodes_ready) {
		cpu_pause();
	}

	/* NUMA verification in parallel */
	if (mpsr->user_nodes) {
		for (i = i_s; i < i_e; i++) {
			if (mpsr->nodes[i] < 0 ||
					mpsr->nodes[i] >= ihk_mc_get_nr_numa_nodes() ||
					!test_bit(mpsr->nodes[i],
						mpsr->proc->vm->numa_mask)) {
				mpsr->phase_ret = -EINVAL;
				break;
			}
		}
	}

	/* Barrier */
	ihk_atomic_inc(&mpsr->phase_done);
	while (ihk_atomic_read(&mpsr->phase_done) <
			(phase * nr_cpus)) {
		cpu_pause();
	}

	if (mpsr->phase_ret != 0) {
		goto out;
	}

	dkprintf("%s: phase %d done\n", __FUNCTION__, phase);
	++phase;

	/* PTE lookup in parallel */
	for (i = i_s; i < i_e; i++) {
		void *phys;
		size_t pgsize;
		int p2align;
		/*
		 * XXX: No page structures for anonymous mappings.
		 * Look up physical addresses by scanning page tables.
		 */
		mpsr->ptep[i] = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
				(void *)mpsr->virt_addr[i], 0, &phys, &pgsize, &p2align);

		/* PTE valid? */
		if (!mpsr->ptep[i] || !pte_is_present(mpsr->ptep[i])) {
			mpsr->status[i] = -ENOENT;
			mpsr->ptep[i] = NULL;
			continue;
		}

		/* PTE is file? */
		if (pte_is_fileoff(mpsr->ptep[i], PAGE_SIZE)) {
			mpsr->status[i] = -EINVAL;
			mpsr->ptep[i] = NULL;
			continue;
		}

		dkprintf("%s: virt 0x%lx:%lu requested to be moved to node %d\n",
			__FUNCTION__, mpsr->virt_addr[i], pgsize, mpsr->nodes[i]);

		/* Large page? */
		if (pgsize > PAGE_SIZE) {
			int nr_sub_pages = (pgsize / PAGE_SIZE);
			int j;

			if (i + nr_sub_pages > count) {
				kprintf("%s: ERROR: page at index %d exceeds the region\n",
						__FUNCTION__, i);
				mpsr->status[i] = -EINVAL;
				break;
			}

			/* Is it contiguous across nr_sub_pages and all
			 * requested to be moved to the same target node? */
			for (j = 0; j < nr_sub_pages; ++j) {
				if (mpsr->virt_addr[i + j] !=
				(mpsr->virt_addr[i] + (j * PAGE_SIZE)) ||
						mpsr->nodes[i] != mpsr->nodes[i + j]) {
					kprintf("%s: ERROR: virt address or node at index %d"
							" is inconsistent\n",
							__FUNCTION__, i + j);
					mpsr->phase_ret = -EINVAL;
					goto pte_out;
				}
			}

			mpsr->nr_pages[i] = nr_sub_pages;
			i += (nr_sub_pages - 1);
		}
		else {
			mpsr->nr_pages[i] = 1;
		}
	}

pte_out:
	/* Barrier */
	ihk_atomic_inc(&mpsr->phase_done);
	while (ihk_atomic_read(&mpsr->phase_done) <
			(phase * nr_cpus)) {
		cpu_pause();
	}

	if (mpsr->phase_ret != 0) {
		goto out;
	}

	dkprintf("%s: phase %d done\n", __FUNCTION__, phase);
	++phase;

	/*
	 * When nodes array is NULL, move_pages doesn't move any pages,
	 * instead will return the node where each page
	 * currently resides by status array.
	 */
	if (!mpsr->user_nodes) {
		/* get nid in parallel */
		for (i = i_s; i < i_e; i++) {
			if (mpsr->status[i] < 0) {
				continue;
			}
			mpsr->status[i] = phys_to_nid(
					pte_get_phys(mpsr->ptep[i]));
		}
		mpsr->phase_ret = 0;
		goto out;  // return node information
	}

	/* Processing of move pages */

	if (cpu_index == 0) {
		/* Allocate new pages on target NUMA nodes */
		for (i = 0; i < count; i++) {
			int pgalign = 0;
			int j;
			void *dst;

			if (!mpsr->ptep[i] || mpsr->status[i] < 0 || !mpsr->nr_pages[i])
				continue;

			/* TODO: store pgalign info in an array as well? */
			if (mpsr->nr_pages[i] > 1) {
				if (mpsr->nr_pages[i] * PAGE_SIZE == PTL2_SIZE)
					pgalign = PTL2_SHIFT - PTL1_SHIFT;
			}

			dst = ihk_mc_alloc_aligned_pages_node(mpsr->nr_pages[i],
					pgalign, IHK_MC_AP_USER, mpsr->nodes[i]);

			if (!dst) {
				mpsr->status[i] = -ENOMEM;
				continue;
			}

			for (j = i; j < (i + mpsr->nr_pages[i]); ++j) {
				mpsr->status[j] = mpsr->nodes[i];
			}

			mpsr->dst_phys[i] = virt_to_phys(dst);

			dkprintf("%s: virt 0x%lx:%lu to node %d, pgalign: %d,"
					" allocated phys: 0x%lx\n",
					__FUNCTION__, mpsr->virt_addr[i],
					mpsr->nr_pages[i] * PAGE_SIZE,
					mpsr->nodes[i], pgalign, mpsr->dst_phys[i]);
		}
	}

	/* Barrier */
	ihk_atomic_inc(&mpsr->phase_done);
	while (ihk_atomic_read(&mpsr->phase_done) <
			(phase * nr_cpus)) {
		cpu_pause();
	}

	if (mpsr->phase_ret != 0) {
		goto out;
	}

	dkprintf("%s: phase %d done\n", __FUNCTION__, phase);
	++phase;

	/* Copy, PTE update, memfree in parallel */
	for (i = i_s; i < i_e; ++i) {
		if (!mpsr->dst_phys[i])
			continue;

		fast_memcpy(phys_to_virt(mpsr->dst_phys[i]),
				phys_to_virt(pte_get_phys(mpsr->ptep[i])),
				mpsr->nr_pages[i] * PAGE_SIZE);

		ihk_mc_free_pages(
				phys_to_virt(pte_get_phys(mpsr->ptep[i])),
				mpsr->nr_pages[i]);

		pte_update_phys(mpsr->ptep[i], mpsr->dst_phys[i]);

		dkprintf("%s: virt 0x%lx:%lu copied and remapped to phys: 0x%lu\n",
				__FUNCTION__, mpsr->virt_addr[i],
				mpsr->nr_pages[i] * PAGE_SIZE,
				mpsr->dst_phys[i]);
	}

	/* XXX: do a separate SMP call with only CPUs running threads
	 * of this process? */
	if (cpu_local_var(current)->proc == mpsr->proc) {
		/* Invalidate all TLBs */
		for (i = 0; i < mpsr->count; i++) {
			if (!mpsr->dst_phys[i])
				continue;

			flush_tlb_single((unsigned long)mpsr->virt_addr[i]);
		}
	}

out:
	if (save_pt) {
		ihk_mc_load_page_table(save_pt);
	}

	return mpsr->phase_ret;
}

time_t time(void) {
	struct syscall_request sreq IHK_DMA_ALIGN;
	struct timespec ats;
	time_t ret = 0;

	if (gettime_local_support) {
		calculate_time_from_tsc(&ats);
		ret = ats.tv_sec;
	}
	else {
		sreq.number = __NR_time;
		sreq.args[0] = (uintptr_t)NULL;
		ret = (time_t)do_syscall(&sreq, ihk_mc_get_processor_id());
	}

	return ret;
}

void calculate_time_from_tsc(struct timespec *ts)
{
	unsigned long seq;
	unsigned long seq2;
	unsigned long ns;
	unsigned long delta;
	struct vsyscall_gtod_data *gtod = vdso.vgtod_virt;

	do {
		for (;;) {
			seq = ACCESS_ONCE(gtod->seq);
			if (unlikely(seq & 1)) {
				cpu_pause();
				continue;
			}
			break;
		}
		rmb(); /* fetch sequence before time */
		ts->tv_sec = gtod->wall_time_sec;
		ns = gtod->wall_time_snsec;
		delta = rdtsc() - gtod->clock.cycle_last;
		ns += delta * gtod->clock.mult;
		ns >>= gtod->clock.shift;
		seq2 = ACCESS_ONCE(gtod->seq);
		rmb(); /* fetch time before checking sequence */
	} while (seq != seq2);
	ts->tv_nsec = ns;

	if (ts->tv_nsec >= NS_PER_SEC) {
		ts->tv_nsec -= NS_PER_SEC;
		++ts->tv_sec;
	}
}

extern void ptrace_syscall_event(struct thread *thread);
long arch_ptrace_syscall_event(struct thread *thread,
				ihk_mc_user_context_t *ctx, long setret)
{
	ihk_mc_syscall_ret(ctx) = setret;
	ptrace_syscall_event(thread);
	return ihk_mc_syscall_ret(ctx);
}
/*** End of File ***/
