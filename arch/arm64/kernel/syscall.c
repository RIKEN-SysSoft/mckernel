/* syscall.c COPYRIGHT FUJITSU LIMITED 2015-2019 */
#include <cpulocal.h>
#include <string.h>
#include <kmalloc.h>
#include <vdso.h>
#include <mman.h>
#include <shm.h>
#include <elfcore.h>
#include <hw_breakpoint.h>
#include <debug-monitors.h>
#include <irq.h>
#include <lwk/compiler.h>
#include <hwcap.h>
#include <prctl.h>
#include <limits.h>
#include <uio.h>
#include <syscall.h>
#include <rusage_private.h>
#include <ihk/debug.h>

void terminate_mcexec(int, int);
extern void ptrace_report_signal(struct thread *thread, int sig);
extern void clear_single_step(struct thread *thread);
void terminate(int, int);
extern long do_sigaction(int sig, struct k_sigaction *act, struct k_sigaction *oact);
long syscall(int num, ihk_mc_user_context_t *ctx);
extern unsigned long do_fork(int, unsigned long, unsigned long, unsigned long,
	unsigned long, unsigned long, unsigned long);
static void __check_signal(unsigned long rc, void *regs, int num, int irq_disabled);

//#define DEBUG_PRINT_SC

#ifdef DEBUG_PRINT_SC
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

#define NOT_IMPLEMENTED()  do { kprintf("%s is not implemented\n", __func__); while(1);} while(0)

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

extern int num_processors;

int obtain_clone_cpuid(cpu_set_t *cpu_set, int use_last)
{
	int min_queue_len = -1;
	int cpu, min_cpu = -1;
#if 0
	int uti_cpu = -1;
#endif
	unsigned long irqstate = 0;

	int start, end, step;

	if (use_last) {
		start = num_processors - 1;
		end = -1;
		step = -1;
	}
	else {
		start = 0;
		end = num_processors;
		step = 1;
	}

	if (!cpu_local_var(current)->proc->nr_processes) {
		irqstate = ihk_mc_spinlock_lock(&runq_reservation_lock);
	}
	else {
		irqstate = cpu_disable_interrupt_save();
	}

	/* Find the first allowed core with the shortest run queue */
	for (cpu = start; cpu != end; cpu += step) {
		struct cpu_local_var *v;

		if (!CPU_ISSET(cpu, cpu_set))
			continue;

		v = get_cpu_local_var(cpu);
		ihk_mc_spinlock_lock_noirq(&v->runq_lock);
		dkprintf("%s: cpu=%d,runq_len=%d,runq_reserved=%d\n",
			 __func__, cpu, v->runq_len, v->runq_reserved);
		if (min_queue_len == -1 ||
		    //v->runq_len + v->runq_reserved < min_queue_len) {
		    v->runq_len < min_queue_len) {
			//min_queue_len = v->runq_len + v->runq_reserved;
			min_queue_len = v->runq_len;
			min_cpu = cpu;
		}

#if 0
		/* Record the last tie CPU */
		if (min_cpu != cpu &&
		    v->runq_len + v->runq_reserved == min_queue_len) {
			uti_cpu = cpu;
		}
		dkprintf("%s: cpu=%d,runq_len=%d,runq_reserved=%d,min_cpu=%d,uti_cpu=%d\n",
			 __func__, cpu, v->runq_len, v->runq_reserved,
			 min_cpu, uti_cpu);
#else

		ihk_mc_spinlock_unlock_noirq(&v->runq_lock);
		if (min_queue_len == 0)
			break;
#endif
	}

#if 0
	min_cpu = use_last ? uti_cpu : min_cpu;
	if (min_cpu != -1) {
		if (get_cpu_local_var(min_cpu)->status != CPU_STATUS_RESERVED)
			get_cpu_local_var(min_cpu)->status =
				CPU_STATUS_RESERVED;
		__sync_fetch_and_add(&get_cpu_local_var(min_cpu)->runq_reserved,
				     1);
	}
#else
	__sync_fetch_and_add(&get_cpu_local_var(min_cpu)->runq_reserved, 1);
#endif

	if (!cpu_local_var(current)->proc->nr_processes) {
		ihk_mc_spinlock_unlock(&runq_reservation_lock, irqstate);
	}
	else {
		cpu_restore_interrupt(irqstate);
	}

	return min_cpu;
}

/* archtecture-depended syscall handlers */
extern unsigned long do_fork(int clone_flags, unsigned long newsp,
			     unsigned long parent_tidptr, unsigned long child_tidptr,
			     unsigned long tlsblock_base, unsigned long curpc,
			     unsigned long cursp);

SYSCALL_DECLARE(clone)
{
	struct process *proc = cpu_local_var(current)->proc;
	struct mcs_rwlock_node_irqsave lock_dump;
	unsigned long ret;

	/* mutex coredump */
	mcs_rwlock_reader_lock(&proc->coredump_lock, &lock_dump);

	if ((int)ihk_mc_syscall_arg0(ctx) & CLONE_VFORK) {
		ret = do_fork(CLONE_VFORK|SIGCHLD, 0, 0, 0, 0,
				ihk_mc_syscall_pc(ctx), ihk_mc_syscall_sp(ctx));
	} else {
		ret = do_fork((int)ihk_mc_syscall_arg0(ctx), /* clone_flags */
			       ihk_mc_syscall_arg1(ctx),	/* newsp */
			       ihk_mc_syscall_arg2(ctx),	/* parent_tidptr */
			       ihk_mc_syscall_arg4(ctx),	/* child_tidptr (swap arg3) */
			       ihk_mc_syscall_arg3(ctx),	/* tlsblock_base (swap arg4) */
			       ihk_mc_syscall_pc(ctx),		/* curpc */
			       ihk_mc_syscall_sp(ctx));		/* cursp */
	}
	mcs_rwlock_reader_unlock(&proc->coredump_lock, &lock_dump);

	return ret;
}

SYSCALL_DECLARE(prctl)
{
	struct process *proc = cpu_local_var(current)->proc;
	int option = (int)ihk_mc_syscall_arg0(ctx);
	unsigned long arg2 = (unsigned long)ihk_mc_syscall_arg1(ctx);
	unsigned long arg3 = (unsigned long)ihk_mc_syscall_arg2(ctx);
	unsigned long arg4 = (unsigned long)ihk_mc_syscall_arg3(ctx);
	unsigned long arg5 = (unsigned long)ihk_mc_syscall_arg4(ctx);
	long error;

	switch (option) {
	case PR_SVE_SET_VL:
		error = SVE_SET_VL(ihk_mc_syscall_arg1(ctx));
		break;
	case PR_SVE_GET_VL:
		error = SVE_GET_VL();
		break;
	case PR_SET_THP_DISABLE:
		if (arg3 || arg4 || arg5) {
			return -EINVAL;
		}
		proc->thp_disable = arg2;
		error = 0;
		break;
	case PR_GET_THP_DISABLE:
		if (arg2 || arg3 || arg4 || arg5) {
			return -EINVAL;
		}
		error = proc->thp_disable;
		break;
	default:
		error = syscall_generic_forwarding(__NR_prctl, ctx);
		break;
	}
	return error;
}

/*
 * @ref.impl linux-linaro/src/linux-linaro/arch/arm64/kernel/signal.c::struct rt_sigframe
 * @ref.impl mckernel/arch/x86/kernel/syscall.c::struct sigsp
 */
struct sigsp {
	unsigned long sigrc;
	int syscallno;
	int restart;
	siginfo_t info;
	struct ucontext uc;
	uint64_t fp;
	uint64_t lr;
};

struct rt_sigframe_user_layout {
	struct sigsp __user *usigframe;
	struct sigsp *ksigframe;

	unsigned long size;	/* size of allocated sigframe data */
	unsigned long limit;	/* largest allowed size */

	unsigned long fpsimd_offset;
	unsigned long esr_offset;
	unsigned long sve_offset;
	unsigned long extra_offset;
	unsigned long end_offset;
};

static void preserve_fpsimd_context(struct fpsimd_context *ctx)
{
	struct fpsimd_state fpsimd;

	/* dump the hardware registers to the fpsimd_state structure */
	fpsimd_save_state(&fpsimd);

	/* copy the FP and status/control registers */
	memcpy(ctx->vregs, fpsimd.vregs, sizeof(fpsimd.vregs));
	ctx->fpsr = fpsimd.fpsr;
	ctx->fpcr = fpsimd.fpcr;

	/* copy the magic/size information */
	ctx->head.magic = FPSIMD_MAGIC;
	ctx->head.size = sizeof(struct fpsimd_context);
}

/* @ref.impl arch/arm64/kernel/signal.c::preserve_sve_context */
static void preserve_sve_context(void *ctx)
{
	struct sve_context *sve_ctx = ctx;
	unsigned int vl = current_thread_info()->sve_vl;
	unsigned int vq;
	unsigned int fpscr[2] = { 0, 0 };

	BUG_ON(!sve_vl_valid(vl));
	vq = sve_vq_from_vl(vl);

	/* sve_context header set */
	sve_ctx->head.magic = SVE_MAGIC;
	sve_ctx->head.size = ALIGN_UP(SVE_SIG_CONTEXT_SIZE(vq), 16);

	/* sve_context vl set */
	sve_ctx->vl = vl;

	/* sve_context reserved area 0 clear */
	memset(sve_ctx->__reserved, 0, sizeof(sve_ctx->__reserved));

	/* sve register save */
	/* fpsr & fpcr discards, because already saved by preserve_fpsimd_context() */
	sve_save_state(ctx + SVE_SIG_FFR_OFFSET(vq), fpscr);
}

static int restore_fpsimd_context(struct fpsimd_context *ctx)
{
	struct fpsimd_state fpsimd;
	unsigned int magic, size;

	/* check the magic/size information */
	magic = ctx->head.magic;
	size = ctx->head.size;
	if (magic != FPSIMD_MAGIC || size != sizeof(struct fpsimd_context))
		return -EINVAL;

	//  copy the FP and status/control registers 
	memcpy(fpsimd.vregs, ctx->vregs, sizeof(fpsimd.vregs));
	fpsimd.fpsr = ctx->fpsr;
	fpsimd.fpcr = ctx->fpcr;

	/* load the hardware registers from the fpsimd_state structure */
	fpsimd_load_state(&fpsimd);

	return 0;
}

/* @ref.impl arch/arm64/kernel/signal.c::__restore_sve_fpsimd_context */
static int __restore_sve_fpsimd_context(void *ctx, unsigned int vq, struct fpsimd_context *fpsimd)
{
	struct fpsimd_sve_state(vq) *sst =
			ctx + SVE_SIG_ZREGS_OFFSET;
	int i = 0;

	/* vq check */
	if (vq != sve_vq_from_vl(current_thread_info()->sve_vl)) {
		return -EINVAL;
	}

	/* copy from fpsimd_context vregs */
	for (i = 0; i < 32; i++) {
		sst->zregs[i][0] = fpsimd->vregs[i];
	}

	/* restore sve register */
	sve_load_state(sst->ffr, &fpsimd->fpsr, vq - 1);

	return 0;
}

/* @ref.impl arch/arm64/kernel/signal.c::restore_sve_fpsimd_context */
static int restore_sve_fpsimd_context(void *ctx, struct fpsimd_context *fpsimd)
{
	struct sve_context const *sve_ctx = ctx;
	uint16_t vl = sve_ctx->vl;
	uint16_t vq;

	/* vl check */
	if (!sve_vl_valid(vl)) {
		return -EINVAL;
	}

	vq = sve_vq_from_vl(vl);

	return __restore_sve_fpsimd_context(ctx, vq, fpsimd);
}

/* @ref.impl arch/arm64/kernel/signal.c::SIGFRAME_MAXSZ */
/* Sanity limit on the maximum size of signal frame we'll try to generate. */
/* This is NOT ABI. */
#define SIGFRAME_MAXSZ _SZ64KB

/* @ref.impl arch/arm64/kernel/signal.c::BUILD_BUG_ON in the __sigframe_alloc */
STATIC_ASSERT(SIGFRAME_MAXSZ == ALIGN_DOWN(SIGFRAME_MAXSZ, 16));
STATIC_ASSERT(SIGFRAME_MAXSZ > ALIGN_UP(sizeof(struct _aarch64_ctx), 16));
STATIC_ASSERT(ALIGN_UP(sizeof(struct sigsp), 16) < SIGFRAME_MAXSZ - ALIGN_UP(sizeof(struct _aarch64_ctx), 16));

/* @ref.impl arch/arm64/kernel/signal.c::parse_user_sigframe */
static int parse_user_sigframe(struct sigsp *sf)
{
	struct sigcontext *sc = &sf->uc.uc_mcontext;
	struct _aarch64_ctx *head;
	char *base = (char *)&sc->__reserved;
	size_t offset = 0;
	size_t limit = sizeof(sc->__reserved);
	int have_extra_context = 0, err = -EINVAL;
	void *kextra_data = NULL;
	struct fpsimd_context *fpsimd_ctx = NULL;
	struct sve_context *sve_ctx = NULL;

	if (ALIGN_UP((unsigned long)base, 16) != (unsigned long)base)
		goto invalid;

	while (1) {
		unsigned int magic, size;

		BUG_ON(limit < offset);

		if (limit - offset < sizeof(*head))
			goto invalid;

		if (ALIGN_DOWN(offset, 16) != offset)
			goto invalid;

		BUG_ON(ALIGN_UP((unsigned long)base + offset, 16) != (unsigned long)base + offset);

		head = (struct _aarch64_ctx *)(base + offset);
		magic = head->magic;
		size = head->size;

		if (limit - offset < size)
			goto invalid;

		switch (magic) {
		case 0:
			if (size)
				goto invalid;

			goto done;

		case FPSIMD_MAGIC:
			if (fpsimd_ctx)
				goto invalid;

			if (size < sizeof(struct fpsimd_context))
				goto invalid;

			fpsimd_ctx = container_of(head, struct fpsimd_context, head);
			break;

		case ESR_MAGIC:
			/* ignore */
			break;

		case SVE_MAGIC: {
			struct sve_context *sve_head =
				container_of(head, struct sve_context, head);

			if (!(elf_hwcap & HWCAP_SVE))
				goto invalid;

			if (sve_ctx)
				goto invalid;

			if (size < sizeof(*sve_ctx))
				goto invalid;

			sve_ctx = sve_head;
			break;
			} /* SVE_MAGIC */

		case EXTRA_MAGIC: {
			struct extra_context const *extra;
			void __user *extra_data;
			unsigned int extra_size;

			if (have_extra_context)
				goto invalid;

			if (size < sizeof(*extra))
				goto invalid;

			extra = (struct extra_context const *)head;
			extra_data = extra->data;
			extra_size = extra->size;

			/* Prevent looping/repeated parsing of extra_conext */
			have_extra_context = 1;

			kextra_data = kmalloc(extra_size + 15, IHK_MC_AP_NOWAIT);
			if (copy_from_user((char *)ALIGN_UP((unsigned long)kextra_data, 16), extra_data, extra_size)) {
				goto invalid;
			}

			/*
			 * Rely on the __user accessors to reject bogus
			 * pointers.
			 */
			base = (char *)ALIGN_UP((unsigned long)kextra_data, 16);
			if (ALIGN_UP((unsigned long)base, 16) != (unsigned long)base)
				goto invalid;

			/* Reject "unreasonably large" frames: */
			limit = extra_size;
			if (limit > SIGFRAME_MAXSZ - sizeof(sc->__reserved))
				goto invalid;

			/*
			 * Ignore trailing terminator in __reserved[]
			 * and start parsing extra_data:
			 */
			offset = 0;
			continue;
			} /* EXTRA_MAGIC */

		default:
			goto invalid;
		}

		if (size < sizeof(*head))
			goto invalid;

		if (limit - offset < size)
			goto invalid;

		offset += size;
	}

done:
	if (!fpsimd_ctx)
		goto invalid;

	if (sve_ctx) {
		err = restore_sve_fpsimd_context(sve_ctx, fpsimd_ctx);
	} else {
		err = restore_fpsimd_context(fpsimd_ctx);
	}

invalid:
	if (kextra_data) {
		kfree(kextra_data);
		kextra_data = NULL;
	}
	return err;
}

SYSCALL_DECLARE(rt_sigreturn)
{
	int i, err = 0;
	struct thread *thread = cpu_local_var(current);
	ihk_mc_user_context_t *regs = ctx;
	struct sigsp ksigsp;
	struct sigsp __user *usigsp;
	siginfo_t info;

	/*
	 * Since we stacked the signal on a 128-bit boundary, then 'sp' should
	 * be word aligned here.
	 */
	if (regs->sp & 15)
		goto bad_frame;

	usigsp = (struct sigsp __user *)regs->sp;
	if (copy_from_user(&ksigsp, usigsp, sizeof(ksigsp))) {
		goto bad_frame;
	}

	for (i = 0; i < 31; i++) {
		regs->regs[i] = ksigsp.uc.uc_mcontext.regs[i];
	}
	regs->sp = ksigsp.uc.uc_mcontext.sp;
	regs->pc = ksigsp.uc.uc_mcontext.pc;
	regs->pstate = ksigsp.uc.uc_mcontext.pstate;

	// Avoid sys_rt_sigreturn() restarting. 
	regs->syscallno = ~0UL;

	err = parse_user_sigframe(&ksigsp);
	if (err)
		goto bad_frame;

	thread->sigmask.__val[0] = ksigsp.uc.uc_sigmask.__val[0];
	thread->sigstack.ss_flags = ksigsp.uc.uc_stack.ss_flags;
	if(ksigsp.restart){
		regs->orig_x0 = regs->regs[0];
		regs->orig_pc = regs->pc;
		return syscall(ksigsp.syscallno, regs);
	}

	if (thread->ctx.thread->flags & (1 << TIF_SINGLESTEP)) {
		memset(&info, 0, sizeof(info));
		info.si_code = TRAP_HWBKPT;
		regs->regs[0] = ksigsp.sigrc;
		clear_single_step(thread);
		set_signal(SIGTRAP, regs, &info);
		check_need_resched();
		check_signal(0, regs, -1);
	}
	return ksigsp.sigrc;

bad_frame:
	ekprintf("[pid:%d]: bad frame in %s: pc=%08llx sp=%08llx\n",
			thread->proc->pid, __FUNCTION__, regs->pc, regs->sp);
	memset(&info, 0, sizeof(info));
	info.si_signo = SIGSEGV;
	info.si_code = SI_KERNEL;
	set_signal(info.si_signo, regs, &info);
	return 0;
}

extern struct cpu_local_var *clv;
extern void interrupt_syscall(struct thread *, int sig);
extern int num_processors;

long
alloc_debugreg(struct thread *thread)
{
	struct user_hwdebug_state *hws = NULL;

	/* LOWER:  breakpoint register area. */
	/* HIGHER: watchpoint register area. */
	hws = kmalloc(sizeof(struct user_hwdebug_state) * 2, IHK_MC_AP_NOWAIT);
	if (hws == NULL) {
		kprintf("alloc_debugreg: no memory.\n");
		return -ENOMEM;
	}
	memset(hws, 0, sizeof(struct user_hwdebug_state) * 2);

	/* initialize dbg_info */
	hws[HWS_BREAK].dbg_info = ptrace_hbp_get_resource_info(NT_ARM_HW_BREAK);
	hws[HWS_WATCH].dbg_info = ptrace_hbp_get_resource_info(NT_ARM_HW_WATCH);

	thread->ptrace_debugreg = (unsigned long *)hws;
	return 0;
}

void
save_debugreg(unsigned long *debugreg)
{
	struct user_hwdebug_state *hws = (struct user_hwdebug_state *)debugreg;
	int i = 0;

	/* save DBGBVR<n>_EL1 and DBGBCR<n>_EL1 (n=0-(core_num_brps-1)) */
	for (i = 0; i < core_num_brps; i++) {
		hws[HWS_BREAK].dbg_regs[i].addr = read_wb_reg(AARCH64_DBG_REG_BVR, i);
		hws[HWS_BREAK].dbg_regs[i].ctrl = read_wb_reg(AARCH64_DBG_REG_BCR, i);
	}

	/* save DBGWVR<n>_EL1 and DBGWCR<n>_EL1 (n=0-(core_num_wrps-1)) */
	for (i = 0; i < core_num_wrps; i++) {
		hws[HWS_WATCH].dbg_regs[i].addr = read_wb_reg(AARCH64_DBG_REG_WVR, i);
		hws[HWS_WATCH].dbg_regs[i].ctrl = read_wb_reg(AARCH64_DBG_REG_WCR, i);
	}
}

void
restore_debugreg(unsigned long *debugreg)
{
	struct user_hwdebug_state *hws = (struct user_hwdebug_state *)debugreg;
	unsigned int mdscr;
	int i = 0;

	/* set MDSCR_EL1.MDE */
	mdscr = mdscr_read();
	mdscr |= DBG_MDSCR_MDE;
	mdscr_write(mdscr);

	/* restore DBGBVR<n>_EL1 and DBGBCR<n>_EL1 (n=0-(core_num_brps-1)) */
	for (i = 0; i < core_num_brps; i++) {
		write_wb_reg(AARCH64_DBG_REG_BVR, i, hws[HWS_BREAK].dbg_regs[i].addr);
		write_wb_reg(AARCH64_DBG_REG_BCR, i, hws[HWS_BREAK].dbg_regs[i].ctrl);
	}

	/* restore DBGWVR<n>_EL1 and DBGWCR<n>_EL1 (n=0-(core_num_wrps-1)) */
	for (i = 0; i < core_num_wrps; i++) {
		write_wb_reg(AARCH64_DBG_REG_WVR, i, hws[HWS_WATCH].dbg_regs[i].addr);
		write_wb_reg(AARCH64_DBG_REG_WCR, i, hws[HWS_WATCH].dbg_regs[i].ctrl);
	}
}

void
clear_debugreg(void)
{
	unsigned int mdscr;

	/* clear DBGBVR<n>_EL1 and DBGBCR<n>_EL1 (n=0-(core_num_brps-1)) */
	/* clear DBGWVR<n>_EL1 and DBGWCR<n>_EL1 (n=0-(core_num_wrps-1)) */
	hw_breakpoint_reset();

	/* clear MDSCR_EL1.MDE */
	mdscr = mdscr_read();
	mdscr &= ~DBG_MDSCR_MDE;
	mdscr_write(mdscr);
}

void clear_single_step(struct thread *thread)
{
	clear_regs_spsr_ss(thread->uctx);
	thread->ctx.thread->flags &= ~(1 << TIF_SINGLESTEP);
}

void set_single_step(struct thread *thread)
{
	thread->ctx.thread->flags |= (1 << TIF_SINGLESTEP);
	set_regs_spsr_ss(thread->uctx);
}

extern int coredump(struct thread *thread, void *regs, int sig);

static int
isrestart(int syscallno, unsigned long rc, int sig, int restart)
{
	if (sig == SIGKILL || sig == SIGSTOP)
		return 0;

	if (syscallno < 0 || rc != -EINTR)
		return 0;

	if (sig == SIGCHLD)
		return 1;

	/* 
	 * The following interfaces are never restarted after being interrupted 
	 * by a signal handler, regardless of the use of SA_RESTART
	 * Interfaces used to wait for signals: 
	 * 	pause(2), sigsuspend(2), sigtimedwait(2), and sigwaitinfo(2).
	 * File descriptor multiplexing interfaces: 
	 * 	epoll_wait(2), epoll_pwait(2), poll(2), ppoll(2), select(2), and pselect(2).
	 * System V IPC interfaces: 
	 * 	msgrcv(2), msgsnd(2), semop(2), and semtimedop(2).
	 * Sleep interfaces: 
	 * 	clock_nanosleep(2), nanosleep(2), and usleep(3).
	 * io_getevents(2).
	 *
	 * Note: following functions will issue another systemcall.
	 *   pause(2)      -> rt_sigsuspend
	 *   epoll_wait(2) -> epoll_pwait
	 *   poll(2)       -> ppoll
	 *   select(2)     -> pselect6
	 */
	switch (syscallno) {
		case __NR_rt_sigsuspend:
		case __NR_rt_sigtimedwait:
		case __NR_epoll_pwait:
		case __NR_ppoll:
		case __NR_pselect6:
		case __NR_msgrcv:
		case __NR_msgsnd:
		case __NR_semop:
		case __NR_semtimedop:
		case __NR_clock_nanosleep:
		case __NR_nanosleep:
		case __NR_io_getevents:
			return 0;
	}

	if (restart)
		return 1;
	return 0;
}

/* @ref.impl arch/arm64/kernel/signal.c::init_user_layout */
static void init_user_layout(struct rt_sigframe_user_layout *user)
{
	const size_t __reserved_size =
		sizeof(user->usigframe->uc.uc_mcontext.__reserved);
	const size_t terminator_size =
		ALIGN_UP(sizeof(struct _aarch64_ctx), 16);

	memset(user, 0, sizeof *user);
	user->size = offsetof(struct sigsp, uc.uc_mcontext.__reserved);
	user->limit = user->size + (__reserved_size - terminator_size -
				    sizeof(struct extra_context));
	/* Reserve space for extension and terminator ^ */

	BUG_ON(user->limit <= user->size);
}

/* @ref.impl arch/arm64/kernel/signal.c::sigframe_size */
static size_t sigframe_size(struct rt_sigframe_user_layout const *user)
{
	size_t size;

	/* FIXME: take user->limit into account? */
	if (user->size > sizeof(struct sigsp)) {
		size = user->size;
	} else {
		size = sizeof(struct sigsp);
	}
	return ALIGN_UP(size, 16);
}

/* @ref.impl arch/arm64/kernel/signal.c::__sigframe_alloc */
static int __sigframe_alloc(struct rt_sigframe_user_layout *user,
			    unsigned long *offset, size_t size, unsigned char extend)
{
	unsigned long padded_size = ALIGN_UP(size, 16);

	/* Sanity-check invariants */
	BUG_ON(user->limit < user->size);
	BUG_ON(user->size != ALIGN_DOWN(user->size, 16));
	BUG_ON(size < sizeof(struct _aarch64_ctx));

	if (padded_size > user->limit - user->size &&
	    !user->extra_offset &&
	    extend) {
		int ret;

		ret = __sigframe_alloc(user, &user->extra_offset,
				       sizeof(struct extra_context), 0);
		if (ret) {
			return ret;
		}

		/*
		 * Further allocations must go after the fixed-size
		 * part of the signal frame:
		 */
		user->size = ALIGN_UP(sizeof(struct sigsp), 16);

		/*
		 * Allow expansion up to SIGFRAME_MAXSZ, ensuring space for
		 * the terminator:
		 */
		user->limit = SIGFRAME_MAXSZ -
			ALIGN_UP(sizeof(struct _aarch64_ctx), 16);
	}

	/* Still not enough space?  Bad luck! */
	if (padded_size > user->limit - user->size) {
		return -ENOMEM;
	}

	/* Anti-leakage check: don't double-allocate the same block: */
	BUG_ON(*offset);

	*offset = user->size;
	user->size += padded_size;

	/* Check invariants again */
	BUG_ON(user->limit < user->size);
	BUG_ON(user->size != ALIGN_DOWN(user->size, 16));
	return 0;
}

/* @ref.impl arch/arm64/kernel/signal.c::sigframe_alloc */
/* Allocate space for an optional record of <size> bytes in the user
 * signal frame.  The offset from the signal frame base address to the
 * allocated block is assigned to *offset.
 */
static int sigframe_alloc(struct rt_sigframe_user_layout *user,
			  unsigned long *offset, size_t size)
{
	return __sigframe_alloc(user, offset, size, 1);
}

/* @ref.impl arch/arm64/kernel/signal.c::sigframe_alloc_end */
/* Allocate the null terminator record and prevent further allocations */
static int sigframe_alloc_end(struct rt_sigframe_user_layout *user)
{
	int ret;
	const size_t __reserved_size =
		sizeof(user->ksigframe->uc.uc_mcontext.__reserved);
	const size_t __reserved_offset =
		offsetof(struct sigsp, uc.uc_mcontext.__reserved);
	const size_t terminator_size =
		ALIGN_UP(sizeof(struct _aarch64_ctx), 16);

	if (user->extra_offset) {
		BUG_ON(user->limit != SIGFRAME_MAXSZ - terminator_size);
	} else {
		BUG_ON(user->limit != __reserved_offset +
		    (__reserved_size - terminator_size -
		     sizeof(struct extra_context)));
	}

	/* Un-reserve the space reserved for the terminator: */
	user->limit += terminator_size;

	ret = sigframe_alloc(user, &user->end_offset,
			     sizeof(struct _aarch64_ctx));

	if (ret) {
		return ret;
	}

	/* Prevent further allocation: */
	user->limit = user->size;
	return 0;
}

/* @ref.impl arch/arm64/kernel/signal.c::apply_user_offset */
/* changed McKernel, void *p and return value is kernel area address, function name */
static void *get_sigframe_context_kaddr(
	struct rt_sigframe_user_layout const *user, unsigned long offset)
{
	char *base = (char *)user->ksigframe;

	BUG_ON(!base);
	BUG_ON(!offset);

	/*
	 * TODO: sanity-check that the result is within appropriate bounds
	 * (should be ensured by the use of set_user_offset() to compute
	 * all offsets.
	 */
	return base + offset;
}

/* @ref.impl arch/arm64/kernel/signal.c::apply_user_offset */
/* changed McKernel, function name */
static void __user *get_sigframe_context_uaddr(
	struct rt_sigframe_user_layout const *user, unsigned long offset)
{
	char __user *base = (char __user *)user->usigframe;

	BUG_ON(!base);
	BUG_ON(!offset);

	/*
	 * TODO: sanity-check that the result is within appropriate bounds
	 * (should be ensured by the use of set_user_offset() to compute
	 * all offsets.
	 */
	return base + offset;
}

/* @ref.impl arch/arm64/kernel/signal.c::setup_sigframe_layout */
/* Determine the layout of optional records in the signal frame */
static int setup_sigframe_layout(struct rt_sigframe_user_layout *user)
{
	int err;

	err = sigframe_alloc(user, &user->fpsimd_offset,
			     sizeof(struct fpsimd_context));
	if (err)
		return err;

	/* fault information, if valid */
	if (current_thread_info()->fault_code) {
		err = sigframe_alloc(user, &user->esr_offset,
				     sizeof(struct esr_context));
		if (err)
			return err;
	}

	if (likely(elf_hwcap & (HWCAP_FP | HWCAP_ASIMD))) {
		if (likely(elf_hwcap & HWCAP_SVE)) {
			unsigned int vq = sve_vq_from_vl(current_thread_info()->sve_vl);

			err = sigframe_alloc(user, &user->sve_offset,
					     SVE_SIG_CONTEXT_SIZE(vq));
			if (err)
				return err;
		}
	}
	return sigframe_alloc_end(user);
}

/* @ref.impl arch/arm64/kernel/signal.c::get_sigframe */
static int get_sigframe(struct thread *thread,
			struct rt_sigframe_user_layout *user,
			struct pt_regs *regs, unsigned long sa_flags)
{
	unsigned long sp, sp_top, frame_size;
	int err;

	init_user_layout(user);

	// get signal frame
	if ((sa_flags & SA_ONSTACK) &&
	   !(thread->sigstack.ss_flags & SS_DISABLE) &&
	   !(thread->sigstack.ss_flags & SS_ONSTACK)) {
		unsigned long lsp;
		lsp = ((unsigned long)(((char *)thread->sigstack.ss_sp) + thread->sigstack.ss_size)) & ~15UL;
		sp = sp_top = lsp;
		thread->sigstack.ss_flags |= SS_ONSTACK;
	}
	else {
		sp = sp_top = regs->sp;
	}
	sp = ALIGN_DOWN(sp, 16);

	/* calc sigframe layout */
	err = setup_sigframe_layout(user);
	if (err)
		return err;

	/* calc new user stack pointer */
	frame_size = sigframe_size(user);
	sp -= frame_size;
	BUG_ON(ALIGN_DOWN(sp, 16) != sp);

	/* set user sp address and kernel sigframe address */
	user->usigframe = (struct sigsp __user *)sp;
	return 0;
}

/* @ref.impl arch/arm64/kernel/signal.c::setup_rt_frame */
static int setup_rt_frame(int usig, unsigned long rc, int to_restart,
			  int syscallno, struct k_sigaction *k, struct sig_pending *pending,
			  struct pt_regs *regs, struct thread *thread)
{
	struct rt_sigframe_user_layout user;
	struct sigsp *kframe;
	struct sigsp __user *uframe;
	int i = 0, err = 0, kpages = 0;
	struct _aarch64_ctx *end;

	/* get signal frame info */
	memset(&user, 0, sizeof(user));
	if (get_sigframe(thread, &user, regs, k->sa.sa_flags)) {
		return 1;
	}

	/* allocate kernel sigframe buffer */
	kpages = (sigframe_size(&user) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	user.ksigframe = ihk_mc_alloc_pages(kpages, IHK_MC_AP_NOWAIT);

	/* set kernel sigframe lowest addr */
	kframe = user.ksigframe;

	/* set user sigframe lowest addr */
	uframe = user.usigframe;

	// init non use data.
	kframe->uc.uc_flags = 0;
	kframe->uc.uc_link = NULL;

	// save alternate stack infomation.
	kframe->uc.uc_stack.ss_sp = uframe;
	kframe->uc.uc_stack.ss_flags = thread->sigstack.ss_size;
	kframe->uc.uc_stack.ss_size = thread->sigstack.ss_flags;

	// save signal frame.
	kframe->fp = regs->regs[29];
	kframe->lr = regs->regs[30];
	kframe->sigrc = rc;

	for (i = 0; i < 31; i++) {
		kframe->uc.uc_mcontext.regs[i] = regs->regs[i];
	}
	kframe->uc.uc_mcontext.sp = regs->sp;
	kframe->uc.uc_mcontext.pc = regs->pc;
	kframe->uc.uc_mcontext.pstate = regs->pstate;

	kframe->uc.uc_mcontext.fault_address = current_thread_info()->fault_address;

	kframe->uc.uc_sigmask = thread->sigmask;

	// save fp simd context.
	preserve_fpsimd_context(get_sigframe_context_kaddr(&user, user.fpsimd_offset));

	if (user.esr_offset) {
		// save esr context.
		struct esr_context *esr_ctx =
			get_sigframe_context_kaddr(&user, user.esr_offset);

		esr_ctx->head.magic = ESR_MAGIC;
		esr_ctx->head.size = sizeof(*esr_ctx);
		esr_ctx->esr = current_thread_info()->fault_code;
	}

	if (user.sve_offset) {
		// save sve context.
		struct sve_context *sve_ctx =
			get_sigframe_context_kaddr(&user, user.sve_offset);
		preserve_sve_context(sve_ctx);
	}

	if (user.extra_offset) {
		// save extra context.
		struct extra_context *extra =
			get_sigframe_context_kaddr(&user, user.extra_offset);
		struct _aarch64_ctx *end = 
			(struct _aarch64_ctx *)((char *)extra +
				ALIGN_UP(sizeof(*extra), 16));
		void __user *extra_data = get_sigframe_context_uaddr(&user,
			ALIGN_UP(sizeof(struct sigsp), 16));
		unsigned int extra_size = ALIGN_UP(user.size, 16) -
			ALIGN_UP(sizeof(struct sigsp), 16);

		/*
		 * ^ FIXME: bounds sanity-checks: both of these should fit
		 * within __reserved!
		 */
		extra->head.magic = EXTRA_MAGIC;
		extra->head.size = sizeof(*extra);
		extra->data = extra_data;
		extra->size = extra_size;

		/* Add the terminator */
		end->magic = 0;
		end->size = 0;
	}

	// set the "end" magic
	end = get_sigframe_context_kaddr(&user, user.end_offset);
	end->magic = 0;
	end->size = 0;

	// save syscall infomation to restart.
	kframe->syscallno = syscallno;
	kframe->restart = to_restart;

	/* set sig handler context */
	// set restart context
	regs->regs[0] = usig;
	regs->sp = (unsigned long)uframe;
	regs->regs[29] = (unsigned long)&uframe->fp;
	regs->pc = (unsigned long)k->sa.sa_handler;

	if (k->sa.sa_flags & SA_RESTORER){
		regs->regs[30] = (unsigned long)k->sa.sa_restorer;
	} else {
		regs->regs[30] = (unsigned long)VDSO_SYMBOL(thread->vm->vdso_addr, sigtramp);
	}

	if(k->sa.sa_flags & SA_SIGINFO){
		kframe->info = pending->info;
		regs->regs[1] = (unsigned long)&uframe->info;
		regs->regs[2] = (unsigned long)&uframe->uc;
	}

	/* copy to user sigframe */
	err = copy_to_user(user.usigframe, user.ksigframe, sigframe_size(&user));

	/* free kernel sigframe buffer */
	ihk_mc_free_pages(user.ksigframe, kpages);

	return err;
}

int
do_signal(unsigned long rc, void *regs0, struct thread *thread, struct sig_pending *pending, int syscallno)
{
	struct pt_regs *regs = regs0;
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
		regs = thread->uctx;

		/*
		 * Call do_signal() directly syscalls,
		 * need to save the return value.
		 */
		if (rc == -EINTR) {
			if (regs->syscallno == __NR_rt_sigtimedwait ||
			    regs->syscallno == __NR_rt_sigsuspend) {
				regs->regs[0] = rc;
			}
		}
	}
	else{
		rc = regs->regs[0];
	}

	mcs_rwlock_writer_lock(&thread->sigcommon->lock, &mcs_rw_node);
	k = thread->sigcommon->action + sig - 1;

	if(k->sa.sa_handler == SIG_IGN){
		kfree(pending);
		mcs_rwlock_writer_unlock(&thread->sigcommon->lock, &mcs_rw_node);
		goto out;
	}
	else if(k->sa.sa_handler){
		// check syscall to have restart ?
		restart = isrestart(syscallno, rc, sig,
				    k->sa.sa_flags & SA_RESTART);
		if (restart == 1) {
			/* Prepare for system call restart. */
			regs->regs[0] = regs->orig_x0;
		}

		if (setup_rt_frame(sig, rc, restart, syscallno, k, pending,
				   regs, thread)) {
			kfree(pending);
			mcs_rwlock_writer_unlock(&thread->sigcommon->lock, &mcs_rw_node);
			kprintf("do_signal,page_fault_thread_vm failed\n");
			terminate(0, sig);
			goto out;
		}

		// check signal handler is ONESHOT
		if(k->sa.sa_flags & SA_RESETHAND) {
			k->sa.sa_handler = SIG_DFL; 
		}

		if(!(k->sa.sa_flags & SA_NODEFER))
			thread->sigmask.__val[0] |= pending->sigmask.__val[0];
		kfree(pending);
		mcs_rwlock_writer_unlock(&thread->sigcommon->lock, &mcs_rw_node);

		if (thread->ctx.thread->flags & (1 << TIF_SINGLESTEP)) {
			siginfo_t info = {
				.si_code = TRAP_HWBKPT,
			};
			clear_single_step(thread);
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
				kmalloc(sizeof(struct pt_regs),
					IHK_MC_AP_NOWAIT);
			if (!thread->coredump_regs) {
				kprintf("%s: Out of memory\n", __func__);
				goto skip;
			}
			memcpy(thread->coredump_regs, regs,
			       sizeof(struct pt_regs));

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
	struct pt_regs *regs = regs0;

	return((regs->pstate & PSR_MODE_MASK) == PSR_MODE_EL0t);
}

void save_syscall_return_value(int num, unsigned long rc)
{
	const struct thread *thread = cpu_local_var(current);

	/*
	 * Save syscall return value.
	 */
	if (thread &&
	    thread->uctx &&
	    ((thread->uctx->regs[0] == thread->uctx->orig_x0) &&
	     (thread->uctx->pc == thread->uctx->orig_pc))) {
		thread->uctx->regs[0] = rc;
	}
}

unsigned long
do_kill(struct thread * thread, int pid, int tid, int sig, siginfo_t *info, int ptracecont)
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

	if(sig > SIGRTMAX || sig < 0)
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
			 (tproc->status != PS_EXITED &&
			  tproc->status != PS_ZOMBIE))) {
			if ((rc = hold_thread(tthread))) {
				kprintf("%s: ERROR hold_thread returned %d,tid=%d\n",
					__func__, rc, tthread->tid);
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

	if (sig < SIGRTMIN) { // SIGRTMIN - SIGRTMAX
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
			ihk_mc_interrupt_cpu(tthread->cpu_id, INTRID_CPU_NOTIFY);
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
	ihk_mc_user_context_t *regs = regs0;
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
		| MAP_SHARED		// 0x01
		| MAP_PRIVATE		// 0x02
		| MAP_FIXED		// 0x10
		| MAP_ANONYMOUS		// 0x20
		| MAP_LOCKED		// 0x2000
		| MAP_POPULATE		// 0x8000
		| MAP_HUGETLB		// 00040000
		| (0x3FU << MAP_HUGE_SHIFT) // FC000000
		;
	const int ignored_flags = 0
		| MAP_DENYWRITE		// 0x0800
		| MAP_NORESERVE		// 0x4000
		| MAP_STACK		// 0x20000
		;
	const int error_flags = 0
		| MAP_GROWSDOWN		// 0x0100
		| MAP_EXECUTABLE	// 0x1000
		| MAP_NONBLOCK		// 0x10000
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
		int hugeshift = flags & (0x3F << MAP_HUGE_SHIFT);

		/* OpenMPI expects -EINVAL when trying to map
		 * /dev/shm/ file with MAP_SHARED | MAP_HUGETLB
		 */
		if (!(flags & MAP_ANONYMOUS)) {
			error = -EINVAL;
			goto out;
		}

		if (hugeshift == 0) {
			/* default hugepage size */
			flags |= ihk_mc_get_linux_default_huge_page_shift() <<
				MAP_HUGE_SHIFT;
		} else if ((first_level_block_support &&
				hugeshift == MAP_HUGE_FIRST_BLOCK) ||
			   (first_level_block_support &&
				hugeshift == MAP_HUGE_FIRST_CONT_BLOCK) ||
			   hugeshift == MAP_HUGE_SECOND_BLOCK ||
			   hugeshift == MAP_HUGE_SECOND_CONT_BLOCK ||
			   hugeshift == MAP_HUGE_THIRD_CONT_BLOCK) {
			/*nop*/
		} else {
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
	addr = (flags & MAP_FIXED)? addr0: VALID_DUMMY_ADDR;
	len = (len0 + pgsize - 1) & ~(pgsize - 1);
	if ((addr & (pgsize - 1))
			|| (len == 0)
			|| !(flags & (MAP_SHARED | MAP_PRIVATE))
			|| ((flags & MAP_SHARED) && (flags & MAP_PRIVATE))
			|| (off0 & (pgsize - 1))) {
		ekprintf("sys_mmap(%lx,%lx,%x,%x,%x,%lx):EINVAL\n",
				addr0, len0, prot, flags0, fd, off0);
		error = -EINVAL;
		goto out;
	}

	if (addr < region->user_start
			|| region->user_end <= addr
			|| len > (region->user_end - region->user_start)) {
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

	addr = do_mmap(addr, len, prot, flags, fd, off0);

	error = 0;
out:
	dkprintf("sys_mmap(%lx,%lx,%x,%x,%d,%lx): %ld %lx\n",
			addr0, len0, prot, flags0, fd, off0, error, addr);
	return (!error)? addr: error;
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
		} else if ((first_level_block_support &&
				hugeshift == SHM_HUGE_FIRST_BLOCK) ||
			   (first_level_block_support &&
				hugeshift == SHM_HUGE_FIRST_CONT_BLOCK) ||
			   hugeshift == SHM_HUGE_SECOND_BLOCK ||
			   hugeshift == SHM_HUGE_SECOND_CONT_BLOCK ||
			   hugeshift == SHM_HUGE_THIRD_CONT_BLOCK) {
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

void
save_uctx(void *uctx, struct pt_regs *regs)
{
	struct trans_uctx {
		volatile int cond;
		int fregsize;
		struct user_pt_regs regs;
		unsigned long tls_baseaddr;
	} *ctx = uctx;

	if (!regs) {
		regs = current_pt_regs();
	}

	ctx->cond = 0;
	ctx->fregsize = 0;
	ctx->regs = regs->user_regs;
	asm volatile(
	"	mrs	%0, tpidr_el0"
	: "=r" (ctx->tls_baseaddr));
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
	unsigned long lphys, rphys;
	unsigned long lpage_left, rpage_left;
	unsigned long lpsize, rpsize;
	void *rva, *lva;
#if 0
	struct vm_range *range;
#endif
	struct mcs_rwlock_node_irqsave lock;
	struct mcs_rwlock_node update_lock;

	/* Sanity checks */
	if (flags) {
		return -EINVAL;
	}
	
	if (liovcnt > IOV_MAX || riovcnt > IOV_MAX) {
		return -EINVAL;
	}

#if 0
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
#endif

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

retry_llookup:
		/* Figure out local physical */
		/* TODO: remember page and do this only if necessary */
		ret = ihk_mc_pt_virt_to_phys_size(lthread->vm->address_space->page_table,
				local_iov[li].iov_base + loff, &lphys, &lpsize);

		if (ret) {
			uint64_t reason = PF_POPULATE | PF_WRITE | PF_USER;
			void *addr;

			if (faulted) {
				ret = -EFAULT;
				goto out;
			}

			/* Fault in pages */
			for (addr = (void *)
					(((unsigned long)local_iov[li].iov_base + loff)
					& PAGE_MASK);
					addr < (local_iov[li].iov_base + loff + to_copy);
					addr += PAGE_SIZE) {

				ret = page_fault_process_vm(lthread->vm, addr, reason);
				if (ret) {
					ret = -EFAULT;
					goto out;
				}
			}

			faulted = 1;
			goto retry_llookup;
		}

		lpage_left = ((((unsigned long)local_iov[li].iov_base + loff +
			lpsize) & ~(lpsize - 1)) -
			((unsigned long)local_iov[li].iov_base + loff));
		if (lpage_left < to_copy) {
			to_copy = lpage_left;
		}

		lva = phys_to_virt(lphys);

retry_rlookup:
		/* Figure out remote physical */
		/* TODO: remember page and do this only if necessary */
		ret = ihk_mc_pt_virt_to_phys_size(rvm->address_space->page_table,
				remote_iov[ri].iov_base + roff, &rphys, &rpsize);

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
			goto retry_rlookup;
		}

		rpage_left = ((((unsigned long)remote_iov[ri].iov_base + roff +
			rpsize) & ~(rpsize - 1)) -
			((unsigned long)remote_iov[ri].iov_base + roff));
		if (rpage_left < to_copy) {
			to_copy = rpage_left;
		}

		rva = phys_to_virt(rphys);

		fast_memcpy(
				(op == PROCESS_VM_READ) ? lva : rva,
				(op == PROCESS_VM_READ) ? rva : lva,
				to_copy);

		copied += to_copy;
		dkprintf("local_iov[%d]: 0x%lx %s remote_iov[%d]: 0x%lx, %lu copied, rpsize: %lu, rpage_left: %lu\n",
			li, local_iov[li].iov_base + loff, 
			(op == PROCESS_VM_READ) ? "<-" : "->", 
			ri, remote_iov[ri].iov_base + roff, to_copy,
			rpsize, rpage_left);

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
			memcpy(mpsr->nodes, mpsr->user_nodes,
			       sizeof(int) * count);
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
			memcpy(mpsr->nodes, mpsr->user_nodes,
			       sizeof(int) * count);
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
			memcpy(mpsr->nodes, mpsr->user_nodes,
			       sizeof(int) * count);
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
			memcpy(mpsr->nodes, mpsr->user_nodes,
			       sizeof(int) * count);
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
	for (i = i_s; i < i_e; i++) {
		if (mpsr->nodes[i] < 0 ||
				mpsr->nodes[i] >= ihk_mc_get_nr_numa_nodes() ||
				!test_bit(mpsr->nodes[i],
					mpsr->proc->vm->numa_mask)) {
			mpsr->phase_ret = -EINVAL;
			break;
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

time_t time(void)
{
	struct timespec ats;
	time_t ret = 0;

	if (gettime_local_support) {
		calculate_time_from_tsc(&ats);
		ret = ats.tv_sec;
	}
	return ret;
}

SYSCALL_DECLARE(time)
{
	return time();
}

void calculate_time_from_tsc(struct timespec *ts)
{
	long ver;
	unsigned long current_tsc;
	time_t sec_delta;
	long ns_delta;

	for (;;) {
		while ((ver = ihk_atomic64_read(&tod_data.version)) & 1) {
			/* settimeofday() is in progress */
			cpu_pause();
		}
		rmb(); /* fetch version before time */
		*ts = tod_data.origin;
		rmb(); /* fetch time before checking version */
		if (ver == ihk_atomic64_read(&tod_data.version)) {
			break;
		}

		/* settimeofday() has intervened */
		cpu_pause();
	}

	current_tsc = rdtsc();
	sec_delta = current_tsc / tod_data.clocks_per_sec;
	ns_delta = NS_PER_SEC * (current_tsc % tod_data.clocks_per_sec)
		/ tod_data.clocks_per_sec;
	/* calc. of ns_delta overflows if clocks_per_sec exceeds 18.44 GHz */

	ts->tv_sec += sec_delta;
	ts->tv_nsec += ns_delta;
	if (ts->tv_nsec >= NS_PER_SEC) {
		ts->tv_nsec -= NS_PER_SEC;
		++ts->tv_sec;
	}
}

extern void ptrace_syscall_event(struct thread *thread);
long arch_ptrace_syscall_event(struct thread *thread,
			       ihk_mc_user_context_t *ctx, long setret)
{
	ptrace_syscall_event(thread);
	return setret;
}
/*** End of File ***/
