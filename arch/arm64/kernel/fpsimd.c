/* fpsimd.c COPYRIGHT FUJITSU LIMITED 2016-2018 */
#include <thread_info.h>
#include <fpsimd.h>
#include <cpuinfo.h>
#include <lwk/compiler.h>
#include <ikc/ihk.h>
#include <hwcap.h>
#include <cls.h>
#include <prctl.h>
#include <cpufeature.h>
#include <kmalloc.h>
#include <debug.h>
#include <process.h>

//#define DEBUG_PRINT_FPSIMD

#ifdef DEBUG_PRINT_FPSIMD
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

#ifdef CONFIG_ARM64_SVE

/* Maximum supported vector length across all CPUs (initially poisoned) */
int sve_max_vl = -1;
/* Default VL for tasks that don't set it explicitly: */
int sve_default_vl = -1;

size_t sve_state_size(struct thread const *thread)
{
	unsigned int vl = thread->ctx.thread->sve_vl;

	BUG_ON(!sve_vl_valid(vl));
	return SVE_SIG_REGS_SIZE(sve_vq_from_vl(vl));
}

void sve_free(struct thread *thread)
{
	if (thread->ctx.thread->sve_state) {
		kfree(thread->ctx.thread->sve_state);
		thread->ctx.thread->sve_state = NULL;
	}
}

void sve_alloc(struct thread *thread)
{
	if (thread->ctx.thread->sve_state) {
		return;
	}

	thread->ctx.thread->sve_state =
		kmalloc(sve_state_size(thread), IHK_MC_AP_NOWAIT);
	BUG_ON(!thread->ctx.thread->sve_state);

	memset(thread->ctx.thread->sve_state, 0, sve_state_size(thread));
}

static int get_nr_threads(struct process *proc)
{
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;
	int nr_threads = 0;

	mcs_rwlock_reader_lock(&proc->threads_lock, &lock);
	list_for_each_entry(child, &proc->threads_list, siblings_list){
		nr_threads++;
	}
	mcs_rwlock_reader_unlock(&proc->threads_lock, &lock);
	return nr_threads;
}

/* @ref.impl arch/arm64/kernel/fpsimd.c::sve_set_vector_length */
int sve_set_vector_length(struct thread *thread,
			unsigned long vl, unsigned long flags)
{
	struct thread_info *ti = thread->ctx.thread;

	BUG_ON(thread == cpu_local_var(current) && cpu_local_var(no_preempt) == 0);

	/*
	 * To avoid accidents, forbid setting for individual threads of a
	 * multithreaded process.  User code that knows what it's doing can
	 * pass PR_SVE_SET_VL_THREAD to override this restriction:
	 */
	if (!(flags & PR_SVE_SET_VL_THREAD) && get_nr_threads(thread->proc) != 1) {
		return -EINVAL;
	}
	flags &= ~(unsigned long)PR_SVE_SET_VL_THREAD;

	if (flags & ~(unsigned long)(PR_SVE_SET_VL_INHERIT |
				     PR_SVE_SET_VL_ONEXEC)) {
		return -EINVAL;
	}

	if (!sve_vl_valid(vl)) {
		return -EINVAL;
	}

	if (vl > sve_max_vl) {
		BUG_ON(!sve_vl_valid(sve_max_vl));
		vl = sve_max_vl;
	}

	if (flags & (PR_SVE_SET_VL_ONEXEC |
		     PR_SVE_SET_VL_INHERIT)) {
		ti->sve_vl_onexec = vl;
	} else {
		/* Reset VL to system default on next exec: */
		ti->sve_vl_onexec = 0;
	}

	/* Only actually set the VL if not deferred: */
	if (flags & PR_SVE_SET_VL_ONEXEC) {
		goto out;
	}

	if (vl != ti->sve_vl) {
		if ((elf_hwcap & HWCAP_SVE)) {
			fp_regs_struct fp_regs;
			memset(&fp_regs, 0, sizeof(fp_regs));

			/* for self at prctl syscall */
			if (thread == cpu_local_var(current)) {
				save_fp_regs(thread);
				clear_fp_regs();
				thread_sve_to_fpsimd(thread, &fp_regs);
				sve_free(thread);

				ti->sve_vl = vl;

				sve_alloc(thread);
				thread_fpsimd_to_sve(thread, &fp_regs);
				restore_fp_regs(thread);
			/* for target thread at ptrace */
			} else {
				thread_sve_to_fpsimd(thread, &fp_regs);
				sve_free(thread);

				ti->sve_vl = vl;

				sve_alloc(thread);
				thread_fpsimd_to_sve(thread, &fp_regs);
			}
		}
	}
	ti->sve_vl = vl;

out:
	ti->sve_flags = flags & PR_SVE_SET_VL_INHERIT;

	return 0;
}

/* @ref.impl arch/arm64/kernel/fpsimd.c::sve_prctl_status */
/*
 * Encode the current vector length and flags for return.
 * This is only required for prctl(): ptrace has separate fields
 */
static int sve_prctl_status(const struct thread_info *ti)
{
	int ret = ti->sve_vl;

	ret |= ti->sve_flags << 16;

	return ret;
}

/* @ref.impl arch/arm64/kernel/fpsimd.c::sve_set_task_vl */
int sve_set_thread_vl(struct thread *thread, const unsigned long vector_length,
			const unsigned long flags)
{
	int ret;

	if (!(elf_hwcap & HWCAP_SVE)) {
		return -EINVAL;
	}

	BUG_ON(thread != cpu_local_var(current));

	preempt_disable();
	ret = sve_set_vector_length(thread, vector_length, flags);
	preempt_enable();

	if (ret) {
		return ret;
	}
	return sve_prctl_status(thread->ctx.thread);
}

/* @ref.impl arch/arm64/kernel/fpsimd.c::sve_get_ti_vl */
int sve_get_thread_vl(const struct thread *thread)
{
	if (!(elf_hwcap & HWCAP_SVE)) {
		return -EINVAL;
	}
	return sve_prctl_status(thread->ctx.thread);
}

void do_sve_acc(unsigned int esr, struct pt_regs *regs)
{
	kprintf("PANIC: CPU: %d PID: %d ESR: %x Trapped SVE access.\n",
		ihk_mc_get_processor_id(), cpu_local_var(current)->proc->pid, esr);
	panic("");
}

void init_sve_vl(void)
{
	extern unsigned long ihk_param_default_vl;
	uint64_t zcr;

	if (unlikely(!(elf_hwcap & HWCAP_SVE))) {
		return;
	}

	zcr = read_system_reg(SYS_ZCR_EL1);
	BUG_ON(((zcr & ZCR_EL1_LEN_MASK) + 1) * 16 > sve_max_vl);

	sve_max_vl = ((zcr & ZCR_EL1_LEN_MASK) + 1) * 16;
	sve_default_vl = ihk_param_default_vl;

	if (sve_default_vl == 0) {
		kprintf("SVE: Getting default VL = 0 from HOST-Linux.\n");
		sve_default_vl = sve_max_vl > 64 ? 64 : sve_max_vl;
		kprintf("SVE: Using default vl(%d byte).\n", sve_default_vl);
	}

	kprintf("SVE: maximum available vector length %u bytes per vector\n",
		sve_max_vl);
	kprintf("SVE: default vector length %u bytes per vector\n",
		sve_default_vl);
}

#else /* CONFIG_ARM64_SVE */

void init_sve_vl(void)
{
	/* nothing to do. */
}

#endif /* CONFIG_ARM64_SVE */

/* @ref.impl arch/arm64/kernel/fpsimd.c::__task_pffr */
static void *__thread_pffr(struct thread *thread)
{
	unsigned int vl = thread->ctx.thread->sve_vl;

	BUG_ON(!sve_vl_valid(vl));
	return (char *)thread->ctx.thread->sve_state + 34 * vl;
}

/* There is a need to call from to check the HWCAP_FP and HWCAP_ASIMD state. */
void thread_fpsimd_load(struct thread *thread)
{
	if (likely(elf_hwcap & HWCAP_SVE)) {
		unsigned int vl = thread->ctx.thread->sve_vl;

		BUG_ON(!sve_vl_valid(vl));
		sve_load_state(__thread_pffr(thread), &thread->fp_regs->fpsr, sve_vq_from_vl(vl) - 1);
		dkprintf("sve for TID %d restored\n", thread->tid);
	} else {
		// Load the current FPSIMD state to memory.
		fpsimd_load_state(thread->fp_regs);
		dkprintf("fp_regs for TID %d restored\n", thread->tid);
	}
}

/* There is a need to call from to check the HWCAP_FP and HWCAP_ASIMD state. */
void thread_fpsimd_save(struct thread *thread)
{
	if (likely(elf_hwcap & HWCAP_SVE)) {
		sve_save_state(__thread_pffr(thread), &thread->fp_regs->fpsr);
		dkprintf("sve for TID %d saved\n", thread->tid);
	} else {
		// Save the current FPSIMD state to memory.
		fpsimd_save_state(thread->fp_regs);
		dkprintf("fp_regs for TID %d saved\n", thread->tid);
	}
}

/* @ref.impl arch/arm64/kernel/fpsimd.c::__task_fpsimd_to_sve */
static void __thread_fpsimd_to_sve(struct thread *thread, fp_regs_struct *fp_regs, unsigned int vq)
{
	struct fpsimd_sve_state(vq) *sst = thread->ctx.thread->sve_state;
	unsigned int i;

	for (i = 0; i < 32; i++) {
		sst->zregs[i][0] = fp_regs->vregs[i];
	}
}

/* @ref.impl arch/arm64/kernel/fpsimd.c::task_fpsimd_to_sve */
void thread_fpsimd_to_sve(struct thread *thread, fp_regs_struct *fp_regs)
{
	unsigned int vl = thread->ctx.thread->sve_vl;

	BUG_ON(!sve_vl_valid(vl));
	__thread_fpsimd_to_sve(thread, fp_regs, sve_vq_from_vl(vl));
}

/* @ref.impl arch/arm64/kernel/fpsimd.c::__task_sve_to_fpsimd */
static void __thread_sve_to_fpsimd(struct thread *thread, fp_regs_struct *fp_regs, unsigned int vq)
{
	struct fpsimd_sve_state(vq) *sst = thread->ctx.thread->sve_state;
	unsigned int i;

	for (i = 0; i < 32; i++) {
		fp_regs->vregs[i] = sst->zregs[i][0];
	}
}

/* @ref.impl arch/arm64/kernel/fpsimd.c::task_sve_to_fpsimd */
void thread_sve_to_fpsimd(struct thread *thread, fp_regs_struct *fp_regs)
{
	unsigned int vl = thread->ctx.thread->sve_vl;

	BUG_ON(!sve_vl_valid(vl));
	__thread_sve_to_fpsimd(thread, fp_regs, sve_vq_from_vl(vl));
}
