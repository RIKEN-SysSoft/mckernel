/* fpsimd.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
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
#include <ihk/debug.h>
#include <process.h>
#include <bitmap.h>

//#define DEBUG_PRINT_FPSIMD

#ifdef DEBUG_PRINT_FPSIMD
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

#ifdef CONFIG_ARM64_SVE

/* Set of available vector lengths, as vq_to_bit(vq): */
static DECLARE_BITMAP(sve_vq_map, SVE_VQ_MAX);

/* Maximum supported vector length across all CPUs (initially poisoned) */
int sve_max_vl = -1;

/* Default VL for tasks that don't set it explicitly: */
int sve_default_vl = -1;

/*
 * Helpers to translate bit indices in sve_vq_map to VQ values (and
 * vice versa).  This allows find_next_bit() to be used to find the
 * _maximum_ VQ not exceeding a certain value.
 */

static unsigned int vq_to_bit(unsigned int vq)
{
	return SVE_VQ_MAX - vq;
}

static unsigned int bit_to_vq(unsigned int bit)
{
	if (bit >= SVE_VQ_MAX) {
		bit = SVE_VQ_MAX - 1;
	}
	return SVE_VQ_MAX - bit;
}

/*
 * All vector length selection from userspace comes through here.
 * We're on a slow path, so some sanity-checks are included.
 * If things go wrong there's a bug somewhere, but try to fall back to a
 * safe choice.
 */
static unsigned int find_supported_vector_length(unsigned int vl)
{
	int bit;
	int max_vl = sve_max_vl;

	if (!sve_vl_valid(vl)) {
		vl = SVE_VL_MIN;
	}

	if (!sve_vl_valid(max_vl)) {
		max_vl = SVE_VL_MIN;
	}

	if (vl > max_vl) {
		vl = max_vl;
	}

	bit = find_next_bit(sve_vq_map, SVE_VQ_MAX,
			    vq_to_bit(sve_vq_from_vl(vl)));
	return sve_vl_from_vq(bit_to_vq(bit));
}

static void sve_probe_vqs(DECLARE_BITMAP(map, SVE_VQ_MAX))
{
	unsigned int vq, vl;
	unsigned long zcr;

	bitmap_zero(map, SVE_VQ_MAX);

	zcr = ZCR_EL1_LEN_MASK;
	zcr = read_sysreg_s(SYS_ZCR_EL1) & ~zcr;

	for (vq = SVE_VQ_MAX; vq >= SVE_VQ_MIN; --vq) {
		/* self-syncing */
		write_sysreg_s(zcr | (vq - 1), SYS_ZCR_EL1);
		vl = sve_get_vl();
		/* skip intervening lengths */
		vq = sve_vq_from_vl(vl);
		set_bit(vq_to_bit(vq), map);
	}
}

void sve_init_vq_map(void)
{
	sve_probe_vqs(sve_vq_map);
}

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

	if (flags & ~(unsigned long)(PR_SVE_VL_INHERIT |
				     PR_SVE_SET_VL_ONEXEC)) {
		return -EINVAL;
	}

	if (!sve_vl_valid(vl)) {
		return -EINVAL;
	}

	/*
	 * Clamp to the maximum vector length that VL-agnostic SVE code can
	 * work with.  A flag may be assigned in the future to allow setting
	 * of larger vector lengths without confusing older software.
	 */
	if (vl > SVE_VL_ARCH_MAX) {
		vl = SVE_VL_ARCH_MAX;
	}

	vl = find_supported_vector_length(vl);

	if (flags & (PR_SVE_VL_INHERIT |
		     PR_SVE_SET_VL_ONEXEC)) {
		ti->sve_vl_onexec = vl;
	} else {
		/* Reset VL to system default on next exec: */
		ti->sve_vl_onexec = 0;
	}

	/* Only actually set the VL if not deferred: */
	if (flags & PR_SVE_SET_VL_ONEXEC) {
		goto out;
	}

	if (vl == ti->sve_vl) {
		goto out;
	}

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
	ti->sve_vl = vl;

out:
	ti->sve_flags = flags & PR_SVE_VL_INHERIT;

	return 0;
}

/* @ref.impl arch/arm64/kernel/fpsimd.c::sve_prctl_status */
/*
 * Encode the current vector length and flags for return.
 * This is only required for prctl(): ptrace has separate fields
 */
static int sve_prctl_status(unsigned long flags)
{
	int ret;
	struct thread_info *ti = cpu_local_var(current)->ctx.thread;

	if (flags & PR_SVE_SET_VL_ONEXEC) {
		ret = ti->sve_vl_onexec;
	}
	else {
		ret = ti->sve_vl;
	}

	if (ti->sve_flags & PR_SVE_VL_INHERIT) {
		ret |= PR_SVE_VL_INHERIT;
	}
	return ret;
}

/* @ref.impl arch/arm64/kernel/fpsimd.c::sve_set_task_vl */
int sve_set_thread_vl(unsigned long arg)
{
	unsigned long vl, flags;
	int ret;

	vl = arg & PR_SVE_VL_LEN_MASK;
	flags = arg & ~vl;

	/* Instead of system_supports_sve() */
	if (unlikely(!(elf_hwcap & HWCAP_SVE))) {
		return -EINVAL;
	}

	ret = sve_set_vector_length(cpu_local_var(current), vl, flags);
	if (ret) {
		return ret;
	}
	return sve_prctl_status(flags);
}

/* @ref.impl arch/arm64/kernel/fpsimd.c::sve_get_ti_vl */
int sve_get_thread_vl(void)
{
	/* Instead of system_supports_sve() */
	if (unlikely(!(elf_hwcap & HWCAP_SVE))) {
		return -EINVAL;
	}
	return sve_prctl_status(0);
}

void do_sve_acc(unsigned int esr, struct pt_regs *regs)
{
	kprintf("PANIC: CPU: %d PID: %d ESR: %x Trapped SVE access.\n",
		ihk_mc_get_processor_id(), cpu_local_var(current)->proc->pid, esr);
	panic("");
}

void sve_setup(void)
{
	extern unsigned long ihk_param_default_vl;
	uint64_t zcr;

	/* Instead of system_supports_sve() */
	if (unlikely(!(elf_hwcap & HWCAP_SVE))) {
		return;
	}

	/* init sve_vq_map bitmap */
	sve_init_vq_map();

	/*
	 * The SVE architecture mandates support for 128-bit vectors,
	 * so sve_vq_map must have at least SVE_VQ_MIN set.
	 * If something went wrong, at least try to patch it up:
	 */
	if (!test_bit(vq_to_bit(SVE_VQ_MIN), sve_vq_map)) {
		set_bit(vq_to_bit(SVE_VQ_MIN), sve_vq_map);
	}

	zcr = read_system_reg(SYS_ZCR_EL1);
	sve_max_vl = sve_vl_from_vq((zcr & ZCR_EL1_LEN_MASK) + 1);

	/*
	 * Sanity-check that the max VL we determined through CPU features
	 * corresponds properly to sve_vq_map.  If not, do our best:
	 */
	if (sve_max_vl != find_supported_vector_length(sve_max_vl)) {
		sve_max_vl = find_supported_vector_length(sve_max_vl);
	}

	sve_default_vl = ihk_param_default_vl;

	if (ihk_param_default_vl !=
		find_supported_vector_length(ihk_param_default_vl)) {
		kprintf("SVE: Getting unsupported default VL = %d "
			"from HOST-Linux.\n", sve_default_vl);
		sve_default_vl = find_supported_vector_length(64);
		kprintf("SVE: Using default vl(%d byte).\n",
			sve_default_vl);
	}

	kprintf("SVE: maximum available vector length %u bytes per vector\n",
		sve_max_vl);
	kprintf("SVE: default vector length %u bytes per vector\n",
		sve_default_vl);
}

#else /* CONFIG_ARM64_SVE */

void sve_setup(void)
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
