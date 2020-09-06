/* thread_info.h COPYRIGHT FUJITSU LIMITED 2015-2019 */
#ifndef __HEADER_ARM64_COMMON_THREAD_INFO_H
#define __HEADER_ARM64_COMMON_THREAD_INFO_H

#define MIN_KERNEL_STACK_SHIFT	18

#include <arch-memory.h>

#if (MIN_KERNEL_STACK_SHIFT < PAGE_SHIFT)
#define KERNEL_STACK_SHIFT	PAGE_SHIFT
#else
#define KERNEL_STACK_SHIFT	MIN_KERNEL_STACK_SHIFT
#endif

#define KERNEL_STACK_SIZE	(UL(1) << KERNEL_STACK_SHIFT)
#define THREAD_START_SP		KERNEL_STACK_SIZE - 16

#ifndef __ASSEMBLY__

#include <process.h>
#include <prctl.h>

struct cpu_context {
	unsigned long x19;
	unsigned long x20;
	unsigned long x21;
	unsigned long x22;
	unsigned long x23;
	unsigned long x24;
	unsigned long x25;
	unsigned long x26;
	unsigned long x27;
	unsigned long x28;
	unsigned long fp;
	unsigned long sp;
	unsigned long pc;
};

struct thread_info {
	unsigned long		flags;		/* low level flags */
//	mm_segment_t		addr_limit;	/* address limit */
//	struct task_struct	*task;		/* main task structure */
//	struct exec_domain	*exec_domain;	/* execution domain */
//	struct restart_block	restart_block;
//	int			preempt_count;	/* 0 => preemptable, <0 => bug */
	int			cpu;		/* cpu */
	struct cpu_context	cpu_context;	/* kernel_context */
	void			*sve_state;	/* SVE registers, if any */
	unsigned int		sve_vl;		/* SVE vector length */
	unsigned int		sve_vl_onexec;	/* SVE vl after next exec */
	unsigned long		sve_flags;	/* SVE related flags */
	unsigned long		fault_address;	/* fault info */
	unsigned long		fault_code;	/* ESR_EL1 value */
};

/* Flags for sve_flags (intentionally defined to match the prctl flags) */

/* Inherit sve_vl and sve_flags across execve(): */
#define THREAD_VL_INHERIT	PR_SVE_VL_INHERIT

struct arm64_cpu_local_thread {
	struct thread_info thread_info;
	unsigned long paniced;
	uint64_t panic_regs[34];
};

union arm64_cpu_local_variables {
	struct arm64_cpu_local_thread arm64_cpu_local_thread;
	unsigned long stack[KERNEL_STACK_SIZE / sizeof(unsigned long)];
};
extern union arm64_cpu_local_variables init_thread_info;

/*
 * how to get the current stack pointer from C
 */
register unsigned long current_stack_pointer asm ("sp");

/*
 * how to get the thread information struct from C
 */
static inline struct thread_info *current_thread_info(void)
{
	unsigned long ti = 0;

	ti = ALIGN_DOWN(current_stack_pointer, KERNEL_STACK_SIZE);

	return (struct thread_info *)ti;
}

/*
 * how to get the pt_regs struct from C
 */
static inline struct pt_regs *current_pt_regs(void)
{
	unsigned long regs = 0;

	regs = ALIGN_DOWN(current_stack_pointer, KERNEL_STACK_SIZE);
	regs += THREAD_START_SP - sizeof(struct pt_regs);

	return (struct pt_regs *)regs;
}

#endif /* !__ASSEMBLY__ */

#define TIF_SINGLESTEP		21

#endif /* !__HEADER_ARM64_COMMON_THREAD_INFO_H */
