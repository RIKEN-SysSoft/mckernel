/* context.h COPYRIGHT FUJITSU LIMITED 2015-2018 */
#ifndef __HEADER_ARM64_IHK_CONTEXT_H
#define __HEADER_ARM64_IHK_CONTEXT_H

#include <registers.h>

struct thread_info;
typedef struct {
	struct thread_info *thread;
} ihk_mc_kernel_context_t;

struct user_pt_regs {
	unsigned long regs[31];
	unsigned long sp;
	unsigned long pc;
	unsigned long pstate;
};

struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			unsigned long regs[31];
			unsigned long sp;
			unsigned long pc;
			unsigned long pstate;
		};
	};
	unsigned long orig_x0;
	unsigned long syscallno;
};

typedef struct pt_regs ihk_mc_user_context_t;

/* @ref.impl arch/arm64/include/asm/ptrace.h */
#define GET_IP(regs)		((unsigned long)(regs)->pc)
#define SET_IP(regs, value)	((regs)->pc = ((uint64_t) (value)))

/* @ref.impl arch/arm64/include/asm/ptrace.h */
/* AArch32 CPSR bits */
#define COMPAT_PSR_MODE_MASK	0x0000001f

/* @ref.impl include/asm-generic/ptrace.h */
static inline unsigned long instruction_pointer(struct pt_regs *regs)
{
	return GET_IP(regs);
}
/* @ref.impl include/asm-generic/ptrace.h */
static inline void instruction_pointer_set(struct pt_regs *regs,
					   unsigned long val)
{
	SET_IP(regs, val);
}

/* @ref.impl arch/arm64/include/asm/ptrace.h */
/*
 * Write a register given an architectural register index r.
 * This handles the common case where 31 means XZR, not SP.
 */
static inline void pt_regs_write_reg(struct pt_regs *regs, int r,
				     unsigned long val)
{
	if (r != 31)
		regs->regs[r] = val;
}

/* temp */
#define ihk_mc_syscall_arg0(uc) (uc)->regs[0]
#define ihk_mc_syscall_arg1(uc) (uc)->regs[1]
#define ihk_mc_syscall_arg2(uc) (uc)->regs[2]
#define ihk_mc_syscall_arg3(uc) (uc)->regs[3]
#define ihk_mc_syscall_arg4(uc) (uc)->regs[4]
#define ihk_mc_syscall_arg5(uc) (uc)->regs[5]

#define ihk_mc_syscall_ret(uc)  (uc)->regs[0]
#define ihk_mc_syscall_number(uc)  (uc)->regs[8]

#define ihk_mc_syscall_pc(uc)   (uc)->pc
#define ihk_mc_syscall_sp(uc)   (uc)->sp

#endif /* !__HEADER_ARM64_IHK_CONTEXT_H */
