/* ptrace.c COPYRIGHT FUJITSU LIMITED 2016-2018 */
#include <errno.h>
#include <debug-monitors.h>
#include <hw_breakpoint.h>
#include <elfcore.h>
#include <fpsimd.h>
#include <kmalloc.h>
#include <memory.h>
#include <uio.h>
#include <lwk/compiler.h>
#include <hwcap.h>
#include <string.h>
#include <thread_info.h>
#include <debug.h>

//#define DEBUG_PRINT_SC

#ifdef DEBUG_PRINT_SC
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

#define NOT_IMPLEMENTED()  do { kprintf("%s is not implemented\n", __func__); while(1);} while(0)

extern void save_debugreg(unsigned long *debugreg);
extern int interrupt_from_user(void *);

enum aarch64_regset {
	REGSET_GPR,
	REGSET_FPR,
	REGSET_TLS,
	REGSET_HW_BREAK,
	REGSET_HW_WATCH,
	REGSET_SYSTEM_CALL,
#ifdef CONFIG_ARM64_SVE
	REGSET_SVE,
#endif /* CONFIG_ARM64_SVE */
};

struct user_regset;
typedef long user_regset_get_fn(struct thread *target,
				const struct user_regset *regset,
				unsigned int pos, unsigned int count,
				void *kbuf, void __user *ubuf);

typedef long user_regset_set_fn(struct thread *target,
				const struct user_regset *regset,
				unsigned int pos, unsigned int count,
				const void *kbuf, const void __user *ubuf);

struct user_regset {
	user_regset_get_fn *get;
	user_regset_set_fn *set;
	unsigned int n;
	unsigned int size;
	unsigned int core_note_type;
};

long ptrace_read_user(struct thread *thread, long addr, unsigned long *value)
{
	return -EIO;
}

long ptrace_write_user(struct thread *thread, long addr, unsigned long value)
{
	return -EIO;
}

long ptrace_read_fpregs(struct thread *thread, void *fpregs)
{
	return -EIO;
}

long ptrace_write_fpregs(struct thread *thread, void *fpregs)
{
	return -EIO;
}

/* @ref.impl arch/arm64/kernel/ptrace.c::ptrace_hbp_get_resource_info */
unsigned int ptrace_hbp_get_resource_info(unsigned int note_type)
{
	unsigned char num;
	unsigned int reg = 0;

	switch (note_type) {
	case NT_ARM_HW_BREAK:
		num = hw_breakpoint_slots(TYPE_INST);
		break;
	case NT_ARM_HW_WATCH:
		num = hw_breakpoint_slots(TYPE_DATA);
		break;
	default:
		return -EINVAL;
	}

	reg |= debug_monitors_arch();
	reg <<= 8;
	reg |= num;

	return reg;
}

/* @ref.impl include/linux/regset.h::user_regset_copyout */
static inline long user_regset_copyout(unsigned int *pos, unsigned int *count,
				       void **kbuf,
				       void __user **ubuf, const void *data,
				       const int start_pos, const int end_pos)
{
	if (*count == 0) {
		return 0;
	}

	BUG_ON(*pos < start_pos);
	if (end_pos < 0 || *pos < end_pos) {
		unsigned int copy = 0;

		if ((end_pos < 0) || (*count < (end_pos - *pos))) {
			copy = *count;
		} else {
			copy = (end_pos - *pos);
		}

		data += *pos - start_pos;
		if (*kbuf) {
			memcpy(*kbuf, data, copy);
			*kbuf += copy;
		} else if (copy_to_user(*ubuf, data, copy)) {
			return -EFAULT;
		} else {
			*ubuf += copy;
		}
		*pos += copy;
		*count -= copy;
	}
	return 0;
}

/* @ref.impl include/linux/regset.h::user_regset_copyin */
static inline long user_regset_copyin(unsigned int *pos, unsigned int *count,
				      const void **kbuf,
				      const void __user **ubuf, void *data,
				      const int start_pos, const int end_pos)
{
	if (*count == 0) {
		return 0;
	}

	BUG_ON(*pos < start_pos);
	if (end_pos < 0 || *pos < end_pos) {
		unsigned int copy = 0;

		if ((end_pos < 0) || (*count < (end_pos - *pos))) {
			copy = *count;
		} else {
			copy = (end_pos - *pos);
		}

		data += *pos - start_pos;
		if (*kbuf) {
			memcpy(data, *kbuf, copy);
			*kbuf += copy;
		} else if (copy_from_user(data, *ubuf, copy)) {
			return -EFAULT;
		} else {
			*ubuf += copy;
		}
		*pos += copy;
		*count -= copy;
	}
	return 0;
}

/* @ref.impl include/linux/regset.h::user_regset_copyout_zero */
static inline long user_regset_copyout_zero(unsigned int *pos,
					    unsigned int *count,
					    void **kbuf, void __user **ubuf,
					    const int start_pos,
					    const int end_pos)
{
	if (*count == 0) {
		return 0;
	}

	BUG_ON(*pos < start_pos);
	if (end_pos < 0 || *pos < end_pos) {
		unsigned int copy = 0;
		char *tmp = NULL;

		if ((end_pos < 0) || (*count < (end_pos - *pos))) {
			copy = *count;
		} else {
			copy = (end_pos - *pos);
		}

		if (*kbuf) {
			memset(*kbuf, 0, copy);
			*kbuf += copy;
		} else {
			tmp = kmalloc(copy, IHK_MC_AP_NOWAIT);
			if (tmp == NULL) {
				return -ENOMEM;
			}
			memset(tmp, 0, copy);

			if (copy_to_user(*ubuf, tmp, copy)) {
				kfree(tmp);
				return -EFAULT;
			} else {
				*ubuf += copy;
			}
			kfree(tmp);
		}
		*pos += copy;
		*count -= copy;
	}
	return 0;
}

/* @ref.impl include/linux/regset.h::user_regset_copyin_ignore */
static inline int user_regset_copyin_ignore(unsigned int *pos,
					    unsigned int *count,
					    const void **kbuf,
					    const void __user **ubuf,
					    const int start_pos,
					    const int end_pos)
{
	if (*count == 0) {
		return 0;
	}

	BUG_ON(*pos < start_pos);
	if (end_pos < 0 || *pos < end_pos) {
		unsigned int copy = 0;

		if ((end_pos < 0) || (*count < (end_pos - *pos))) {
			copy = *count;
		} else {
			copy = (end_pos - *pos);
		}

		if (*kbuf) {
			*kbuf += copy;
		} else {
			*ubuf += copy;
		}
		*pos += copy;
		*count -= copy;
	}
	return 0;
}

/* @ref.impl include/linux/regset.h::copy_regset_to_user */
static inline long copy_regset_to_user(struct thread *target,
				       const struct user_regset *regset,
				       unsigned int offset, unsigned int size,
				       void __user *data)
{
	if (!regset->get) {
		return -EOPNOTSUPP;
	}
	return regset->get(target, regset, offset, size, NULL, data);
}

/* @ref.impl include/linux/regset.h::copy_regset_from_user */
static inline long copy_regset_from_user(struct thread *target,
					 const struct user_regset *regset,
					 unsigned int offset, unsigned int size,
					 const void __user *data)
{
	if (!regset->set) {
		return -EOPNOTSUPP;
	}
	return regset->set(target, regset, offset, size, NULL, data);
}

/*
 * Bits which are always architecturally RES0 per ARM DDI 0487A.h
 * Userspace cannot use these until they have an architectural meaning.
 * We also reserve IL for the kernel; SS is handled dynamically.
 */
#define SPSR_EL1_AARCH64_RES0_BITS	0xffffffff0fdffc20UL

static int valid_native_regs(struct user_pt_regs *regs)
{
	regs->pstate &= ~SPSR_EL1_AARCH64_RES0_BITS;

	if (interrupt_from_user(regs) && !(regs->pstate & PSR_MODE32_BIT) &&
	    (regs->pstate & PSR_D_BIT) == 0 &&
	    (regs->pstate & PSR_A_BIT) == 0 &&
	    (regs->pstate & PSR_I_BIT) == 0 &&
	    (regs->pstate & PSR_F_BIT) == 0) {
		return 1;
	}

	/* Force PSR to a valid 64-bit EL0t */
	regs->pstate &= PSR_N_BIT | PSR_Z_BIT | PSR_C_BIT | PSR_V_BIT;

	return 0;
}

static int valid_user_regs(struct user_pt_regs *regs, struct thread *thread)
{
	if (!(thread->ctx.thread->flags & TIF_SINGLESTEP)) {
		regs->pstate &= ~DBG_SPSR_SS;
	}
	return valid_native_regs(regs);
}

/* read NT_PRSTATUS */
static long gpr_get(struct thread *target, const struct user_regset *regset,
		    unsigned int pos, unsigned int count,
		    void *kbuf, void __user *ubuf)
{
	struct user_pt_regs *uregs = &target->uctx->user_regs;
	return user_regset_copyout(&pos, &count, &kbuf, &ubuf, uregs, 0, -1);
}

/* write NT_PRSTATUS */
static long gpr_set(struct thread *target, const struct user_regset *regset,
		    unsigned int pos, unsigned int count,
		    const void *kbuf, const void __user *ubuf)
{
	long ret;
	struct user_pt_regs newregs = target->uctx->user_regs;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &newregs, 0, -1);
	if (ret) {
		goto out;
	}

	if (!valid_user_regs(&newregs, target)) {
		ret = -EINVAL;
		goto out;
	}
	target->uctx->user_regs = newregs;
out:
	return ret;
}

/* read NT_PRFPREG */
static long fpr_get(struct thread *target,
		    const struct user_regset *regset,
		    unsigned int pos, unsigned int count,
		    void *kbuf, void __user *ubuf)
{
	long ret = -EINVAL;

	if (target->fp_regs == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	if (likely(elf_hwcap & (HWCAP_FP | HWCAP_ASIMD))) {
		struct user_fpsimd_state *uregs;

		if (likely(elf_hwcap & HWCAP_SVE)) {
			/* sync to sve --> fpsimd */
			thread_sve_to_fpsimd(target, target->fp_regs);
		}

		uregs = &target->fp_regs->user_fpsimd;
		ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf, uregs, 0, -1);
	}
out:
	return ret;
}

/* write NT_PRFPREG */
static long __fpr_set(struct thread *target,
		      const struct user_regset *regset,
		      unsigned int pos, unsigned int count,
		      const void *kbuf, const void __user *ubuf,
		      unsigned int start_pos)
{
	long ret = -EINVAL;

	if (target->fp_regs == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	if (likely(elf_hwcap & (HWCAP_FP | HWCAP_ASIMD))) {
		struct user_fpsimd_state newstate;

		if (likely(elf_hwcap & HWCAP_SVE)) {
			/* sync to sve --> fpsimd */
			thread_sve_to_fpsimd(target, target->fp_regs);
		}

		newstate = target->fp_regs->user_fpsimd;
		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &newstate,
					 start_pos, start_pos + sizeof(newstate));
		if (ret) {
			goto out;
		}

		target->fp_regs->user_fpsimd = newstate;

		if (likely(elf_hwcap & HWCAP_SVE)) {
			/* sync to fpsimd --> sve */
			thread_fpsimd_to_sve(target, target->fp_regs);
		}
	}
out:
	return ret;
}

/* write NT_PRFPREG */
static long fpr_set(struct thread *target, const struct user_regset *regset,
		    unsigned int pos, unsigned int count,
		    const void *kbuf, const void __user *ubuf)
{
	return __fpr_set(target, regset, pos, count, kbuf, ubuf, 0);
}

/* read NT_ARM_TLS */
static long tls_get(struct thread *target, const struct user_regset *regset,
		    unsigned int pos, unsigned int count,
		    void *kbuf, void __user *ubuf)
{
	unsigned long *tls = &target->tlsblock_base;
	return user_regset_copyout(&pos, &count, &kbuf, &ubuf, tls, 0, -1);
}

/* write NT_ARM_TLS */
static long tls_set(struct thread *target, const struct user_regset *regset,
		    unsigned int pos, unsigned int count,
		    const void *kbuf, const void __user *ubuf)
{
	long ret;
	unsigned long tls = target->tlsblock_base;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &tls, 0, -1);
	if (ret) {
		goto out;
	}

	target->tlsblock_base = tls;
out:
	return ret;
}

/* read NT_ARM_SYSTEM_CALL */
static long system_call_get(struct thread *target,
			    const struct user_regset *regset,
			    unsigned int pos, unsigned int count,
			    void *kbuf, void __user *ubuf)
{
	int syscallno = target->uctx->syscallno;

	return user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				   &syscallno, 0, -1);
}

/* write NT_ARM_SYSTEM_CALL */
static long system_call_set(struct thread *target,
			    const struct user_regset *regset,
			    unsigned int pos, unsigned int count,
			    const void *kbuf, const void __user *ubuf)
{
	int syscallno = target->uctx->syscallno;
	long ret;

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &syscallno, 0, -1);
	if (ret) {
		goto out;
	}

	target->uctx->syscallno = syscallno;
out:
	return ret;
}

#define PTRACE_HBP_ADDR_SZ	sizeof(uint64_t)
#define PTRACE_HBP_CTRL_SZ	sizeof(uint32_t)
#define PTRACE_HBP_PAD_SZ	sizeof(uint32_t)

/* read NT_ARM_HW_BREAK or NT_ARM_HW_WATCH */
static long hw_break_get(struct thread *target,
			 const struct user_regset *regset,
			 unsigned int pos, unsigned int count,
			 void *kbuf, void __user *ubuf)
{
	unsigned int note_type = regset->core_note_type;
	long ret = -EINVAL;
	int idx = 0, offset, limit, bw;
	uint32_t info, ctrl;
	uint64_t addr;
	struct user_hwdebug_state *hws = NULL;

	if (note_type != NT_ARM_HW_BREAK &&
	    note_type != NT_ARM_HW_WATCH) {
		goto out;
	}

	if (target->ptrace_debugreg == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	bw = (note_type == NT_ARM_HW_BREAK ? HWS_BREAK : HWS_WATCH);
	hws = (struct user_hwdebug_state *)target->ptrace_debugreg + bw;

	/* Resource info */
	info = hws->dbg_info;
	ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf, &info, 0,
				  sizeof(info));
	if (ret) {
		goto out;
	}

	/* Pad */
	offset = offsetof(struct user_hwdebug_state, pad);
	ret = user_regset_copyout_zero(&pos, &count, &kbuf, &ubuf, offset,
				       offset + PTRACE_HBP_PAD_SZ);
	if (ret) {
		goto out;
	}

	/* (address, ctrl) registers */
	offset = offsetof(struct user_hwdebug_state, dbg_regs);
	limit = regset->n * regset->size;
	while (count && offset < limit) {
		addr = hws->dbg_regs[idx].addr;
		ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf, &addr,
					  offset, offset + PTRACE_HBP_ADDR_SZ);
		if (ret) {
			goto out;
		}
		offset += PTRACE_HBP_ADDR_SZ;

		ctrl = hws->dbg_regs[idx].ctrl;
		ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf, &ctrl,
					  offset, offset + PTRACE_HBP_CTRL_SZ);
		if (ret) {
			goto out;
		}
		offset += PTRACE_HBP_CTRL_SZ;

		ret = user_regset_copyout_zero(&pos, &count, &kbuf, &ubuf,
					       offset,
					       offset + PTRACE_HBP_PAD_SZ);
		if (ret) {
			goto out;
		}
		offset += PTRACE_HBP_PAD_SZ;
		idx++;
	}
out:
	return ret;
}

/* write NT_ARM_HW_BREAK or NT_ARM_HW_WATCH */
static long hw_break_set(struct thread *target,
			 const struct user_regset *regset,
			 unsigned int pos, unsigned int count,
			 const void *kbuf, const void __user *ubuf)
{
	unsigned int note_type = regset->core_note_type;
	long ret = -EINVAL;
	int idx = 0, offset, limit, bw;
	uint32_t ctrl;
	uint64_t addr;
	struct user_hwdebug_state *hws = NULL;

	if (note_type != NT_ARM_HW_BREAK &&
	    note_type != NT_ARM_HW_WATCH) {
		goto out;
	}

	if (target->ptrace_debugreg == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	bw = (note_type == NT_ARM_HW_BREAK ? HWS_BREAK : HWS_WATCH);
	hws = (struct user_hwdebug_state *)target->ptrace_debugreg + bw;

	/* Resource info and pad */
	offset = offsetof(struct user_hwdebug_state, dbg_regs);
	ret = user_regset_copyin_ignore(&pos, &count, &kbuf, &ubuf, 0, offset);
	if (ret) {
		goto out;
	}

	/* (address, ctrl) registers */
	limit = regset->n * regset->size;
	while (count && offset < limit) {
		if (count < PTRACE_HBP_ADDR_SZ) {
			ret = -EINVAL;
			goto out;
		}

		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &addr,
					 offset, offset + PTRACE_HBP_ADDR_SZ);
		if (ret) {
			goto out;
		}
		hws->dbg_regs[idx].addr = addr;
		offset += PTRACE_HBP_ADDR_SZ;

		if (!count) {
			break;
		}

		ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &ctrl,
					 offset, offset + PTRACE_HBP_CTRL_SZ);
		if (ret) {
			goto out;
		}
		hws->dbg_regs[idx].ctrl = ctrl;
		offset += PTRACE_HBP_CTRL_SZ;

		ret = user_regset_copyin_ignore(&pos, &count, &kbuf, &ubuf,
						offset,
						offset + PTRACE_HBP_PAD_SZ);
		if (ret) {
			goto out;
		}
		offset += PTRACE_HBP_PAD_SZ;
		idx++;
	}
out:
	return ret;
}

#ifdef CONFIG_ARM64_SVE

/* read NT_ARM_SVE */
static long sve_get(struct thread *target,
		    const struct user_regset *regset,
		    unsigned int pos, unsigned int count,
		    void *kbuf, void __user *ubuf)
{
	long ret = -EINVAL;
	struct user_sve_header header;
	unsigned int vq;
	unsigned long start, end;

	if (target->fp_regs == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	/* Instead of system_supports_sve() */
	if (unlikely(!(elf_hwcap & HWCAP_SVE))) {
		goto out;
	}

	/* Header */
	memset(&header, 0, sizeof(header));

	header.vl = target->ctx.thread->sve_vl;

	BUG_ON(!sve_vl_valid(header.vl));
	vq = sve_vq_from_vl(header.vl);

	BUG_ON(!sve_vl_valid(sve_max_vl));
	header.max_vl = sve_max_vl;

	/* McKernel processes always enable SVE. */
	header.flags = SVE_PT_REGS_SVE;

	header.size = SVE_PT_SIZE(vq, header.flags);
	header.max_size = SVE_PT_SIZE(sve_vq_from_vl(header.max_vl),
				      SVE_PT_REGS_SVE);

	ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf, &header,
				  0, sizeof(header));
	if (ret) {
		goto out;
	}

	/* Registers: FPSIMD-only case */
	/*
	 * If McKernel, Nothing to do.
	 * Because McKernel processes always enable SVE.
	 */

	/* Otherwise: full SVE case */
	start = SVE_PT_SVE_OFFSET;
	end = SVE_PT_SVE_FFR_OFFSET(vq) + SVE_PT_SVE_FFR_SIZE(vq);

	BUG_ON(end < start);
	BUG_ON(end - start > sve_state_size(target));
	ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				  target->ctx.thread->sve_state,
				  start, end);
	if (ret) {
		goto out;
	}

	start = end;
	end = SVE_PT_SVE_FPSR_OFFSET(vq);

	BUG_ON(end < start);
	ret = user_regset_copyout_zero(&pos, &count, &kbuf, &ubuf,
				       start, end);
	if (ret) {
		goto out;
	}

	start = end;
	end = SVE_PT_SVE_FPCR_OFFSET(vq) + SVE_PT_SVE_FPCR_SIZE;

	BUG_ON((char *)(&target->fp_regs->fpcr + 1) <
	       (char *)&target->fp_regs->fpsr);
	BUG_ON(end < start);
	BUG_ON((char *)(&target->fp_regs->fpcr + 1) -
	       (char *)&target->fp_regs->fpsr !=
	        end - start);

	ret = user_regset_copyout(&pos, &count, &kbuf, &ubuf,
				  &target->fp_regs->fpsr,
				  start, end);
	if (ret) {
		goto out;
	}

	start = end;
	end = (SVE_PT_SIZE(SVE_VQ_MAX, SVE_PT_REGS_SVE) + 15) / 16 * 16;

	BUG_ON(end < start);
	ret = user_regset_copyout_zero(&pos, &count, &kbuf, &ubuf,
				       start, end);
out:
	return ret;
}

/* write NT_ARM_SVE case */
static long sve_set(struct thread *target,
		    const struct user_regset *regset,
		    unsigned int pos, unsigned int count,
		    const void *kbuf, const void __user *ubuf)
{
	long ret = -EINVAL;
	struct user_sve_header header;
	unsigned int vq;
	unsigned long start, end;

	if (target->fp_regs == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	/* Instead of system_supports_sve() */
	if (unlikely(!(elf_hwcap & HWCAP_SVE))) {
		goto out;
	}

	/* Header */
	if (count < sizeof(header)) {
		goto out;
	}

	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf, &header,
				 0, sizeof(header));
	if (ret) {
		goto out;
	}

	/*
	 * Apart from PT_SVE_REGS_MASK, all PT_SVE_* flags are consumed by
	 * sve_set_vector_length(), which will also validate them for us:
	 */
	ret = sve_set_vector_length(target, header.vl,
				    header.flags & ~SVE_PT_REGS_MASK);
	if (ret) {
		goto out;
	}

	/* Actual VL set may be less than the user asked for: */
	BUG_ON(!sve_vl_valid(target->ctx.thread->sve_vl));
	vq = sve_vq_from_vl(target->ctx.thread->sve_vl);

	/* Registers: FPSIMD-only case */
	if ((header.flags & SVE_PT_REGS_MASK) == SVE_PT_REGS_FPSIMD) {
		ret = __fpr_set(target, regset, pos, count, kbuf, ubuf,
				SVE_PT_FPSIMD_OFFSET);
		goto out;
	}

	/* Otherwise: full SVE case */
	start = SVE_PT_SVE_OFFSET;
	end = SVE_PT_SVE_FFR_OFFSET(vq) + SVE_PT_SVE_FFR_SIZE(vq);

	BUG_ON(end < start);
	BUG_ON(end - start > sve_state_size(target));
	ret = user_regset_copyin(&pos, &count, &kbuf, &ubuf,
				 target->ctx.thread->sve_state,
				 start, end);
	if (ret) {
		goto out;
	}

	start = end;
	end = SVE_PT_SVE_FPSR_OFFSET(vq);

	BUG_ON(end < start);
	ret = user_regset_copyin_ignore(&pos, &count, &kbuf, &ubuf,
					start, end);
	if (ret) {
		goto out;
	}

	start = end;
	end = SVE_PT_SVE_FPCR_OFFSET(vq) + SVE_PT_SVE_FPCR_SIZE;

	BUG_ON((char *)(&target->fp_regs->fpcr + 1) <
		(char *)&target->fp_regs->fpsr);
	BUG_ON(end < start);
	BUG_ON((char *)(&target->fp_regs->fpcr + 1) -
		(char *)&target->fp_regs->fpsr !=
		 end - start);

	user_regset_copyin(&pos, &count, &kbuf, &ubuf,
			   &target->fp_regs->fpsr,
			   start, end);
out:
	return ret;
}

#endif /* CONFIG_ARM64_SVE */

static const struct user_regset aarch64_regsets[] = {
	[REGSET_GPR] = {
		.core_note_type = NT_PRSTATUS,
		.n = sizeof(struct user_pt_regs) / sizeof(uint64_t),
		.size = sizeof(uint64_t),
		.get = gpr_get,
		.set = gpr_set
	},
	[REGSET_FPR] = {
		.core_note_type = NT_PRFPREG,
		.n = sizeof(struct user_fpsimd_state) / sizeof(uint32_t),
		/*
		 * We pretend we have 32-bit registers because the fpsr and
		 * fpcr are 32-bits wide.
		 */
		.size = sizeof(uint32_t),
		.get = fpr_get,
		.set = fpr_set
	},
	[REGSET_TLS] = {
		.core_note_type = NT_ARM_TLS,
		.n = 1,
		.size = sizeof(void *),
		.get = tls_get,
		.set = tls_set
	},
	[REGSET_HW_BREAK] = {
		.core_note_type = NT_ARM_HW_BREAK,
		.n = sizeof(struct user_hwdebug_state) / sizeof(uint32_t),
		.size = sizeof(uint32_t),
		.get = hw_break_get,
		.set = hw_break_set
	},
	[REGSET_HW_WATCH] = {
		.core_note_type = NT_ARM_HW_WATCH,
		.n = sizeof(struct user_hwdebug_state) / sizeof(uint32_t),
		.size = sizeof(uint32_t),
		.get = hw_break_get,
		.set = hw_break_set
	},
	[REGSET_SYSTEM_CALL] = {
		.core_note_type = NT_ARM_SYSTEM_CALL,
		.n = 1,
		.size = sizeof(int),
		.get = system_call_get,
		.set = system_call_set
	},
#ifdef CONFIG_ARM64_SVE
	[REGSET_SVE] = { /* Scalable Vector Extension */
		.core_note_type = NT_ARM_SVE,
		.n = (SVE_PT_SIZE(SVE_VQ_MAX, SVE_PT_REGS_SVE) + 15) / 16,
		.size = 16,
		.get = sve_get,
		.set = sve_set
	},
#endif /* CONFIG_ARM64_SVE */
};

static const struct user_regset *
find_regset(const struct user_regset *regset, unsigned int type, int n)
{
	int i = 0;

	for (i = 0; i < n; i++) {
		if (regset[i].core_note_type == type) {
			return &regset[i];
		}
	}
	return NULL;
}

static long ptrace_regset(struct thread *thread, int req, long type, struct iovec *iov)
{
	long rc = -EINVAL;
	const struct user_regset *regset = find_regset(aarch64_regsets, type,
					sizeof(aarch64_regsets) / sizeof(aarch64_regsets[0]));

	if (!regset) {
		kprintf("%s: not supported type 0x%x\n", __FUNCTION__, type);
		goto out;
	}

	if ((iov->iov_len % regset->size) != 0) {
		goto out;
	}

	if ((size_t)(regset->n * regset->size) < iov->iov_len) {
		iov->iov_len = (size_t)(regset->n * regset->size);
	}

	if (req == PTRACE_GETREGSET) {
		rc = copy_regset_to_user(thread, regset, 0,
					 iov->iov_len, iov->iov_base);
	} else {
		rc = copy_regset_from_user(thread, regset, 0,
					   iov->iov_len, iov->iov_base);
	}
out:
	return rc;
}

long ptrace_read_regset(struct thread *thread, long type, struct iovec *iov)
{
	return ptrace_regset(thread, PTRACE_GETREGSET, type, iov);
}

long ptrace_write_regset(struct thread *thread, long type, struct iovec *iov)
{
	return ptrace_regset(thread, PTRACE_SETREGSET, type, iov);
}

void ptrace_report_signal(struct thread *thread, int sig)
{
	struct mcs_rwlock_node_irqsave lock;
	struct process *proc = thread->proc;
	int parent_pid;
	siginfo_t info;
	struct thread_info tinfo;

	dkprintf("ptrace_report_signal, tid=%d, pid=%d\n", thread->tid, thread->proc->pid);

	/* save thread_info, if called by ptrace_report_exec() */
	if (sig == ((SIGTRAP | (PTRACE_EVENT_EXEC << 8)))) {
		memcpy(&tinfo, thread->ctx.thread, sizeof(struct thread_info));
	}

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

	/* restore thread_info, if called by ptrace_report_exec() */
	if (sig == ((SIGTRAP | (PTRACE_EVENT_EXEC << 8)))) {
		memcpy(thread->ctx.thread, &tinfo, sizeof(struct thread_info));
	}
}

long
arch_ptrace(long request, int pid, long addr, long data)
{
	return -EIO;
}

