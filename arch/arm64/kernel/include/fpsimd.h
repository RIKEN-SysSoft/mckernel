/* fpsimd.h COPYRIGHT FUJITSU LIMITED 2016-2019 */
#ifndef __HEADER_ARM64_COMMON_FPSIMD_H
#define __HEADER_ARM64_COMMON_FPSIMD_H

#include <ptrace.h>

#ifndef __ASSEMBLY__

/*
 * FP/SIMD storage area has:
 *  - FPSR and FPCR
 *  - 32 128-bit data registers
 *
 * Note that user_fpsimd forms a prefix of this structure, which is
 * relied upon in the ptrace FP/SIMD accessors.
 */
/* @ref.impl arch/arm64/include/asm/fpsimd.h::struct fpsimd_state */
struct fpsimd_state {
	union {
		struct user_fpsimd_state user_fpsimd;
		struct {
			__uint128_t vregs[32];
			unsigned int fpsr;
			unsigned int fpcr;
			/*
			 * For ptrace compatibility, pad to next 128-bit
			 * boundary here if extending this struct.
			 */
		};
	};
	/* the id of the last cpu to have restored this state */
	unsigned int cpu;
};

/* need for struct process */
typedef struct fpsimd_state fp_regs_struct;

extern void thread_fpsimd_to_sve(struct thread *thread, fp_regs_struct *fp_regs);
extern void thread_sve_to_fpsimd(struct thread *thread, fp_regs_struct *fp_regs);

#ifdef CONFIG_ARM64_SVE

extern size_t sve_state_size(struct thread const *thread);
extern void sve_free(struct thread *thread);
extern void sve_alloc(struct thread *thread);
extern void sve_save_state(void *state, unsigned int *pfpsr);
extern void sve_load_state(void const *state, unsigned int const *pfpsr, unsigned long vq_minus_1);
extern unsigned int sve_get_vl(void);
extern int sve_set_thread_vl(unsigned long arg);
extern int sve_get_thread_vl(void);
extern int sve_set_vector_length(struct thread *thread, unsigned long vl, unsigned long flags);

#define SVE_SET_VL(arg)	sve_set_thread_vl(arg)
#define SVE_GET_VL()	sve_get_thread_vl()

/* Maximum VL that SVE VL-agnostic software can transparently support */
#define SVE_VL_ARCH_MAX 0x100

#else /* CONFIG_ARM64_SVE */

#include <ihk/debug.h>
#include <errno.h>

static void sve_save_state(void *state, unsigned int *pfpsr)
{
	panic("PANIC:sve_save_state() was called CONFIG_ARM64_SVE off.\n");
}

static void sve_load_state(void const *state, unsigned int const *pfpsr, unsigned long vq_minus_1)
{
	panic("PANIC:sve_load_state() was called CONFIG_ARM64_SVE off.\n");
}

static unsigned int sve_get_vl(void)
{
	panic("PANIC:sve_get_vl() was called CONFIG_ARM64_SVE off.\n");
	return (unsigned int)-1;
}

static int sve_set_vector_length(struct thread *thread, unsigned long vl, unsigned long flags)
{
	return -EINVAL;
}

/* for prctl syscall */
#define SVE_SET_VL(a)	(-EINVAL)
#define SVE_GET_VL()	(-EINVAL)

#endif /* CONFIG_ARM64_SVE */

extern void sve_setup(void);
extern void fpsimd_save_state(struct fpsimd_state *state);
extern void fpsimd_load_state(struct fpsimd_state *state);
extern void thread_fpsimd_save(struct thread *thread);
extern void thread_fpsimd_load(struct thread *thread);

extern int sve_max_vl;
extern int sve_default_vl;

#endif /* !__ASSEMBLY__ */

#endif /* !__HEADER_ARM64_COMMON_FPSIMD_H */
