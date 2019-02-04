/* ptrace.h COPYRIGHT FUJITSU LIMITED 2015-2019 */
#ifndef __HEADER_ARM64_COMMON_PTRACE_H
#define __HEADER_ARM64_COMMON_PTRACE_H

/*
 * PSR bits
 */
#define PSR_MODE_EL0t   0x00000000
#define PSR_MODE_EL1t   0x00000004
#define PSR_MODE_EL1h   0x00000005
#define PSR_MODE_EL2t   0x00000008
#define PSR_MODE_EL2h   0x00000009
#define PSR_MODE_EL3t   0x0000000c
#define PSR_MODE_EL3h   0x0000000d
#define PSR_MODE_MASK   0x0000000f

/* AArch32 CPSR bits */
#define PSR_MODE32_BIT	0x00000010

/* AArch64 SPSR bits */
#define PSR_F_BIT       0x00000040
#define PSR_I_BIT       0x00000080
#define PSR_A_BIT       0x00000100
#define PSR_D_BIT       0x00000200
#define PSR_Q_BIT       0x08000000
#define PSR_V_BIT       0x10000000
#define PSR_C_BIT       0x20000000
#define PSR_Z_BIT       0x40000000
#define PSR_N_BIT       0x80000000

/*
 * Groups of PSR bits
 */
#define PSR_f           0xff000000      /* Flags                */
#define PSR_s           0x00ff0000      /* Status               */
#define PSR_x           0x0000ff00      /* Extension            */
#define PSR_c           0x000000ff      /* Control              */

/* Current Exception Level values, as contained in CurrentEL */
#define CurrentEL_EL1	(1 << 2)
#define CurrentEL_EL2	(2 << 2)

/* thread->ptrace_debugreg lower-area and higher-area */
#define HWS_BREAK	0
#define HWS_WATCH	1

#ifndef __ASSEMBLY__

#include <lwk/compiler.h>
#include <ihk/types.h>

struct user_hwdebug_state {
	uint32_t dbg_info;
	uint32_t pad;
	struct {
		uint64_t addr;
		uint32_t ctrl;
		uint32_t pad;
	} dbg_regs[16];
};

struct user_fpsimd_state {
	__uint128_t	vregs[32];
	uint32_t	fpsr;
	uint32_t	fpcr;
	uint32_t	__reserved[2];
};

extern unsigned int ptrace_hbp_get_resource_info(unsigned int note_type);

/* SVE/FP/SIMD state (NT_ARM_SVE) */

struct user_sve_header {
	uint32_t size;		/* total meaningful regset content in bytes */
	uint32_t max_size;	/* maxmium possible size for this thread */
	uint16_t vl;		/* current vector length */
	uint16_t max_vl;	/* maximum possible vector length */
	uint16_t flags;
	uint16_t __reserved;
};

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

struct thread;
struct user_regset;

typedef int user_regset_active_fn(struct thread *target,
				  const struct user_regset *regset);

typedef long user_regset_get_fn(struct thread *target,
				const struct user_regset *regset,
				unsigned int pos, unsigned int count,
				void *kbuf, void __user *ubuf);

typedef long user_regset_set_fn(struct thread *target,
				const struct user_regset *regset,
				unsigned int pos, unsigned int count,
				const void *kbuf, const void __user *ubuf);

typedef int user_regset_writeback_fn(struct thread *target,
				     const struct user_regset *regset,
				     int immediate);

typedef unsigned int user_regset_get_size_fn(struct thread *target,
					     const struct user_regset *regset);

struct user_regset {
	user_regset_get_fn		*get;
	user_regset_set_fn		*set;
	user_regset_active_fn		*active;
	user_regset_writeback_fn	*writeback;
	user_regset_get_size_fn		*get_size;
	unsigned int			n;
	unsigned int			size;
	unsigned int			align;
	unsigned int			bias;
	unsigned int			core_note_type;
};

struct user_regset_view {
	const char *name;
	const struct user_regset *regsets;
	unsigned int n;
	uint32_t e_flags;
	uint16_t e_machine;
	uint8_t ei_osabi;
};

extern const struct user_regset_view *current_user_regset_view(void);
extern const struct user_regset *find_regset(
		const struct user_regset_view *view,
		unsigned int type);
extern unsigned int regset_size(struct thread *target,
		const struct user_regset *regset);

/* Definitions for user_sve_header.flags: */
#define SVE_PT_REGS_MASK	(1 << 0)

#define SVE_PT_REGS_FPSIMD	0
#define SVE_PT_REGS_SVE		SVE_PT_REGS_MASK

#define SVE_PT_VL_THREAD	PR_SVE_SET_VL_THREAD
#define SVE_PT_VL_INHERIT	PR_SVE_VL_INHERIT
#define SVE_PT_VL_ONEXEC	PR_SVE_SET_VL_ONEXEC

/*
 * The remainder of the SVE state follows struct user_sve_header.  The
 * total size of the SVE state (including header) depends on the
 * metadata in the header:  SVE_PT_SIZE(vq, flags) gives the total size
 * of the state in bytes, including the header.
 *
 * Refer to <asm/sigcontext.h> for details of how to pass the correct
 * "vq" argument to these macros.
 */

/* Offset from the start of struct user_sve_header to the register data */
#define SVE_PT_REGS_OFFSET					\
	((sizeof(struct sve_context) + (SVE_VQ_BYTES - 1))	\
		/ SVE_VQ_BYTES * SVE_VQ_BYTES)

/*
 * The register data content and layout depends on the value of the
 * flags field.
 */

/*
 * (flags & SVE_PT_REGS_MASK) == SVE_PT_REGS_FPSIMD case:
 *
 * The payload starts at offset SVE_PT_FPSIMD_OFFSET, and is of type
 * struct user_fpsimd_state.  Additional data might be appended in the
 * future: use SVE_PT_FPSIMD_SIZE(vq, flags) to compute the total size.
 * SVE_PT_FPSIMD_SIZE(vq, flags) will never be less than
 * sizeof(struct user_fpsimd_state).
 */

#define SVE_PT_FPSIMD_OFFSET		SVE_PT_REGS_OFFSET

#define SVE_PT_FPSIMD_SIZE(vq, flags)	(sizeof(struct user_fpsimd_state))

/*
 * (flags & SVE_PT_REGS_MASK) == SVE_PT_REGS_SVE case:
 *
 * The payload starts at offset SVE_PT_SVE_OFFSET, and is of size
 * SVE_PT_SVE_SIZE(vq, flags).
 *
 * Additional macros describe the contents and layout of the payload.
 * For each, SVE_PT_SVE_x_OFFSET(args) is the start offset relative to
 * the start of struct user_sve_header, and SVE_PT_SVE_x_SIZE(args) is
 * the size in bytes:
 *
 *	x	type				description
 *	-	----				-----------
 *	ZREGS		\
 *	ZREG		|
 *	PREGS		| refer to <asm/sigcontext.h>
 *	PREG		|
 *	FFR		/
 *
 *	FPSR	uint32_t			FPSR
 *	FPCR	uint32_t			FPCR
 *
 * Additional data might be appended in the future.
 */

#define SVE_PT_SVE_ZREG_SIZE(vq)	SVE_SIG_ZREG_SIZE(vq)
#define SVE_PT_SVE_PREG_SIZE(vq)	SVE_SIG_PREG_SIZE(vq)
#define SVE_PT_SVE_FFR_SIZE(vq)		SVE_SIG_FFR_SIZE(vq)
#define SVE_PT_SVE_FPSR_SIZE		sizeof(uint32_t)
#define SVE_PT_SVE_FPCR_SIZE		sizeof(uint32_t)

#define __SVE_SIG_TO_PT(offset) \
	((offset) - SVE_SIG_REGS_OFFSET + SVE_PT_REGS_OFFSET)

#define SVE_PT_SVE_OFFSET		SVE_PT_REGS_OFFSET

#define SVE_PT_SVE_ZREGS_OFFSET \
	__SVE_SIG_TO_PT(SVE_SIG_ZREGS_OFFSET)
#define SVE_PT_SVE_ZREG_OFFSET(vq, n) \
	__SVE_SIG_TO_PT(SVE_SIG_ZREG_OFFSET(vq, n))
#define SVE_PT_SVE_ZREGS_SIZE(vq) \
	(SVE_PT_SVE_ZREG_OFFSET(vq, SVE_NUM_ZREGS) - SVE_PT_SVE_ZREGS_OFFSET)

#define SVE_PT_SVE_PREGS_OFFSET(vq) \
	__SVE_SIG_TO_PT(SVE_SIG_PREGS_OFFSET(vq))
#define SVE_PT_SVE_PREG_OFFSET(vq, n) \
	__SVE_SIG_TO_PT(SVE_SIG_PREG_OFFSET(vq, n))
#define SVE_PT_SVE_PREGS_SIZE(vq) \
	(SVE_PT_SVE_PREG_OFFSET(vq, SVE_NUM_PREGS) - \
		SVE_PT_SVE_PREGS_OFFSET(vq))

#define SVE_PT_SVE_FFR_OFFSET(vq) \
	__SVE_SIG_TO_PT(SVE_SIG_FFR_OFFSET(vq))

#define SVE_PT_SVE_FPSR_OFFSET(vq)				\
	((SVE_PT_SVE_FFR_OFFSET(vq) + SVE_PT_SVE_FFR_SIZE(vq) + \
			(SVE_VQ_BYTES - 1))			\
		/ SVE_VQ_BYTES * SVE_VQ_BYTES)
#define SVE_PT_SVE_FPCR_OFFSET(vq) \
	(SVE_PT_SVE_FPSR_OFFSET(vq) + SVE_PT_SVE_FPSR_SIZE)

/*
 * Any future extension appended after FPCR must be aligned to the next
 * 128-bit boundary.
 */

#define SVE_PT_SVE_SIZE(vq, flags)					\
	((SVE_PT_SVE_FPCR_OFFSET(vq) + SVE_PT_SVE_FPCR_SIZE		\
			- SVE_PT_SVE_OFFSET + (SVE_VQ_BYTES - 1))	\
		/ SVE_VQ_BYTES * SVE_VQ_BYTES)

#define SVE_PT_SIZE(vq, flags)						\
	(((flags) & SVE_PT_REGS_MASK) == SVE_PT_REGS_SVE ?		\
		  SVE_PT_SVE_OFFSET + SVE_PT_SVE_SIZE(vq, flags)	\
		: SVE_PT_FPSIMD_OFFSET + SVE_PT_FPSIMD_SIZE(vq, flags))

#endif /* !__ASSEMBLY__ */

#endif /* !__HEADER_ARM64_COMMON_PTRACE_H */
