/* ptrace.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
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

struct user_hwdebug_state {
	unsigned int dbg_info;
	unsigned int pad;
	struct {
		unsigned long addr;
		unsigned int ctrl;
		unsigned int pad;
	} dbg_regs[16];
};

unsigned int ptrace_hbp_get_resource_info(unsigned int note_type);

#endif /* !__ASSEMBLY__ */

#endif /* !__HEADER_ARM64_COMMON_PTRACE_H */
