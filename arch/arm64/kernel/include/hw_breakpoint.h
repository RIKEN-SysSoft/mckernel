/* hw_breakpoint.h COPYRIGHT FUJITSU LIMITED 2016 */
#ifndef __HEADER_ARM64_COMMON_HW_BREAKPOINT_H
#define __HEADER_ARM64_COMMON_HW_BREAKPOINT_H

#include <ihk/types.h>

int hw_breakpoint_slots(int type);
unsigned long read_wb_reg(int reg, int n);
void write_wb_reg(int reg, int n, unsigned long val);
void hw_breakpoint_reset(void);
void arch_hw_breakpoint_init(void);

struct user_hwdebug_state;
int arch_validate_hwbkpt_settings(long note_type, struct user_hwdebug_state *hws, size_t len);

extern int core_num_brps;
extern int core_num_wrps;
extern int max_br_size;
extern int max_wr_size;

/* @ref.impl include/uapi/linux/hw_breakpoint.h::HW_BREAKPOINT_LEN_n, HW_BREAKPOINT_xxx, bp_type_idx */
enum {
	HW_BREAKPOINT_LEN_1 = 1,
	HW_BREAKPOINT_LEN_2 = 2,
	HW_BREAKPOINT_LEN_4 = 4,
	HW_BREAKPOINT_LEN_8 = 8,
};

enum {
	HW_BREAKPOINT_EMPTY	= 0,
	HW_BREAKPOINT_R		= 1,
	HW_BREAKPOINT_W		= 2,
	HW_BREAKPOINT_RW	= HW_BREAKPOINT_R | HW_BREAKPOINT_W,
	HW_BREAKPOINT_X		= 4,
	HW_BREAKPOINT_INVALID	= HW_BREAKPOINT_RW | HW_BREAKPOINT_X,
};

enum bp_type_idx {
	TYPE_INST	= 0,
	TYPE_DATA	= 1,
	TYPE_MAX
};

/* Breakpoint */
#define ARM_BREAKPOINT_EXECUTE	0

/* Watchpoints */
#define ARM_BREAKPOINT_LOAD	1
#define ARM_BREAKPOINT_STORE	2
#define AARCH64_ESR_ACCESS_MASK	(1 << 6)

/* Privilege Levels */
#define AARCH64_BREAKPOINT_EL1	1
#define AARCH64_BREAKPOINT_EL0	2

/* Lengths */
#define ARM_BREAKPOINT_LEN_1	0x1
#define ARM_BREAKPOINT_LEN_2	0x3
#define ARM_BREAKPOINT_LEN_4	0xf
#define ARM_BREAKPOINT_LEN_8	0xff

/* @ref.impl arch/arm64/include/asm/hw_breakpoint.h::ARM_MAX_[BRP|WRP] */
/*
 * Limits.
 * Changing these will require modifications to the register accessors.
 */
#define ARM_MAX_BRP		16
#define ARM_MAX_WRP		16

/* @ref.impl arch/arm64/include/asm/hw_breakpoint.h::AARCH64_DBG_REG_xxx */
/* Virtual debug register bases. */
#define AARCH64_DBG_REG_BVR	0
#define AARCH64_DBG_REG_BCR	(AARCH64_DBG_REG_BVR + ARM_MAX_BRP)
#define AARCH64_DBG_REG_WVR	(AARCH64_DBG_REG_BCR + ARM_MAX_BRP)
#define AARCH64_DBG_REG_WCR	(AARCH64_DBG_REG_WVR + ARM_MAX_WRP)

/* @ref.impl arch/arm64/include/asm/hw_breakpoint.h::AARCH64_DBG_REG_NAME_xxx */
/* Debug register names. */
#define AARCH64_DBG_REG_NAME_BVR	"bvr"
#define AARCH64_DBG_REG_NAME_BCR	"bcr"
#define AARCH64_DBG_REG_NAME_WVR	"wvr"
#define AARCH64_DBG_REG_NAME_WCR	"wcr"

/* @ref.impl arch/arm64/include/asm/hw_breakpoint.h::AARCH64_DBG_[READ|WRITE] */
/* Accessor macros for the debug registers. */
#define AARCH64_DBG_READ(N, REG, VAL) do {\
	asm volatile("mrs %0, dbg" REG #N "_el1" : "=r" (VAL));\
} while (0)

#define AARCH64_DBG_WRITE(N, REG, VAL) do {\
	asm volatile("msr dbg" REG #N "_el1, %0" :: "r" (VAL));\
} while (0)

#endif /* !__HEADER_ARM64_COMMON_HW_BREAKPOINT_H */
