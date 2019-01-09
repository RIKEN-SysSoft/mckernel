/* asm-offsets.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
#ifndef __HEADER_ARM64_COMMON_ASM_OFFSETS_H
#define __HEADER_ARM64_COMMON_ASM_OFFSETS_H

#define S_X0		0x00	/* offsetof(struct pt_regs, regs[0]) */
#define S_X1		0x08	/* offsetof(struct pt_regs, regs[1]) */
#define S_X2		0x10	/* offsetof(struct pt_regs, regs[2]) */
#define S_X3		0x18	/* offsetof(struct pt_regs, regs[3]) */
#define S_X4		0x20	/* offsetof(struct pt_regs, regs[4]) */
#define S_X5		0x28	/* offsetof(struct pt_regs, regs[5]) */
#define S_X6		0x30	/* offsetof(struct pt_regs, regs[6]) */
#define S_X7		0x38	/* offsetof(struct pt_regs, regs[7]) */
#define S_LR		0xf0	/* offsetof(struct pt_regs, regs[30]) */
#define S_SP		0xf8	/* offsetof(struct pt_regs, sp) */
#define S_PC		0x100	/* offsetof(struct pt_regs, pc) */
#define S_PSTATE	0x108	/* offsetof(struct pt_regs, pstate) */
#define S_ORIG_X0	0x110	/* offsetof(struct pt_regs, orig_x0) */
#define S_ORIG_PC	0x118	/* offsetof(struct pt_regs, orig_pc) */
#define S_SYSCALLNO	0x120	/* offsetof(struct pt_regs, syscallno) */
#define S_FRAME_SIZE	0x130	/* sizeof(struct pt_regs) must be 16 byte align */

#define CPU_INFO_SETUP	0x10	/* offsetof(struct cpu_info, cpu_setup) */
#define CPU_INFO_SZ	0x18	/* sizeof(struct cpu_info) */

#define TI_FLAGS	0x00	/* offsetof(struct thread_info, flags) */
#define TI_CPU_CONTEXT	0x10	/* offsetof(struct thread_info, cpu_context) */

#endif /* !__HEADER_ARM64_COMMON_ASM_OFFSETS_H */
