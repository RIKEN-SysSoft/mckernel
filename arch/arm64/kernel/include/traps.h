/* traps.h COPYRIGHT FUJITSU LIMITED 2017 */

#ifndef __ASM_TRAP_H
#define __ASM_TRAP_H

#include <types.h>
#include <arch-lock.h>

struct pt_regs;

/* @ref.impl arch/arm64/include/asm/traps.h */
struct undef_hook {
	struct list_head node;
	uint32_t instr_mask;
	uint32_t instr_val;
	uint64_t pstate_mask;
	uint64_t pstate_val;
	int (*fn)(struct pt_regs *regs, uint32_t instr);
};

/* @ref.impl arch/arm64/include/asm/traps.h */
void register_undef_hook(struct undef_hook *hook);

/* @ref.impl arch/arm64/include/asm/traps.h */
void unregister_undef_hook(struct undef_hook *hook);

#endif /* __ASM_TRAP_H */

