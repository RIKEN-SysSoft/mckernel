/* irqflags.h COPYRIGHT FUJITSU LIMITED 2015 */
#ifndef __HEADER_ARM64_COMMON_IRQFLAGS_H
#define __HEADER_ARM64_COMMON_IRQFLAGS_H

#include <ptrace.h>

/*
 * save and restore debug state
 */
static inline unsigned long local_dbg_save(void)
{
	unsigned long flags;
	asm volatile(
		"mrs    %0, daif		// local_dbg_save\n"
		"msr    daifset, #8"
		: "=r" (flags)
		:
		: "memory");
	return flags;
}

static inline void local_dbg_restore(unsigned long flags)
{
	asm volatile(
		"msr    daif, %0		// local_dbg_restore"
		:
		: "r" (flags)
		: "memory");
}

#endif /* !__HEADER_ARM64_COMMON_IRQFLAGS_H */
