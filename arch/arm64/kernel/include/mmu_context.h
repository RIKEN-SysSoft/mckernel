/* mmu_context.h COPYRIGHT FUJITSU LIMITED 2015 */
#ifndef __HEADER_ARM64_COMMON_MMU_CONTEXT_H
#define __HEADER_ARM64_COMMON_MMU_CONTEXT_H

#include <pgtable.h>
#include <memory.h>

/*
 * Set TTBR0 to empty_zero_page. No translations will be possible via TTBR0.
 */
static inline void cpu_set_reserved_ttbr0(void)
{
	unsigned long ttbr = virt_to_phys(empty_zero_page);

	asm(
	"	msr	ttbr0_el1, %0			// set TTBR0\n"
	"	isb"
	:
	: "r" (ttbr));
}

#endif /* !__HEADER_ARM64_COMMON_MMU_CONTEXT_H */
