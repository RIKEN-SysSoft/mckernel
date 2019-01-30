/* archdeps.h COPYRIGHT FUJITSU LIMITED 2017 */
#ifndef __HEADER_MCCTRL_ARM64_ARCHDEPS_H
#define __HEADER_MCCTRL_ARM64_ARCHDEPS_H

extern int translate_rva_to_rpa(ihk_os_t os, unsigned long rpt, unsigned long rva,
				unsigned long *rpap, unsigned long *pgsizep);

#ifdef POSTK_DEBUG_ARCH_DEP_12
#define PFN_WRITE_COMBINED PTE_ATTRINDX(MT_NORMAL_NC)

static inline bool pte_is_write_combined(pte_t pte)
{
	return ((pte_val(pte) & PTE_ATTRINDX_MASK) == PFN_WRITE_COMBINED);
}
#endif /* POSTK_DEBUG_ARCH_DEP_12 */

#define ARMV8_IDX_COUNTER0	1
#define ARCH_PERF_COUNTER_START	ARMV8_IDX_COUNTER0

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
static const unsigned long arch_rus_vm_flags = VM_RESERVED | VM_MIXEDMAP | VM_EXEC;
#else
static const unsigned long arch_rus_vm_flags = VM_DONTDUMP | VM_MIXEDMAP | VM_EXEC;
#endif
#endif /* __HEADER_MCCTRL_ARM64_ARCHDEPS_H */
