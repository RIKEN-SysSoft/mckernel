/* archdeps.h COPYRIGHT FUJITSU LIMITED 2017 */
#ifndef __HEADER_MCCTRL_ARM64_ARCHDEPS_H
#define __HEADER_MCCTRL_ARM64_ARCHDEPS_H

#ifdef POSTK_DEBUG_ARCH_DEP_83 /* arch depend translate_rva_to_rpa() move */
extern int translate_rva_to_rpa(ihk_os_t os, unsigned long rpt, unsigned long rva,
				unsigned long *rpap, unsigned long *pgsizep);
#endif /* POSTK_DEBUG_ARCH_DEP_83 */

#ifdef POSTK_DEBUG_ARCH_DEP_12
#define PFN_WRITE_COMBINED PTE_ATTRINDX(MT_NORMAL_NC)

static inline bool pte_is_write_combined(pte_t pte)
{
	return ((pte_val(pte) & PTE_ATTRINDX_MASK) == PFN_WRITE_COMBINED);
}
#endif /* POSTK_DEBUG_ARCH_DEP_12 */

#ifdef POSTK_DEBUG_ARCH_DEP_86 /* make perf counter start id architecture dependent */
#define ARMV8_IDX_COUNTER0	1
#define ARCH_PERF_CONTER_START	ARMV8_IDX_COUNTER0
#endif /* POSTK_DEBUG_ARCH_DEP_86 */

#endif /* __HEADER_MCCTRL_ARM64_ARCHDEPS_H */
