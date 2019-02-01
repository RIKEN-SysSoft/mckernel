/* archdeps.h COPYRIGHT FUJITSU LIMITED 2017 */
#ifndef __HEADER_MCCTRL_X86_64_ARCHDEPS_H
#define __HEADER_MCCTRL_X86_64_ARCHDEPS_H

extern int translate_rva_to_rpa(ihk_os_t os, unsigned long rpt, unsigned long rva,
				unsigned long *rpap, unsigned long *pgsizep);

#ifdef POSTK_DEBUG_ARCH_DEP_12
#define PFN_WRITE_COMBINED _PAGE_PWT

static inline bool pte_is_write_combined(pte_t pte)
{
	return ((pte_flags(pte) & _PAGE_PWT) && !(pte_flags(pte) & _PAGE_PCD));
}
#endif /* POSTK_DEBUG_ARCH_DEP_12 */
#endif /* __HEADER_MCCTRL_X86_64_ARCHDEPS_H */
