/* archdeps.h COPYRIGHT FUJITSU LIMITED 2017 */
#ifdef POSTK_DEBUG_ARCH_DEP_83 /* arch depend translate_rva_to_rpa() move */
#ifndef __HEADER_MCCTRL_ARM64_ARCHDEPS_H
#define __HEADER_MCCTRL_ARM64_ARCHDEPS_H

extern int translate_rva_to_rpa(ihk_os_t os, unsigned long rpt, unsigned long rva,
				unsigned long *rpap, unsigned long *pgsizep);

#ifdef POSTK_DEBUG_ARCH_DEP_12

#define PFN_WRITE_COMBINED PTE_ATTRINDX(MT_NORMAL_NC)
static inline bool pte_is_write_combined(pte_t pte)
{
#if defined(MIDR_CPU_MODEL_MASK)
	/*
	 * Fix up arm64 braindamage of using NORMAL_NC for write
	 * combining when Device GRE exists specifically for the
	 * purpose. Needed on ThunderX2.
	 */
	switch (read_cpuid_id() & MIDR_CPU_MODEL_MASK) {
#if defined(ARM_CPU_IMP_BRCM) && defined(BRCM_CPU_PART_VULCAN)
		case MIDR_CPU_MODEL(ARM_CPU_IMP_BRCM, BRCM_CPU_PART_VULCAN):
#endif
		case MIDR_CPU_MODEL(0x43, 0x0af):  /* Cavium ThunderX2 */
			return ((pte_val(pte) & PTE_ATTRINDX_MASK) ==
					PTE_ATTRINDX(MT_DEVICE_GRE));
	}
#endif
	return ((pte_val(pte) & PTE_ATTRINDX_MASK) == PFN_WRITE_COMBINED);
}
#endif /* POSTK_DEBUG_ARCH_DEP_12 */
#endif /* __HEADER_MCCTRL_ARM64_ARCHDEPS_H */
#endif /* POSTK_DEBUG_ARCH_DEP_83 */
