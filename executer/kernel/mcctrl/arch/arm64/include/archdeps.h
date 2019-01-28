/* archdeps.h COPYRIGHT FUJITSU LIMITED 2017 */
#ifndef __HEADER_MCCTRL_ARM64_ARCHDEPS_H
#define __HEADER_MCCTRL_ARM64_ARCHDEPS_H

#ifdef POSTK_DEBUG_ARCH_DEP_100 /* rus_mmap() setting vm_flags arch depend defined */
#include <linux/mm.h>
#endif /* POSTK_DEBUG_ARCH_DEP_100 */

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
	case MIDR_CPU_MODEL(ARM_CPU_IMP_CAVIUM, CAVIUM_CPU_PART_THUNDERX2):
		return ((pte_val(pte) & PTE_ATTRINDX_MASK) ==
				PTE_ATTRINDX(MT_DEVICE_GRE));
	}
#endif
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
