/* virt.h COPYRIGHT FUJITSU LIMITED 2015-2017 */
#ifndef __HEADER_ARM64_COMMON_VIRT_H
#define __HEADER_ARM64_COMMON_VIRT_H

/* @ref.impl linux-v4.15-rc3 arch/arm64/include/asm/virt.h */
#define BOOT_CPU_MODE_EL1	(0xe11)
#define BOOT_CPU_MODE_EL2	(0xe12)

/* Hyp Debug Configuration Register bits */
#define MDCR_EL2_TPMS		(1 << 14)
#define MDCR_EL2_E2PB_MASK	(UL(0x3))
#define MDCR_EL2_E2PB_SHIFT	(UL(12))
#define MDCR_EL2_TDRA		(1 << 11)
#define MDCR_EL2_TDOSA		(1 << 10)
#define MDCR_EL2_TDA		(1 << 9)
#define MDCR_EL2_TDE		(1 << 8)
#define MDCR_EL2_HPME		(1 << 7)
#define MDCR_EL2_TPM		(1 << 6)
#define MDCR_EL2_TPMCR		(1 << 5)
#define MDCR_EL2_HPMN_MASK	(0x1F)

#ifndef __ASSEMBLY__

#include <sysreg.h>
#include <ptrace.h>


/* @ref.impl linux-v4.15-rc3 arch/arm64/include/asm/virt.h */
static inline int is_kernel_in_hyp_mode(void)
{
	return read_sysreg(CurrentEL) == CurrentEL_EL2;
}

#endif /* !__ASSEMBLY__ */

#endif /* !__HEADER_ARM64_COMMON_VIRT_H */
