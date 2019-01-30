/* virt.h COPYRIGHT FUJITSU LIMITED 2015 */
#ifndef __HEADER_ARM64_COMMON_VIRT_H
#define __HEADER_ARM64_COMMON_VIRT_H

/* @ref.impl linux-v4.15-rc3 arch/arm64/include/asm/virt.h */
#define BOOT_CPU_MODE_EL1	(0xe11)
#define BOOT_CPU_MODE_EL2	(0xe12)

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
