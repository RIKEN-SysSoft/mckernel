/* cputype.h COPYRIGHT FUJITSU LIMITED 2015-2017 */
/* @ref.impl arch/arm64/include/asm/cputype.h */
#ifndef __HEADER_ARM64_COMMON_CPUTYPE_H
#define __HEADER_ARM64_COMMON_CPUTYPE_H

#include <sysreg.h>

#define MPIDR_LEVEL_BITS_SHIFT	3
#define MPIDR_LEVEL_BITS	(1 << MPIDR_LEVEL_BITS_SHIFT)
#define MPIDR_LEVEL_MASK	((1 << MPIDR_LEVEL_BITS) - 1)

#define MPIDR_LEVEL_SHIFT(level) \
	(((1 << level) >> 1) << MPIDR_LEVEL_BITS_SHIFT)

#define MPIDR_AFFINITY_LEVEL(mpidr, level) \
	((mpidr >> MPIDR_LEVEL_SHIFT(level)) & MPIDR_LEVEL_MASK)

#define read_cpuid(reg) read_sysreg_s(SYS_ ## reg)

#define MIDR_REVISION_MASK	0xf
#define MIDR_REVISION(midr)	((midr) & MIDR_REVISION_MASK)

#define MIDR_PARTNUM_SHIFT	4
#define MIDR_PARTNUM_MASK	(0xfff << MIDR_PARTNUM_SHIFT)
#define MIDR_PARTNUM(midr)	\
	(((midr) & MIDR_PARTNUM_MASK) >> MIDR_PARTNUM_SHIFT)

#define MIDR_VARIANT_SHIFT	20
#define MIDR_VARIANT_MASK	(0xf << MIDR_VARIANT_SHIFT)
#define MIDR_VARIANT(midr)	\
	(((midr) & MIDR_VARIANT_MASK) >> MIDR_VARIANT_SHIFT)

#define MIDR_IMPLEMENTOR_SHIFT	24
#define MIDR_IMPLEMENTOR_MASK	(0xff << MIDR_IMPLEMENTOR_SHIFT)
#define MIDR_IMPLEMENTOR(midr)	\
	(((midr) & MIDR_IMPLEMENTOR_MASK) >> MIDR_IMPLEMENTOR_SHIFT)

#define ARM_CPU_IMP_CAVIUM	0x43

#ifndef __ASSEMBLY__

static unsigned int read_cpuid_id(void)
{
	return read_cpuid(MIDR_EL1);
}

#endif /* !__ASSEMBLY__ */

#endif /* !__HEADER_ARM64_COMMON_CPUTYPE_H */
