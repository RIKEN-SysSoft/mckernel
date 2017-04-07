/* cpuinfo.h COPYRIGHT FUJITSU LIMITED 2016 */
#ifndef __HEADER_ARM64_COMMON_CPUINFO_H
#define __HEADER_ARM64_COMMON_CPUINFO_H

/* @ref.impl arch/arm64/include/cpu.h */
/*
 * Records attributes of an individual CPU.
 */
struct cpuinfo_arm64 {
	unsigned int reg_midr;
	unsigned int hwid;	/* McKernel Original. */
};

#endif /* !__HEADER_ARM64_COMMON_CPUINFO_H */
