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

/* @ref.impl arch/arm64/include/uapi/asm/hwcap.h */
/*
 * HWCAP flags - for elf_hwcap (in kernel) and AT_HWCAP
 */
#define HWCAP_FP		(1 << 0)
#define HWCAP_ASIMD		(1 << 1)
#define HWCAP_EVTSTRM		(1 << 2)
#define HWCAP_AES		(1 << 3)
#define HWCAP_PMULL		(1 << 4)
#define HWCAP_SHA1		(1 << 5)
#define HWCAP_SHA2		(1 << 6)
#define HWCAP_CRC32		(1 << 7)

#endif /* !__HEADER_ARM64_COMMON_CPUINFO_H */
