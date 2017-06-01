/* cpuinfo.h COPYRIGHT FUJITSU LIMITED 2016-2017 */
#ifndef __HEADER_ARM64_COMMON_CPUINFO_H
#define __HEADER_ARM64_COMMON_CPUINFO_H

#include <types.h>

/* @ref.impl arch/arm64/include/cpu.h */
/*
 * Records attributes of an individual CPU.
 */
struct cpuinfo_arm64 {
	uint32_t reg_midr;
	unsigned int hwid;	/* McKernel Original. */

	uint32_t reg_ctr;
	uint32_t reg_cntfrq;
	uint32_t reg_dczid;
	uint32_t reg_revidr;

	uint64_t reg_id_aa64dfr0;
	uint64_t reg_id_aa64dfr1;
	uint64_t reg_id_aa64isar0;
	uint64_t reg_id_aa64isar1;
	uint64_t reg_id_aa64mmfr0;
	uint64_t reg_id_aa64mmfr1;
	uint64_t reg_id_aa64mmfr2;
	uint64_t reg_id_aa64pfr0;
	uint64_t reg_id_aa64pfr1;
};

#endif /* !__HEADER_ARM64_COMMON_CPUINFO_H */
