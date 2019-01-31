/* cpufeature.c COPYRIGHT FUJITSU LIMITED 2017-2018 */

#include <cpufeature.h>
#include <ihk/debug.h>
#include <traps.h>
#include <bitops.h>
#include <cputype.h>
#include <sysreg.h>
#include <generic-errno.h>
#include <ptrace.h>
#include <hwcap.h>

#ifdef POSTK_DEBUG_ARCH_DEP_65
unsigned long elf_hwcap;
#endif /* POSTK_DEBUG_ARCH_DEP_65 */

/* @ref.impl arch/arm64/kernel/cpufeature.c */
#define __ARM64_FTR_BITS(SIGNED, VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL) \
	{						\
		.sign = SIGNED,				\
		.visible = VISIBLE,			\
		.strict = STRICT,			\
		.type = TYPE,				\
		.shift = SHIFT,				\
		.width = WIDTH,				\
		.safe_val = SAFE_VAL,			\
	}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
/* Define a feature with unsigned values */
#define ARM64_FTR_BITS(VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL) \
	__ARM64_FTR_BITS(FTR_UNSIGNED, VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL)


/* @ref.impl arch/arm64/kernel/cpufeature.c */
/* Define a feature with a signed value */
#define S_ARM64_FTR_BITS(VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL) \
	__ARM64_FTR_BITS(FTR_SIGNED, VISIBLE, STRICT, TYPE, SHIFT, WIDTH, SAFE_VAL)

/* @ref.impl arch/arm64/kernel/cpufeature.c */
#define ARM64_FTR_END					\
	{						\
		.width = 0,				\
	}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_id_aa64isar0[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_EXACT, ID_AA64ISAR0_RDM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_ATOMICS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_CRC32_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_SHA2_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_SHA1_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64ISAR0_AES_SHIFT, 4, 0),
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_id_aa64pfr0[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR0_SVE_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64PFR0_GIC_SHIFT, 4, 0),
	S_ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR0_ASIMD_SHIFT, 4, ID_AA64PFR0_ASIMD_NI),
	S_ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64PFR0_FP_SHIFT, 4, ID_AA64PFR0_FP_NI),
	/* Linux doesn't care about the EL3 */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_EXACT, ID_AA64PFR0_EL3_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64PFR0_EL2_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64PFR0_EL1_SHIFT, 4, ID_AA64PFR0_EL1_64BIT_ONLY),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64PFR0_EL0_SHIFT, 4, ID_AA64PFR0_EL0_64BIT_ONLY),
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_id_aa64mmfr0[] = {
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR0_TGRAN4_SHIFT, 4, ID_AA64MMFR0_TGRAN4_NI),
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR0_TGRAN64_SHIFT, 4, ID_AA64MMFR0_TGRAN64_NI),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR0_TGRAN16_SHIFT, 4, ID_AA64MMFR0_TGRAN16_NI),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR0_BIGENDEL0_SHIFT, 4, 0),
	/* Linux shouldn't care about secure memory */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_EXACT, ID_AA64MMFR0_SNSMEM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR0_BIGENDEL_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR0_ASID_SHIFT, 4, 0),
	/*
	 * Differing PARange is fine as long as all peripherals and memory are mapped
	 * within the minimum PARange of all CPUs
	 */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64MMFR0_PARANGE_SHIFT, 4, 0),
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_id_aa64mmfr1[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64MMFR1_PAN_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR1_LOR_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR1_HPD_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR1_VHE_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR1_VMIDBITS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR1_HADBS_SHIFT, 4, 0),
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_id_aa64mmfr2[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR2_LVA_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR2_IESB_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR2_LSM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR2_UAO_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64MMFR2_CNP_SHIFT, 4, 0),
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/include/asm/cachetype.h */
#define ICACHE_POLICY_RESERVED	0
#define ICACHE_POLICY_AIVIVT	1
#define ICACHE_POLICY_VIPT	2
#define ICACHE_POLICY_PIPT	3

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_ctr[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_EXACT, 31, 1, 1),	/* RAO */
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_HIGHER_SAFE, 24, 4, 0),	/* CWG */
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, 20, 4, 0),	/* ERG */
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, 16, 4, 1),	/* DminLine */
	/*
	 * Linux can handle differing I-cache policies. Userspace JITs will
	 * make use of *minLine.
	 * If we have differing I-cache policies, report it as the weakest - AIVIVT.
	 */
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_NONSTRICT, FTR_EXACT, 14, 2, ICACHE_POLICY_AIVIVT),	/* L1Ip */
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, 0, 4, 0),	/* IminLine */
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
struct arm64_ftr_reg arm64_ftr_reg_ctrel0 = {
	.name		= "SYS_CTR_EL0",
	.ftr_bits	= ftr_ctr
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_id_mmfr0[] = {
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 28, 4, 0xf),	/* InnerShr */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 24, 4, 0),	/* FCSE */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, 20, 4, 0),	/* AuxReg */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 16, 4, 0),	/* TCM */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 12, 4, 0),	/* ShareLvl */
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 8, 4, 0xf),	/* OuterShr */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 4, 4, 0),	/* PMSA */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 0, 4, 0),	/* VMSA */
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_id_aa64dfr0[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 36, 28, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE, ID_AA64DFR0_PMSVER_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64DFR0_CTX_CMPS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64DFR0_WRPS_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, ID_AA64DFR0_BRPS_SHIFT, 4, 0),
	/*
	 * We can instantiate multiple PMU instances with different levels
	 * of support.
	 */
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_EXACT, ID_AA64DFR0_PMUVER_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64DFR0_TRACEVER_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_AA64DFR0_DEBUGVER_SHIFT, 4, 0x6),
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_mvfr2[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 4, 4, 0),		/* FPMisc */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 0, 4, 0),		/* SIMDMisc */
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_dczid[] = {
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_EXACT, 4, 1, 1),		/* DZP */
	ARM64_FTR_BITS(FTR_VISIBLE, FTR_STRICT, FTR_LOWER_SAFE, 0, 4, 0),	/* BS */
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_id_isar5[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_ISAR5_RDM_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_ISAR5_CRC32_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_ISAR5_SHA2_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_ISAR5_SHA1_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_ISAR5_AES_SHIFT, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, ID_ISAR5_SEVL_SHIFT, 4, 0),
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_id_mmfr4[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 4, 4, 0),		/* ac2 */
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_id_pfr0[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 12, 4, 0),	/* State3 */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 8, 4, 0),		/* State2 */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 4, 4, 0),		/* State1 */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 0, 4, 0),		/* State0 */
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_id_dfr0[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 28, 4, 0),
	S_ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 24, 4, 0xf),	/* PerfMon */
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 20, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 16, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 12, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 8, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 4, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 0, 4, 0),
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_zcr[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_NONSTRICT, FTR_LOWER_SAFE,
		ZCR_EL1_LEN_SHIFT, ZCR_EL1_LEN_SIZE, 0),	/* LEN */
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
/*
 * Common ftr bits for a 32bit register with all hidden, strict
 * attributes, with 4bit feature fields and a default safe value of
 * 0. Covers the following 32bit registers:
 * id_isar[0-4], id_mmfr[1-3], id_pfr1, mvfr[0-1]
 */
static const struct arm64_ftr_bits ftr_generic_32bits[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 28, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 24, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 20, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 16, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 12, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 8, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 4, 4, 0),
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_LOWER_SAFE, 0, 4, 0),
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
/* Table for a single 32bit feature value */
static const struct arm64_ftr_bits ftr_single32[] = {
	ARM64_FTR_BITS(FTR_HIDDEN, FTR_STRICT, FTR_EXACT, 0, 32, 0),
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_ftr_bits ftr_raz[] = {
	ARM64_FTR_END,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
#define ARM64_FTR_REG(id, table) {		\
	.sys_id = id,				\
	.reg = 	&(struct arm64_ftr_reg){	\
		.name = #id,			\
		.ftr_bits = &((table)[0]),	\
	}}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct __ftr_reg_entry {
	uint32_t		sys_id;
	struct arm64_ftr_reg 	*reg;
} arm64_ftr_regs[] = {

	/* Op1 = 0, CRn = 0, CRm = 1 */
	ARM64_FTR_REG(SYS_ID_PFR0_EL1, ftr_id_pfr0),
	ARM64_FTR_REG(SYS_ID_PFR1_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_ID_DFR0_EL1, ftr_id_dfr0),
	ARM64_FTR_REG(SYS_ID_MMFR0_EL1, ftr_id_mmfr0),
	ARM64_FTR_REG(SYS_ID_MMFR1_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_ID_MMFR2_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_ID_MMFR3_EL1, ftr_generic_32bits),

	/* Op1 = 0, CRn = 0, CRm = 2 */
	ARM64_FTR_REG(SYS_ID_ISAR0_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_ID_ISAR1_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_ID_ISAR2_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_ID_ISAR3_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_ID_ISAR4_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_ID_ISAR5_EL1, ftr_id_isar5),
	ARM64_FTR_REG(SYS_ID_MMFR4_EL1, ftr_id_mmfr4),

	/* Op1 = 0, CRn = 0, CRm = 3 */
	ARM64_FTR_REG(SYS_MVFR0_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_MVFR1_EL1, ftr_generic_32bits),
	ARM64_FTR_REG(SYS_MVFR2_EL1, ftr_mvfr2),

	/* Op1 = 0, CRn = 0, CRm = 4 */
	ARM64_FTR_REG(SYS_ID_AA64PFR0_EL1, ftr_id_aa64pfr0),
	ARM64_FTR_REG(SYS_ID_AA64PFR1_EL1, ftr_raz),
	ARM64_FTR_REG(SYS_ID_AA64ZFR0_EL1, ftr_raz),

	/* Op1 = 0, CRn = 0, CRm = 5 */
	ARM64_FTR_REG(SYS_ID_AA64DFR0_EL1, ftr_id_aa64dfr0),
	ARM64_FTR_REG(SYS_ID_AA64DFR1_EL1, ftr_raz),

	/* Op1 = 0, CRn = 0, CRm = 6 */
	ARM64_FTR_REG(SYS_ID_AA64ISAR0_EL1, ftr_id_aa64isar0),
	ARM64_FTR_REG(SYS_ID_AA64ISAR1_EL1, ftr_raz),

	/* Op1 = 0, CRn = 0, CRm = 7 */
	ARM64_FTR_REG(SYS_ID_AA64MMFR0_EL1, ftr_id_aa64mmfr0),
	ARM64_FTR_REG(SYS_ID_AA64MMFR1_EL1, ftr_id_aa64mmfr1),
	ARM64_FTR_REG(SYS_ID_AA64MMFR2_EL1, ftr_id_aa64mmfr2),

	/* Op1 = 0, CRn = 1, CRm = 2 */
	ARM64_FTR_REG(SYS_ZCR_EL1, ftr_zcr),

	/* Op1 = 3, CRn = 0, CRm = 0 */
	{ SYS_CTR_EL0, &arm64_ftr_reg_ctrel0 },
	ARM64_FTR_REG(SYS_DCZID_EL0, ftr_dczid),

	/* Op1 = 3, CRn = 14, CRm = 0 */
	ARM64_FTR_REG(SYS_CNTFRQ_EL0, ftr_single32),
};


/* @ref.impl lib/bsearch.c */
/*
 * bsearch - binary search an array of elements
 * @key: pointer to item being searched for
 * @base: pointer to first element to search
 * @num: number of elements
 * @size: size of each element
 * @cmp: pointer to comparison function
 *
 * This function does a binary search on the given array.  The
 * contents of the array should already be in ascending sorted order
 * under the provided comparison function.
 *
 * Note that the key need not have the same type as the elements in
 * the array, e.g. key could be a string and the comparison function
 * could compare the string with the struct's name field.  However, if
 * the key and elements in the array are of the same type, you can use
 * the same comparison function for both sort() and bsearch().
 */
void *bsearch(const void *key, const void *base, size_t num, size_t size,
	      int (*cmp)(const void *key, const void *elt))
{
	size_t start = 0, end = num;
	int result;

	while (start < end) {
		size_t mid = start + (end - start) / 2;

		result = cmp(key, base + mid * size);
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return (void *)base + mid * size;
	}

	return NULL;
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static int search_cmp_ftr_reg(const void *id, const void *regp)
{
	return (int)(unsigned long)id - (int)((const struct __ftr_reg_entry *)regp)->sys_id;
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
/*
 * get_arm64_ftr_reg - Lookup a feature register entry using its
 * sys_reg() encoding. With the array arm64_ftr_regs sorted in the
 * ascending order of sys_id , we use binary search to find a matching
 * entry.
 *
 * returns - Upon success,  matching ftr_reg entry for id.
 *         - NULL on failure. It is upto the caller to decide
 *     the impact of a failure.
 */
static struct arm64_ftr_reg *get_arm64_ftr_reg(uint32_t sys_id)
{
	const struct __ftr_reg_entry *ret;

	ret = bsearch((const void *)(unsigned long)sys_id,
		      arm64_ftr_regs,
		      sizeof(arm64_ftr_regs)/sizeof(arm64_ftr_regs[0]),
		      sizeof(arm64_ftr_regs[0]),
		      search_cmp_ftr_reg);
	if (ret)
		return ret->reg;
	return NULL;
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static uint64_t arm64_ftr_set_value(const struct arm64_ftr_bits *ftrp, int64_t reg,
			       int64_t ftr_val)
{
	uint64_t mask = arm64_ftr_mask(ftrp);

	reg &= ~mask;
	reg |= (ftr_val << ftrp->shift) & mask;
	return reg;
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static int64_t arm64_ftr_safe_value(const struct arm64_ftr_bits *ftrp, int64_t new,
				int64_t cur)
{
	int64_t ret = 0;

	switch (ftrp->type) {
	case FTR_EXACT:
		ret = ftrp->safe_val;
		break;
	case FTR_LOWER_SAFE:
		ret = new < cur ? new : cur;
		break;
	case FTR_HIGHER_SAFE:
		ret = new > cur ? new : cur;
		break;
	default:
		kprintf("Unknown FTR type: %d\n", ftrp->type);
		panic("Unknown FTR type");
	}

	return ret;
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static void sort_ftr_regs(void)
{
	int i;

	/* Check that the array is sorted so that we can do the binary search */
	for (i = 1; i < sizeof(arm64_ftr_regs)/sizeof(arm64_ftr_regs[0]); i++) {
		if (arm64_ftr_regs[i].sys_id < arm64_ftr_regs[i - 1].sys_id) {
			panic("FTR regs array is broken.");
		}
	}
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static void init_cpu_ftr_reg(uint32_t sys_reg, uint64_t new)
{
	uint64_t val = 0;
	uint64_t strict_mask = ~0x0ULL;
	uint64_t user_mask = 0;
	uint64_t valid_mask = 0;

	const struct arm64_ftr_bits *ftrp;
	struct arm64_ftr_reg *reg = get_arm64_ftr_reg(sys_reg);

	if (!reg) {
		kprintf("missing sys_reg: 0x%x\n", sys_reg);
		panic("FTR register not found.");
	}

	for (ftrp  = reg->ftr_bits; ftrp->width; ftrp++) {
		uint64_t ftr_mask = arm64_ftr_mask(ftrp);
		int64_t ftr_new = arm64_ftr_value(ftrp, new);

		val = arm64_ftr_set_value(ftrp, val, ftr_new);

		valid_mask |= ftr_mask;
		if (!ftrp->strict)
			strict_mask &= ~ftr_mask;
		if (ftrp->visible)
			user_mask |= ftr_mask;
		else
			reg->user_val = arm64_ftr_set_value(ftrp,
							    reg->user_val,
							    ftrp->safe_val);
	}

	val &= valid_mask;

	reg->sys_val = val;
	reg->strict_mask = strict_mask;
	reg->user_mask = user_mask;
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
void init_cpu_features(struct cpuinfo_arm64 *info)
{
	/* Before we start using the tables, make sure it is sorted */
	sort_ftr_regs();

	init_cpu_ftr_reg(SYS_CTR_EL0, info->reg_ctr);
	init_cpu_ftr_reg(SYS_DCZID_EL0, info->reg_dczid);
	init_cpu_ftr_reg(SYS_CNTFRQ_EL0, info->reg_cntfrq);
	init_cpu_ftr_reg(SYS_ID_AA64DFR0_EL1, info->reg_id_aa64dfr0);
	init_cpu_ftr_reg(SYS_ID_AA64DFR1_EL1, info->reg_id_aa64dfr1);
	init_cpu_ftr_reg(SYS_ID_AA64ISAR0_EL1, info->reg_id_aa64isar0);
	init_cpu_ftr_reg(SYS_ID_AA64ISAR1_EL1, info->reg_id_aa64isar1);
	init_cpu_ftr_reg(SYS_ID_AA64MMFR0_EL1, info->reg_id_aa64mmfr0);
	init_cpu_ftr_reg(SYS_ID_AA64MMFR1_EL1, info->reg_id_aa64mmfr1);
	init_cpu_ftr_reg(SYS_ID_AA64MMFR2_EL1, info->reg_id_aa64mmfr2);
	init_cpu_ftr_reg(SYS_ID_AA64PFR0_EL1, info->reg_id_aa64pfr0);
	init_cpu_ftr_reg(SYS_ID_AA64PFR1_EL1, info->reg_id_aa64pfr1);
	init_cpu_ftr_reg(SYS_ID_AA64ZFR0_EL1, info->reg_id_aa64zfr0);

	//if (id_aa64pfr0_32bit_el0(info->reg_id_aa64pfr0)) {
	//	panic("AArch32 is not supported.");
	//}

	if (id_aa64pfr0_sve(info->reg_id_aa64pfr0)) {
		init_cpu_ftr_reg(SYS_ZCR_EL1, info->reg_zcr);
	}
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static void update_cpu_ftr_reg(struct arm64_ftr_reg *reg, uint64_t new)
{
	const struct arm64_ftr_bits *ftrp;

	for (ftrp = reg->ftr_bits; ftrp->width; ftrp++) {
		int64_t ftr_cur = arm64_ftr_value(ftrp, reg->sys_val);
		int64_t ftr_new = arm64_ftr_value(ftrp, new);

		if (ftr_cur == ftr_new)
			continue;
		/* Find a safe value */
		ftr_new = arm64_ftr_safe_value(ftrp, ftr_new, ftr_cur);
		reg->sys_val = arm64_ftr_set_value(ftrp, reg->sys_val, ftr_new);
	}

}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static int check_update_ftr_reg(uint32_t sys_id, int cpu, uint64_t val, uint64_t boot)
{
	struct arm64_ftr_reg *regp = get_arm64_ftr_reg(sys_id);

	if (!regp) {
		kprintf("missing sys_reg: 0x%x\n", sys_id);
		panic("FTR register not found.");
	}

	update_cpu_ftr_reg(regp, val);
	if ((boot & regp->strict_mask) == (val & regp->strict_mask))
		return 0;
	kprintf("SANITY CHECK: Unexpected variation in %s. Boot CPU: %#016llx, CPU%d: %#016llx\n",
		regp->name, boot, cpu, val);
	return 1;
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
/*
 * Update system wide CPU feature registers with the values from a
 * non-boot CPU. Also performs SANITY checks to make sure that there
 * aren't any insane variations from that of the boot CPU.
 */
void update_cpu_features(int cpu,
			 struct cpuinfo_arm64 *info,
			 struct cpuinfo_arm64 *boot)
{
	int taint = 0;

	/*
	 * The kernel can handle differing I-cache policies, but otherwise
	 * caches should look identical. Userspace JITs will make use of
	 * *minLine.
	 */
	taint |= check_update_ftr_reg(SYS_CTR_EL0, cpu,
				      info->reg_ctr, boot->reg_ctr);

	/*
	 * Userspace may perform DC ZVA instructions. Mismatched block sizes
	 * could result in too much or too little memory being zeroed if a
	 * process is preempted and migrated between CPUs.
	 */
	taint |= check_update_ftr_reg(SYS_DCZID_EL0, cpu,
				      info->reg_dczid, boot->reg_dczid);

	/* If different, timekeeping will be broken (especially with KVM) */
	taint |= check_update_ftr_reg(SYS_CNTFRQ_EL0, cpu,
				      info->reg_cntfrq, boot->reg_cntfrq);

	/*
	 * The kernel uses self-hosted debug features and expects CPUs to
	 * support identical debug features. We presently need CTX_CMPs, WRPs,
	 * and BRPs to be identical.
	 * ID_AA64DFR1 is currently RES0.
	 */
	taint |= check_update_ftr_reg(SYS_ID_AA64DFR0_EL1, cpu,
				      info->reg_id_aa64dfr0, boot->reg_id_aa64dfr0);
	taint |= check_update_ftr_reg(SYS_ID_AA64DFR1_EL1, cpu,
				      info->reg_id_aa64dfr1, boot->reg_id_aa64dfr1);
	/*
	 * Even in big.LITTLE, processors should be identical instruction-set
	 * wise.
	 */
	taint |= check_update_ftr_reg(SYS_ID_AA64ISAR0_EL1, cpu,
				      info->reg_id_aa64isar0, boot->reg_id_aa64isar0);
	taint |= check_update_ftr_reg(SYS_ID_AA64ISAR1_EL1, cpu,
				      info->reg_id_aa64isar1, boot->reg_id_aa64isar1);

	/*
	 * Differing PARange support is fine as long as all peripherals and
	 * memory are mapped within the minimum PARange of all CPUs.
	 * Linux should not care about secure memory.
	 */
	taint |= check_update_ftr_reg(SYS_ID_AA64MMFR0_EL1, cpu,
				      info->reg_id_aa64mmfr0, boot->reg_id_aa64mmfr0);
	taint |= check_update_ftr_reg(SYS_ID_AA64MMFR1_EL1, cpu,
				      info->reg_id_aa64mmfr1, boot->reg_id_aa64mmfr1);
	taint |= check_update_ftr_reg(SYS_ID_AA64MMFR2_EL1, cpu,
				      info->reg_id_aa64mmfr2, boot->reg_id_aa64mmfr2);

	/*
	 * EL3 is not our concern.
	 * ID_AA64PFR1 is currently RES0.
	 */
	taint |= check_update_ftr_reg(SYS_ID_AA64PFR0_EL1, cpu,
				      info->reg_id_aa64pfr0, boot->reg_id_aa64pfr0);
	taint |= check_update_ftr_reg(SYS_ID_AA64PFR1_EL1, cpu,
				      info->reg_id_aa64pfr1, boot->reg_id_aa64pfr1);
	taint |= check_update_ftr_reg(SYS_ID_AA64ZFR0_EL1, cpu,
				      info->reg_id_aa64zfr0, boot->reg_id_aa64zfr0);

	/*
	 * If we have AArch32, we care about 32-bit features for compat.
	 * If the system doesn't support AArch32, don't update them.
	 */
	//if (id_aa64pfr0_32bit_el0(read_system_reg(SYS_ID_AA64PFR0_EL1)) &&
	//    id_aa64pfr0_32bit_el0(info->reg_id_aa64pfr0)) {
	//	panic("AArch32 is not supported.");
	//}

	if (id_aa64pfr0_sve(info->reg_id_aa64pfr0)) {
		taint |= check_update_ftr_reg(SYS_ZCR_EL1, cpu,
					info->reg_zcr, boot->reg_zcr);
	}

	/*
	 * Mismatched CPU features are a recipe for disaster. Don't even
	 * pretend to support them.
	 */
	if (taint) {
		kprintf("Unsupported CPU feature variation.\n");
	}
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
uint64_t read_system_reg(uint32_t id)
{
	struct arm64_ftr_reg *regp = get_arm64_ftr_reg(id);

	/* We shouldn't get a request for an unsupported register */
	if (!regp) {
		kprintf("missing sys_reg: 0x%x\n", id);
		panic("FTR register not found.");
	}

	return regp->sys_val;
}

/* @ref.impl arch/arm64/include/asm/insn.h */
enum aarch64_insn_imm_type {
	AARCH64_INSN_IMM_ADR,
	AARCH64_INSN_IMM_26,
	AARCH64_INSN_IMM_19,
	AARCH64_INSN_IMM_16,
	AARCH64_INSN_IMM_14,
	AARCH64_INSN_IMM_12,
	AARCH64_INSN_IMM_9,
	AARCH64_INSN_IMM_7,
	AARCH64_INSN_IMM_6,
	AARCH64_INSN_IMM_S,
	AARCH64_INSN_IMM_R,
	AARCH64_INSN_IMM_MAX
};

/* @ref.impl arch/arm64/include/asm/insn.h */
enum aarch64_insn_register_type {
	AARCH64_INSN_REGTYPE_RT,
	AARCH64_INSN_REGTYPE_RN,
	AARCH64_INSN_REGTYPE_RT2,
	AARCH64_INSN_REGTYPE_RM,
	AARCH64_INSN_REGTYPE_RD,
	AARCH64_INSN_REGTYPE_RA,
};

/* @ref.impl arch/arm64/kernel/insn.c */
static int aarch64_get_imm_shift_mask(enum aarch64_insn_imm_type type,
				      uint32_t *maskp, int *shiftp)
{
	uint32_t mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_26:
		mask = BIT(26) - 1;
		shift = 0;
		break;
	case AARCH64_INSN_IMM_19:
		mask = BIT(19) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_16:
		mask = BIT(16) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_14:
		mask = BIT(14) - 1;
		shift = 5;
		break;
	case AARCH64_INSN_IMM_12:
		mask = BIT(12) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_9:
		mask = BIT(9) - 1;
		shift = 12;
		break;
	case AARCH64_INSN_IMM_7:
		mask = BIT(7) - 1;
		shift = 15;
		break;
	case AARCH64_INSN_IMM_6:
	case AARCH64_INSN_IMM_S:
		mask = BIT(6) - 1;
		shift = 10;
		break;
	case AARCH64_INSN_IMM_R:
		mask = BIT(6) - 1;
		shift = 16;
		break;
	default:
		return -EINVAL;
	}

	*maskp = mask;
	*shiftp = shift;

	return 0;
}

/* @ref.impl arch/arm64/kernel/insn.c */
#define ADR_IMM_HILOSPLIT	2
#define ADR_IMM_SIZE		(1UL << 21) //2MiB
#define ADR_IMM_LOMASK		((1 << ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_HIMASK		((ADR_IMM_SIZE >> ADR_IMM_HILOSPLIT) - 1)
#define ADR_IMM_LOSHIFT		29
#define ADR_IMM_HISHIFT		5

/* @ref.impl arch/arm64/kernel/insn.c */
uint64_t aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, uint32_t insn)
{
	uint32_t immlo, immhi, mask;
	int shift;

	switch (type) {
	case AARCH64_INSN_IMM_ADR:
		shift = 0;
		immlo = (insn >> ADR_IMM_LOSHIFT) & ADR_IMM_LOMASK;
		immhi = (insn >> ADR_IMM_HISHIFT) & ADR_IMM_HIMASK;
		insn = (immhi << ADR_IMM_HILOSPLIT) | immlo;
		mask = ADR_IMM_SIZE - 1;
		break;
	default:
		if (aarch64_get_imm_shift_mask(type, &mask, &shift) < 0) {
			kprintf("aarch64_insn_decode_immediate: unknown immediate encoding %d\n",
			       type);
			return 0;
		}
	}

	return (insn >> shift) & mask;
}

/* @ref.impl arch/arm64/kernel/insn.c */
uint32_t aarch64_insn_decode_register(enum aarch64_insn_register_type type,
				      uint32_t insn)
{
	int shift;

	switch (type) {
	case AARCH64_INSN_REGTYPE_RT:
	case AARCH64_INSN_REGTYPE_RD:
		shift = 0;
		break;
	case AARCH64_INSN_REGTYPE_RN:
		shift = 5;
		break;
	case AARCH64_INSN_REGTYPE_RT2:
	case AARCH64_INSN_REGTYPE_RA:
		shift = 10;
		break;
	case AARCH64_INSN_REGTYPE_RM:
		shift = 16;
		break;
	default:
		kprintf("%s: unknown register type encoding %d\n", __func__,
		       type);
		return 0;
	}

	return (insn >> shift) & GENMASK(4, 0);
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
/*
 * With CRm == 0, reg should be one of :
 * MIDR_EL1, MPIDR_EL1 or REVIDR_EL1.
 */
static inline int emulate_id_reg(uint32_t id, uint64_t *valp)
{
	switch (id) {
	case SYS_MIDR_EL1:
		*valp = read_cpuid_id();
		break;
	case SYS_MPIDR_EL1:
		*valp = SYS_MPIDR_SAFE_VAL;
		break;
	case SYS_REVIDR_EL1:
		/* IMPLEMENTATION DEFINED values are emulated with 0 */
		*valp = 0;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
/*
 * We emulate only the following system register space.
 * Op0 = 0x3, CRn = 0x0, Op1 = 0x0, CRm = [0, 4 - 7]
 * See Table C5-6 System instruction encodings for System register accesses,
 * ARMv8 ARM(ARM DDI 0487A.f) for more details.
 */
static inline int is_emulated(uint32_t id)
{
	return (sys_reg_Op0(id) == 0x3 &&
		sys_reg_CRn(id) == 0x0 &&
		sys_reg_Op1(id) == 0x0 &&
		(sys_reg_CRm(id) == 0 ||
		 ((sys_reg_CRm(id) >= 4) && (sys_reg_CRm(id) <= 7))));
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static int emulate_sys_reg(uint32_t id, uint64_t *valp)
{
	struct arm64_ftr_reg *regp;

	if (!is_emulated(id))
		return -EINVAL;

	if (sys_reg_CRm(id) == 0)
		return emulate_id_reg(id, valp);

	regp = get_arm64_ftr_reg(id);
	if (regp)
		*valp = arm64_ftr_reg_user_value(regp);
	else
		/*
		 * The untracked registers are either IMPLEMENTATION DEFINED
		 * (e.g, ID_AFR0_EL1) or reserved RAZ.
		 */
		*valp = 0;
	return 0;
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static int emulate_mrs(struct pt_regs *regs, uint32_t insn)
{
	int rc;
	uint32_t sys_reg, dst;
	uint64_t val;

	/*
	 * sys_reg values are defined as used in mrs/msr instruction.
	 * shift the imm value to get the encoding.
	 */
	sys_reg = (uint32_t)aarch64_insn_decode_immediate(AARCH64_INSN_IMM_16, insn) << 5;
	rc = emulate_sys_reg(sys_reg, &val);
	if (!rc) {
		dst = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT, insn);
		pt_regs_write_reg(regs, dst, val);
		regs->pc += 4;
	}

	return rc;
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static struct undef_hook mrs_hook = {
	.instr_mask = 0xfff00000,
	.instr_val  = 0xd5300000,
	.pstate_mask = COMPAT_PSR_MODE_MASK,
	.pstate_val = PSR_MODE_EL0t,
	.fn = emulate_mrs,
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
int enable_mrs_emulation(void)
{
	register_undef_hook(&mrs_hook);
	return 0;
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static int
feature_matches(uint64_t reg, const struct arm64_cpu_capabilities *entry)
{
	int val = cpuid_feature_extract_field(reg, entry->field_pos, entry->sign);

	return val >= entry->min_field_value;
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static int
has_cpuid_feature(const struct arm64_cpu_capabilities *entry, int scope)
{
	uint64_t val = 0;

	//WARN_ON(scope == SCOPE_LOCAL_CPU && preemptible());
	if (scope == SCOPE_SYSTEM) {
		val = read_system_reg(entry->sys_reg);
	} else {
		panic("invalid argument. SCOPE_LOCAL_CPU is not implemented.");
		//val = __raw_read_system_reg(entry->sys_reg);
	}
	return feature_matches(val, entry);
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
#define HWCAP_CAP(reg, field, s, min_value, type, cap)	\
	{						\
		.desc = #cap,				\
		.def_scope = SCOPE_SYSTEM,		\
		.matches = has_cpuid_feature,		\
		.sys_reg = reg,				\
		.field_pos = field,			\
		.sign = s,				\
		.min_field_value = min_value,		\
		.hwcap_type = type,			\
		.hwcap = cap,				\
	}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static const struct arm64_cpu_capabilities arm64_elf_hwcaps[] = {
	HWCAP_CAP(SYS_ID_AA64ISAR0_EL1, ID_AA64ISAR0_AES_SHIFT, FTR_UNSIGNED, 2, CAP_HWCAP, HWCAP_PMULL),
	HWCAP_CAP(SYS_ID_AA64ISAR0_EL1, ID_AA64ISAR0_AES_SHIFT, FTR_UNSIGNED, 1, CAP_HWCAP, HWCAP_AES),
	HWCAP_CAP(SYS_ID_AA64ISAR0_EL1, ID_AA64ISAR0_SHA1_SHIFT, FTR_UNSIGNED, 1, CAP_HWCAP, HWCAP_SHA1),
	HWCAP_CAP(SYS_ID_AA64ISAR0_EL1, ID_AA64ISAR0_SHA2_SHIFT, FTR_UNSIGNED, 1, CAP_HWCAP, HWCAP_SHA2),
	HWCAP_CAP(SYS_ID_AA64ISAR0_EL1, ID_AA64ISAR0_CRC32_SHIFT, FTR_UNSIGNED, 1, CAP_HWCAP, HWCAP_CRC32),
	HWCAP_CAP(SYS_ID_AA64ISAR0_EL1, ID_AA64ISAR0_ATOMICS_SHIFT, FTR_UNSIGNED, 2, CAP_HWCAP, HWCAP_ATOMICS),
	HWCAP_CAP(SYS_ID_AA64ISAR0_EL1, ID_AA64ISAR0_RDM_SHIFT, FTR_UNSIGNED, 1, CAP_HWCAP, HWCAP_ASIMDRDM),
	HWCAP_CAP(SYS_ID_AA64PFR0_EL1, ID_AA64PFR0_FP_SHIFT, FTR_SIGNED, 0, CAP_HWCAP, HWCAP_FP),
	HWCAP_CAP(SYS_ID_AA64PFR0_EL1, ID_AA64PFR0_FP_SHIFT, FTR_SIGNED, 1, CAP_HWCAP, HWCAP_FPHP),
	HWCAP_CAP(SYS_ID_AA64PFR0_EL1, ID_AA64PFR0_ASIMD_SHIFT, FTR_SIGNED, 0, CAP_HWCAP, HWCAP_ASIMD),
	HWCAP_CAP(SYS_ID_AA64PFR0_EL1, ID_AA64PFR0_ASIMD_SHIFT, FTR_SIGNED, 1, CAP_HWCAP, HWCAP_ASIMDHP),
#ifdef CONFIG_ARM64_SVE
	HWCAP_CAP(SYS_ID_AA64PFR0_EL1, ID_AA64PFR0_SVE_SHIFT, FTR_UNSIGNED, 1, CAP_HWCAP, HWCAP_SVE),
#endif
	{},
};

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static void cap_set_elf_hwcap(const struct arm64_cpu_capabilities *cap)
{
	switch (cap->hwcap_type) {
	case CAP_HWCAP:
		elf_hwcap |= cap->hwcap;
		break;
	default:
		kprintf("invalid cpu capability type.\n");
	}
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
static void setup_elf_hwcaps(const struct arm64_cpu_capabilities *hwcaps)
{
	/* @ref.impl drivers/clocksource/arm_arch_timer.c::arch_timer_evtstrm_enable */
#ifdef CONFIG_ARM_ARCH_TIMER_EVTSTREAM
	elf_hwcap |= HWCAP_EVTSTRM;
#endif /* CONFIG_ARM_ARCH_TIMER_EVTSTREAM */

	/* We support emulation of accesses to CPU ID feature registers */
	elf_hwcap |= HWCAP_CPUID;
	for (; hwcaps->matches; hwcaps++) {
		if (hwcaps->matches(hwcaps, hwcaps->def_scope)) {
			cap_set_elf_hwcap(hwcaps);
		}
	}
}

/* @ref.impl arch/arm64/kernel/cpufeature.c */
void setup_cpu_features(void)
{
	setup_elf_hwcaps(arm64_elf_hwcaps);
}

#ifdef POSTK_DEBUG_ARCH_DEP_65
unsigned long arch_get_hwcap(void)
{
	return elf_hwcap;
}
#endif /* POSTK_DEBUG_ARCH_DEP_65 */
