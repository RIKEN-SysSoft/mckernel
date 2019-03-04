/* cpufeature.h COPYRIGHT FUJITSU LIMITED 2017 */

#ifndef __ASM_CPUFEATURE_H
#define __ASM_CPUFEATURE_H

#include <types.h>
#include <cpuinfo.h>
#include <sysreg.h>

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
/* CPU feature register tracking */
enum ftr_type {
	FTR_EXACT,	/* Use a predefined safe value */
	FTR_LOWER_SAFE,	/* Smaller value is safe */
	FTR_HIGHER_SAFE,/* Bigger value is safe */
};

#define FTR_STRICT	(1)	/* SANITY check strict matching required */
#define FTR_NONSTRICT	(0)	/* SANITY check ignored */

#define FTR_SIGNED	(1)	/* Value should be treated as signed */
#define FTR_UNSIGNED	(0)	/* Value should be treated as unsigned */

#define FTR_VISIBLE	(1)	/* Feature visible to the user space */
#define FTR_HIDDEN	(0)	/* Feature is hidden from the user */

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
struct arm64_ftr_bits {
	int		sign;	/* Value is signed ? */
	int		visible;
	int		strict;	/* CPU Sanity check: strict matching required ? */
	enum ftr_type	type;
	uint8_t		shift;
	uint8_t		width;
	int64_t		safe_val; /* safe value for FTR_EXACT features */
};

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
/*
 * @arm64_ftr_reg - Feature register
 * @strict_mask		Bits which should match across all CPUs for sanity.
 * @sys_val		Safe value across the CPUs (system view)
 */
struct arm64_ftr_reg {
	const char			*name;
	uint64_t			strict_mask;
	uint64_t			user_mask;
	uint64_t			sys_val;
	uint64_t			user_val;
	const struct arm64_ftr_bits	*ftr_bits;
};

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
extern struct arm64_ftr_reg arm64_ftr_reg_ctrel0;

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
/* scope of capability check */
enum {
	SCOPE_SYSTEM,
	SCOPE_LOCAL_CPU,
};

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
struct arm64_cpu_capabilities {
	const char *desc;
	uint16_t capability;
	int def_scope;/* default scope */
	int (*matches)(const struct arm64_cpu_capabilities *caps, int scope);
	int (*enable)(void *);/* Called on all active CPUs */
	uint32_t sys_reg;
	uint8_t field_pos;
	uint8_t min_field_value;
	uint8_t hwcap_type;
	int sign;
	unsigned long hwcap;
};

/* @ref.impl include/linux/bitops.h */
/*
 * Create a contiguous bitmask starting at bit position @l and ending at
 * position @h. For example
 * GENMASK_ULL(39, 21) gives us the 64bit vector 0x000000ffffe00000.
 */
#define GENMASK(h, l) \
	(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
static inline uint64_t arm64_ftr_mask(const struct arm64_ftr_bits *ftrp)
{
	return (uint64_t)GENMASK(ftrp->shift + ftrp->width - 1, ftrp->shift);
}

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
static inline int
cpuid_feature_extract_signed_field_width(uint64_t features, int field, int width)
{
	return (int64_t)(features << (64 - width - field)) >> (64 - width);
}

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
static inline int
cpuid_feature_extract_signed_field(uint64_t features, int field)
{
	return cpuid_feature_extract_signed_field_width(features, field, 4);
}

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
static inline unsigned int
cpuid_feature_extract_unsigned_field_width(uint64_t features, int field, int width)
{
	return (uint64_t)(features << (64 - width - field)) >> (64 - width);
}

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
static inline unsigned int
cpuid_feature_extract_unsigned_field(uint64_t features, int field)
{
	return cpuid_feature_extract_unsigned_field_width(features, field, 4);
}

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
static inline uint64_t arm64_ftr_reg_user_value(const struct arm64_ftr_reg *reg)
{
	return (reg->user_val | (reg->sys_val & reg->user_mask));
}

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
static inline int
cpuid_feature_extract_field_width(uint64_t features, int field, int width, int sign)
{
	return (sign) ?
		cpuid_feature_extract_signed_field_width(features, field, width) :
		cpuid_feature_extract_unsigned_field_width(features, field, width);
}

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
static inline int
cpuid_feature_extract_field(uint64_t features, int field, int sign)
{
	return cpuid_feature_extract_field_width(features, field, 4, sign);
}

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
static inline int64_t arm64_ftr_value(const struct arm64_ftr_bits *ftrp, uint64_t val)
{
	return (int64_t)cpuid_feature_extract_field_width(val, ftrp->shift, ftrp->width, ftrp->sign);
}

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
static inline int id_aa64pfr0_32bit_el0(uint64_t pfr0)
{
	uint32_t val = cpuid_feature_extract_unsigned_field(pfr0, ID_AA64PFR0_EL0_SHIFT);

	return val == ID_AA64PFR0_EL0_32BIT_64BIT;
}

/* @ref.impl arch/arm64/include/asm/cpufeature.h */
static inline int id_aa64pfr0_sve(uint64_t pfr0)
{
	uint32_t val = cpuid_feature_extract_unsigned_field(pfr0, ID_AA64PFR0_SVE_SHIFT);

	return val > 0;
}

void setup_cpu_features(void);
void update_cpu_features(int cpu,
			 struct cpuinfo_arm64 *info,
			 struct cpuinfo_arm64 *boot);
uint64_t read_system_reg(uint32_t id);
void init_cpu_features(struct cpuinfo_arm64 *info);
int enable_mrs_emulation(void);

/* @ref.impl arch/arm64/include/asm/hwcap.h */
enum {
	CAP_HWCAP = 1,
#ifdef CONFIG_COMPAT
	CAP_COMPAT_HWCAP,
	CAP_COMPAT_HWCAP2,
#endif
};

#endif /* __ASM_CPUFEATURE_H */
