/* perfctr_armv8pmu.c COPYRIGHT FUJITSU LIMITED 2016-2018 */
#include <arch-perfctr.h>
#include <mc_perf_event.h>
#include <ihk/perfctr.h>
#include <errno.h>
#include <ihk/debug.h>
#include <debug.h>
#include <sysreg.h>
#include <virt.h>
#include <bitops.h>
#include <string.h>
#include <signal.h>
#include <cls.h>
#include <process.h>

#define BIT(nr) (1UL << (nr))

//#define DEBUG_PRINT_PMU
#ifdef DEBUG_PRINT_PMU
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif


/*
 * @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c
 * Perf Events' indices
 */
#define	ARMV8_IDX_CYCLE_COUNTER	0
#define	ARMV8_IDX_COUNTER0	1
#define	ARMV8_IDX_COUNTER_LAST	(ARMV8_IDX_CYCLE_COUNTER + get_per_cpu_pmu()->num_events - 1)

/* @ref.impl linux-v4.15-rc3 arch/arm64/include/asm/perf_event.h */
#define	ARMV8_PMU_MAX_COUNTERS	32
#define	ARMV8_PMU_COUNTER_MASK	(ARMV8_PMU_MAX_COUNTERS - 1)

/*
 * ARMv8 low level PMU access
 */

/*
 * @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c
 * Perf Event to low level counters mapping
 */
#define	ARMV8_IDX_TO_COUNTER(x)	\
	(((x) - ARMV8_IDX_COUNTER0) & ARMV8_PMU_COUNTER_MASK)

/*
 * @ref.impl linux-v4.15-rc3 arch/arm64/include/asm/perf_event.h
 * Per-CPU PMCR: config reg
 */
#define ARMV8_PMU_PMCR_E	(1 << 0) /* Enable all counters */
#define ARMV8_PMU_PMCR_P	(1 << 1) /* Reset all counters */
#define ARMV8_PMU_PMCR_C	(1 << 2) /* Cycle counter reset */
#define ARMV8_PMU_PMCR_D	(1 << 3) /* CCNT counts every 64th cpu cycle */
#define ARMV8_PMU_PMCR_X	(1 << 4) /* Export to ETM */
#define ARMV8_PMU_PMCR_DP	(1 << 5) /* Disable CCNT if non-invasive debug*/
#define ARMV8_PMU_PMCR_LC	(1 << 6) /* Overflow on 64 bit cycle counter */
#define	ARMV8_PMU_PMCR_N_SHIFT	11	 /* Number of counters supported */
#define	ARMV8_PMU_PMCR_N_MASK	0x1f
#define	ARMV8_PMU_PMCR_MASK	0x7f	 /* Mask for writable bits */

/*
 * @ref.impl linux-v4.15-rc3 arch/arm64/include/asm/perf_event.h
 * PMOVSR: counters overflow flag status reg
 */
#define	ARMV8_PMU_OVSR_MASK		0xffffffff	/* Mask for writable bits */
#define	ARMV8_PMU_OVERFLOWED_MASK	ARMV8_PMU_OVSR_MASK

/*
 * @ref.impl linux-v4.15-rc3 arch/arm64/include/asm/perf_event.h
 * PMXEVTYPER: Event selection reg
 */
#define	ARMV8_PMU_EVTYPE_MASK	0xc800ffff	/* Mask for writable bits */
#define	ARMV8_PMU_EVTYPE_EVENT	0xffff		/* Mask for EVENT bits */

/*
 * @ref.impl linux-v4.15-rc3 arch/arm64/include/asm/perf_event.h
 * Event filters for PMUv3
 */
#define	ARMV8_PMU_EXCLUDE_EL1	(1 << 31)
#define	ARMV8_PMU_EXCLUDE_EL0	(1 << 30)
#define	ARMV8_PMU_INCLUDE_EL2	(1 << 27)

/*
 * @ref.impl linux-v4.15-rc3 arch/arm64/include/asm/perf_event.h
 * PMUSERENR: user enable reg
 */
#define ARMV8_PMU_USERENR_MASK	0xf		/* Mask for writable bits */
#define ARMV8_PMU_USERENR_EN	(1 << 0) /* PMU regs can be accessed at EL0 */
#define ARMV8_PMU_USERENR_SW	(1 << 1) /* PMSWINC can be written at EL0 */
#define ARMV8_PMU_USERENR_CR	(1 << 2) /* Cycle counter can be read at EL0 */
#define ARMV8_PMU_USERENR_ER	(1 << 3) /* Event counter can be read at EL0 */

/*
 * @ref.impl linux-v4.15-rc3 arch/arm64/include/asm/perf_event.h
 * PMUv3 event types: required events
 */
#define ARMV8_PMUV3_PERFCTR_SW_INCR				0x00
#define ARMV8_PMUV3_PERFCTR_L1D_CACHE_REFILL			0x03
#define ARMV8_PMUV3_PERFCTR_L1D_CACHE				0x04
#define ARMV8_PMUV3_PERFCTR_BR_MIS_PRED				0x10
#define ARMV8_PMUV3_PERFCTR_CPU_CYCLES				0x11
#define ARMV8_PMUV3_PERFCTR_BR_PRED				0x12

/*
 * @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c
 * ARMv8 PMUv3 Performance Events handling code.
 * Common event types (some are defined in asm/perf_event.h).
 */

/* At least one of the following is required. */
#define ARMV8_PMUV3_PERFCTR_INST_RETIRED			0x08
#define ARMV8_PMUV3_PERFCTR_INST_SPEC				0x1B

/* Common architectural events. */
#define ARMV8_PMUV3_PERFCTR_LD_RETIRED				0x06
#define ARMV8_PMUV3_PERFCTR_ST_RETIRED				0x07
#define ARMV8_PMUV3_PERFCTR_EXC_TAKEN				0x09
#define ARMV8_PMUV3_PERFCTR_EXC_RETURN				0x0A
#define ARMV8_PMUV3_PERFCTR_CID_WRITE_RETIRED			0x0B
#define ARMV8_PMUV3_PERFCTR_PC_WRITE_RETIRED			0x0C
#define ARMV8_PMUV3_PERFCTR_BR_IMMED_RETIRED			0x0D
#define ARMV8_PMUV3_PERFCTR_BR_RETURN_RETIRED			0x0E
#define ARMV8_PMUV3_PERFCTR_UNALIGNED_LDST_RETIRED		0x0F
#define ARMV8_PMUV3_PERFCTR_TTBR_WRITE_RETIRED			0x1C
#define ARMV8_PMUV3_PERFCTR_CHAIN				0x1E
#define ARMV8_PMUV3_PERFCTR_BR_RETIRED				0x21

/* Common microarchitectural events. */
#define ARMV8_PMUV3_PERFCTR_L1I_CACHE_REFILL			0x01
#define ARMV8_PMUV3_PERFCTR_L1I_TLB_REFILL			0x02
#define ARMV8_PMUV3_PERFCTR_L1D_TLB_REFILL			0x05
#define ARMV8_PMUV3_PERFCTR_MEM_ACCESS				0x13
#define ARMV8_PMUV3_PERFCTR_L1I_CACHE				0x14
#define ARMV8_PMUV3_PERFCTR_L1D_CACHE_WB			0x15
#define ARMV8_PMUV3_PERFCTR_L2D_CACHE				0x16
#define ARMV8_PMUV3_PERFCTR_L2D_CACHE_REFILL			0x17
#define ARMV8_PMUV3_PERFCTR_L2D_CACHE_WB			0x18
#define ARMV8_PMUV3_PERFCTR_BUS_ACCESS				0x19
#define ARMV8_PMUV3_PERFCTR_MEMORY_ERROR			0x1A
#define ARMV8_PMUV3_PERFCTR_BUS_CYCLES				0x1D
#define ARMV8_PMUV3_PERFCTR_L1D_CACHE_ALLOCATE			0x1F
#define ARMV8_PMUV3_PERFCTR_L2D_CACHE_ALLOCATE			0x20
#define ARMV8_PMUV3_PERFCTR_BR_MIS_PRED_RETIRED			0x22
#define ARMV8_PMUV3_PERFCTR_STALL_FRONTEND			0x23
#define ARMV8_PMUV3_PERFCTR_STALL_BACKEND			0x24
#define ARMV8_PMUV3_PERFCTR_L1D_TLB				0x25
#define ARMV8_PMUV3_PERFCTR_L1I_TLB				0x26
#define ARMV8_PMUV3_PERFCTR_L2I_CACHE				0x27
#define ARMV8_PMUV3_PERFCTR_L2I_CACHE_REFILL			0x28
#define ARMV8_PMUV3_PERFCTR_L3D_CACHE_ALLOCATE			0x29
#define ARMV8_PMUV3_PERFCTR_L3D_CACHE_REFILL			0x2A
#define ARMV8_PMUV3_PERFCTR_L3D_CACHE				0x2B
#define ARMV8_PMUV3_PERFCTR_L3D_CACHE_WB			0x2C
#define ARMV8_PMUV3_PERFCTR_L2D_TLB_REFILL			0x2D
#define ARMV8_PMUV3_PERFCTR_L2I_TLB_REFILL			0x2E
#define ARMV8_PMUV3_PERFCTR_L2D_TLB				0x2F
#define ARMV8_PMUV3_PERFCTR_L2I_TLB				0x30

/* @ref.impl linux-v4.15-rc3 include/linux/perf/arm_pmu.h */
#define HW_OP_UNSUPPORTED		0xFFFF
#define C(_x)				PERF_COUNT_HW_CACHE_##_x
#define CACHE_OP_UNSUPPORTED		0xFFFF

#define PERF_MAP_ALL_UNSUPPORTED					\
	[0 ... PERF_COUNT_HW_MAX - 1] = HW_OP_UNSUPPORTED

#define PERF_CACHE_MAP_ALL_UNSUPPORTED					\
[0 ... C(MAX) - 1] = {							\
	[0 ... C(OP_MAX) - 1] = {					\
		[0 ... C(RESULT_MAX) - 1] = CACHE_OP_UNSUPPORTED,	\
	},								\
}

/* PMUv3 HW events mapping. */

/*
 * @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c
 * ARMv8 Architectural defined events, not all of these may
 * be supported on any given implementation. Undefined events will
 * be disabled at run-time.
 */
static const unsigned armv8_pmuv3_perf_map[PERF_COUNT_HW_MAX] = {
	PERF_MAP_ALL_UNSUPPORTED,
	[PERF_COUNT_HW_CPU_CYCLES]		= ARMV8_PMUV3_PERFCTR_CPU_CYCLES,
	[PERF_COUNT_HW_INSTRUCTIONS]		= ARMV8_PMUV3_PERFCTR_INST_RETIRED,
	[PERF_COUNT_HW_CACHE_REFERENCES]	= ARMV8_PMUV3_PERFCTR_L1D_CACHE,
	[PERF_COUNT_HW_CACHE_MISSES]		= ARMV8_PMUV3_PERFCTR_L1D_CACHE_REFILL,
	[PERF_COUNT_HW_BRANCH_INSTRUCTIONS]	= ARMV8_PMUV3_PERFCTR_PC_WRITE_RETIRED,
	[PERF_COUNT_HW_BRANCH_MISSES]		= ARMV8_PMUV3_PERFCTR_BR_MIS_PRED,
	[PERF_COUNT_HW_BUS_CYCLES]		= ARMV8_PMUV3_PERFCTR_BUS_CYCLES,
	[PERF_COUNT_HW_STALLED_CYCLES_FRONTEND]	= ARMV8_PMUV3_PERFCTR_STALL_FRONTEND,
	[PERF_COUNT_HW_STALLED_CYCLES_BACKEND]	= ARMV8_PMUV3_PERFCTR_STALL_BACKEND,
};

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static const unsigned armv8_pmuv3_perf_cache_map[PERF_COUNT_HW_CACHE_MAX]
						[PERF_COUNT_HW_CACHE_OP_MAX]
						[PERF_COUNT_HW_CACHE_RESULT_MAX] = {
	PERF_CACHE_MAP_ALL_UNSUPPORTED,

	[C(L1D)][C(OP_READ)][C(RESULT_ACCESS)]	= ARMV8_PMUV3_PERFCTR_L1D_CACHE,
	[C(L1D)][C(OP_READ)][C(RESULT_MISS)]	= ARMV8_PMUV3_PERFCTR_L1D_CACHE_REFILL,
	[C(L1D)][C(OP_WRITE)][C(RESULT_ACCESS)]	= ARMV8_PMUV3_PERFCTR_L1D_CACHE,
	[C(L1D)][C(OP_WRITE)][C(RESULT_MISS)]	= ARMV8_PMUV3_PERFCTR_L1D_CACHE_REFILL,

	[C(L1I)][C(OP_READ)][C(RESULT_ACCESS)]	= ARMV8_PMUV3_PERFCTR_L1I_CACHE,
	[C(L1I)][C(OP_READ)][C(RESULT_MISS)]	= ARMV8_PMUV3_PERFCTR_L1I_CACHE_REFILL,

	[C(DTLB)][C(OP_READ)][C(RESULT_MISS)]	= ARMV8_PMUV3_PERFCTR_L1D_TLB_REFILL,
	[C(DTLB)][C(OP_READ)][C(RESULT_ACCESS)]	= ARMV8_PMUV3_PERFCTR_L1D_TLB,

	[C(ITLB)][C(OP_READ)][C(RESULT_MISS)]	= ARMV8_PMUV3_PERFCTR_L1I_TLB_REFILL,
	[C(ITLB)][C(OP_READ)][C(RESULT_ACCESS)]	= ARMV8_PMUV3_PERFCTR_L1I_TLB,

	[C(BPU)][C(OP_READ)][C(RESULT_ACCESS)]	= ARMV8_PMUV3_PERFCTR_BR_PRED,
	[C(BPU)][C(OP_READ)][C(RESULT_MISS)]	= ARMV8_PMUV3_PERFCTR_BR_MIS_PRED,
	[C(BPU)][C(OP_WRITE)][C(RESULT_ACCESS)]	= ARMV8_PMUV3_PERFCTR_BR_PRED,
	[C(BPU)][C(OP_WRITE)][C(RESULT_MISS)]	= ARMV8_PMUV3_PERFCTR_BR_MIS_PRED,
};

/* @ref.impl linux-v4.15-rc3 drivers/perf/arm_pmu.c */
static int
armpmu_map_cache_event(const unsigned (*cache_map)
				      [PERF_COUNT_HW_CACHE_MAX]
				      [PERF_COUNT_HW_CACHE_OP_MAX]
				      [PERF_COUNT_HW_CACHE_RESULT_MAX],
		       uint64_t config)
{
	unsigned int cache_type, cache_op, cache_result, ret;

	cache_type = (config >>  0) & 0xff;
	if (cache_type >= PERF_COUNT_HW_CACHE_MAX)
		return -EINVAL;

	cache_op = (config >>  8) & 0xff;
	if (cache_op >= PERF_COUNT_HW_CACHE_OP_MAX)
		return -EINVAL;

	cache_result = (config >> 16) & 0xff;
	if (cache_result >= PERF_COUNT_HW_CACHE_RESULT_MAX)
		return -EINVAL;

	if (!cache_map)
		return -ENOENT;

	ret = (int)(*cache_map)[cache_type][cache_op][cache_result];

	if (ret == CACHE_OP_UNSUPPORTED)
		return -ENOENT;

	return ret;
}

/* @ref.impl linux-v4.15-rc3 drivers/perf/arm_pmu.c */
static int
armpmu_map_hw_event(const unsigned int (*event_map)[PERF_COUNT_HW_MAX],
		    uint64_t config)
{
	int mapping;

	if (config >= PERF_COUNT_HW_MAX)
		return -EINVAL;

	if (!event_map)
		return -ENOENT;

	mapping = (*event_map)[config];
	return mapping == HW_OP_UNSUPPORTED ? -ENOENT : mapping;
}

/* @ref.impl linux-v4.15-rc3 drivers/perf/arm_pmu.c */
static int
armpmu_map_raw_event(uint32_t raw_event_mask, uint64_t config)
{
	return (int)(config & raw_event_mask);
}

/* @ref.impl linux-v4.15-rc3 drivers/perf/arm_pmu.c */
static int
armpmu_map_event(uint32_t type, uint64_t config,
		 const unsigned int (*event_map)[PERF_COUNT_HW_MAX],
		 const unsigned int (*cache_map)
				[PERF_COUNT_HW_CACHE_MAX]
				[PERF_COUNT_HW_CACHE_OP_MAX]
				[PERF_COUNT_HW_CACHE_RESULT_MAX],
		 uint32_t raw_event_mask)
{
	switch (type) {
	case PERF_TYPE_HARDWARE:
		return armpmu_map_hw_event(event_map, config);
	case PERF_TYPE_HW_CACHE:
		return armpmu_map_cache_event(cache_map, config);
	case PERF_TYPE_RAW:
		return armpmu_map_raw_event(raw_event_mask, config);
	}
	return -ENOENT;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_counter_valid(int idx)
{
	return idx >= ARMV8_IDX_CYCLE_COUNTER &&
		idx <= ARMV8_IDX_COUNTER_LAST;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline uint32_t armv8pmu_getreset_flags(void)
{
	uint32_t value;

	/* Read */
	value = read_sysreg(pmovsclr_el0);

	/* Write to clear flags */
	value &= ARMV8_PMU_OVSR_MASK;
	write_sysreg(value, pmovsclr_el0);

	return value;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_has_overflowed(uint32_t pmovsr)
{
	return pmovsr & ARMV8_PMU_OVERFLOWED_MASK;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static int __armv8_pmuv3_map_event(uint32_t type, uint64_t config,
				   const unsigned int (*extra_event_map)
						  [PERF_COUNT_HW_MAX],
				   const unsigned int (*extra_cache_map)
						  [PERF_COUNT_HW_CACHE_MAX]
						  [PERF_COUNT_HW_CACHE_OP_MAX]
						  [PERF_COUNT_HW_CACHE_RESULT_MAX])
{
	int hw_event_id;

	hw_event_id = armpmu_map_event(type, config, &armv8_pmuv3_perf_map,
				       &armv8_pmuv3_perf_cache_map,
				       ARMV8_PMU_EVTYPE_EVENT);

	/* Onl expose micro/arch events supported by this PMU */
	if ((hw_event_id > 0) && (hw_event_id < ARMV8_PMUV3_MAX_COMMON_EVENTS)
	    && test_bit(hw_event_id, get_per_cpu_pmu()->pmceid_bitmap)) {
		return hw_event_id;
	}

	return armpmu_map_event(type, config, extra_event_map, extra_cache_map,
				ARMV8_PMU_EVTYPE_EVENT);
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static int armv8_pmuv3_map_event(uint32_t type, uint64_t config)
{
	return __armv8_pmuv3_map_event(type, config, NULL, NULL);
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline uint32_t armv8pmu_pmcr_read(void)
{
	return read_sysreg(pmcr_el0);
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline void armv8pmu_pmcr_write(uint32_t val)
{
	val &= ARMV8_PMU_PMCR_MASK;
	isb();
	write_sysreg(val, pmcr_el0);
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_select_counter(int idx)
{
	uint32_t counter;

	if (!armv8pmu_counter_valid(idx)) {
		ekprintf("%s: The count_register#%d is not implemented.\n",
			__func__, idx);
		return -EINVAL;
	}

	counter = ARMV8_IDX_TO_COUNTER(idx);
	write_sysreg(counter, pmselr_el0);
	isb();

	return idx;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline uint32_t armv8pmu_read_counter(int idx)
{
	uint32_t value = 0;

	if (!armv8pmu_counter_valid(idx)) {
		ekprintf("%s: The count_register#%d is not implemented.\n",
			__func__, idx);
	}
	else if (idx == ARMV8_IDX_CYCLE_COUNTER) {
		value = read_sysreg(pmccntr_el0);
	}
	else if (armv8pmu_select_counter(idx) == idx) {
		value = read_sysreg(pmxevcntr_el0);
	}

	return value;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline void armv8pmu_write_counter(int idx, uint32_t value)
{
	if (!armv8pmu_counter_valid(idx)) {
		ekprintf("%s: The count_register#%d is not implemented.\n",
			__func__, idx);
	}
	else if (idx == ARMV8_IDX_CYCLE_COUNTER) {
		/*
		 * Set the upper 32bits as this is a 64bit counter but we only
		 * count using the lower 32bits and we want an interrupt when
		 * it overflows.
		 */
		uint64_t value64 = 0xffffffff00000000ULL | value;

		write_sysreg(value64, pmccntr_el0);
	}
	else if (armv8pmu_select_counter(idx) == idx) {
		write_sysreg(value, pmxevcntr_el0);
	}
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_enable_intens(int idx)
{
	uint32_t counter;

	if (!armv8pmu_counter_valid(idx)) {
		ekprintf("%s: The count_register#%d is not implemented.\n",
			__func__, idx);
		return -EINVAL;
	}

	counter = ARMV8_IDX_TO_COUNTER(idx);
	write_sysreg(BIT(counter), pmintenset_el1);
	return idx;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_disable_intens(int idx)
{
	uint32_t counter = ARMV8_IDX_TO_COUNTER(idx);

	write_sysreg(BIT(counter), pmintenclr_el1);
	isb();
	/* Clear the overflow flag in case an interrupt is pending. */
	write_sysreg(BIT(counter), pmovsclr_el0);
	isb();

	return idx;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static int armv8pmu_set_event_filter(unsigned long *config_base, int mode)
{
	/* exclude_idle is unused mode, unsupported */
//	if (attr->exclude_idle)
//		return -EPERM;

	/*
	 * If we're running in hyp mode, then we *are* the hypervisor.
	 * Therefore we ignore exclude_hv in this configuration, since
	 * there's no hypervisor to sample anyway. This is consistent
	 * with other architectures (x86 and Power).
	 */
	if (is_kernel_in_hyp_mode()) {
		if (mode & PERFCTR_KERNEL_MODE)
			*config_base |= ARMV8_PMU_INCLUDE_EL2;
	} else {
		if (!(mode & PERFCTR_KERNEL_MODE))
			*config_base |= ARMV8_PMU_EXCLUDE_EL1;
		/* exclude_hv is unused mode, unsupported */
//		if (!attr->exclude_hv)
//			config_base |= ARMV8_PMU_INCLUDE_EL2;
	}
	if (!(mode & PERFCTR_USER_MODE))
		*config_base |= ARMV8_PMU_EXCLUDE_EL0;

	return 0;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline void armv8pmu_write_evtype(int idx, uint32_t val)
{
	if (armv8pmu_select_counter(idx) == idx) {
		val &= ARMV8_PMU_EVTYPE_MASK;
		write_sysreg(val, pmxevtyper_el0);
	}
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_enable_counter(int idx)
{
	uint32_t counter;

	if (!armv8pmu_counter_valid(idx)) {
		ekprintf("%s: The count_register#%d is not implemented.\n",
			__func__, idx);
		return -EINVAL;
	}

	counter = ARMV8_IDX_TO_COUNTER(idx);
	write_sysreg(BIT(counter), pmcntenset_el0);
	return idx;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_disable_counter(int idx)
{
	uint32_t counter;

	if (!armv8pmu_counter_valid(idx)) {
		ekprintf("%s: The count_register#%d is not implemented.\n",
			__func__, idx);
		return -EINVAL;
	}

	counter = ARMV8_IDX_TO_COUNTER(idx);
	write_sysreg(BIT(counter), pmcntenclr_el0);
	return idx;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static ihk_spinlock_t pmu_lock = SPIN_LOCK_UNLOCKED;
static int armv8pmu_start(void)
{
	unsigned long flags;

	flags = ihk_mc_spinlock_lock(&pmu_lock);
	/* Enable all counters */
	armv8pmu_pmcr_write(armv8pmu_pmcr_read() | ARMV8_PMU_PMCR_E);
	ihk_mc_spinlock_unlock(&pmu_lock, flags);

	return 0;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static void armv8pmu_stop(void)
{
	unsigned long flags;

	flags = ihk_mc_spinlock_lock(&pmu_lock);
	/* Disable all counters */
	armv8pmu_pmcr_write(armv8pmu_pmcr_read() & ~ARMV8_PMU_PMCR_E);
	ihk_mc_spinlock_unlock(&pmu_lock, flags);
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static void armv8pmu_disable_event(int idx)
{
	unsigned long flags;

	/*
	 * Disable counter and interrupt
	 */
	flags = ihk_mc_spinlock_lock(&pmu_lock);

	/*
	 * Disable counter
	 */
	armv8pmu_disable_counter(idx);

	/*
	 * Disable interrupt for this counter
	 */
	armv8pmu_disable_intens(idx);

	ihk_mc_spinlock_unlock(&pmu_lock, flags);
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static void armv8pmu_reset(void *info)
{
	struct arm_pmu *cpu_pmu = (struct arm_pmu *)info;
	uint32_t idx, nb_cnt =
		cpu_pmu->per_cpu[ihk_mc_get_processor_id()].num_events;

	/* The counter and interrupt enable registers are unknown at reset. */
	for (idx = ARMV8_IDX_CYCLE_COUNTER; idx < nb_cnt; ++idx) {
		armv8pmu_disable_counter(idx);
		armv8pmu_disable_intens(idx);
	}

	/*
	 * Initialize & Reset PMNC. Request overflow interrupt for
	 * 64 bit cycle counter but cheat in armv8pmu_write_counter().
	 */
	armv8pmu_pmcr_write(ARMV8_PMU_PMCR_P | ARMV8_PMU_PMCR_C |
			    ARMV8_PMU_PMCR_LC);
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static int armv8pmu_get_event_idx(int num_events, unsigned long used_mask,
				  unsigned long config)
{
	int idx;
	unsigned long evtype = config & ARMV8_PMU_EVTYPE_EVENT;

	/* Always prefer to place a cycle counter into the cycle counter. */
	if (evtype == ARMV8_PMUV3_PERFCTR_CPU_CYCLES) {
		if (!(used_mask & (1UL << ARMV8_IDX_CYCLE_COUNTER)))
			return ARMV8_IDX_CYCLE_COUNTER;
	}

	/*
	 * Otherwise use events counters
	 */
	for (idx = ARMV8_IDX_COUNTER0; idx < num_events; ++idx) {
		if (!(used_mask & (1UL << idx)))
			return idx;
	}

	/* The counters are all in use. */
	return -EAGAIN;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c:__armv8pmu_probe_pmu() */
/* Extract get num_events processing. */
static uint32_t armv8pmu_read_num_pmnc_events(void)
{
	uint32_t num_events = 0;

	/* Read the nb of CNTx counters supported from PMNC */
	num_events = (armv8pmu_pmcr_read() >> ARMV8_PMU_PMCR_N_SHIFT)
		& ARMV8_PMU_PMCR_N_MASK;

	/* Add the CPU cycles counter */
	num_events += 1;

	return num_events;
}

static void armv8pmu_handle_irq(void *priv)
{
	struct siginfo info;
	uint32_t pmovsr;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	long irqstate;
	struct mckfd *fdp;
	struct pt_regs *regs = (struct pt_regs *)priv;

	/*
	 * Get and reset the IRQ flags
	 */
	pmovsr = armv8pmu_getreset_flags();

	/*
	 * Did an overflow occur?
	 */
	if (!armv8pmu_has_overflowed(pmovsr))
		return;

	/*
	 * Handle the counter(s) overflow(s)
	 */
	/* same as x86_64 mckernel */
	irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);
	for (fdp = proc->mckfd; fdp; fdp = fdp->next) {
		if (fdp->sig_no > 0)
			break;
	}
	ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);

	if (fdp) {
		memset(&info, '\0', sizeof(info));
		info.si_signo = fdp->sig_no;
		info._sifields._sigfault.si_addr = (void *)regs->pc;
		info._sifields._sigpoll.si_fd = fdp->fd;
		set_signal(fdp->sig_no, regs, &info);
	}
	else {
		set_signal(SIGIO, regs, NULL);
	}
}

static void armv8pmu_enable_user_access_pmu_regs(void)
{
	uint32_t value = 0;

	value = read_sysreg(pmuserenr_el0);
	write_sysreg(value | (ARMV8_PMU_USERENR_ER | ARMV8_PMU_USERENR_CR),
		     pmuserenr_el0);
}

static void armv8pmu_disable_user_access_pmu_regs(void)
{
	uint32_t value = 0;

	value = read_sysreg(pmuserenr_el0);
	write_sysreg(value & ~(ARMV8_PMU_USERENR_ER | ARMV8_PMU_USERENR_CR),
		     pmuserenr_el0);
}

static void armv8pmu_create_pmceid_bitmap(unsigned long *bitmap, uint32_t nbits)
{
	uint32_t pmceid[2];

	memset(bitmap, 0, BITS_TO_LONGS(nbits) * sizeof(unsigned long));

	pmceid[0] = read_sysreg(pmceid0_el0);
	bitmap[0] = (unsigned long)pmceid[0];

	pmceid[1] = read_sysreg(pmceid1_el0);
	bitmap[0] |= (unsigned long)pmceid[1] << 32;
}

static struct ihk_mc_interrupt_handler armv8pmu_handler = {
	.func = armv8pmu_handle_irq,
	.priv = NULL,
};

int armv8pmu_init(struct arm_pmu* cpu_pmu)
{
	cpu_pmu->read_counter = armv8pmu_read_counter;
	cpu_pmu->write_counter = armv8pmu_write_counter;
	cpu_pmu->reset = armv8pmu_reset;
	cpu_pmu->enable_pmu = armv8pmu_start;
	cpu_pmu->disable_pmu = armv8pmu_stop;
	cpu_pmu->enable_counter = armv8pmu_enable_counter;
	cpu_pmu->disable_counter = armv8pmu_disable_counter;
	cpu_pmu->enable_intens = armv8pmu_enable_intens;
	cpu_pmu->disable_intens = armv8pmu_disable_intens;
	cpu_pmu->set_event_filter = armv8pmu_set_event_filter;
	cpu_pmu->write_evtype = armv8pmu_write_evtype;
	cpu_pmu->get_event_idx = armv8pmu_get_event_idx;
	cpu_pmu->map_event = armv8_pmuv3_map_event;
	cpu_pmu->enable_user_access_pmu_regs =
		armv8pmu_enable_user_access_pmu_regs;
	cpu_pmu->disable_user_access_pmu_regs =
		armv8pmu_disable_user_access_pmu_regs;
	cpu_pmu->handler = &armv8pmu_handler;
	return 0;
}

void armv8pmu_per_cpu_init(struct per_cpu_arm_pmu *per_cpu)
{
	per_cpu->num_events = armv8pmu_read_num_pmnc_events();
	armv8pmu_create_pmceid_bitmap(per_cpu->pmceid_bitmap,
					ARMV8_PMUV3_MAX_COMMON_EVENTS);
}
