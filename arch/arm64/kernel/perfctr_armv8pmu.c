/* perfctr_armv8pmu.c COPYRIGHT FUJITSU LIMITED 2016-2018 */
#include <arch-perfctr.h>
#include <mc_perf_event.h>
#include <ihk/perfctr.h>
#include <errno.h>
#include <ihk/debug.h>
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
 * read pmevcntr<n>_el0 functions
 */
#define read_pmevcntrN_el0(N) \
static uint32_t read_pmevcntr##N##_el0(void) \
{ \
	return read_sysreg(pmevcntr##N##_el0); \
}

read_pmevcntrN_el0(0)
read_pmevcntrN_el0(1)
read_pmevcntrN_el0(2)
read_pmevcntrN_el0(3)
read_pmevcntrN_el0(4)
read_pmevcntrN_el0(5)
read_pmevcntrN_el0(6)
read_pmevcntrN_el0(7)
read_pmevcntrN_el0(8)
read_pmevcntrN_el0(9)
read_pmevcntrN_el0(10)
read_pmevcntrN_el0(11)
read_pmevcntrN_el0(12)
read_pmevcntrN_el0(13)
read_pmevcntrN_el0(14)
read_pmevcntrN_el0(15)
read_pmevcntrN_el0(16)
read_pmevcntrN_el0(17)
read_pmevcntrN_el0(18)
read_pmevcntrN_el0(19)
read_pmevcntrN_el0(20)
read_pmevcntrN_el0(21)
read_pmevcntrN_el0(22)
read_pmevcntrN_el0(23)
read_pmevcntrN_el0(24)
read_pmevcntrN_el0(25)
read_pmevcntrN_el0(26)
read_pmevcntrN_el0(27)
read_pmevcntrN_el0(28)
read_pmevcntrN_el0(29)
read_pmevcntrN_el0(30)

static uint32_t (* const read_pmevcntr_el0[])(void) = {
	read_pmevcntr0_el0, read_pmevcntr1_el0, read_pmevcntr2_el0,
	read_pmevcntr3_el0, read_pmevcntr4_el0, read_pmevcntr5_el0,
	read_pmevcntr6_el0, read_pmevcntr7_el0, read_pmevcntr8_el0,
	read_pmevcntr9_el0, read_pmevcntr10_el0, read_pmevcntr11_el0,
	read_pmevcntr12_el0, read_pmevcntr13_el0, read_pmevcntr14_el0,
	read_pmevcntr15_el0, read_pmevcntr16_el0, read_pmevcntr17_el0,
	read_pmevcntr18_el0, read_pmevcntr19_el0, read_pmevcntr20_el0,
	read_pmevcntr21_el0, read_pmevcntr22_el0, read_pmevcntr23_el0,
	read_pmevcntr24_el0, read_pmevcntr25_el0, read_pmevcntr26_el0,
	read_pmevcntr27_el0, read_pmevcntr28_el0, read_pmevcntr29_el0,
	read_pmevcntr30_el0,
};


/*
 * write pmevcntr<n>_el0 functions
 */
#define write_pmevcntrN_el0(N) \
static void write_pmevcntr##N##_el0(uint32_t v) \
{ \
	write_sysreg(v, pmevcntr##N##_el0); \
}

write_pmevcntrN_el0(0)
write_pmevcntrN_el0(1)
write_pmevcntrN_el0(2)
write_pmevcntrN_el0(3)
write_pmevcntrN_el0(4)
write_pmevcntrN_el0(5)
write_pmevcntrN_el0(6)
write_pmevcntrN_el0(7)
write_pmevcntrN_el0(8)
write_pmevcntrN_el0(9)
write_pmevcntrN_el0(10)
write_pmevcntrN_el0(11)
write_pmevcntrN_el0(12)
write_pmevcntrN_el0(13)
write_pmevcntrN_el0(14)
write_pmevcntrN_el0(15)
write_pmevcntrN_el0(16)
write_pmevcntrN_el0(17)
write_pmevcntrN_el0(18)
write_pmevcntrN_el0(19)
write_pmevcntrN_el0(20)
write_pmevcntrN_el0(21)
write_pmevcntrN_el0(22)
write_pmevcntrN_el0(23)
write_pmevcntrN_el0(24)
write_pmevcntrN_el0(25)
write_pmevcntrN_el0(26)
write_pmevcntrN_el0(27)
write_pmevcntrN_el0(28)
write_pmevcntrN_el0(29)
write_pmevcntrN_el0(30)

static void (* const write_pmevcntr_el0[])(uint32_t) = {
	write_pmevcntr0_el0, write_pmevcntr1_el0, write_pmevcntr2_el0,
	write_pmevcntr3_el0, write_pmevcntr4_el0, write_pmevcntr5_el0,
	write_pmevcntr6_el0, write_pmevcntr7_el0, write_pmevcntr8_el0,
	write_pmevcntr9_el0, write_pmevcntr10_el0, write_pmevcntr11_el0,
	write_pmevcntr12_el0, write_pmevcntr13_el0, write_pmevcntr14_el0,
	write_pmevcntr15_el0, write_pmevcntr16_el0, write_pmevcntr17_el0,
	write_pmevcntr18_el0, write_pmevcntr19_el0, write_pmevcntr20_el0,
	write_pmevcntr21_el0, write_pmevcntr22_el0, write_pmevcntr23_el0,
	write_pmevcntr24_el0, write_pmevcntr25_el0, write_pmevcntr26_el0,
	write_pmevcntr27_el0, write_pmevcntr28_el0, write_pmevcntr29_el0,
	write_pmevcntr30_el0,
};

/*
 * write pmevtyper<n>_el0 functions
 */
#define write_pmevtyperN_el0(N) \
static void write_pmevtyper##N##_el0(uint32_t v) \
{ \
	write_sysreg(v, pmevtyper##N##_el0); \
}

write_pmevtyperN_el0(0)
write_pmevtyperN_el0(1)
write_pmevtyperN_el0(2)
write_pmevtyperN_el0(3)
write_pmevtyperN_el0(4)
write_pmevtyperN_el0(5)
write_pmevtyperN_el0(6)
write_pmevtyperN_el0(7)
write_pmevtyperN_el0(8)
write_pmevtyperN_el0(9)
write_pmevtyperN_el0(10)
write_pmevtyperN_el0(11)
write_pmevtyperN_el0(12)
write_pmevtyperN_el0(13)
write_pmevtyperN_el0(14)
write_pmevtyperN_el0(15)
write_pmevtyperN_el0(16)
write_pmevtyperN_el0(17)
write_pmevtyperN_el0(18)
write_pmevtyperN_el0(19)
write_pmevtyperN_el0(20)
write_pmevtyperN_el0(21)
write_pmevtyperN_el0(22)
write_pmevtyperN_el0(23)
write_pmevtyperN_el0(24)
write_pmevtyperN_el0(25)
write_pmevtyperN_el0(26)
write_pmevtyperN_el0(27)
write_pmevtyperN_el0(28)
write_pmevtyperN_el0(29)
write_pmevtyperN_el0(30)

static void (* const write_pmevtyper_el0[])(uint32_t) = {
	write_pmevtyper0_el0, write_pmevtyper1_el0, write_pmevtyper2_el0,
	write_pmevtyper3_el0, write_pmevtyper4_el0, write_pmevtyper5_el0,
	write_pmevtyper6_el0, write_pmevtyper7_el0, write_pmevtyper8_el0,
	write_pmevtyper9_el0, write_pmevtyper10_el0, write_pmevtyper11_el0,
	write_pmevtyper12_el0, write_pmevtyper13_el0, write_pmevtyper14_el0,
	write_pmevtyper15_el0, write_pmevtyper16_el0, write_pmevtyper17_el0,
	write_pmevtyper18_el0, write_pmevtyper19_el0, write_pmevtyper20_el0,
	write_pmevtyper21_el0, write_pmevtyper22_el0, write_pmevtyper23_el0,
	write_pmevtyper24_el0, write_pmevtyper25_el0, write_pmevtyper26_el0,
	write_pmevtyper27_el0, write_pmevtyper28_el0, write_pmevtyper29_el0,
	write_pmevtyper30_el0,
};

#define	ARMV8_IDX_CYCLE_COUNTER	31
#define	ARMV8_IDX_COUNTER0	0

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

/* disable -Woverride-init for the following initializations */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverride-init"

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

/* restore warnings */
#pragma GCC diagnostic pop

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

static inline int armv8pmu_counter_mask_valid(unsigned long counter_mask)
{
	int num;
	unsigned long event;
	unsigned long cycle;
	unsigned long invalid_mask;

	num = get_per_cpu_pmu()->num_events;
	num--; /* Sub the CPU cycles counter */
	event = ((1UL << num) - 1) << ARMV8_IDX_COUNTER0;
	cycle = 1UL << ARMV8_IDX_CYCLE_COUNTER;
	invalid_mask = ~(event | cycle);

	return !(counter_mask & invalid_mask);
}

static inline int armv8pmu_counter_valid(int idx)
{
	return armv8pmu_counter_mask_valid(1UL << idx);
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

static inline int armv8pmu_counter_has_overflowed(uint32_t pmnc, int idx)
{
	return pmnc & BIT(idx);
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


static int armv8_pmuv3_map_hw_event(uint64_t config)
{
	return __armv8_pmuv3_map_event(PERF_TYPE_HARDWARE, config, NULL, NULL);
}


static int armv8_pmuv3_map_cache_event(uint64_t config)
{
	return __armv8_pmuv3_map_event(PERF_TYPE_HW_CACHE, config, NULL, NULL);
}

static int armv8_pmuv3_map_raw_event(uint64_t config)
{
	return __armv8_pmuv3_map_event(PERF_TYPE_RAW, config, NULL, NULL);
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
	else {
		value = read_pmevcntr_el0[idx]();
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
		//uint64_t value64 = 0xffffffff00000000ULL | value;
		uint64_t value64 = 0x0ULL | value;

		write_sysreg(value64, pmccntr_el0);
	}
	else {
		write_pmevcntr_el0[idx](value);
	}
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_enable_intens(unsigned long counter_mask)
{
	if (!armv8pmu_counter_mask_valid(counter_mask)) {
		ekprintf("%s: invalid counter mask(%#lx)\n",
			__func__, counter_mask);
		return -EINVAL;
	}

	write_sysreg(counter_mask, pmintenset_el1);
	return 0;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_disable_intens(unsigned long counter_mask)
{
	if (!armv8pmu_counter_mask_valid(counter_mask)) {
		ekprintf("%s: invalid counter mask(%#lx)\n",
			__func__, counter_mask);
		return -EINVAL;
	}
	write_sysreg(counter_mask, pmintenclr_el1);
	isb();
	/* Clear the overflow flag in case an interrupt is pending. */
	write_sysreg(counter_mask, pmovsclr_el0);
	isb();
	return 0;
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
	if (!armv8pmu_counter_valid(idx)) {
		ekprintf("%s: The count_register#%d is not implemented.\n",
			 __func__, idx);
		return;
	} else if (idx != ARMV8_IDX_CYCLE_COUNTER) {
		write_pmevtyper_el0[idx](val);
	}
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_enable_counter(unsigned long counter_mask)
{
	if (!armv8pmu_counter_mask_valid(counter_mask)) {
		ekprintf("%s: invalid counter mask 0x%lx.\n",
			 __func__, counter_mask);
		return -EINVAL;
	}
	write_sysreg(counter_mask, pmcntenset_el0);
	return 0;
}

/* @ref.impl linux-v4.15-rc3 arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_disable_counter(unsigned long counter_mask)
{
	if (!armv8pmu_counter_mask_valid(counter_mask)) {
		ekprintf("%s: invalid counter mask 0x%lx.\n",
			 __func__, counter_mask);
		return -EINVAL;
	}
	write_sysreg(counter_mask, pmcntenclr_el0);
	return 0;
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
static void armv8pmu_reset(void *info)
{
	struct arm_pmu *cpu_pmu = (struct arm_pmu *)info;
	uint32_t nb_cnt =
		cpu_pmu->per_cpu[ihk_mc_get_processor_id()].num_events;
	nb_cnt--; /* Sub the CPU cycles counter */
	unsigned long event = ((1UL << nb_cnt) - 1) << ARMV8_IDX_COUNTER0;
	unsigned long cycle = 1UL << ARMV8_IDX_CYCLE_COUNTER;
	unsigned long valid_mask = event | cycle;

	/* The counter and interrupt enable registers are unknown at reset. */
	armv8pmu_disable_counter(valid_mask);
	armv8pmu_disable_intens(valid_mask);

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
	int idx, end;
	unsigned long evtype = config & ARMV8_PMU_EVTYPE_EVENT;

	/* Always prefer to place a cycle counter into the cycle counter. */
	if (evtype == ARMV8_PMUV3_PERFCTR_CPU_CYCLES) {
		if (!(used_mask & (1UL << ARMV8_IDX_CYCLE_COUNTER)))
			return ARMV8_IDX_CYCLE_COUNTER;
	}

	/*
	 * Otherwise use events counters
	 */
	end = ARMV8_IDX_COUNTER0 + num_events;
	end--; /* Sub the CPU cycles counter */
	for (idx = ARMV8_IDX_COUNTER0; idx < end; ++idx) {
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
	uint32_t pmovsr;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	const struct per_cpu_arm_pmu *cpu_pmu = get_per_cpu_pmu();
	int idx;

	/*
	 * Get and reset the IRQ flags
	 */
	pmovsr = armv8pmu_getreset_flags();

	/*
	 * Did an overflow occur?
	 */
	if (!armv8pmu_has_overflowed(pmovsr))
		return;

	if (!proc->monitoring_event) {
		return;
	}
	/*
	 * Handle the counter(s) overflow(s)
	 */
	for (idx = 0; idx < cpu_pmu->num_events; idx++) {
		struct mc_perf_event *event = NULL;
		struct mc_perf_event *sub;

		if (!armv8pmu_counter_has_overflowed(pmovsr, idx)) {
			continue;
		}

		if (proc->monitoring_event->counter_id == idx) {
			event = proc->monitoring_event;
		} else {
			list_for_each_entry(sub,
					&proc->monitoring_event->sibling_list,
					group_entry) {
				if (sub->counter_id == idx) {
					event = sub;
					break;
				}
			}
		}

		if (!event) {
			continue;
		}
		ihk_mc_event_update(event);
		ihk_mc_event_set_period(event);
	}
	return;
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
	cpu_pmu->map_hw_event = armv8_pmuv3_map_hw_event;
	cpu_pmu->map_cache_event = armv8_pmuv3_map_cache_event;
	cpu_pmu->map_raw_event = armv8_pmuv3_map_raw_event;
	cpu_pmu->enable_user_access_pmu_regs =
		armv8pmu_enable_user_access_pmu_regs;
	cpu_pmu->disable_user_access_pmu_regs =
		armv8pmu_disable_user_access_pmu_regs;
	cpu_pmu->handler = &armv8pmu_handler;
	cpu_pmu->counter_mask_valid = &armv8pmu_counter_mask_valid;
	return 0;
}

void armv8pmu_per_cpu_init(struct per_cpu_arm_pmu *per_cpu)
{
	per_cpu->num_events = armv8pmu_read_num_pmnc_events();
	armv8pmu_create_pmceid_bitmap(per_cpu->pmceid_bitmap,
					ARMV8_PMUV3_MAX_COMMON_EVENTS);
}
