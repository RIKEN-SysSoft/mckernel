/* perfctr_armv8pmu.c COPYRIGHT FUJITSU LIMITED 2016-2017 */
#include <arch-perfctr.h>
#include <mc_perf_event.h>
#include <ihk/perfctr.h>
#include <errno.h>
#include <ihk/debug.h>
#include <debug.h>

#define BIT(nr) (1UL << (nr))

//#define DEBUG_PRINT_PMU
#ifdef DEBUG_PRINT_PMU
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif


/*
 * @ref.impl arch/arm64/kernel/perf_event.c
 * Perf Events' indices
 */
#define	ARMV8_IDX_CYCLE_COUNTER	0
#define	ARMV8_IDX_COUNTER0	1
#define	ARMV8_IDX_COUNTER_LAST	(ARMV8_IDX_CYCLE_COUNTER + get_cpu_pmu()->num_events - 1)

#define	ARMV8_MAX_COUNTERS	32
#define	ARMV8_COUNTER_MASK	(ARMV8_MAX_COUNTERS - 1)

/*
 * ARMv8 low level PMU access
 */

/*
 * @ref.impl arch/arm64/kernel/perf_event.c
 * Perf Event to low level counters mapping
 */
#define	ARMV8_IDX_TO_COUNTER(x)	\
	(((x) - ARMV8_IDX_COUNTER0) & ARMV8_COUNTER_MASK)

/*
 * @ref.impl arch/arm64/kernel/perf_event.c
 * Per-CPU PMCR: config reg
 */
#define ARMV8_PMCR_E		(1 << 0) /* Enable all counters */
#define ARMV8_PMCR_P		(1 << 1) /* Reset all counters */
#define ARMV8_PMCR_C		(1 << 2) /* Cycle counter reset */
#define ARMV8_PMCR_D		(1 << 3) /* CCNT counts every 64th cpu cycle */
#define ARMV8_PMCR_X		(1 << 4) /* Export to ETM */
#define ARMV8_PMCR_DP		(1 << 5) /* Disable CCNT if non-invasive debug*/
#define	ARMV8_PMCR_N_SHIFT	11	 /* Number of counters supported */
#define	ARMV8_PMCR_N_MASK	0x1f
#define	ARMV8_PMCR_MASK		0x3f	 /* Mask for writable bits */

/*
 * @ref.impl arch/arm64/kernel/perf_event.c
 * PMOVSR: counters overflow flag status reg
 */
#define	ARMV8_OVSR_MASK		0xffffffff	/* Mask for writable bits */
#define	ARMV8_OVERFLOWED_MASK	ARMV8_OVSR_MASK

/*
 * @ref.impl arch/arm64/kernel/perf_event.c
 * PMXEVTYPER: Event selection reg
 */
#define	ARMV8_EVTYPE_MASK	0xc80003ff	/* Mask for writable bits */
#define	ARMV8_EVTYPE_EVENT	0x3ff		/* Mask for EVENT bits */

/*
 * @ref.impl arch/arm64/kernel/perf_event.c
 * Event filters for PMUv3
 */
#define	ARMV8_EXCLUDE_EL1	(1 << 31)
#define	ARMV8_EXCLUDE_EL0	(1 << 30)
#define	ARMV8_INCLUDE_EL2	(1 << 27)

/*
 * @ref.impl arch/arm64/kernel/perf_event.c
 * ARMv8 PMUv3 Performance Events handling code.
 * Common event types.
 */
enum armv8_pmuv3_perf_types {
	/* Required events. */
	ARMV8_PMUV3_PERFCTR_PMNC_SW_INCR			= 0x00,
	ARMV8_PMUV3_PERFCTR_L1_DCACHE_REFILL			= 0x03,
	ARMV8_PMUV3_PERFCTR_L1_DCACHE_ACCESS			= 0x04,
	ARMV8_PMUV3_PERFCTR_PC_BRANCH_MIS_PRED			= 0x10,
	ARMV8_PMUV3_PERFCTR_CLOCK_CYCLES			= 0x11,
	ARMV8_PMUV3_PERFCTR_PC_BRANCH_PRED			= 0x12,

	/* At least one of the following is required. */
	ARMV8_PMUV3_PERFCTR_INSTR_EXECUTED			= 0x08,
	ARMV8_PMUV3_PERFCTR_OP_SPEC				= 0x1B,

	/* Common architectural events. */
	ARMV8_PMUV3_PERFCTR_MEM_READ				= 0x06,
	ARMV8_PMUV3_PERFCTR_MEM_WRITE				= 0x07,
	ARMV8_PMUV3_PERFCTR_EXC_TAKEN				= 0x09,
	ARMV8_PMUV3_PERFCTR_EXC_EXECUTED			= 0x0A,
	ARMV8_PMUV3_PERFCTR_CID_WRITE				= 0x0B,
	ARMV8_PMUV3_PERFCTR_PC_WRITE				= 0x0C,
	ARMV8_PMUV3_PERFCTR_PC_IMM_BRANCH			= 0x0D,
	ARMV8_PMUV3_PERFCTR_PC_PROC_RETURN			= 0x0E,
	ARMV8_PMUV3_PERFCTR_MEM_UNALIGNED_ACCESS		= 0x0F,
	ARMV8_PMUV3_PERFCTR_TTBR_WRITE				= 0x1C,

	/* Common microarchitectural events. */
	ARMV8_PMUV3_PERFCTR_L1_ICACHE_REFILL			= 0x01,
	ARMV8_PMUV3_PERFCTR_ITLB_REFILL				= 0x02,
	ARMV8_PMUV3_PERFCTR_DTLB_REFILL				= 0x05,
	ARMV8_PMUV3_PERFCTR_MEM_ACCESS				= 0x13,
	ARMV8_PMUV3_PERFCTR_L1_ICACHE_ACCESS			= 0x14,
	ARMV8_PMUV3_PERFCTR_L1_DCACHE_WB			= 0x15,
	ARMV8_PMUV3_PERFCTR_L2_CACHE_ACCESS			= 0x16,
	ARMV8_PMUV3_PERFCTR_L2_CACHE_REFILL			= 0x17,
	ARMV8_PMUV3_PERFCTR_L2_CACHE_WB				= 0x18,
	ARMV8_PMUV3_PERFCTR_BUS_ACCESS				= 0x19,
	ARMV8_PMUV3_PERFCTR_MEM_ERROR				= 0x1A,
	ARMV8_PMUV3_PERFCTR_BUS_CYCLES				= 0x1D,
};

/* @ref.impl arch/arm64/kernel/perf_event.c */
#define HW_OP_UNSUPPORTED		0xFFFF

/* @ref.impl arch/arm64/kernel/perf_event.c */
#define C(_x) \
	PERF_COUNT_HW_CACHE_##_x

/* @ref.impl arch/arm64/kernel/perf_event.c */
#define CACHE_OP_UNSUPPORTED		0xFFFF

/*
 * @ref.impl arch/arm64/kernel/perf_event.c
 *  PMUv3 HW events mapping.
 */
static const unsigned armv8_pmuv3_perf_map[PERF_COUNT_HW_MAX] = {
	[PERF_COUNT_HW_CPU_CYCLES]		= ARMV8_PMUV3_PERFCTR_CLOCK_CYCLES,
	[PERF_COUNT_HW_INSTRUCTIONS]		= ARMV8_PMUV3_PERFCTR_INSTR_EXECUTED,
	[PERF_COUNT_HW_CACHE_REFERENCES]	= ARMV8_PMUV3_PERFCTR_L1_DCACHE_ACCESS,
	[PERF_COUNT_HW_CACHE_MISSES]		= ARMV8_PMUV3_PERFCTR_L1_DCACHE_REFILL,
	[PERF_COUNT_HW_BRANCH_INSTRUCTIONS]	= HW_OP_UNSUPPORTED,
	[PERF_COUNT_HW_BRANCH_MISSES]		= ARMV8_PMUV3_PERFCTR_PC_BRANCH_MIS_PRED,
	[PERF_COUNT_HW_BUS_CYCLES]		= HW_OP_UNSUPPORTED,
	[PERF_COUNT_HW_STALLED_CYCLES_FRONTEND]	= HW_OP_UNSUPPORTED,
	[PERF_COUNT_HW_STALLED_CYCLES_BACKEND]	= HW_OP_UNSUPPORTED,
	[PERF_COUNT_HW_REF_CPU_CYCLES]          = HW_OP_UNSUPPORTED, /* TODO[PMU]: PERF_COUNT_HW_REF_CPU_CYCLESはCentOSに無かったので確認.*/
};

/* @ref.impl arch/arm64/kernel/perf_event.c */
static const unsigned armv8_pmuv3_perf_cache_map[PERF_COUNT_HW_CACHE_MAX]
						[PERF_COUNT_HW_CACHE_OP_MAX]
						[PERF_COUNT_HW_CACHE_RESULT_MAX] = {
	[C(L1D)] = {
		[C(OP_READ)] = {
			[C(RESULT_ACCESS)]	= ARMV8_PMUV3_PERFCTR_L1_DCACHE_ACCESS,
			[C(RESULT_MISS)]	= ARMV8_PMUV3_PERFCTR_L1_DCACHE_REFILL,
		},
		[C(OP_WRITE)] = {
			[C(RESULT_ACCESS)]	= ARMV8_PMUV3_PERFCTR_L1_DCACHE_ACCESS,
			[C(RESULT_MISS)]	= ARMV8_PMUV3_PERFCTR_L1_DCACHE_REFILL,
		},
		[C(OP_PREFETCH)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
	},
	[C(L1I)] = {
		[C(OP_READ)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
		[C(OP_WRITE)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
		[C(OP_PREFETCH)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
	},
	[C(LL)] = {
		[C(OP_READ)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
		[C(OP_WRITE)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
		[C(OP_PREFETCH)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
	},
	[C(DTLB)] = {
		[C(OP_READ)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
		[C(OP_WRITE)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
		[C(OP_PREFETCH)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
	},
	[C(ITLB)] = {
		[C(OP_READ)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
		[C(OP_WRITE)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
		[C(OP_PREFETCH)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
	},
	[C(BPU)] = {
		[C(OP_READ)] = {
			[C(RESULT_ACCESS)]	= ARMV8_PMUV3_PERFCTR_PC_BRANCH_PRED,
			[C(RESULT_MISS)]	= ARMV8_PMUV3_PERFCTR_PC_BRANCH_MIS_PRED,
		},
		[C(OP_WRITE)] = {
			[C(RESULT_ACCESS)]	= ARMV8_PMUV3_PERFCTR_PC_BRANCH_PRED,
			[C(RESULT_MISS)]	= ARMV8_PMUV3_PERFCTR_PC_BRANCH_MIS_PRED,
		},
		[C(OP_PREFETCH)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
	},
	[C(NODE)] = {
		[C(OP_READ)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
		[C(OP_WRITE)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
		[C(OP_PREFETCH)] = {
			[C(RESULT_ACCESS)]	= CACHE_OP_UNSUPPORTED,
			[C(RESULT_MISS)]	= CACHE_OP_UNSUPPORTED,
		},
	},
};

/* @ref.impl arch/arm64/kernel/perf_event.c */
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

	ret = (int)(*cache_map)[cache_type][cache_op][cache_result];

	if (ret == CACHE_OP_UNSUPPORTED)
		return -ENOENT;

	return ret;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static int
armpmu_map_event(const unsigned (*event_map)[PERF_COUNT_HW_MAX], uint64_t config)
{
	int mapping;

	if (config >= PERF_COUNT_HW_MAX)
		return -EINVAL;

	mapping = (*event_map)[config];
	return mapping == HW_OP_UNSUPPORTED ? -ENOENT : mapping;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static int
armpmu_map_raw_event(uint32_t raw_event_mask, uint64_t config)
{
	return (int)(config & raw_event_mask);
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static int map_cpu_event(uint32_t type, uint64_t config,
			 const unsigned (*event_map)[PERF_COUNT_HW_MAX],
			 const unsigned (*cache_map)
					[PERF_COUNT_HW_CACHE_MAX]
					[PERF_COUNT_HW_CACHE_OP_MAX]
					[PERF_COUNT_HW_CACHE_RESULT_MAX],
			 uint32_t raw_event_mask)
{
	switch (type) {
	case PERF_TYPE_HARDWARE:
		return armpmu_map_event(event_map, config);
	case PERF_TYPE_HW_CACHE:
		return armpmu_map_cache_event(cache_map, config);
	case PERF_TYPE_RAW:
		return armpmu_map_raw_event(raw_event_mask, config);
	}
	return -ENOENT;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_counter_valid(int idx)
{
	return idx >= ARMV8_IDX_CYCLE_COUNTER && idx <= ARMV8_IDX_COUNTER_LAST;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline uint32_t armv8pmu_getreset_flags(void)
{
	uint32_t value;

	/* Read */
	asm volatile("mrs %0, pmovsclr_el0" : "=r" (value));

	/* Write to clear flags */
	value &= ARMV8_OVSR_MASK;
	asm volatile("msr pmovsclr_el0, %0" :: "r" (value));

	return value;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_has_overflowed(uint32_t pmovsr)
{
	return pmovsr & ARMV8_OVERFLOWED_MASK;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_counter_has_overflowed(uint32_t pmnc, int idx)
{
	int ret = 0;
	uint32_t counter;

	if (!armv8pmu_counter_valid(idx)) {
		ekprintf("CPU%u checking wrong counter %d overflow status\n",
			ihk_mc_get_processor_id(), idx);
	} else {
		counter = ARMV8_IDX_TO_COUNTER(idx);
		ret = pmnc & BIT(counter);
	}

	return ret;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static int armv8_pmuv3_map_event(uint32_t type, uint64_t config)
{
	return map_cpu_event(type, config, &armv8_pmuv3_perf_map,
				&armv8_pmuv3_perf_cache_map,
				ARMV8_EVTYPE_EVENT);
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline uint32_t armv8pmu_pmcr_read(void)
{
	uint32_t val;
	asm volatile("mrs %0, pmcr_el0" : "=r" (val));
	return val;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline void armv8pmu_pmcr_write(uint32_t val)
{
	val &= ARMV8_PMCR_MASK;
	isb();
	asm volatile("msr pmcr_el0, %0" :: "r" (val));
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_select_counter(int idx)
{
	uint32_t counter;

	if (!armv8pmu_counter_valid(idx)) {
		ekprintf("CPU%u selecting wrong PMNC counter %d\n",
			ihk_mc_get_processor_id(), idx);
		return -EINVAL;
	}

	counter = ARMV8_IDX_TO_COUNTER(idx);
	asm volatile("msr pmselr_el0, %0" :: "r" (counter));
	isb();

	return idx;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline uint32_t armv8pmu_read_counter(int idx)
{
	uint32_t value = 0;

	if (!armv8pmu_counter_valid(idx))
		ekprintf("CPU%u reading wrong counter %d\n",
			ihk_mc_get_processor_id(), idx);
	else if (idx == ARMV8_IDX_CYCLE_COUNTER)
		asm volatile("mrs %0, pmccntr_el0" : "=r" (value));
	else if (armv8pmu_select_counter(idx) == idx)
		asm volatile("mrs %0, pmxevcntr_el0" : "=r" (value));

	return value;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline void armv8pmu_write_counter(int idx, uint32_t value)
{
	if (!armv8pmu_counter_valid(idx))
		ekprintf("CPU%u writing wrong counter %d\n",
			ihk_mc_get_processor_id(), idx);
	else if (idx == ARMV8_IDX_CYCLE_COUNTER)
		asm volatile("msr pmccntr_el0, %0" :: "r" (value));
	else if (armv8pmu_select_counter(idx) == idx)
		asm volatile("msr pmxevcntr_el0, %0" :: "r" (value));
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_enable_intens(int idx)
{
	uint32_t counter;

	if (!armv8pmu_counter_valid(idx)) {
		ekprintf("CPU%u enabling wrong PMNC counter IRQ enable %d\n",
			ihk_mc_get_processor_id(), idx);
		return -EINVAL;
	}

	counter = ARMV8_IDX_TO_COUNTER(idx);
	asm volatile("msr pmintenset_el1, %0" :: "r" (BIT(counter)));
	return idx;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_disable_intens(int idx)
{
	uint32_t counter;

	if (!armv8pmu_counter_valid(idx)) {
		ekprintf("CPU%u disabling wrong PMNC counter IRQ enable %d\n",
			ihk_mc_get_processor_id(), idx);
		return -EINVAL;
	}

	counter = ARMV8_IDX_TO_COUNTER(idx);
	asm volatile("msr pmintenclr_el1, %0" :: "r" (BIT(counter)));
	isb();
	/* Clear the overflow flag in case an interrupt is pending. */
	asm volatile("msr pmovsclr_el0, %0" :: "r" (BIT(counter)));
	isb();
	return idx;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static int armv8pmu_set_event_filter(unsigned long* config_base, int mode)
{
	if (!(mode & PERFCTR_USER_MODE)) {
		*config_base |= ARMV8_EXCLUDE_EL0;
        }

        if (!(mode & PERFCTR_KERNEL_MODE)) {
		*config_base |= ARMV8_EXCLUDE_EL1;
        }

        if (0) {
		/* 共通部がexclude_hvを無視してくるので常にexcludeとする。 */
		*config_base |= ARMV8_INCLUDE_EL2;
        }
	return 0;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline void armv8pmu_write_evtype(int idx, uint32_t val)
{
	if (armv8pmu_select_counter(idx) == idx) {
		val &= ARMV8_EVTYPE_MASK;
		asm volatile("msr pmxevtyper_el0, %0" :: "r" (val));
	}
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_enable_counter(int idx)
{
	uint32_t counter;

	if (!armv8pmu_counter_valid(idx)) {
		ekprintf("CPU%u enabling wrong PMNC counter %d\n",
			ihk_mc_get_processor_id(), idx);
		return -EINVAL;
	}

	counter = ARMV8_IDX_TO_COUNTER(idx);
	asm volatile("msr pmcntenset_el0, %0" :: "r" (BIT(counter)));
	return idx;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static inline int armv8pmu_disable_counter(int idx)
{
	uint32_t counter;

	if (!armv8pmu_counter_valid(idx)) {
		ekprintf("CPU%u disabling wrong PMNC counter %d\n",
			ihk_mc_get_processor_id(), idx);
		return -EINVAL;
	}

	counter = ARMV8_IDX_TO_COUNTER(idx);
	asm volatile("msr pmcntenclr_el0, %0" :: "r" (BIT(counter)));
	return idx;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static int armv8pmu_start(void)
{
	/* Enable user-mode access to counters. */
	asm volatile("msr pmuserenr_el0, %0" :: "r"(1));

	/* Enable all counters */
	armv8pmu_pmcr_write(armv8pmu_pmcr_read() | ARMV8_PMCR_E);
	return 0;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static void armv8pmu_stop(void)
{
	/* Disable all counters */
	armv8pmu_pmcr_write(armv8pmu_pmcr_read() & ~ARMV8_PMCR_E);

	/* Disable user-mode access to counters. */
	asm volatile("msr pmuserenr_el0, %0" :: "r" (0));
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static void armv8pmu_disable_event(int idx)
{
	/*
	 * Disable counter
	 */
	armv8pmu_disable_counter(idx);

	/*
	 * Disable interrupt for this counter
	 */
	armv8pmu_disable_intens(idx);
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static void armv8pmu_reset(void* info)
{
	struct arm_pmu* cpu_pmu = (struct arm_pmu*)info;
	uint32_t idx, nb_cnt = cpu_pmu->num_events;
	
	/* The counter and interrupt enable registers are unknown at reset. */
	for (idx = ARMV8_IDX_CYCLE_COUNTER; idx < nb_cnt; ++idx)
		armv8pmu_disable_event(idx);
	
	/* Initialize & Reset PMNC: C and P bits. */
	armv8pmu_pmcr_write(ARMV8_PMCR_P | ARMV8_PMCR_C);
	
	/* Disable access from userspace. */
	asm volatile("msr pmuserenr_el0, %0" :: "r" (0));
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static int armv8pmu_get_event_idx(int num_events, unsigned long used_mask)
{
	int idx;
	for (idx = ARMV8_IDX_COUNTER0; idx < num_events; ++idx) {
		if (!(used_mask & (1UL << idx))) {
			return idx;
		}
	}
	/* The counters are all in use. */
	return -EAGAIN;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static uint32_t  armv8pmu_read_num_pmnc_events(void)
{
	uint32_t nb_cnt;

	/* Read the nb of CNTx counters supported from PMNC */
	nb_cnt = (armv8pmu_pmcr_read() >> ARMV8_PMCR_N_SHIFT) & ARMV8_PMCR_N_MASK;

	/* Add the CPU cycles counter and return */
	return nb_cnt + 1;
}

/* @ref.impl arch/arm64/kernel/perf_event.c */
static void armv8pmu_handle_irq(void *priv)
{
	uint32_t pmovsr;

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
	 * TODO[PMU]: Handle the counter(s) overflow(s)
	 */
}

static struct ihk_mc_interrupt_handler armv8pmu_handler = {
	.func = armv8pmu_handle_irq,
	.priv = NULL,
};

int armv8pmu_init(struct arm_pmu* cpu_pmu)
{
	cpu_pmu->num_events = armv8pmu_read_num_pmnc_events();
	cpu_pmu->read_counter = armv8pmu_read_counter;
	cpu_pmu->write_counter = armv8pmu_write_counter;
	cpu_pmu->set_event_filter = armv8pmu_set_event_filter;
	cpu_pmu->write_evtype = armv8pmu_write_evtype;
	cpu_pmu->enable_intens = armv8pmu_enable_intens;
	cpu_pmu->disable_intens = armv8pmu_disable_intens;
	cpu_pmu->enable_counter = armv8pmu_enable_counter;
	cpu_pmu->disable_counter = armv8pmu_disable_counter;
	cpu_pmu->enable_pmu = armv8pmu_start;
	cpu_pmu->disable_pmu = armv8pmu_stop;
	cpu_pmu->get_event_idx = armv8pmu_get_event_idx;
	cpu_pmu->map_event = armv8_pmuv3_map_event;
	cpu_pmu->handler = &armv8pmu_handler;
	return 0;
}
