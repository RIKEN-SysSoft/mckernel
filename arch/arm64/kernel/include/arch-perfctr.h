#ifndef __ARCH_PERFCTR_H__
#define __ARCH_PERFCTR_H__

#include <ihk/types.h>
#include <ihk/cpu.h>

/* @ref.impl arch/arm64/include/asm/pmu.h */
struct arm_pmu {
	struct ihk_mc_interrupt_handler* handler;
	uint32_t (*read_counter)(int);
	void (*write_counter)(int, uint32_t);
	void (*reset)(void*);
	int (*enable_pmu)(void);
	void (*disable_pmu)(void);
	int (*enable_counter)(int);
	int (*disable_counter)(int);
	int (*enable_intens)(int);
	int (*disable_intens)(int);
	int (*set_event_filter)(unsigned long*, int);
	void (*write_evtype)(int, uint32_t);
	int (*get_event_idx)(int, unsigned long);
	int (*map_event)(uint32_t, uint64_t);
	int num_events;
};

static inline const struct arm_pmu* get_cpu_pmu(void)
{
	extern struct arm_pmu cpu_pmu;
	return &cpu_pmu;
}
int arm64_init_perfctr(void);
int arm64_enable_pmu(void);
void arm64_disable_pmu(void);
int armv8pmu_init(struct arm_pmu* cpu_pmu);

/* TODO[PMU]: 共通部に定義があっても良い。今後の動向を見てここの定義を削除する */
/*
 * Generalized hardware cache events:
 *
 *       { L1-D, L1-I, LLC, ITLB, DTLB, BPU, NODE } x
 *       { read, write, prefetch } x
 *       { accesses, misses }
 */
enum perf_hw_cache_id {
	PERF_COUNT_HW_CACHE_L1D			= 0,
	PERF_COUNT_HW_CACHE_L1I			= 1,
	PERF_COUNT_HW_CACHE_LL			= 2,
	PERF_COUNT_HW_CACHE_DTLB		= 3,
	PERF_COUNT_HW_CACHE_ITLB		= 4,
	PERF_COUNT_HW_CACHE_BPU			= 5,
	PERF_COUNT_HW_CACHE_NODE		= 6,

	PERF_COUNT_HW_CACHE_MAX,		/* non-ABI */
};

enum perf_hw_cache_op_id {
	PERF_COUNT_HW_CACHE_OP_READ		= 0,
	PERF_COUNT_HW_CACHE_OP_WRITE		= 1,
	PERF_COUNT_HW_CACHE_OP_PREFETCH		= 2,

	PERF_COUNT_HW_CACHE_OP_MAX,		/* non-ABI */
};

enum perf_hw_cache_op_result_id {
	PERF_COUNT_HW_CACHE_RESULT_ACCESS	= 0,
	PERF_COUNT_HW_CACHE_RESULT_MISS		= 1,

	PERF_COUNT_HW_CACHE_RESULT_MAX,		/* non-ABI */
};

#endif
