/* arch-perfctr.h COPYRIGHT FUJITSU LIMITED 2016-2017 */
#ifndef __ARCH_PERFCTR_H__
#define __ARCH_PERFCTR_H__

#include <ihk/types.h>
#include <ihk/cpu.h>
#include <bitops.h>

struct per_cpu_arm_pmu {
	int num_events;
#define ARMV8_PMUV3_MAX_COMMON_EVENTS 0x40
	DECLARE_BITMAP(pmceid_bitmap, ARMV8_PMUV3_MAX_COMMON_EVENTS);
};

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
	int (*get_event_idx)(int num_events, unsigned long used_mask,
			     unsigned long config);
	int (*map_event)(uint32_t, uint64_t);
	void (*enable_user_access_pmu_regs)(void);
	void (*disable_user_access_pmu_regs)(void);
	struct per_cpu_arm_pmu *per_cpu;
};

static inline const struct arm_pmu* get_cpu_pmu(void)
{
	extern struct arm_pmu cpu_pmu;
	return &cpu_pmu;
}

static inline const struct per_cpu_arm_pmu *get_per_cpu_pmu(void)
{
	const struct arm_pmu *cpu_pmu = get_cpu_pmu();

	return &cpu_pmu->per_cpu[ihk_mc_get_processor_id()];
}

int arm64_init_perfctr(void);
void arm64_init_per_cpu_perfctr(void);
int arm64_enable_pmu(void);
void arm64_disable_pmu(void);
int armv8pmu_init(struct arm_pmu* cpu_pmu);
void armv8pmu_per_cpu_init(struct per_cpu_arm_pmu *per_cpu);
void arm64_enable_user_access_pmu_regs(void);
void arm64_disable_user_access_pmu_regs(void);

#endif
