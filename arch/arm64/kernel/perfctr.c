/* perfctr.c COPYRIGHT FUJITSU LIMITED 2015-2018 */
#include <arch-perfctr.h>
#include <ihk/perfctr.h>
#include <mc_perf_event.h>
#include <errno.h>
#include <ihk/debug.h>
#include <registers.h>
#include <string.h>
#include <ihk/mm.h>
#include <irq.h>
#include <process.h>

/*
 * @ref.impl arch/arm64/kernel/perf_event.c
 * Set at runtime when we know what CPU type we are.
 */
struct arm_pmu cpu_pmu;
extern int ihk_param_pmu_irq_affi[CONFIG_SMP_MAX_CORES];
extern int ihk_param_nr_pmu_irq_affi;

int arm64_init_perfctr(void)
{
	int ret;
	int i;
	int pages;
	const struct ihk_mc_cpu_info *cpu_info;

	memset(&cpu_pmu, 0, sizeof(cpu_pmu));
	ret = armv8pmu_init(&cpu_pmu);
	if (ret) {
		return ret;
	}

	cpu_info = ihk_mc_get_cpu_info();
	pages = (sizeof(struct per_cpu_arm_pmu) * cpu_info->ncpus +
		 PAGE_SIZE - 1) >> PAGE_SHIFT;
	cpu_pmu.per_cpu = ihk_mc_alloc_pages(pages, IHK_MC_AP_NOWAIT);
	if (cpu_pmu.per_cpu == NULL) {
		return -ENOMEM;
	}
	memset(cpu_pmu.per_cpu, 0, pages * PAGE_SIZE);

	if (0 < ihk_param_nr_pmu_irq_affi) {
		for (i = 0; i < ihk_param_nr_pmu_irq_affi; i++) {
			ret = ihk_mc_register_interrupt_handler(ihk_param_pmu_irq_affi[i],
								cpu_pmu.handler);
			if (ret) {
				break;
			}
		}
	}
	else {
		ret = ihk_mc_register_interrupt_handler(INTRID_PERF_OVF,
							cpu_pmu.handler);
	}
	return ret;
}

void arm64_init_per_cpu_perfctr(void)
{
	armv8pmu_per_cpu_init(&cpu_pmu.per_cpu[ihk_mc_get_processor_id()]);
}

int arm64_enable_pmu(void)
{
	int ret;
	if (cpu_pmu.reset) {
		cpu_pmu.reset(&cpu_pmu);
	}
	ret = cpu_pmu.enable_pmu();
	return ret;
}

void arm64_disable_pmu(void)
{
	cpu_pmu.disable_pmu();
}

void arm64_enable_user_access_pmu_regs(void)
{
	cpu_pmu.enable_user_access_pmu_regs();
}

void arm64_disable_user_access_pmu_regs(void)
{
	cpu_pmu.disable_user_access_pmu_regs();
}

static int __ihk_mc_perfctr_init(int counter, uint32_t type, uint64_t config, int mode)
{
	int ret = -1;
	unsigned long config_base = 0;

	ret = cpu_pmu.disable_counter(counter);
	if (ret < 0) {
		return ret;
	}

	ret = cpu_pmu.enable_intens(counter);
	if (ret < 0) {
		return ret;
	}

	ret = cpu_pmu.set_event_filter(&config_base, mode);
	if (ret) {
		return ret;
	}
	config_base |= config;
	cpu_pmu.write_evtype(counter, config_base);
	return ret;
}

int ihk_mc_perfctr_init_raw(int counter, uint64_t config, int mode)
{
	int ret;
	ret = __ihk_mc_perfctr_init(counter, PERF_TYPE_RAW, config, mode);
	return ret;
}

int ihk_mc_perfctr_start(unsigned long counter_mask)
{
	int ret = 0, i;

	for (i = 0; i < sizeof(counter_mask) * BITS_PER_BYTE; i++) {
		if (counter_mask & (1UL << i)) {
			ret = cpu_pmu.enable_counter(i);
			if (ret < 0) {
				kprintf("%s: enable failed(idx=%d)\n",
					__func__, i);
				break;
			}
		}
	}
	return ret;
}

int ihk_mc_perfctr_stop(unsigned long counter_mask, int flags)
{
	int i = 0;

	for (i = 0; i < sizeof(counter_mask) * BITS_PER_BYTE; i++) {
		if (!(counter_mask & (1UL << i)))
			continue;

		int ret = 0;

		ret = cpu_pmu.disable_counter(i);
		if (ret < 0) {
			continue;
		}

		if (flags & IHK_MC_PERFCTR_DISABLE_INTERRUPT) {
			// when ihk_mc_perfctr_start is called,
			// ihk_mc_perfctr_init is also called so disable
			// interrupt
			ret = cpu_pmu.disable_intens(i);
			if (ret < 0) {
				continue;
			}
		}
	}
	return 0;
}

int ihk_mc_perfctr_reset(int counter)
{
	cpu_pmu.write_counter(counter, 0);
	return 0;
}

int ihk_mc_perfctr_set(int counter, long val)
{
	uint32_t v = val;
	cpu_pmu.write_counter(counter, v);
	return 0;
}

int ihk_mc_perfctr_read_mask(unsigned long counter_mask, unsigned long *value)
{
	/* this function not used yet. */
	panic("not implemented.");
	return 0;
}

int ihk_mc_perfctr_alloc(struct thread *thread, struct mc_perf_event *event)
{
	const int counters = ihk_mc_perf_get_num_counters();

	return cpu_pmu.get_event_idx(counters,
				     thread->pmc_alloc_map,
				     event->hw_config);
}

unsigned long ihk_mc_perfctr_read(int counter)
{
	unsigned long count;
	count = cpu_pmu.read_counter(counter);
	return count;
}

unsigned long ihk_mc_perfctr_value(int counter, unsigned long correction)
{
	unsigned long count = ihk_mc_perfctr_read(counter) + correction;

	count &= ((1UL << 32) - 1);
	return count;
}

int ihk_mc_perfctr_alloc_counter(unsigned int *type, unsigned long *config,
				 unsigned long pmc_status)
{
	int ret;

	if (*type == PERF_TYPE_HARDWARE) {
		switch (*config) {
		case PERF_COUNT_HW_INSTRUCTIONS:
			ret = cpu_pmu.map_event(*type, *config);
			if (ret < 0) {
				return -1;
			}
			*type = PERF_TYPE_RAW;
			break;
		default:
			// Unexpected config
			return -1;
		}
	}
	else if (*type != PERF_TYPE_RAW) {
		return -1;
	}
	ret = cpu_pmu.get_event_idx(get_per_cpu_pmu()->num_events, pmc_status,
				    *config);
        return ret;
}

int ihk_mc_perf_counter_mask_check(unsigned long counter_mask)
{
	return 1;
}

int ihk_mc_perf_get_num_counters(void)
{
	const struct per_cpu_arm_pmu *per_cpu_arm_pmu = get_per_cpu_pmu();

	return per_cpu_arm_pmu->num_events;
}

int ihk_mc_perfctr_set_extra(struct mc_perf_event *event)
{
	/* Nothing to do. */
	return 0;
}
