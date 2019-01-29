/* perfctr.c COPYRIGHT FUJITSU LIMITED 2015-2017 */
#include <arch-perfctr.h>
#include <ihk/perfctr.h>
#include <mc_perf_event.h>
#include <errno.h>
#include <ihk/debug.h>
#include <registers.h>
#include <string.h>

/*
 * @ref.impl arch/arm64/kernel/perf_event.c
 * Set at runtime when we know what CPU type we are.
 */
struct arm_pmu cpu_pmu;
extern int ihk_param_pmu_irq_affiniry[CONFIG_SMP_MAX_CORES];
extern int ihk_param_nr_pmu_irq_affiniry;


int arm64_init_perfctr(void)
{
	int ret;
	int i;

	memset(&cpu_pmu, 0, sizeof(cpu_pmu));
	ret = armv8pmu_init(&cpu_pmu);
	if (!ret) {
		return ret;
	}
	for (i = 0; i < ihk_param_nr_pmu_irq_affiniry; i++) {
		ret = ihk_mc_register_interrupt_handler(ihk_param_pmu_irq_affiniry[i], cpu_pmu.handler);
	}
	return ret;
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

extern unsigned int *arm64_march_perfmap;

static int __ihk_mc_perfctr_init(int counter, uint32_t type, uint64_t config, int mode)
{
	int ret;
	unsigned long config_base = 0;
	int mapping;

	mapping = cpu_pmu.map_event(type, config);
	if (mapping < 0) {
		return mapping;
	}

	ret = cpu_pmu.disable_counter(counter);
	if (!ret) {
		return ret;
	}

	ret = cpu_pmu.enable_intens(counter);
	if (!ret) {
		return ret;
	}

	ret = cpu_pmu.set_event_filter(&config_base, mode);
	if (!ret) {
		return ret;
	}
	config_base |= (unsigned long)mapping;
	cpu_pmu.write_evtype(counter, config_base);
	return ret;
}

int ihk_mc_perfctr_init_raw(int counter, uint64_t config, int mode)
{
	int ret;
	ret = __ihk_mc_perfctr_init(counter, PERF_TYPE_RAW, config, mode);
	return ret;
}

int ihk_mc_perfctr_init(int counter, uint64_t config, int mode)
{
	int ret;
	ret = __ihk_mc_perfctr_init(counter, PERF_TYPE_RAW, config, mode);
	return ret;
}

int ihk_mc_perfctr_start(unsigned long counter_mask)
{
	int ret = 0;
	int counter;
	unsigned long counter_bit;

	for (counter = 0, counter_bit = 1;
	     counter_bit < counter_mask;
	     counter++, counter_bit <<= 1) {
		if (!(counter_mask & counter_bit))
			continue;

		ret = cpu_pmu.enable_counter(counter_mask);
		if (ret < 0)
			break;
	}

	return ret < 0 ? ret : 0;
}

int ihk_mc_perfctr_stop(unsigned long counter_mask)
{
	int ret = 0;
	int counter;
	unsigned long counter_bit;

	for (counter = 0, counter_bit = 1;
	     counter_bit < counter_mask;
	     counter++, counter_bit <<= 1) {
		if (!(counter_mask & counter_bit))
			continue;

		ret = cpu_pmu.disable_counter(counter);
		if (ret < 0)
			break;

		// ihk_mc_perfctr_startが呼ばれるときには、
		// init系関数が呼ばれるのでdisableにする。
		ret = cpu_pmu.disable_intens(counter);
		if (ret < 0)
			break;
	}

	return ret < 0 ? ret : 0;
}

int ihk_mc_perfctr_reset(int counter)
{
	// TODO[PMU]: ihk_mc_perfctr_setと同様にサンプリングレートの共通部実装の扱いを見てから本実装。
	cpu_pmu.write_counter(counter, 0);
	return 0;
}

//int ihk_mc_perfctr_set(int counter, unsigned long val)
int ihk_mc_perfctr_set(int counter, long val) /* 0416_patchtemp */
{
	// TODO[PMU]: 共通部でサンプリングレートの計算をして、設定するカウンタ値をvalに渡してくるようになると想定。サンプリングレートの扱いを見てから本実装。
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

unsigned long ihk_mc_perfctr_read(int counter)
{
	unsigned long count;
	count = cpu_pmu.read_counter(counter);
	return count;
}

//int ihk_mc_perfctr_alloc_counter(unsigned long pmc_status)
int ihk_mc_perfctr_alloc_counter(unsigned int *type, unsigned long *config, unsigned long pmc_status) /* 0416_patchtemp */
{
	int ret;
	ret = cpu_pmu.get_event_idx(cpu_pmu.num_events, pmc_status);
        return ret;
}

/* 0416_patchtemp */
/* ihk_mc_perfctr_fixed_init() stub added. */
int ihk_mc_perfctr_fixed_init(int counter, int mode)
{
	return -1;
}

int ihk_mc_perf_counter_mask_check(unsigned long counter_mask)
{
	return 1;
}

int ihk_mc_perf_get_num_counters(void)
{
	return cpu_pmu.per_cpu[ihk_mc_get_processor_id()].num_events;
}
