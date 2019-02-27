/* perfctr.c COPYRIGHT FUJITSU LIMITED 2018 */
/**
 * \file perfctr.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Manipulate performance counter.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */

#include <ihk/perfctr.h>
#include <march.h>
#include <errno.h>
#include <cls.h>
#include <ihk/cpu.h>
#include <registers.h>
#include <mc_perf_event.h>
#include <config.h>
#include <ihk/debug.h>

extern unsigned int *x86_march_perfmap;
extern int running_on_kvm(void);
static int ihk_mc_perfctr_fixed_init(int counter, int mode);

//#define PERFCTR_DEBUG
#ifdef PERFCTR_DEBUG
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

#define X86_CR4_PCE     0x00000100

#define PERFCTR_CHKANDJUMP(cond, msg, err)								\
    do {																\
		if(cond) {														\
			ekprintf("%s,"msg"\n", __FUNCTION__);						\
			ret = err;                                                  \
			goto fn_fail;                                               \
		}                                                               \
    } while(0)

int perf_counters_discovered;
int NUM_PERF_COUNTERS;
unsigned long PERF_COUNTERS_MASK;
int NUM_FIXED_PERF_COUNTERS;
unsigned long FIXED_PERF_COUNTERS_MASK;

void x86_init_perfctr(void)
{
	int i = 0;
	unsigned long reg;
	unsigned long value = 0;
	uint64_t op;
	uint64_t eax;
	uint64_t ebx;
	uint64_t ecx;
	uint64_t edx;

#ifndef ENABLE_PERF
	return;
#endif //ENABLE_PERF

	/* Do not do it on KVM */
	if (running_on_kvm()) return;

	/* Allow PMC to be read from user space */
	asm volatile("movq %%cr4, %0" : "=r"(reg));
	reg |= X86_CR4_PCE;
	asm volatile("movq %0, %%cr4" : : "r"(reg));
	
	/* Detect number of supported performance counters */
	if (!perf_counters_discovered) {
		/* See Table 35.2 - Architectural MSRs in Vol 3C */
		op = 0x0a;
		asm volatile("cpuid" : "=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx):"a"(op));

		NUM_PERF_COUNTERS = ((eax & 0xFF00) >> 8);
		PERF_COUNTERS_MASK = (1 << NUM_PERF_COUNTERS) - 1;
		
		NUM_FIXED_PERF_COUNTERS = (edx & 0x0F);
		FIXED_PERF_COUNTERS_MASK =
			((1UL << NUM_FIXED_PERF_COUNTERS) - 1) <<
			BASE_FIXED_PERF_COUNTERS;
	
		perf_counters_discovered = 1;
		kprintf("NUM_PERF_COUNTERS: %d, NUM_FIXED_PERF_COUNTERS: %d\n",
				NUM_PERF_COUNTERS, NUM_FIXED_PERF_COUNTERS);
	}

	/* Clear Fixed Counter Control */
	value = rdmsr(MSR_PERF_FIXED_CTRL);
	value &= 0xfffffffffffff000L;
	wrmsr(MSR_PERF_FIXED_CTRL, value);

	/* Clear Generic Counter Control */
	for (i = 0; i < NUM_PERF_COUNTERS; i++) {
		wrmsr(MSR_IA32_PERFEVTSEL0 + i, 0);
	}

	/* Enable PMC Control */
	value = rdmsr(MSR_PERF_GLOBAL_CTRL);
	value |= PERF_COUNTERS_MASK;
	value |= FIXED_PERF_COUNTERS_MASK;
	wrmsr(MSR_PERF_GLOBAL_CTRL, value);
}

static int set_perfctr_x86_direct(int counter, int mode, unsigned int value)
{
	if (counter < 0 || counter >= NUM_PERF_COUNTERS) {
		return -EINVAL;
	}

	// clear mode flags
	value &= ~(3 << 16);

	// set mode flags
	if(mode & PERFCTR_USER_MODE) {
		value |= 1 << 16;
        }
        if(mode & PERFCTR_KERNEL_MODE) {
		value |= 1 << 17;
        }

    //	wrmsr(MSR_PERF_GLOBAL_CTRL, 0);

	value |= (1 << 22) | (1 << 18); /* EN */
	value |= (1 << 20); /* Enable overflow interrupt */

	wrmsr(MSR_IA32_PERFEVTSEL0 + counter, value);

	//kprintf("wrmsr: %d <= %x\n", MSR_PERF_GLOBAL_CTRL, 0);
	//kprintf("wrmsr: %d <= %x\n", MSR_IA32_PERFEVTSEL0 + counter, value);

	return 0;
}

static int set_pmc_x86_direct(int counter, long val)
{
	unsigned long cnt_bit = 0;

	if (counter < 0) {
		return -EINVAL;
	}

	val &= 0x000000ffffffffff; // 40bit Mask

	cnt_bit = 1UL << counter;
	if (cnt_bit & PERF_COUNTERS_MASK) {
		// set generic pmc
		wrmsr(MSR_IA32_PMC0 + counter, val);
	}
	else if (cnt_bit & FIXED_PERF_COUNTERS_MASK) {
		// set fixed pmc
		wrmsr(MSR_IA32_FIXED_CTR0 +
			counter - BASE_FIXED_PERF_COUNTERS, val);
	}
	else {
		return -EINVAL;
	}

	return 0;
}

static int set_perfctr_x86(int counter, int event, int mask, int inv, int count,
                           int mode)
{
	return set_perfctr_x86_direct(counter, mode,
	                              CVAL2(event, mask, inv, count));
}

static int set_fixed_counter(int counter, int mode)
{
	unsigned long value = 0;
	unsigned int  ctr_mask = 0xf;
	int counter_idx = counter - BASE_FIXED_PERF_COUNTERS;
	unsigned int  set_val = 0;

	if (counter_idx < 0 || counter_idx >= NUM_FIXED_PERF_COUNTERS) {
		return -EINVAL;
	}

	// clear specified fixed counter info
	value = rdmsr(MSR_PERF_FIXED_CTRL);
	ctr_mask <<= counter_idx * 4;
	value &= ~ctr_mask;
	
	if (mode & PERFCTR_USER_MODE) {
		set_val |= 1 << 1;
	}
	if (mode & PERFCTR_KERNEL_MODE) {
		set_val |= 1;
	}

	set_val <<= counter_idx * 4;
	value |= set_val;

	wrmsr(MSR_PERF_FIXED_CTRL, value);

	return 0;
}

#ifdef POSTK_DEBUG_TEMP_FIX_29
int ihk_mc_perfctr_init_raw(int counter, uint64_t config, int mode)
#else
int ihk_mc_perfctr_init_raw(int counter, unsigned int code, int mode)
#endif /*POSTK_DEBUG_TEMP_FIX_29*/
{
	// PAPI_REF_CYC counted by fixed counter
	if (counter >= BASE_FIXED_PERF_COUNTERS &&
		counter < BASE_FIXED_PERF_COUNTERS + NUM_FIXED_PERF_COUNTERS) {
		return ihk_mc_perfctr_fixed_init(counter, mode);
	}

	if (counter < 0 || counter >= NUM_PERF_COUNTERS) {
		return -EINVAL;
	}

#ifdef POSTK_DEBUG_TEMP_FIX_29
	return set_perfctr_x86_direct(counter, mode, config);
#else
	return set_perfctr_x86_direct(counter, mode, code);
#endif /*POSTK_DEBUG_TEMP_FIX_29*/
}

#ifdef POSTK_DEBUG_TEMP_FIX_29
int ihk_mc_perfctr_init(int counter, uint64_t config, int mode)
#else
int ihk_mc_perfctr_init(int counter, enum ihk_perfctr_type type, int mode)
#endif /*POSTK_DEBUG_TEMP_FIX_29*/
{
#ifdef POSTK_DEBUG_TEMP_FIX_29
	enum ihk_perfctr_type type;

	switch (config) {
	case PERF_COUNT_HW_CPU_CYCLES :
		type = APT_TYPE_CYCLE;
		break;
	case PERF_COUNT_HW_INSTRUCTIONS :
		type = APT_TYPE_INSTRUCTIONS;
		break;
	default :
		// Not supported config.
		type = PERFCTR_MAX_TYPE;
	}
#endif /*POSTK_DEBUG_TEMP_FIX_29*/

	if (counter < 0 || counter >= NUM_PERF_COUNTERS) {
		return -EINVAL;
	}
	if (type < 0 || type >= PERFCTR_MAX_TYPE) {
		return -EINVAL;
	}
	if (!x86_march_perfmap[type]) {
		return -EINVAL;
	}

	return set_perfctr_x86_direct(counter, mode, x86_march_perfmap[type]);
}

int ihk_mc_perfctr_set_extra(struct mc_perf_event *event)
{
	struct thread *thread = cpu_local_var(current);

	// allocate extra_reg
	if (thread->extra_reg_alloc_map & (1UL << event->extra_reg.idx)) {
		if (event->extra_reg.idx == EXTRA_REG_RSP_0) {
			event->extra_reg.idx = EXTRA_REG_RSP_1;
		}
		else if (event->extra_reg.idx == EXTRA_REG_RSP_1) {
			event->extra_reg.idx = EXTRA_REG_RSP_0;
		}

		if (thread->extra_reg_alloc_map & (1UL << event->extra_reg.idx)) {
			// extra_regs are full
			return -1;
		}
	}

	if (event->extra_reg.idx == EXTRA_REG_RSP_0) {
		event->hw_config &= ~0xffUL;
		event->hw_config |= ihk_mc_get_extra_reg_event(EXTRA_REG_RSP_0);
		event->extra_reg.reg = MSR_OFFCORE_RSP_0;
	}
	else if (event->extra_reg.idx == EXTRA_REG_RSP_1) {
		event->hw_config &= ~0xffUL;
		event->hw_config |= ihk_mc_get_extra_reg_event(EXTRA_REG_RSP_1);
		event->extra_reg.reg = MSR_OFFCORE_RSP_1;
	}
		
	thread->extra_reg_alloc_map |= (1UL << event->extra_reg.idx);
	wrmsr(event->extra_reg.reg, event->extra_reg.config);
	return 0;
}

#ifdef HAVE_MARCH_PERFCTR_START
extern void x86_march_perfctr_start(unsigned long counter_mask);
#endif

int ihk_mc_perfctr_start(unsigned long counter_mask)
{
	int ret = 0;
	unsigned long value = 0;
	unsigned long mask = PERF_COUNTERS_MASK | FIXED_PERF_COUNTERS_MASK;

	PERFCTR_CHKANDJUMP(counter_mask & ~mask, "counter_mask out of range", -EINVAL);

#ifdef HAVE_MARCH_PERFCTR_START
	x86_march_perfctr_start(counter_mask);
#endif
	counter_mask &= mask;
	value = rdmsr(MSR_PERF_GLOBAL_CTRL);
	value |= counter_mask;
	wrmsr(MSR_PERF_GLOBAL_CTRL, value);
 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}

int ihk_mc_perfctr_stop(unsigned long counter_mask, int flags)
{
	int ret = 0;
	unsigned long value;
	unsigned long mask = PERF_COUNTERS_MASK | FIXED_PERF_COUNTERS_MASK;

	PERFCTR_CHKANDJUMP(counter_mask & ~mask, "counter_mask out of range", -EINVAL);

	counter_mask &= mask;
	value = rdmsr(MSR_PERF_GLOBAL_CTRL);
	value &= ~counter_mask;
	wrmsr(MSR_PERF_GLOBAL_CTRL, value);

	if(counter_mask >> 32 & 0x1) {
		value = rdmsr(MSR_PERF_FIXED_CTRL);
		value &= ~(0xf);
		wrmsr(MSR_PERF_FIXED_CTRL, value);
	}
		
	if(counter_mask >> 32 & 0x2) {
		value = rdmsr(MSR_PERF_FIXED_CTRL);
		value &= ~(0xf << 4);
		wrmsr(MSR_PERF_FIXED_CTRL, value);
	}

	if(counter_mask >> 32 & 0x4) {
		value = rdmsr(MSR_PERF_FIXED_CTRL);
		value &= ~(0xf << 8);
		wrmsr(MSR_PERF_FIXED_CTRL, value);
	}
 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}

// init for fixed counter
static int ihk_mc_perfctr_fixed_init(int counter, int mode)
{
	unsigned long value = 0;
	unsigned int  ctr_mask = 0xf;
	int counter_idx = counter - BASE_FIXED_PERF_COUNTERS;
	unsigned int  set_val = 0;

	if (counter_idx < 0 || counter_idx >= NUM_FIXED_PERF_COUNTERS) {
		return -EINVAL;
	}

	// clear specified fixed counter info
	value = rdmsr(MSR_PERF_FIXED_CTRL);
	ctr_mask <<= counter_idx * 4;
	value &= ~ctr_mask;
	
	if (mode & PERFCTR_USER_MODE) {
		set_val |= 1 << 1;
	}
	if (mode & PERFCTR_KERNEL_MODE) {
		set_val |= 1;
	}

	// enable PMI on overflow
	set_val |= 1 << 3;

	set_val <<= counter_idx * 4;
	value |= set_val;

	wrmsr(MSR_PERF_FIXED_CTRL, value);

	return 0;
}

int ihk_mc_perfctr_reset(int counter)
{
	return set_pmc_x86_direct(counter, 0);
}

int ihk_mc_perfctr_set(int counter, long val)
{
	return set_pmc_x86_direct(counter, val);
}

int ihk_mc_perfctr_read_mask(unsigned long counter_mask, unsigned long *value)
{
	int i, j;

	for (i = 0, j = 0; i < NUM_PERF_COUNTERS && counter_mask;
	     i++, counter_mask >>= 1) {
		if (counter_mask & 1) {
			value[j++] = rdpmc(i);
		}
	}
	return 0;
}

unsigned long ihk_mc_perfctr_read(int counter)
{
	unsigned long retval = 0;
	unsigned long cnt_bit = 0;

	if (counter < 0) {
		return -EINVAL;
	}

	cnt_bit = 1UL << counter;

	if (cnt_bit & PERF_COUNTERS_MASK) {
		// read generic pmc
		retval = rdpmc(counter);
	}
	else if (cnt_bit & FIXED_PERF_COUNTERS_MASK) {
		// read fixed pmc
		retval = rdpmc((1 << 30) +
			(counter - BASE_FIXED_PERF_COUNTERS));
	}
	else {
		retval = -EINVAL;
	}

	return retval;
}

// read by rdmsr
unsigned long ihk_mc_perfctr_read_msr(int counter)
{
	unsigned int idx = 0;
	unsigned long retval = 0;
	unsigned long cnt_bit = 0;

	if (counter < 0) {
		return -EINVAL;
	}

	cnt_bit = 1UL << counter;

	if (cnt_bit & PERF_COUNTERS_MASK) {
		// read generic pmc
		idx = MSR_IA32_PMC0 + counter;
		retval = (unsigned long) rdmsr(idx);
	}
	else if (cnt_bit & FIXED_PERF_COUNTERS_MASK) {
		// read fixed pmc
		idx = MSR_IA32_FIXED_CTR0 + counter;
		retval = (unsigned long) rdmsr(idx);
	}
	else {
		retval = -EINVAL;
	}

	return retval;
}

int ihk_mc_perfctr_alloc_counter(unsigned int *type, unsigned long *config, unsigned long pmc_status)
{
	int ret = -1;
	int i = 0;

	if(*type == PERF_TYPE_HARDWARE) {
		switch(*config){
		case PERF_COUNT_HW_INSTRUCTIONS :
			*type = PERF_TYPE_RAW;
			*config = 0x5300c0;
			break;
		default :
			// Unexpected config
			return -1;
		}
	}
	else if(*type != PERF_TYPE_RAW) {
		return -1;
	}

	// find avail generic counter
	for (i = 0; i < NUM_PERF_COUNTERS; i++) {
		if (!(pmc_status & (1 << i))) {
			ret = i;
			break;
		}
	}

	return ret;
}

int ihk_mc_perf_counter_mask_check(unsigned long counter_mask)
{
	if ((counter_mask & PERF_COUNTERS_MASK) |
	    (counter_mask & FIXED_PERF_COUNTERS_MASK)) {
		return 1;
	}
	return 0;
}

int ihk_mc_perf_get_num_counters(void)
{
	return NUM_PERF_COUNTERS;
}
