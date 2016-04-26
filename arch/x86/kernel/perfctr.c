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
#include <ihk/debug.h>
#include <registers.h>

extern unsigned int *x86_march_perfmap;

#define X86_CR4_PCE     0x00000100

void x86_init_perfctr(void)
{
	unsigned long reg;
	unsigned long value = 0;

	/* Allow PMC to be read from user space */
	asm volatile("movq %%cr4, %0" : "=r"(reg));
	reg |= X86_CR4_PCE;
	asm volatile("movq %0, %%cr4" : : "r"(reg));

	/* Enable PMC Control */
        value = rdmsr(MSR_PERF_GLOBAL_CTRL);
        value |= X86_IA32_PERF_COUNTERS_MASK;
        value |= X86_IA32_FIXED_PERF_COUNTERS_MASK;
        wrmsr(MSR_PERF_GLOBAL_CTRL, value);
}

static int set_perfctr_x86_direct(int counter, int mode, unsigned int value)
{
	if (counter < 0 || counter >= X86_IA32_NUM_PERF_COUNTERS) {
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
	kprintf("wrmsr: %d <= %x\n", MSR_IA32_PERFEVTSEL0 + counter, value);

	return 0;
}

static int set_pmc_x86_direct(int counter, unsigned long val)
{
	unsigned long cnt_bit = 0;

	if (counter < 0) {
		return -EINVAL;
	}

	cnt_bit = 1UL << counter;
	if ( cnt_bit & X86_IA32_PERF_COUNTERS_MASK ) {
		// set generic pmc
		wrmsr(MSR_IA32_PMC0 + counter, val);
	}
	else if ( cnt_bit & X86_IA32_FIXED_PERF_COUNTERS_MASK ) {
		// set fixed pmc
		wrmsr(MSR_IA32_FIXED_CTR0 + counter - X86_IA32_BASE_FIXED_PERF_COUNTERS, val);
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
	unsigned int  ctr_mask = 0x7;
	int counter_idx = counter - X86_IA32_BASE_FIXED_PERF_COUNTERS ;
	unsigned int  set_val = 0;

	if (counter_idx < 0 || counter_idx >= X86_IA32_NUM_FIXED_PERF_COUNTERS) {
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

int ihk_mc_perfctr_init_raw(int counter, unsigned int code, int mode)
{
	if (counter < 0 || counter >= X86_IA32_NUM_PERF_COUNTERS) {
		return -EINVAL;
	}

	return set_perfctr_x86_direct(counter, mode, code);
}
int ihk_mc_perfctr_init(int counter, enum ihk_perfctr_type type, int mode)
{
	if (counter < 0 || counter >= X86_IA32_NUM_PERF_COUNTERS) {
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

#ifdef HAVE_MARCH_PERFCTR_START
extern void x86_march_perfctr_start(unsigned long counter_mask);
#endif

int ihk_mc_perfctr_start(unsigned long counter_mask)
{
	unsigned long value = 0;
	unsigned long mask = X86_IA32_PERF_COUNTERS_MASK | X86_IA32_FIXED_PERF_COUNTERS_MASK;

#ifdef HAVE_MARCH_PERFCTR_START
	x86_march_perfctr_start(counter_mask);
#endif
	counter_mask &= mask;
	value = rdmsr(MSR_PERF_GLOBAL_CTRL);
	value |= counter_mask;
	wrmsr(MSR_PERF_GLOBAL_CTRL, value);

	return 0;
}

int ihk_mc_perfctr_stop(unsigned long counter_mask)
{
	unsigned long value;
	unsigned long mask = X86_IA32_PERF_COUNTERS_MASK | X86_IA32_FIXED_PERF_COUNTERS_MASK;

	counter_mask &= mask;
	value = rdmsr(MSR_PERF_GLOBAL_CTRL);
	value &= ~counter_mask;
	wrmsr(MSR_PERF_GLOBAL_CTRL, value);

	return 0;
}

// init for fixed counter
int ihk_mc_perfctr_fixed_init(int counter, int mode)
{
	unsigned long value = 0;
	unsigned int  ctr_mask = 0x7;
	int counter_idx = counter - X86_IA32_BASE_FIXED_PERF_COUNTERS ;
	unsigned int  set_val = 0;

	if (counter_idx < 0 || counter_idx >= X86_IA32_NUM_FIXED_PERF_COUNTERS) {
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

int ihk_mc_perfctr_reset(int counter)
{
	return set_pmc_x86_direct(counter, 0);
}

int ihk_mc_perfctr_set(int counter, unsigned long val)
{
	return set_pmc_x86_direct(counter, val);
}

int ihk_mc_perfctr_read_mask(unsigned long counter_mask, unsigned long *value)
{
	int i, j;

	for (i = 0, j = 0; i < X86_IA32_NUM_PERF_COUNTERS && counter_mask;
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

	if ( cnt_bit & X86_IA32_PERF_COUNTERS_MASK ) {
		// read generic pmc
		retval = rdpmc(counter);
	}
	else if ( cnt_bit & X86_IA32_FIXED_PERF_COUNTERS_MASK ) {
		// read fixed pmc
		retval = rdpmc((1 << 30) + (counter - X86_IA32_BASE_FIXED_PERF_COUNTERS));
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

	if ( cnt_bit & X86_IA32_PERF_COUNTERS_MASK ) {
		// read generic pmc
		idx = MSR_IA32_PMC0 + counter;
		retval = (unsigned long) rdmsr(idx);
	}
	else if ( cnt_bit & X86_IA32_FIXED_PERF_COUNTERS_MASK ) {
		// read fixed pmc
		idx = MSR_IA32_FIXED_CTR0 + counter;
		retval = (unsigned long) rdmsr(idx);
	}
	else {
		retval = -EINVAL;
	}

	return retval;
}

int ihk_mc_perfctr_alloc_counter(unsigned long pmc_status)
{
	int i = 0;
        int ret = -1;

        // find avail generic counter
        for(i = 0; i < X86_IA32_NUM_PERF_COUNTERS; i++) {
		if(!(pmc_status & (1 << i))) {
			ret = i;
			pmc_status |= (1 << i);
			break;
		}
	}

	if(ret < 0){
		return ret;
	}

        return ret;
}
