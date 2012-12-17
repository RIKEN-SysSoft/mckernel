#include <aal/perfctr.h>
#include <march.h>
#include <errno.h>
#include <aal/debug.h>
#include <registers.h>

extern unsigned int *x86_march_perfmap;

#define X86_CR4_PCE     0x00000100

void x86_init_perfctr(void)
{
	unsigned long reg;

	/* Allow PMC to be read from user space */
	asm volatile("movq %%cr4, %0" : "=r"(reg));
	reg |= X86_CR4_PCE;
	asm volatile("movq %0, %%cr4" : : "r"(reg));
}

static int set_perfctr_x86_direct(int counter, int mode, unsigned int value)
{
	if (counter < 0 || counter >= X86_IA32_NUM_PERF_COUNTERS) {
		return -EINVAL;
	}

	if (mode & PERFCTR_USER_MODE) {
		value |= 1 << 16;
	}
	if (mode & PERFCTR_KERNEL_MODE) {
		value |= 1 << 17;
	}
    //	wrmsr(MSR_PERF_GLOBAL_CTRL, 0);

	value |= (1 << 22) | (1 << 18); /* EN */

	wrmsr(MSR_IA32_PERFEVTSEL0 + counter, value);

	kprintf("wrmsr: %d <= %x\n", MSR_PERF_GLOBAL_CTRL, 0);
	kprintf("wrmsr: %d <= %x\n", MSR_IA32_PERFEVTSEL0 + counter, value);
	return 0;
}

static int set_perfctr_x86(int counter, int event, int mask, int inv, int count,
                           int mode)
{
	return set_perfctr_x86_direct(counter, mode,
	                              CVAL2(event, mask, inv, count));
}

int aal_mc_perfctr_init(int counter, enum aal_perfctr_type type, int mode)
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

int aal_mc_perfctr_start(unsigned long counter_mask)
{
	unsigned int value = 0;

#ifdef HAVE_MARCH_PERFCTR_START
	x86_march_perfctr_start(counter_mask);
#endif
	counter_mask &= ((1 << X86_IA32_NUM_PERF_COUNTERS) - 1);
	value = rdmsr(MSR_PERF_GLOBAL_CTRL);
    value |= counter_mask;
	wrmsr(MSR_PERF_GLOBAL_CTRL, value);

	return 0;
}

int aal_mc_perfctr_stop(unsigned long counter_mask)
{
	unsigned int value;

	counter_mask &= ((1 << X86_IA32_NUM_PERF_COUNTERS) - 1);
	value = rdmsr(MSR_PERF_GLOBAL_CTRL);
	value &= ~counter_mask;
	wrmsr(MSR_PERF_GLOBAL_CTRL, value);

	return 0;
}

int aal_mc_perfctr_reset(int counter)
{
	if (counter < 0 || counter >= X86_IA32_NUM_PERF_COUNTERS) {
		return -EINVAL;
	}

	wrmsr(MSR_IA32_PMC0 + counter, 0);

	return 0;
}

int aal_mc_perfctr_read_mask(unsigned long counter_mask, unsigned long *value)
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

unsigned long aal_mc_perfctr_read(int counter)
{
	if (counter < 0 || counter >= X86_IA32_NUM_PERF_COUNTERS) {
		return -EINVAL;
	}

	return rdpmc(counter);
}

