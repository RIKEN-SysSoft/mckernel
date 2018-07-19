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
#include <ihk/debug.h>
#include <ihk/cpu.h>
#include <registers.h>
#include <mc_perf_event.h>
#include <config.h>
#include <kmalloc.h>
#include <string.h>
#include <cbuf.h>


extern unsigned int *x86_march_perfmap;
extern int running_on_kvm(void);
#ifdef POSTK_DEBUG_TEMP_FIX_31
int ihk_mc_perfctr_fixed_init(int counter, int mode);
#endif/*POSTK_DEBUG_TEMP_FIX_31*/

#define PERFCTR_DEBUG

#ifdef PERFCTR_DEBUG
#define	dkprintf(...)	do { kprintf(__VA_ARGS__); } while (0)
#define	ekprintf(...)	do { kprintf(__VA_ARGS__); } while (0)
#else
#define	dkprintf(...)	do { } while (0)
#define	ekprintf(...)	do { kprintf(__VA_ARGS__); } while (0)
#endif

#define X86_CR4_PCE     0x00000100

#define PERFCTR_CHKANDJUMP(cond, msg, err)			\
    do {							\
		if(cond) {					\
			ekprintf("%s,"msg"\n", __FUNCTION__);	\
			ret = err;                              \
			goto fn_fail;                           \
		}                                               \
    } while(0)


static volatile int pebs_error;

int perf_counters_discovered = 0;
int X86_IA32_NUM_PERF_COUNTERS = 0;
unsigned long X86_IA32_PERF_COUNTERS_MASK = 0;
int X86_IA32_NUM_FIXED_PERF_COUNTERS = 0;
unsigned long X86_IA32_FIXED_PERF_COUNTERS_MASK = 0;




static int setup_pebs_buffer(unsigned long buffer_size)
{
	struct pebs_data *pebs_cpu;
	struct debug_store *ds;
	unsigned long num_pebs;

	pebs_cpu = &cpu_local_var(pebs);
	ds = pebs_cpu->cpu_ds;
	if (ds->pebs_base)
		kfree((void *)ds->pebs_base);

	ds->pebs_base = (unsigned long)kmalloc(buffer_size, IHK_MC_PG_KERNEL);
	if (!ds->pebs_base) {
		kprintf("Error: Cannot allocate PEBS buffer\n");
		kfree(ds);
		return -ENOMEM;
	}
	memset((void *)ds->pebs_base, 0, buffer_size);
	num_pebs = buffer_size / sizeof(struct pebs_v2);
	dkprintf("Number of PEBS elements that fit into the buffer: %lu\n", num_pebs);

	ds->pebs_index = ds->pebs_base;
	ds->pebs_max = ds->pebs_base + (num_pebs - 1) * sizeof(struct pebs_v2) + 1;
	ds->pebs_thresh = ds->pebs_base + (num_pebs - num_pebs/10) * sizeof(struct pebs_v2);

	return 0;
}

static void setup_pebs_countdown(long int countdown)
{
	struct pebs_data *pebs_cpu;

	pebs_cpu = &cpu_local_var(pebs);
	pebs_cpu->cpu_ds->pebs_reset[0] = -(long long)countdown;
}

/* Allocate DS and PEBS buffer */
static int allocate_pebs_buffer()
{
	int err;
	struct pebs_data *pebs_cpu;
	struct debug_store *ds;

	pebs_cpu = &cpu_local_var(pebs);

	/* Setup DS area */
	ds = kmalloc(sizeof(struct debug_store), IHK_MC_PG_KERNEL);
	if (!ds) {
		kprintf("Error: Cannot allocate DS\n");
		return -1;
	}
	memset(ds, 0, sizeof(struct debug_store));
	pebs_cpu->cpu_ds = ds;

	/* Set up buffer */
	if ((err=setup_pebs_buffer(DEFAULT_PEBS_BUFFER_SIZE)))
		return err;
	setup_pebs_countdown(DEFAULT_PEBS_COUNTDOWN);

	return 0;
}

void arch_init_perfctr_extra(void)
{
	struct pebs_data *pebs_cpu;
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
	//TODO apparently it is no longer working
	asm volatile("movq %%cr4, %0" : "=r"(reg));
	reg |= X86_CR4_PCE;
	asm volatile("movq %0, %%cr4" : : "r"(reg));

	/* Detect number of supported performance counters */
	if (!perf_counters_discovered) {
		/* See Table 35.2 - Architectural MSRs in Vol 3C */
		op = 0x0a;
		asm volatile("cpuid" : "=a"(eax),"=b"(ebx),"=c"(ecx),"=d"(edx):"a"(op));

		X86_IA32_NUM_PERF_COUNTERS = ((eax & 0xFF00) >> 8);
		X86_IA32_PERF_COUNTERS_MASK = (1 << X86_IA32_NUM_PERF_COUNTERS) - 1;

		X86_IA32_NUM_FIXED_PERF_COUNTERS = (edx & 0x0F);
		X86_IA32_FIXED_PERF_COUNTERS_MASK =
			((1UL << X86_IA32_NUM_FIXED_PERF_COUNTERS) - 1) <<
			X86_IA32_BASE_FIXED_PERF_COUNTERS;

		perf_counters_discovered = 1;
		kprintf("X86_IA32_NUM_PERF_COUNTERS: %d, X86_IA32_NUM_FIXED_PERF_COUNTERS: %d\n",
				X86_IA32_NUM_PERF_COUNTERS, X86_IA32_NUM_FIXED_PERF_COUNTERS);

		// TODO discover number of counters supporting PEBS
	}

	/* Clear Fixed Counter Control */
	value = rdmsr(MSR_PERF_FIXED_CTRL);
	value &= 0xfffffffffffff000L;
	wrmsr(MSR_PERF_FIXED_CTRL, value);

	/* Clear Generic Counter Control */
	for(i = 0; i < X86_IA32_NUM_PERF_COUNTERS; i++) {
		wrmsr(MSR_IA32_PERFEVTSEL0 + i, 0);
	}

	/* Allocate memory for DS and buffer */
	kprintf("Allocating PEBS buffer\n");
	if (allocate_pebs_buffer() < 0) {
		//TODO do something here?
		kprintf("Error allocating PEBS buffer\n");
		return;
	}

	/* Set up DS */
	kprintf("Setting up DS area\n");
	pebs_cpu = &cpu_local_var(pebs);
	wrmsrl(MSR_IA32_DS_AREA, pebs_cpu->cpu_ds);

	/* Enable PMC Control */
	//value = rdmsr(MSR_PERF_GLOBAL_CTRL);
	//value |= X86_IA32_PERF_COUNTERS_MASK;
	//value |= X86_IA32_FIXED_PERF_COUNTERS_MASK;
	//wrmsr(MSR_PERF_GLOBAL_CTRL, value);
}

static int set_perfctr_x86_direct(int counter, int mode, unsigned int value,
				  long int countdown, unsigned long buffer_size)
{
	struct pebs_data *cpu_pebs;
	struct thread *thr;
	uint64_t pgc;

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

	cpu_pebs = &cpu_local_var(pebs);
	thr = cpu_local_var(current);

	/* disable counters */
	rdmsrl(MSR_PERF_GLOBAL_CTRL, pgc);
	wrmsrl(MSR_PERF_GLOBAL_CTRL, 0);

	/* disable and reset PEBS buffer */
	wrmsrl(MSR_IA32_PEBS_ENABLE, 0);
	cpu_pebs->cpu_ds->pebs_index = cpu_pebs->cpu_ds->pebs_base;

	value |= (1 << 22) | (1 << 18); /* EN */
	/* PEBS/PMC specific config */
	if (mode & PERFCTR_PEBS) {
		int err;

		//TODO check if the requested counter supports PEBS

		/* Allocate per process pebs buffer */
		if (!thr->pebs_buffer) {
			dkprintf("Allocating PEBS out cbuf!\n");

			if ((err = cbuf_init(&thr->pebs_buffer, PEBS_OUT_BUFFER_SIZE)))
				return err;

			if ((err = cbuf_init(&thr->pebs_vma_mmap_buffer,
							DEFAULT_PEBS_VMA_BUFFER_SIZE))) {
				cbuf_destroy(&thr->pebs_buffer);
				return err;
			}

			if ((err = cbuf_init(&thr->pebs_vma_umap_buffer,
							DEFAULT_PEBS_VMA_BUFFER_SIZE))) {
				cbuf_destroy(&thr->pebs_buffer);
				cbuf_destroy(&thr->pebs_vma_mmap_buffer);
				return err;
			}
		} else {
			dkprintf("Resetting  PEBS out cbuf!\n");
			cbuf_reset(thr->pebs_buffer);
			cbuf_reset(thr->pebs_vma_mmap_buffer);
			cbuf_reset(thr->pebs_vma_umap_buffer);
		}

		/* Enable PEBS for counter 0 */
		if ((buffer_size != 0) &&
		    (cpu_pebs->buffer_size != buffer_size)) {
			dkprintf("Updating hardware PEBS buffer size!\n");
			setup_pebs_buffer(buffer_size);
		}
		setup_pebs_countdown(countdown);
		dkprintf("Enabling PEBS, writing to MSR_IA32_PEBS_ENABLE!\n");
		wrmsrl(MSR_IA32_PEBS_ENABLE, 1);
		arch_barrier();
		cpu_pebs->enabled = true;
	} else {
		/* Enable overflow interrupt */
		value |= (1 << 20);
		cpu_pebs->enabled = false;
	}

	/* allocate pmc data structures for the calling process */
	if (thr->pmc == NULL) {
		thr->pmc = kmalloc(sizeof(struct pmc)*X86_IA32_NUM_PERF_COUNTERS,
				   IHK_MC_PG_KERNEL);
		if (!thr->pmc)
			return -ENOMEM;
		memset(thr->pmc, 0,
		       sizeof(struct pmc)*X86_IA32_NUM_PERF_COUNTERS);
	}

	/* save countdown */
	thr->pmc[counter].countdown = countdown;

	/* actually program the performance counter */
	wrmsrl(MSR_IA32_PERFEVTSEL0 + counter, value);
	wrmsrl(MSR_IA32_PMC0, -(long long)countdown);

	/* restore counters */
	wrmsrl(MSR_PERF_GLOBAL_CTRL, pgc);

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
	                              CVAL2(event, mask, inv, count), 0, 0);
}

static int set_fixed_counter(int counter, int mode)
{
	unsigned long value = 0;
	unsigned int  ctr_mask = 0xf;
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

#ifdef POSTK_DEBUG_TEMP_FIX_29
int ihk_mc_perfctr_init_raw(int counter, uint64_t config, int mode)
#else
int ihk_mc_perfctr_init_raw(int counter, unsigned int code, int mode)
#endif /*POSTK_DEBUG_TEMP_FIX_29*/
{
#ifdef POSTK_DEBUG_TEMP_FIX_31
	// PAPI_REF_CYC counted by fixed counter
	if (counter >= X86_IA32_BASE_FIXED_PERF_COUNTERS) {
		return ihk_mc_perfctr_fixed_init(counter, mode);
	}
#endif /*POSTK_DEBUG_TEMP_FIX_31*/

	if (counter < 0 || counter >= X86_IA32_NUM_PERF_COUNTERS) {
		return -EINVAL;
	}

#ifdef POSTK_DEBUG_TEMP_FIX_29
	return set_perfctr_x86_direct(counter, mode, config, 0, 0);
#else
	return set_perfctr_x86_direct(counter, mode, code, 0, 0);
#endif /*POSTK_DEBUG_TEMP_FIX_29*/
}

#ifdef POSTK_DEBUG_TEMP_FIX_29
int ihk_mc_perfctr_init(int counter, uint64_t config, int mode,
			long int countdown, unsigned long buffer_size)
#else
int ihk_mc_perfctr_init(int counter, enum ihk_perfctr_type type, int mode,
			long int countdown, unsigned long buffer_size)
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

	if (counter < 0 || counter >= X86_IA32_NUM_PERF_COUNTERS) {
		return -EINVAL;
	}
	if (type < 0 || type >= PERFCTR_MAX_TYPE) {
		return -EINVAL;
	}
	if (!x86_march_perfmap[type]) {
		return -EINVAL;
	}

	return set_perfctr_x86_direct(counter, mode, x86_march_perfmap[type],
				      countdown, buffer_size);
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

#ifdef POSTK_DEBUG_TEMP_FIX_30
int ihk_mc_perfctr_start(int counter)
#else
int ihk_mc_perfctr_start(unsigned long counter_mask)
#endif /*POSTK_DEBUG_TEMP_FIX_30*/
{
	int ret = 0;
	unsigned long value = 0;
	unsigned long mask = X86_IA32_PERF_COUNTERS_MASK | X86_IA32_FIXED_PERF_COUNTERS_MASK;
#ifdef POSTK_DEBUG_TEMP_FIX_30
	unsigned long counter_mask = 1UL << counter;
#endif /*POSTK_DEBUG_TEMP_FIX_30*/

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

#ifdef POSTK_DEBUG_TEMP_FIX_30
int ihk_mc_perfctr_stop(int counter)
#else
int ihk_mc_perfctr_stop(unsigned long counter_mask)
#endif/*POSTK_DEBUG_TEMP_FIX_30*/
{
	int ret = 0;
	unsigned long value;
	unsigned long mask = X86_IA32_PERF_COUNTERS_MASK | X86_IA32_FIXED_PERF_COUNTERS_MASK;
#ifdef POSTK_DEBUG_TEMP_FIX_30
	unsigned long counter_mask = 1UL << counter;
#endif/*POSTK_DEBUG_TEMP_FIX_30*/

	PERFCTR_CHKANDJUMP(counter_mask & ~mask, "counter_mask out of range", -EINVAL);

	counter_mask &= mask;
	value = rdmsr(MSR_PERF_GLOBAL_CTRL);
	value &= ~counter_mask;
	wrmsr(MSR_PERF_GLOBAL_CTRL, value);

	// TODO extend for multiple PEBS counters
	if (counter_mask & 0x1) {
		wrmsrl(MSR_IA32_PEBS_ENABLE, 0);
	}

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
int ihk_mc_perfctr_fixed_init(int counter, int mode)
{
	unsigned long value = 0;
	unsigned int  ctr_mask = 0xf;
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


size_t ihk_mc_perfctr_pebs_read(void *user_buf, size_t user_size)
{
	struct cbuf *thr_pebs;
	unsigned long flags;
	size_t nelem_read;

	flags = cpu_disable_interrupt_save();
	thr_pebs = cpu_local_var(current)->pebs_buffer;
	nelem_read = cbuf_read_into_user_buffer(thr_pebs, user_buf, user_size);
	cpu_restore_interrupt(flags);

	return nelem_read*sizeof(cbuf_t);
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
       	for(i = 0; i < X86_IA32_NUM_PERF_COUNTERS; i++) {
		if(!(pmc_status & (1 << i))) {
			ret = i;
			break;
		}
	}

	return ret;
}

void harvest_pebs_buffer(int cpuid, struct cbuf *cbuf)
{
	struct pebs_v2 *pebs, *end;
	struct debug_store *ds = get_cpu_local_var(cpuid)->pebs.cpu_ds;
	unsigned long watermark, ts, nelem;


	ts = rdtsc();
	watermark = 0xFFFFFFFFFFFFFFFF;
	nelem = ((char *)ds->pebs_index - (char *)ds->pebs_base)/sizeof(struct pebs_v2);

	cbuf_write_one(cbuf, watermark);
	cbuf_write_one(cbuf, ts);
	cbuf_write_one(cbuf, nelem);

	end = (struct pebs_v2 *)ds->pebs_index;
	for (pebs = (struct pebs_v2 *)ds->pebs_base; pebs < end; pebs++) {
		cbuf_write_one(cbuf, pebs->psdla);
	}

	/* reset ds */
	ds->pebs_index = ds->pebs_base;
}
