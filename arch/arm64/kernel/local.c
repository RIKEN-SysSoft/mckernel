/* local.c COPYRIGHT FUJITSU LIMITED 2015-2018 */
#include <cpulocal.h>
#include <ihk/atomic.h>
#include <ihk/mm.h>
#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <registers.h>
#include <string.h>
#include <bitmap.h>
#include <cputype.h>

#define HWID_BITS NR_CPUS

/* BSP initialized stack area */
union arm64_cpu_local_variables init_thread_info __attribute__((aligned(KERNEL_STACK_SIZE)));

/* BSP/AP idle stack pointer head */
static union arm64_cpu_local_variables *locals;
size_t arm64_cpu_local_variables_span = KERNEL_STACK_SIZE; /* for debugger */
DECLARE_BITMAP(hwid_bitmap, HWID_BITS);
int hwid_bitmap_inited;

void create_hwid_bitmap(void)
{
	int i = 0;
	struct ihk_mc_cpu_info *cpu_info = ihk_mc_get_cpu_info();

	bitmap_zero(hwid_bitmap, HWID_BITS);
	for (i = 0; i < cpu_info->ncpus; i++) {
		bitmap_set(hwid_bitmap, cpu_info->hw_ids[i], 1);
	}
	hwid_bitmap_inited = 1;
}

/* allocate & initialize BSP/AP idle stack */
void init_processors_local(int max_id)
{
	int i = 0;
	union arm64_cpu_local_variables *tmp;
	const int npages = ((max_id + 1) *
			    (ALIGN_UP(KERNEL_STACK_SIZE, PAGE_SIZE) >>
			     PAGE_SHIFT));

	if (npages < 1) {
		panic("idle kernel stack allocation failed.");
	}

	/* allocate one more for alignment */
	locals = ihk_mc_alloc_pages(npages, IHK_MC_AP_CRITICAL);
	if (locals == NULL) {
		panic("idle kernel stack allocation failed.");
	}
	locals = (union arm64_cpu_local_variables *)ALIGN_UP((unsigned long)locals, KERNEL_STACK_SIZE);

	/* clear struct process, struct process_vm, struct thread_info area */
	for (i = 0, tmp = locals; i < max_id; i++, tmp++) {
		memset(tmp, 0, sizeof(struct thread_info));
	}
	kprintf("locals = %p\n", locals);

	/* create hwid bitmap for ihk_mc_get_processor_id() */
	create_hwid_bitmap();
}

/* get id (logical processor id) local variable address */
union arm64_cpu_local_variables *get_arm64_cpu_local_variable(int id)
{
	return locals + id;
}

/* get id (logical processor id) kernel stack address */
static void *get_arm64_cpu_local_kstack(int id)
{
	return (char *)get_arm64_cpu_local_variable(id) + THREAD_START_SP;
}

/* get current cpu local variable address */
union arm64_cpu_local_variables *get_arm64_this_cpu_local(void)
{
	int id = ihk_mc_get_processor_id();
	return get_arm64_cpu_local_variable(id);
}

/* get current kernel stack address */
void *get_arm64_this_cpu_kstack(void)
{
	int id = ihk_mc_get_processor_id();
	return get_arm64_cpu_local_kstack(id);
}

/* assign logical processor id for current_thread_info.cpu */
/* logical processor id BSP:0, AP0:1, AP1:2, ... APn:n-1 */
static ihk_atomic_t last_processor_id = IHK_ATOMIC_INIT(-1);
void assign_processor_id(void)
{
	int id;
	union arm64_cpu_local_variables *v;

	id = ihk_atomic_inc_return(&last_processor_id);

	v = get_arm64_cpu_local_variable(id);
	v->arm64_cpu_local_thread.thread_info.cpu = id;
}

/** IHK **/
/* get current logical processor id */
int ihk_mc_get_processor_id(void)
{
	int id = current_thread_info()->cpu;

	if (hwid_bitmap_inited) {
		const uint64_t mpidr = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;

		/* check on bitmaparea */
		if (mpidr >= HWID_BITS) {
			panic("HWID_BITS larger equal mpidr hwid detected.");
		}

		/* check on McK */
		if (!test_bit(mpidr, hwid_bitmap)) {
			id = -1;
		}
	}
	return id;
}

/* get current physical processor id (not equal AFFINITY !!) */
int ihk_mc_get_hardware_processor_id(void)
{
	return ihk_mc_get_cpu_info()->hw_ids[ihk_mc_get_processor_id()];
}
