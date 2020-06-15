/**
 * \file local.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Manipulate information for individual CPUs. These information
 *  resides in memory.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY
 */

#include <cpulocal.h>
#include <ihk/atomic.h>
#include <ihk/mm.h>
#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <registers.h>
#include <string.h>

struct x86_cpu_local_variables *locals;
size_t x86_cpu_local_variables_span = LOCALS_SPAN;	/* for debugger */

void init_processors_local(int max_id)
{
	size_t size;

	size = LOCALS_SPAN * max_id;
	/* Is contiguous allocating adequate?? */
	locals = ihk_mc_alloc_pages(size/PAGE_SIZE, IHK_MC_AP_CRITICAL);
	memset(locals, 0, size);

	kprintf("locals = %p\n", locals);
}

/*@
  @ requires \valid(id);
  @ ensures \result == locals + (LOCALS_SPAN * id);
  @ assigns \nothing;
  @*/
struct x86_cpu_local_variables *get_x86_cpu_local_variable(int id)
{
	return (struct x86_cpu_local_variables *)
		((char *)locals + (LOCALS_SPAN * id));
}

void *get_x86_cpu_local_kstack(int id)
{
	return ((char *)locals + (LOCALS_SPAN * (id + 1)));
}

struct x86_cpu_local_variables *get_x86_this_cpu_local(void)
{
	int id = ihk_mc_get_processor_id();

	return get_x86_cpu_local_variable(id);
}

void *get_x86_this_cpu_kstack(void)
{
	int id = ihk_mc_get_processor_id();

	return get_x86_cpu_local_kstack(id);
}

static void set_fs_base(void *address)
{
	wrmsr(MSR_FS_BASE, (unsigned long)address);
}

static void set_gs_base(void *address)
{
	wrmsr(MSR_GS_BASE, (unsigned long)address);
}

static ihk_atomic_t last_processor_id = IHK_ATOMIC_INIT(-1);

void assign_processor_id(void)
{
	int id;
	struct x86_cpu_local_variables *v;

	id = ihk_atomic_inc_return(&last_processor_id);

	v = get_x86_cpu_local_variable(id);
	set_gs_base(v);

	v->processor_id = id;
}

void init_boot_processor_local(void)
{
	static struct x86_cpu_local_variables avar;

	memset(&avar, -1, sizeof(avar));
	set_gs_base(&avar);
	return;
}

/** IHK **/
/*@
  @ ensures \result == %gs;
  @ assigns \nothing;
  */
extern int num_processors;
int ihk_mc_get_processor_id(void)
{
	int id;
	void *gs;

	gs = (void *)rdmsr(MSR_GS_BASE);
	if (gs < (void *)locals ||
			gs > ((void *)locals + LOCALS_SPAN * num_processors)) {
		return -1;
	}

	asm volatile("movl %%gs:0, %0" : "=r"(id));

	return id;
}

/*@
  @ ensures \result == (locals + (LOCALS_SPAN * %gs))->apic_id;
  @ assigns \nothing;
  */
int ihk_mc_get_hardware_processor_id(void)
{
	struct x86_cpu_local_variables *v =  get_x86_this_cpu_local();

	return v->apic_id;
}
