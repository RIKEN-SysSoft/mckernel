/**
 * \file local.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Manipulate information for individual CPUs. These information
 *  resides in memory.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
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

void init_processors_local(int max_id)
{
	/* Is contiguous allocating adequate?? */
	locals = ihk_mc_alloc_pages(max_id, IHK_MC_AP_CRITICAL);
	memset(locals, 0, PAGE_SIZE * max_id);

	kprintf("locals = %p\n", locals);
}

struct x86_cpu_local_variables *get_x86_cpu_local_variable(int id)
{
	return (struct x86_cpu_local_variables *)
		((char *)locals + (id << PAGE_SHIFT));
}

static void *get_x86_cpu_local_kstack(int id)
{
	return ((char *)locals + ((id + 1) << PAGE_SHIFT));
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

/** IHK **/
int ihk_mc_get_processor_id(void)
{
	int id;

	asm volatile("movl %%gs:0, %0" : "=r"(id));

	return id;
}

int ihk_mc_get_hardware_processor_id(void)
{
	struct x86_cpu_local_variables *v =  get_x86_this_cpu_local();

	return v->apic_id;
}
