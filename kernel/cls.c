/**
 * \file cls.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Initialization of cpu local variable
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY:
 */

#include <kmsg.h>
#include <string.h>
#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <ihk/lock.h>
#include <ihk/mm.h>
#include <ihk/page_alloc.h>
#include <cls.h>
#include <page.h>
#include <rusage_private.h>
#include <ihk/monitor.h>

extern int num_processors;

struct cpu_local_var *clv;
int cpu_local_var_initialized = 0;

void cpu_local_var_init(void)
{
	int z;
	int i;

	z = sizeof(struct cpu_local_var) * num_processors;
	z = (z + PAGE_SIZE - 1) >> PAGE_SHIFT;

	clv = ihk_mc_alloc_pages(z, IHK_MC_AP_CRITICAL);
	memset(clv, 0, z * PAGE_SIZE);

	for (i = 0; i < num_processors; i++) {
		clv[i].monitor = monitor->cpu + i;
		clv[i].rusage = rusage.cpu + i;
		INIT_LIST_HEAD(&clv[i].smp_func_req_list);
#ifdef ENABLE_PER_CPU_ALLOC_CACHE
		clv[i].free_chunks.rb_node = NULL;
#endif
	}

	cpu_local_var_initialized = 1;
	smp_mb();
}

struct cpu_local_var *get_cpu_local_var(int id)
{
	return clv + id;
}

void preempt_enable(void)
{
	if (cpu_local_var_initialized)
		--cpu_local_var(no_preempt);
}

void preempt_disable(void)
{
	if (cpu_local_var_initialized)
		++cpu_local_var(no_preempt);
}
