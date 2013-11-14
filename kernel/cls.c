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

extern int num_processors;

struct cpu_local_var *clv;

void cpu_local_var_init(void)
{
	int z;

	z = sizeof(struct cpu_local_var) * num_processors;
	z = (z + PAGE_SIZE - 1) >> PAGE_SHIFT;

	clv = allocate_pages(z, IHK_MC_AP_CRITICAL);
	memset(clv, 0, z * PAGE_SIZE);
}

struct cpu_local_var *get_cpu_local_var(int id)
{
	return clv + id;
}
