/* psci.c COPYRIGHT FUJITSU LIMITED 2015-2018 */
/* @ref.impl arch/arm64/kernel/psci.c */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Copyright (C) 2013 ARM Limited
 *
 * Author: Will Deacon <will.deacon@arm.com>
 */

#include <psci.h>
#include <errno.h>
#include <ihk/types.h>
#include <compiler.h>
#include <lwk/compiler.h>
#include <ihk/debug.h>

//#define DEBUG_PRINT_PSCI

#ifdef DEBUG_PRINT_PSCI
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

#define PSCI_POWER_STATE_TYPE_POWER_DOWN	1

extern uint64_t ihk_param_cpu_logical_map;
static uint64_t *__cpu_logical_map = &ihk_param_cpu_logical_map;
#define cpu_logical_map(cpu)    __cpu_logical_map[cpu]

struct psci_power_state {
	uint16_t id;
	uint8_t type;
	uint8_t affinity_level;
};

static int psci_to_linux_errno(int errno)
{
	switch (errno) {
	case PSCI_RET_SUCCESS:
		return 0;
	case PSCI_RET_NOT_SUPPORTED:
		return -EOPNOTSUPP;
	case PSCI_RET_INVALID_PARAMS:
		return -EINVAL;
	case PSCI_RET_DENIED:
		return -EPERM;
	};

	return -EINVAL;
}

static uint32_t psci_power_state_pack(struct psci_power_state state)
{
	return ((state.id << PSCI_0_2_POWER_STATE_ID_SHIFT)
			& PSCI_0_2_POWER_STATE_ID_MASK) |
		((state.type << PSCI_0_2_POWER_STATE_TYPE_SHIFT)
		 & PSCI_0_2_POWER_STATE_TYPE_MASK) |
		((state.affinity_level << PSCI_0_2_POWER_STATE_AFFL_SHIFT)
		 & PSCI_0_2_POWER_STATE_AFFL_MASK);
}

static noinline int __invoke_psci_fn_hvc(uint64_t function_id, uint64_t arg0, uint64_t arg1,
					 uint64_t arg2)
{
	asm volatile(
			__asmeq("%0", "x0")
			__asmeq("%1", "x1")
			__asmeq("%2", "x2")
			__asmeq("%3", "x3")
			"hvc	#0\n"
		: "+r" (function_id)
		: "r" (arg0), "r" (arg1), "r" (arg2));

	return function_id;
}

static noinline int __invoke_psci_fn_smc(uint64_t function_id, uint64_t arg0, uint64_t arg1,
					 uint64_t arg2)
{
	asm volatile(
			__asmeq("%0", "x0")
			__asmeq("%1", "x1")
			__asmeq("%2", "x2")
			__asmeq("%3", "x3")
			"smc	#0\n"
		: "+r" (function_id)
		: "r" (arg0), "r" (arg1), "r" (arg2));

	return function_id;
}


static int (*invoke_psci_fn)(uint64_t, uint64_t, uint64_t, uint64_t) = NULL;

#define PSCI_METHOD_INVALID	-1
#define PSCI_METHOD_HVC		0
#define PSCI_METHOD_SMC		1
int psci_init(void)
{
	extern unsigned long ihk_param_psci_method;
	int ret = 0;

	if (ihk_param_psci_method == PSCI_METHOD_SMC) {
		dkprintf("psci_init(): set invoke_psci_fn = __invoke_psci_fn_smc\n");
		invoke_psci_fn = __invoke_psci_fn_smc;
	} else if (ihk_param_psci_method == PSCI_METHOD_HVC) {
		dkprintf("psci_init(): set invoke_psci_fn = __invoke_psci_fn_hvc\n");
		invoke_psci_fn = __invoke_psci_fn_hvc;
	} else {
		ekprintf("psci_init(): ihk_param_psci_method invalid value. %ld\n", ihk_param_psci_method);
		ret = -1;
	}
	return ret;
}

int psci_cpu_off(void)
{
	int err;
	uint32_t fn, power_state;

	struct psci_power_state state = {
		.type = PSCI_POWER_STATE_TYPE_POWER_DOWN,
	};

	fn = PSCI_0_2_FN_CPU_OFF;
	power_state = psci_power_state_pack(state);
	err = invoke_psci_fn(fn, power_state, 0, 0);
	return psci_to_linux_errno(err);
}

static int psci_cpu_on(unsigned long cpuid, unsigned long entry_point)
{
	int err;
	uint32_t fn;

	fn = PSCI_0_2_FN64_CPU_ON;
	err = invoke_psci_fn(fn, cpuid, entry_point, 0);
	return psci_to_linux_errno(err);
}

int cpu_psci_cpu_boot(unsigned int cpu, unsigned long pc)
{
	return psci_cpu_on(cpu_logical_map(cpu), pc);
}
