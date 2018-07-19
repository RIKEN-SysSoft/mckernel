/**
 * \file cpu.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare architecture-dependent types and functions to control CPU.
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com>
 *      Copyright (C) 2015  RIKEN AICS
 */
/*
 * HISTORY
 */

#ifndef ARCH_CPU_H
#define ARCH_CPU_H

#include <ihk/types.h>

#define arch_barrier()	asm volatile("" : : : "memory")

//TODO properly place this somewhere or delete it
#define DEFAULT_PEBS_COUNTDOWN 100
#define DEFAULT_PEBS_BUFFER_SIZE (64*1024)
#define DEFAULT_PEBS_VMA_BUFFER_SIZE (18*1024) //Multiple of 3
#define PEBS_OUT_BUFFER_SIZE ((1024UL*1024*1024)/sizeof(cbuf_t)-1)


struct pebs_v2 {
	uint64_t flags;
	uint64_t ip;
	uint64_t ax;
	uint64_t bx;
	uint64_t cx;
	uint64_t dx;
	uint64_t si;
	uint64_t di;
	uint64_t bp;
	uint64_t sp;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
	uint64_t status;
	uint64_t psdla;
	uint64_t res1;
	uint64_t res2;
	uint64_t eventing_ip;
	uint64_t res3;
};
// size of pebs_v2 = 24*8 = 192 bytes

struct debug_store {
	uint64_t bts_base;
	uint64_t bts_index;
	uint64_t bts_max;
	uint64_t bts_thresh;

	uint64_t pebs_base;
	uint64_t pebs_index;
	uint64_t pebs_max;
	uint64_t pebs_thresh;
	uint64_t pebs_reset[4];
};

struct pebs_data {
	struct debug_store * cpu_ds;
	uint64_t old_lvtpc;
	int cpu_initialized;
	char enabled;
	long int countdown;
	unsigned long buffer_size;
};



static inline void rmb(void)
{
	arch_barrier();
}

static inline void wmb(void)
{
	arch_barrier();
}

static unsigned long read_tsc(void)
{
	unsigned int low, high;

	asm volatile("rdtsc" : "=a"(low), "=d"(high));

	return (low | ((unsigned long)high << 32));
}

#endif /* ARCH_CPU_H */
