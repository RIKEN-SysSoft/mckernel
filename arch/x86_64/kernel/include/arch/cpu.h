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

#define mb()    asm volatile("mfence":::"memory")
#define rmb()   asm volatile("lfence":::"memory")
#define wmb()   asm volatile("sfence" ::: "memory")

#define smp_mb()    mb()
#define smp_rmb()   rmb()
#define smp_wmb()	barrier()

#define arch_barrier()	asm volatile("" : : : "memory")

static inline unsigned long read_tsc(void)
{
	unsigned int low, high;

	asm volatile("rdtsc" : "=a"(low), "=d"(high));

	return (low | ((unsigned long)high << 32));
}

#define smp_load_acquire(p)						\
({									\
	typeof(*p) ___p1 = ACCESS_ONCE(*p);				\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	___p1;								\
})

#define smp_store_release(p, v)			\
({							\
	compiletime_assert_atomic_type(*p);	\
	barrier();							\
	WRITE_ONCE(*p, v);					\
})

void arch_flush_icache_all(void);

#endif /* ARCH_CPU_H */
