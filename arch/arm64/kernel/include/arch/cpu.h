/* cpu.h COPYRIGHT FUJITSU LIMITED 2016-2018 */
#ifndef __HEADER_ARM64_ARCH_CPU_H
#define __HEADER_ARM64_ARCH_CPU_H

#ifndef __ASSEMBLY__

#define sev()		asm volatile("sev" : : : "memory")
#define wfe()		asm volatile("wfe" : : : "memory")
#define wfi()		asm volatile("wfi" : : : "memory")

#define isb()		asm volatile("isb" : : : "memory")
#define dmb(opt)	asm volatile("dmb " #opt : : : "memory")
#define dsb(opt)	asm volatile("dsb " #opt : : : "memory")

#include <registers.h>

#define mb()		dsb(sy)
#define rmb()		dsb(ld)
#define wmb()		dsb(st)

#define dma_rmb()	dmb(oshld)
#define dma_wmb()	dmb(oshst)

//#ifndef CONFIG_SMP
//#else
#define smp_mb()	dmb(ish)
#define smp_rmb()	dmb(ishld)
#define smp_wmb()	dmb(ishst)

#define arch_barrier()	smp_mb()

#define smp_store_release(p, v)						\
do {									\
	compiletime_assert_atomic_type(*p);				\
	switch (sizeof(*p)) {						\
	case 4:								\
		asm volatile ("stlr %w1, %0"				\
				: "=Q" (*p) : "r" (v) : "memory");	\
		break;							\
	case 8:								\
		asm volatile ("stlr %1, %0"				\
				: "=Q" (*p) : "r" (v) : "memory");	\
		break;							\
	}								\
} while (0)

#define smp_load_acquire(p)						\
({									\
	typeof(*p) ___p1;						\
	compiletime_assert_atomic_type(*p);				\
	switch (sizeof(*p)) {						\
	case 4:								\
		asm volatile ("ldar %w0, %1"				\
			: "=r" (___p1) : "Q" (*p) : "memory");		\
		break;							\
	case 8:								\
		asm volatile ("ldar %0, %1"				\
			: "=r" (___p1) : "Q" (*p) : "memory");		\
		break;							\
	}								\
	___p1;								\
})
//#endif /*CONFIG_SMP*/

#define read_barrier_depends()		do { } while(0)
#define smp_read_barrier_depends()	do { } while(0)

#define set_mb(var, value)	do { var = value; smp_mb(); } while (0)
#define nop()		asm volatile("nop");

#define smp_mb__before_atomic()	smp_mb()
#define smp_mb__after_atomic()	smp_mb()

#define read_tsc()						\
({								\
	unsigned long cval;					\
	cval = rdtsc();						\
	cval;							\
})

void init_tod_data(void);

#if defined(CONFIG_HAS_NMI)
static inline void cpu_enable_nmi(void)
{
	asm volatile("msr    daifclr, #2": : : "memory");
}

static inline void cpu_disable_nmi(void)
{
	asm volatile("msr    daifset, #2": : : "memory");
}
#else/*defined(CONFIG_HAS_NMI)*/
static inline void cpu_enable_nmi(void)
{
}

static inline void cpu_disable_nmi(void)
{
}
#endif/*defined(CONFIG_HAS_NMI)*/

#endif	/* __ASSEMBLY__ */

#endif /* !__HEADER_ARM64_ARCH_CPU_H */
