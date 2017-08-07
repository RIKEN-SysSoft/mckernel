#ifndef _IHK_HFI1_COMMON_H_
#define _IHK_HFI1_COMMON_H_

#include <ihk/atomic.h>
#include <ihk/types.h>
#include <kmalloc.h>
#include <lwk/compiler.h>
#include <arch-lock.h>
#include <page.h>
#include <string.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

/* From: mckernel/kernel/include/xpmem_private.h */
#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)
#define min(x, y)	({                                              \
	__typeof__(x) _min1 = (x);                                      \
	__typeof__(y) _min2 = (y);                                      \
	(void) (&_min1 == &_min2);                                      \
	_min1 < _min2 ? _min1 : _min2;})


#define BIT_ULL(nr) (1ULL << (nr))

/* Disable debug macros */
#define hfi1_cdbg(...) do {} while(0)
#define SDMA_DBG(...) do {} while(0)
#define WARN_ON(...) do {} while(0)
#define WARN_ON_ONCE WARN_ON // use the local definition
#define trace_hfi1_ahg_allocate(...) do {} while(0)
#define trace_hfi1_ahg_deallocate(...) do {} while(0)

/* Byte swapping */
#define be32_to_cpu(x) __builtin_bswap32(x)
#define be16_to_cpu(x) __builtin_bswap16(x)
#define le32_to_cpu(x) x
#define le16_to_cpu(x) x
#define cpu_to_le16(x) x
#define cpu_to_le32(x) x
#define cpu_to_le64(x) x
#define __cpu_to_le64(x) x
#define __le64_to_cpu(x) x
#define __le32_to_cpu(x) x
#define __le16_to_cpu(x) x
//TODO: double-check
#define cpu_to_be16(x) __builtin_bswap16(x)
#define cpu_to_be32(x) __builtin_bswap32(x)

/* Compiler */
#ifndef likely
# define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* From: kernel-xppsl_1.5.2/include/linux/compiler.h */
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

/* Atomic ops */
#define atomic_inc ihk_atomic_inc
#define atomic_dec ihk_atomic_dec
#define atomic_read ihk_atomic_read
#define atomic_add ihk_atomic_add
#define atomic_t ihk_atomic_t
typedef ihk_spinlock_t spinlock_t;

/* TODO***********************************/
#define spin_lock_irqsave(lock, flags) do {} while(0)
#define spin_unlock_irqsave(lock, flags) do {} while(0)
#define spin_unlock_irqrestore(lock, flags) do {} while(0)
#define ____cacheline_aligned_in_smp __attribute__((aligned(64)))
#define __iomem
#define spin_lock(...) do {} while(0)
#define spin_unlock(...) do {} while(0)
#define smp_wmb() barrier()
#define smp_rmb() barrier()
/***********************************************/

#define __rcu
#define __percpu
#define GFP_KERNEL 0
#define send_routine void *

/* hfi1 pio.h */
#define SC_MAX    4     /* count of send context types */

/* kernel-xppsl_1.5.2/include/linux/seqlock.h */
/***********************************************/
typedef struct seqcount {
	unsigned sequence;
} seqcount_t;

typedef struct {
	struct seqcount seqcount;
	spinlock_t lock;
} seqlock_t;

static inline unsigned raw_seqcount_begin(const seqcount_t *s)
{
	unsigned ret = ACCESS_ONCE(s->sequence);
	smp_rmb();
	return ret & ~1;
}
/***********************************************/

/* Misc */
/* From: kernel-xppsl_1.5.2/include/linux/kernel.h */
#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })

#define SIZE_MAX	(~(size_t)0)
#define MAX_TID_PAIR_ENTRIES 1024	/* max receive expected pairs */
#define PIO_BLOCK_SIZE 64			/* bytes */
/* From: chip.c/h */
#define TXE_NUM_SDMA_ENGINES 16
#define CCE_NUM_INT_CSRS 12
//num_vls = HFI1_MAX_VLS_SUPPORTED;
//num_vls = dd->chip_sdma_engines;
#define HFI1_MAX_VLS_SUPPORTED 8


/* integer typedefs */
typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;

typedef __signed__ long __s64;
typedef unsigned long __u64;

typedef __u64 u64;
typedef __s64 s64;

typedef __u32 u32;
typedef __s32 s32;

typedef __u16 u16;
typedef __s16 s16;

typedef __u8  u8;
typedef __s8  s8;

typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;

typedef unsigned int uint;

/* TODO: There should be a header file that I can include */
typedef _Bool bool;
#define false 0
#define true !false

/* TODO: double check this typedef */
typedef u64 dma_addr_t;

/* From: kernel-xppsl_1.5.2/include/linux/types.h */
typedef unsigned gfp_t;
#define CONFIG_PHYS_ADDR_T_64BIT
#ifdef CONFIG_PHYS_ADDR_T_64BIT
typedef u64 phys_addr_t;
#else
typedef u32 phys_addr_t;
#endif
typedef phys_addr_t resource_size_t;

/* kernel-xppsl_1.5.2/include/asm-generic/io.h */
#ifndef __raw_writeq
static inline void __raw_writeq(u64 b, volatile void __iomem *addr)
{
	*(volatile u64 __force *) addr = b;
}
#endif
#define writeq(b, addr) __raw_writeq(__cpu_to_le64(b), addr)


/* TODO: I'm not sure if this definition is correct */ 
#define LOCK_PREFIX "lock; "

/* From: kernel-xppsl_1.5.2/arch/x86/include/asm/bitops.h */
#define BITOP_ADDR(x) "+m" (*(volatile long *) (x))
#define LINUX_ADDR BITOP_ADDR(addr)

/* From: kernel-xppsl_1.5.2/arch/x86/include/asm/bitops.h */
static inline int test_and_set_bit(int nr, volatile unsigned long *addr)
{
	int oldbit;

	asm volatile(LOCK_PREFIX "bts %2,%1\n\t"
		     "sbb %0,%0" : "=r" (oldbit), LINUX_ADDR : "Ir" (nr) : "memory");

	return oldbit;
}

/* From: kernel-xppsl_1.5.2/arch/x86/include/asm/atomic.h */
static inline int atomic_dec_and_test(atomic_t *v)
{
	unsigned char c;

	asm volatile(LOCK_PREFIX "decl %0; sete %1"
		     : "+m" (v->counter), "=qm" (c)
		     : : "memory");
	return c != 0;
}

/* From: kernel-xppsl_1.5.2/include/linux/slab.h */
static inline void *kmalloc_array(size_t n, size_t size, gfp_t flags)
{
	if (size != 0 && n > SIZE_MAX / size)
		return NULL;
	return kmalloc(n * size, flags);
}

static inline void *kcalloc(size_t n, size_t size, gfp_t flags)
{
	void *mem = kmalloc(n * size, flags);
	if (mem)
		memset(mem, 0, n * size);
	return mem;
}

#endif
