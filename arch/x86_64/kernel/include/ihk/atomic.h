/**
 * \file atomic.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Atomic memory operations.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef HEADER_X86_COMMON_IHK_ATOMIC_H
#define HEADER_X86_COMMON_IHK_ATOMIC_H
 
#include <lwk/compiler.h>

/***********************************************************************
 * ihk_atomic_t
 */

typedef struct {
	int counter;
} ihk_atomic_t;

#define IHK_ATOMIC_INIT(i)	{ (i) }


static inline int ihk_atomic_read(const ihk_atomic_t *v)
{
	return (*(volatile int *)&(v)->counter);
}

static inline void ihk_atomic_set(ihk_atomic_t *v, int i)
{
	v->counter = i;
}

static inline void ihk_atomic_add(int i, ihk_atomic_t *v)
{
	asm volatile("lock addl %1,%0"
		     : "+m" (v->counter)
		     : "ir" (i));
}

static inline void ihk_atomic_sub(int i, ihk_atomic_t *v)
{
	asm volatile("lock subl %1,%0"
		     : "+m" (v->counter)
		     : "ir" (i));
}

static inline void ihk_atomic_inc(ihk_atomic_t *v)
{
	asm volatile("lock incl %0"
		     : "+m" (v->counter));
}

static inline void ihk_atomic_dec(ihk_atomic_t *v)
{
	asm volatile("lock decl %0"
		     : "+m" (v->counter));
}

static inline int ihk_atomic_dec_and_test(ihk_atomic_t *v)
{
	unsigned char c;

	asm volatile("lock decl %0; sete %1"
		     : "+m" (v->counter), "=qm" (c)
		     : : "memory");
	return c != 0;
}

static inline int ihk_atomic_inc_and_test(ihk_atomic_t *v)
{
	unsigned char c;

	asm volatile("lock incl %0; sete %1"
		     : "+m" (v->counter), "=qm" (c)
		     : : "memory");
	return c != 0;
}

static inline int ihk_atomic_add_return(int i, ihk_atomic_t *v)
{
	int __i;

	__i = i;
	asm volatile("lock xaddl %0, %1"
		     : "+r" (i), "+m" (v->counter)
		     : : "memory");
	return i + __i;
}

static inline int ihk_atomic_sub_return(int i, ihk_atomic_t *v)
{
	return ihk_atomic_add_return(-i, v);
}

#define ihk_atomic_inc_return(v)  (ihk_atomic_add_return(1, v))
#define ihk_atomic_dec_return(v)  (ihk_atomic_sub_return(1, v))

/***********************************************************************
 * ihk_atomic64_t
 */

typedef struct {
	long counter64;
} ihk_atomic64_t;

#define IHK_ATOMIC64_INIT(i) { .counter64 = (i) }

static inline long ihk_atomic64_read(const ihk_atomic64_t *v)
{
	return *(volatile long *)&(v)->counter64;
}

static inline void ihk_atomic64_set(ihk_atomic64_t *v, long i)
{
	v->counter64 = i;
}

static inline void ihk_atomic64_inc(ihk_atomic64_t *v)
{
	asm volatile ("lock incq %0" : "+m"(v->counter64));
}

static inline long ihk_atomic64_add_return(long i, ihk_atomic64_t *v)
{
	long __i;

	__i = i;
	asm volatile("lock xaddq %0, %1"
		     : "+r" (i), "+m" (v->counter64)
		     : : "memory");
	return i + __i;
}

static inline long ihk_atomic64_sub_return(long i, ihk_atomic64_t *v)
{
	return ihk_atomic64_add_return(-i, v);
}

/***********************************************************************
 * others
 */

/*
 * Note: no "lock" prefix even on SMP: xchg always implies lock anyway
 * Note 2: xchg has side effect, so that attribute volatile is necessary,
 *	  but generally the primitive is invalid, *ptr is output argument. --ANK
 */
#define __xg(x) ((volatile long *)(x))

#define xchg4(ptr, x)						\
({									\
	int __x = (x);					\
	asm volatile("xchgl %k0,%1"				\
			 : "=r" (__x)				\
			 : "m" (*ptr), "0" (__x)		\
			 : "memory");				\
	__x;								\
})

static inline unsigned long xchg8(unsigned long *ptr, unsigned long x)
{
	unsigned long __x = (x);
	asm volatile("xchgq %0,%1"
			 : "=r" (__x)
			 : "m" (*(volatile unsigned long*)(ptr)), "0" (__x)
			 : "memory");

	return __x;
}

#define __X86_CASE_B	1
#define __X86_CASE_W	2
#define __X86_CASE_L	4
#define __X86_CASE_Q	8

extern void __xchg_wrong_size(void)
	__compiletime_error("Bad argument size for xchg");

/*
 * An exchange-type operation, which takes a value and a pointer, and
 * returns the old value.
 */
#define __xchg_op(ptr, arg, op, lock)					\
	({								\
		__typeof__(*(ptr)) __ret = (arg);			\
		switch (sizeof(*(ptr))) {				\
		case __X86_CASE_B:					\
			asm volatile (lock #op "b %b0, %1\n"		\
				      : "+q" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		case __X86_CASE_W:					\
			asm volatile (lock #op "w %w0, %1\n"		\
				      : "+r" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		case __X86_CASE_L:					\
			asm volatile (lock #op "l %0, %1\n"		\
				      : "+r" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		case __X86_CASE_Q:					\
			asm volatile (lock #op "q %q0, %1\n"		\
				      : "+r" (__ret), "+m" (*(ptr))	\
				      : : "memory", "cc");		\
			break;						\
		default:						\
			__xchg_wrong_size();			\
		}							\
		__ret;							\
	})

/*
 * Note: no "lock" prefix even on SMP: xchg always implies lock anyway.
 * Since this is generally used to protect other memory information, we
 * use "asm volatile" and "memory" clobbers to prevent gcc from moving
 * information around.
 */
#define xchg(ptr, v)	__xchg_op((ptr), (v), xchg, "")

static inline unsigned long atomic_cmpxchg8(unsigned long *addr,
		unsigned long oldval,
		unsigned long newval)
{
	asm volatile("lock; cmpxchgq %2, %1\n"
		     : "=a" (oldval), "+m" (*addr)
		     : "r" (newval), "0" (oldval)
		     : "memory"
	);

	return oldval;
}

static inline unsigned long atomic_cmpxchg4(unsigned int *addr,
		unsigned int oldval,
		unsigned int newval)
{
	asm volatile("lock; cmpxchgl %2, %1\n"
		     : "=a" (oldval), "+m" (*addr)
		     : "r" (newval), "0" (oldval)
		     : "memory"
	);

	return oldval;
}

static inline void ihk_atomic_add_long(long i, long *v) {
	asm volatile("lock addq %1,%0"
					: "+m" (*v)
					: "ir" (i));
}
static inline void ihk_atomic_add_ulong(long i, unsigned long *v) {
	asm volatile("lock addq %1,%0"
					: "+m" (*v)
					: "ir" (i));
}

static inline unsigned long ihk_atomic_add_long_return(long i, long *v) {
        long __i;

        __i = i;
        asm volatile("lock xaddq %0, %1"
                     : "+r" (i), "+m" (*v)
                     : : "memory");
        return i + __i;
}

extern void __cmpxchg_wrong_size(void)
	__compiletime_error("Bad argument size for cmpxchg");

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */
#define __raw_cmpxchg(ptr, old, new, size, lock)		\
({									\
	__typeof__(*(ptr)) __ret;					\
	__typeof__(*(ptr)) __old = (old);				\
	__typeof__(*(ptr)) __new = (new);				\
	switch (size) {							\
	case __X86_CASE_B:						\
	{								\
		volatile uint8_t *__ptr = (volatile uint8_t *)(ptr);\
		asm volatile(lock "cmpxchgb %2,%1"			\
			     : "=a" (__ret), "+m" (*__ptr)		\
			     : "q" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_W:						\
	{								\
		volatile uint16_t *__ptr = (volatile uint16_t *)(ptr);\
		asm volatile(lock "cmpxchgw %2,%1"			\
			     : "=a" (__ret), "+m" (*__ptr)		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_L:						\
	{								\
		volatile uint32_t *__ptr = (volatile uint32_t *)(ptr);\
		asm volatile(lock "cmpxchgl %2,%1"			\
			     : "=a" (__ret), "+m" (*__ptr)		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	}								\
	case __X86_CASE_Q:						\
	{								\
		volatile uint64_t *__ptr = (volatile uint64_t *)(ptr);\
		asm volatile(lock "cmpxchgq %2,%1"			\
			     : "=a" (__ret), "+m" (*__ptr)		\
			     : "r" (__new), "0" (__old)			\
			     : "memory");				\
		break;							\
	}								\
	default:							\
		__cmpxchg_wrong_size();		\
	}								\
	__ret;								\
})

#define __cmpxchg(ptr, old, new, size)					\
	__raw_cmpxchg((ptr), (old), (new), (size), "lock; ")

#define cmpxchg(ptr, old, new)						\
	__cmpxchg(ptr, old, new, sizeof(*(ptr)))

#endif
