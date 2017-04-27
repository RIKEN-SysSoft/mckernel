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

static inline void ihk_atomic64_inc(ihk_atomic64_t *v)
{
	asm volatile ("lock incq %0" : "+m"(v->counter64));
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

#define __xchg(x, ptr, size)						\
({									\
	__typeof(*(ptr)) __x = (x);					\
	switch (size) {							\
	case 1:								\
		asm volatile("xchgb %b0,%1"				\
			     : "=q" (__x)				\
			     : "m" (*__xg(ptr)), "0" (__x)		\
			     : "memory");				\
		break;							\
	case 2:								\
		asm volatile("xchgw %w0,%1"				\
			     : "=r" (__x)				\
			     : "m" (*__xg(ptr)), "0" (__x)		\
			     : "memory");				\
		break;							\
	case 4:								\
		asm volatile("xchgl %k0,%1"				\
			     : "=r" (__x)				\
			     : "m" (*__xg(ptr)), "0" (__x)		\
			     : "memory");				\
		break;							\
	case 8:								\
		asm volatile("xchgq %0,%1"				\
			     : "=r" (__x)				\
			     : "m" (*__xg(ptr)), "0" (__x)		\
			     : "memory");				\
		break;							\
	default:							\
		panic("xchg for wrong size");					\
	}								\
	__x;								\
})


#define xchg(ptr, v)							\
	__xchg((v), (ptr), sizeof(*ptr))

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

#endif
