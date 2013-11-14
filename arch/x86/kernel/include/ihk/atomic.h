/**
 * \file atomic.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Atomic memory operations.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */

#ifndef HEADER_X86_COMMON_IHK_ATOMIC_H
#define HEADER_X86_COMMON_IHK_ATOMIC_H
 
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


#endif
