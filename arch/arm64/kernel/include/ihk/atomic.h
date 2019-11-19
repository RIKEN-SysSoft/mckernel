/* atomic.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
#ifndef __HEADER_ARM64_IHK_ATOMIC_H
#define __HEADER_ARM64_IHK_ATOMIC_H

#include <arch/cpu.h>

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

/* @ref.impl arch/arm64/include/asm/atomic.h::atomic_add (atomic_##op) */
static inline void ihk_atomic_add(int i, ihk_atomic_t *v)
{
	unsigned long tmp;
	int result;

	asm volatile("// atomic_add\n"
"1:	ldxr	%w0, %2\n"
"	add	%w0, %w0, %w3\n"
"	stxr	%w1, %w0, %2\n"
"	cbnz	%w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
	: "Ir" (i));
}

/* @ref.impl arch/arm64/include/asm/atomic.h::atomic_sub (atomic_##op) */
static inline void ihk_atomic_sub(int i, ihk_atomic_t *v)
{
	unsigned long tmp;
	int result;

	asm volatile("// atomic_sub\n"
"1:	ldxr	%w0, %2\n"
"	sub	%w0, %w0, %w3\n"
"	stxr	%w1, %w0, %2\n"
"	cbnz	%w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
	: "Ir" (i));
}

/* @ref.impl arch/arm64/include/asm/atomic.h::atomic_inc */
#define ihk_atomic_inc(v)		ihk_atomic_add(1, v)

/* @ref.impl arch/arm64/include/asm/atomic.h::atomic_dec */
#define ihk_atomic_dec(v)		ihk_atomic_sub(1, v)

/* @ref.impl arch/arm64/include/asm/atomic.h::atomic_add_return (atomic_##op##_return) */
static inline int ihk_atomic_add_return(int i, ihk_atomic_t *v)
{
	unsigned long tmp;
	int result;

	asm volatile("// atomic_add_return\n"
"1:	ldxr	%w0, %2\n"
"	add	%w0, %w0, %w3\n"
"	stlxr	%w1, %w0, %2\n"
"	cbnz	%w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
	: "Ir" (i)
	: "memory");

	smp_mb();
	return result;
}

/* @ref.impl arch/arm64/include/asm/atomic.h::atomic_sub_return (atomic_##op##_return) */
static inline int ihk_atomic_sub_return(int i, ihk_atomic_t *v)
{
	unsigned long tmp;
	int result;

	asm volatile("// atomic_sub_return\n"
"1:	ldxr	%w0, %2\n"
"	sub	%w0, %w0, %w3\n"
"	stlxr	%w1, %w0, %2\n"
"	cbnz	%w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (v->counter)
	: "Ir" (i)
	: "memory");

	smp_mb();
	return result;
}

/* @ref.impl arch/arm64/include/asm/atomic.h::atomic_inc_and_test */
#define ihk_atomic_inc_and_test(v)	(ihk_atomic_add_return(1, v) == 0)

/* @ref.impl arch/arm64/include/asm/atomic.h::atomic_dec_and_test */
#define ihk_atomic_dec_and_test(v)	(ihk_atomic_sub_return(1, v) == 0)

/* @ref.impl arch/arm64/include/asm/atomic.h::atomic_inc_return */
#define ihk_atomic_inc_return(v)  	(ihk_atomic_add_return(1, v))

/* @ref.impl arch/arm64/include/asm/atomic.h::atomic_dec_return */
#define ihk_atomic_dec_return(v)  	(ihk_atomic_sub_return(1, v))

/***********************************************************************
 * ihk_atomic64_t
 */
typedef struct {
	long counter64;
} ihk_atomic64_t;

#define IHK_ATOMIC64_INIT(i)	{ .counter64 = (i) }

static inline long ihk_atomic64_read(const ihk_atomic64_t *v)
{
	return *(volatile long *)&(v)->counter64;
}

static inline void ihk_atomic64_set(ihk_atomic64_t *v, long i)
{
	v->counter64 = i;
}

/* @ref.impl arch/arm64/include/asm/atomic.h::atomic64_add (atomic64_##op) */
static inline void ihk_atomic64_add(long i, ihk_atomic64_t *v)
{
	long result;
	unsigned long tmp;

	asm volatile("// atomic64_add\n"
"1:	ldxr	%0, %2\n"
"	add	%0, %0, %3\n"
"	stxr	%w1, %0, %2\n"
"	cbnz	%w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (v->counter64)
	: "Ir" (i));
}

/* @ref.impl arch/arm64/include/asm/atomic.h::atomic64_inc */
#define ihk_atomic64_inc(v)			ihk_atomic64_add(1LL, (v))

#define ihk_atomic64_cmpxchg(p, o, n) cmpxchg(&((p)->counter64), o, n)

/***********************************************************************
 * others
 */
/* @ref.impl arch/arm64/include/asm/cmpxchg.h::__xchg */
static inline unsigned long __xchg(unsigned long x, volatile void *ptr, int size)
{
	unsigned long ret = 0, tmp;

	switch (size) {
	case 1:
		asm volatile("//	__xchg1\n"
		"1:	ldxrb	%w0, %2\n"
		"	stlxrb	%w1, %w3, %2\n"
		"	cbnz	%w1, 1b\n"
			: "=&r" (ret), "=&r" (tmp), "+Q" (*(unsigned char *)ptr)
			: "r" (x)
			: "memory");
		break;
	case 2:
		asm volatile("//	__xchg2\n"
		"1:	ldxrh	%w0, %2\n"
		"	stlxrh	%w1, %w3, %2\n"
		"	cbnz	%w1, 1b\n"
			: "=&r" (ret), "=&r" (tmp), "+Q" (*(unsigned short *)ptr)
			: "r" (x)
			: "memory");
		break;
	case 4:
		asm volatile("//	__xchg4\n"
		"1:	ldxr	%w0, %2\n"
		"	stlxr	%w1, %w3, %2\n"
		"	cbnz	%w1, 1b\n"
			: "=&r" (ret), "=&r" (tmp), "+Q" (*(unsigned int *)ptr)
			: "r" (x)
			: "memory");
		break;
	case 8:
		asm volatile("//	__xchg8\n"
		"1:	ldxr	%0, %2\n"
		"	stlxr	%w1, %3, %2\n"
		"	cbnz	%w1, 1b\n"
			: "=&r" (ret), "=&r" (tmp), "+Q" (*(unsigned long *)ptr)
			: "r" (x)
			: "memory");
		break;
/*
	default:
		BUILD_BUG();
*/
	}

	smp_mb();
	return ret;
}

/* @ref.impl arch/arm64/include/asm/cmpxchg.h::xchg */
#define xchg(ptr,x) \
({ \
	__typeof__(*(ptr)) __ret; \
	__ret = (__typeof__(*(ptr))) \
		__xchg((unsigned long)(x), (ptr), sizeof(*(ptr))); \
	__ret; \
})

#define xchg4(ptr, x) xchg(ptr,x)
#define xchg8(ptr, x) xchg(ptr,x)

/* @ref.impl arch/arm64/include/asm/cmpxchg.h::__cmpxchg */
static inline unsigned long __cmpxchg(volatile void *ptr, unsigned long old,
				unsigned long new, int size)
{
	unsigned long oldval = 0, res;

	switch (size) {
	case 1:
		do {
			asm volatile("// __cmpxchg1\n"
			"	ldxrb	%w1, %2\n"
			"	mov	%w0, #0\n"
			"	cmp	%w1, %w3\n"
			"	b.ne	1f\n"
			"	stxrb	%w0, %w4, %2\n"
			"1:\n"
				: "=&r" (res), "=&r" (oldval), "+Q" (*(unsigned char *)ptr)
				: "Ir" (old), "r" (new)                                                               				: "cc");
		} while (res);
		break;

	case 2:
		do {
			asm volatile("// __cmpxchg2\n"
			"	ldxrh	%w1, %2\n"
			"	mov	%w0, #0\n"
			"	cmp	%w1, %w3\n"
			"	b.ne	1f\n"
			"	stxrh	%w0, %w4, %2\n"
			"1:\n"
				: "=&r" (res), "=&r" (oldval), "+Q" (*(unsigned short *)ptr)
				: "Ir" (old), "r" (new)
				: "cc");
		} while (res);
		break;

	case 4:
		do {
			asm volatile("// __cmpxchg4\n"
			"	ldxr	%w1, %2\n"
			"	mov	%w0, #0\n"
			"	cmp	%w1, %w3\n"
			"	b.ne	1f\n"
			"	stxr	%w0, %w4, %2\n"
			"1:\n"
				: "=&r" (res), "=&r" (oldval), "+Q" (*(unsigned int *)ptr)
				: "Ir" (old), "r" (new)
				: "cc");
		} while (res);
		break;

	case 8:
		do {
			asm volatile("// __cmpxchg8\n"
			"	ldxr	%1, %2\n"
			"	mov	%w0, #0\n"
			"	cmp	%1, %3\n"
			"	b.ne	1f\n"
			"	stxr	%w0, %4, %2\n"
			"1:\n"
				: "=&r" (res), "=&r" (oldval), "+Q" (*(unsigned long *)ptr)
				: "Ir" (old), "r" (new)
				: "cc");
		} while (res);
		break;
/*
	default:
		BUILD_BUG();
*/
	}

	return oldval;
}

/* @ref.impl arch/arm64/include/asm/cmpxchg.h::__cmpxchg_mb */
static inline unsigned long __cmpxchg_mb(volatile void *ptr, unsigned long old,
					 unsigned long new, int size)
{
	unsigned long ret;

	smp_mb();
	ret = __cmpxchg(ptr, old, new, size);
	smp_mb();

	return ret;
}

/* @ref.impl arch/arm64/include/asm/cmpxchg.h::cmpxchg */
#define cmpxchg(ptr, o, n) \
({ \
	__typeof__(*(ptr)) __ret; \
	__ret = (__typeof__(*(ptr))) \
		__cmpxchg_mb((ptr), (unsigned long)(o), (unsigned long)(n), \
			sizeof(*(ptr))); \
	__ret; \
})

#define atomic_cmpxchg4(ptr, o, n)	cmpxchg(ptr,o,n)
#define atomic_cmpxchg8(ptr, o, n)	cmpxchg(ptr,o,n)

static inline void ihk_atomic_add_long(long i, long *v)
{
	long result;
	unsigned long tmp;

	asm volatile("// atomic64_add\n"
"1:	ldxr	%0, %2\n"
"	add	%0, %0, %3\n"
"	stxr	%w1, %0, %2\n"
"	cbnz	%w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (*v)
	: "Ir" (i));
}

static inline void ihk_atomic_add_ulong(long i, unsigned long *v)
{
	long result;
	unsigned long tmp;

	asm volatile("// atomic64_add\n"
"1:	ldxr	%0, %2\n"
"	add	%0, %0, %3\n"
"	stxr	%w1, %0, %2\n"
"	cbnz	%w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (*v)
	: "Ir" (i));
}

static inline unsigned long ihk_atomic_add_long_return(long i, long *v)
{
	unsigned long result;
	unsigned long tmp;

	asm volatile("// atomic64_add_return\n"
"1:	ldxr	%0, %2\n"
"	add	%0, %0, %3\n"
"	stlxr	%w1, %0, %2\n"
"	cbnz	%w1, 1b"
	: "=&r" (result), "=&r" (tmp), "+Q" (*v)
	: "Ir" (i)
	: "memory");

	smp_mb();
	return result;
}

#endif /* !__HEADER_ARM64_COMMON_IHK_ATOMIC_H */
