#ifndef HEADER_X86_COMMON_AAL_ATOMIC_H
#define HEADER_X86_COMMON_AAL_ATOMIC_H
 
typedef struct {
	int counter;
} aal_atomic_t;

#define AAL_ATOMIC_INIT(i)	{ (i) }


static inline int aal_atomic_read(const aal_atomic_t *v)
{
	return (*(volatile int *)&(v)->counter);
}

static inline void aal_atomic_set(aal_atomic_t *v, int i)
{
	v->counter = i;
}

static inline void aal_atomic_add(int i, aal_atomic_t *v)
{
	asm volatile("lock addl %1,%0"
		     : "+m" (v->counter)
		     : "ir" (i));
}

static inline void aal_atomic_sub(int i, aal_atomic_t *v)
{
	asm volatile("lock subl %1,%0"
		     : "+m" (v->counter)
		     : "ir" (i));
}

static inline void aal_atomic_inc(aal_atomic_t *v)
{
	asm volatile("lock incl %0"
		     : "+m" (v->counter));
}

static inline void aal_atomic_dec(aal_atomic_t *v)
{
	asm volatile("lock decl %0"
		     : "+m" (v->counter));
}

static inline int aal_atomic_dec_and_test(aal_atomic_t *v)
{
	unsigned char c;

	asm volatile("lock decl %0; sete %1"
		     : "+m" (v->counter), "=qm" (c)
		     : : "memory");
	return c != 0;
}

static inline int aal_atomic_inc_and_test(aal_atomic_t *v)
{
	unsigned char c;

	asm volatile("lock incl %0; sete %1"
		     : "+m" (v->counter), "=qm" (c)
		     : : "memory");
	return c != 0;
}

static inline int aal_atomic_add_return(int i, aal_atomic_t *v)
{
	int __i;

	__i = i;
	asm volatile("lock xaddl %0, %1"
		     : "+r" (i), "+m" (v->counter)
		     : : "memory");
	return i + __i;
}

static inline int aal_atomic_sub_return(int i, aal_atomic_t *v)
{
	return aal_atomic_add_return(-i, v);
}

#define aal_atomic_inc_return(v)  (aal_atomic_add_return(1, v))
#define aal_atomic_dec_return(v)  (aal_atomic_sub_return(1, v))

#endif
