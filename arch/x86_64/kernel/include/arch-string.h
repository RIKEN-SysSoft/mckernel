#ifndef _ASM_X86_STRING_H
#define _ASM_X86_STRING_H

#define ARCH_FAST_MEMCPY

static inline void *__inline_memcpy(void *to, const void *from, size_t n)
{
	unsigned long d0, d1, d2;
	asm volatile("rep ; movsl\n\t"
		     "testb $2,%b4\n\t"
		     "je 1f\n\t"
		     "movsw\n"
		     "1:\ttestb $1,%b4\n\t"
		     "je 2f\n\t"
		     "movsb\n"
		     "2:"
		     : "=&c" (d0), "=&D" (d1), "=&S" (d2)
		     : "0" (n / 4), "q" (n), "1" ((long)to), "2" ((long)from)
		     : "memory");
	return to;
}

#define ARCH_FAST_MEMSET

static inline void *__inline_memset(void *s, unsigned long c, size_t count)
{
	int d0, d1;
	asm volatile("rep ; stosl\n\t"
		     "testb $2,%b3\n\t"
		     "je 1f\n\t"
		     "stosw\n"
		     "1:\ttestb $1,%b3\n\t"
		     "je 2f\n\t"
		     "stosb\n"
		     "2:"
		     : "=&c" (d0), "=&D" (d1)
		     : "a" (c), "q" (count), "0" (count/4), "1" ((long)s)
		     : "memory");
	return s;
}

#endif
