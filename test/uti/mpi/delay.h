#ifndef __DELAY_H_INCLUDED__
#define __DELAY_H_INCLUDED__

static inline uint64_t rdtsc_light(void)
{
	uint64_t x;

	/* rdtscp don't jump over earlier instructions */
	__asm__ __volatile__("rdtscp;"
			     "shl $32, %%rdx;"
			     "or %%rdx, %%rax" :
			     "=a"(x) :
			     :
			     "%rcx", "%rdx", "memory");
	return x;
}

static inline void asmloop(unsigned long n)
{
	int j;

	for (j = 0; j < n; j++) {
		asm volatile(
			     "movq $0, %%rcx\n\t"
			     "1:\t"
			     "addq $1, %%rcx\n\t"
			     "cmpq $99, %%rcx\n\t"
			     "jle 1b\n\t"
			     :
			     :
			     : "rcx", "cc");
	}
}

void ndelay_init(void);
void ndelay(long delay_nsec);
void cdelay_init(void);
void cdelay(long delay_cyc);

#endif
