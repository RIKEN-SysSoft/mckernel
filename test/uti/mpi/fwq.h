#ifndef __FWQ_H_INCLUDED__
#define __FWQ_H_INCLUDED__

static inline void fixed_size_work(void)
{
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

static inline void bulk_fsw(unsigned long n)
{
	int j;

	for (j = 0; j < (n); j++) {
		fixed_size_work();
	}
}

void fwq_init(void);
void fwq(long delay_nsec);

#endif
