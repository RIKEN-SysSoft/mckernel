#include <aal/lock.h>

#if 0

void aal_mc_spinlock_init(aal_spinlock_t *lock)
{
	*lock = 0;
}

void aal_mc_spinlock_lock(aal_spinlock_t *lock, unsigned long *flags)
{
	int inc = 0x00010000;
	int tmp;
	
	cpu_disable_interrupt_save(flags);
	asm volatile("lock ; xaddl %0, %1\n"
	             "movzwl %w0, %2\n\t"
	             "shrl $16, %0\n\t"
	             "1:\t"
	             "cmpl %0, %2\n\t"
	             "je 2f\n\t"
	             "rep ; nop\n\t"
	             "movzwl %1, %2\n\t"
	             "jmp 1b\n"
	             "2:"
	             : "+Q" (inc), "+m" (*lock), "=r" (tmp) : : "memory", "cc");
}

void aal_mc_spinlock_unlock(aal_spinlock_t *lock, unsigned long *flags)
{
	asm volatile ("lock incw %0" : "+m"(*lock) : : "memory", "cc");
	cpu_restore_interrupt(*flags);
}

#endif
