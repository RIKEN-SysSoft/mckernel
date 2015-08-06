/*
 * Excerpted from Linux 3.0: arch/x86/include/asm/spinlock.h
 */
#ifndef __HEADER_X86_COMMON_ARCH_LOCK
#define __HEADER_X86_COMMON_ARCH_LOCK

#include <ihk/cpu.h>

//#define DEBUG_SPINLOCK

#ifdef DEBUG_SPINLOCK
int __kprintf(const char *format, ...);
#endif

typedef int ihk_spinlock_t;

extern void preempt_enable(void);
extern void preempt_disable(void);

#define IHK_STATIC_SPINLOCK_FUNCS

static void ihk_mc_spinlock_init(ihk_spinlock_t *lock)
{
	*lock = 0;
}
#define SPIN_LOCK_UNLOCKED 0

static void ihk_mc_spinlock_lock_noirq(ihk_spinlock_t *lock)
{
	int inc = 0x00010000;
	int tmp;

#if 0
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
#endif

#ifdef DEBUG_SPINLOCK
	__kprintf("[%d] trying to grab lock: 0x%lX\n", 
	          ihk_mc_get_processor_id(), lock);
#endif

	preempt_disable();

	asm volatile("lock; xaddl %0, %1\n"
			"movzwl %w0, %2\n\t"
			"shrl $16, %0\n\t"
			"1:\t"
			"cmpl %0, %2\n\t"
			"je 2f\n\t"
			"rep ; nop\n\t"
			"movzwl %1, %2\n\t"
			/* don't need lfence here, because loads are in-order */
			"jmp 1b\n"
			"2:"
			: "+r" (inc), "+m" (*lock), "=&r" (tmp)
			:
			: "memory", "cc");

#ifdef DEBUG_SPINLOCK
	__kprintf("[%d] holding lock: 0x%lX\n", ihk_mc_get_processor_id(), lock);
#endif
}

static unsigned long ihk_mc_spinlock_lock(ihk_spinlock_t *lock)
{
	unsigned long flags;
	
	flags = cpu_disable_interrupt_save();

	ihk_mc_spinlock_lock_noirq(lock);

	return flags;
}

static void ihk_mc_spinlock_unlock_noirq(ihk_spinlock_t *lock)
{
	asm volatile ("lock incw %0" : "+m"(*lock) : : "memory", "cc");
	
	preempt_enable();
}

static void ihk_mc_spinlock_unlock(ihk_spinlock_t *lock, unsigned long flags)
{
	ihk_mc_spinlock_unlock_noirq(lock);

	cpu_restore_interrupt(flags);
#ifdef DEBUG_SPINLOCK
	__kprintf("[%d] released lock: 0x%lX\n", ihk_mc_get_processor_id(), lock);
#endif
}

#endif

