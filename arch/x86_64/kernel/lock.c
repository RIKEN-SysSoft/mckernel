/**
 * \file lock.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Spin lock.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#include <ihk/lock.h>

#if 0

void ihk_mc_spinlock_init(ihk_spinlock_t *lock)
{
	*lock = 0;
}

unsigned long ihk_mc_spinlock_lock(ihk_spinlock_t *lock)
{
	int inc = 0x00010000;
	int tmp;
	unsigned long flags;

	flags = cpu_disable_interrupt_save();

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
	return flags;
}

void ihk_mc_spinlock_unlock(ihk_spinlock_t *lock, unsigned long flags)
{
	asm volatile ("lock incw %0" : "+m"(*lock) : : "memory", "cc");
	cpu_restore_interrupt(flags);
}

#endif
