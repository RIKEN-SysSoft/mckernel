/* This is copy of the necessary part from McKernel, for uti-futex */

#ifndef __HEADER_X86_COMMON_ARCH_LOCK
#define __HEADER_X86_COMMON_ARCH_LOCK

#include <linux/preempt.h>
#include <cpu.h>

#define ihk_mc_spinlock_lock __ihk_mc_spinlock_lock
#define ihk_mc_spinlock_unlock __ihk_mc_spinlock_unlock

#define ihk_mc_spinlock_lock_noirq __ihk_mc_spinlock_lock_noirq
#define ihk_mc_spinlock_unlock_noirq __ihk_mc_spinlock_unlock_noirq

typedef unsigned short __ticket_t;
typedef unsigned int __ticketpair_t;

typedef struct ihk_spinlock {
	union {
		__ticketpair_t head_tail;
		struct __raw_tickets {
			__ticket_t head, tail;
		} tickets;
	};
} _ihk_spinlock_t;

static inline void ihk_mc_spinlock_init(_ihk_spinlock_t *lock)
{
	lock->head_tail = 0;
}

static inline void __ihk_mc_spinlock_lock_noirq(_ihk_spinlock_t *lock)
{
	register struct __raw_tickets inc = { .tail = 0x0002 };

	preempt_disable();

	asm volatile ("lock xaddl %0, %1\n"
			: "+r" (inc), "+m" (*(lock)) : : "memory", "cc");

	if (inc.head == inc.tail)
		goto out;

	for (;;) {
		if (*((volatile __ticket_t *)&lock->tickets.head) == inc.tail)
			goto out;
		cpu_pause();
	}

out:
	barrier();  /* make sure nothing creeps before the lock is taken */
}

static inline void __ihk_mc_spinlock_unlock_noirq(_ihk_spinlock_t *lock)
{
	__ticket_t inc = 0x0002;

	asm volatile ("lock addw %1, %0\n"
			: "+m" (lock->tickets.head)
			: "ri" (inc) : "memory", "cc");

	preempt_enable();
}

static inline unsigned long __ihk_mc_spinlock_lock(_ihk_spinlock_t *lock)
{
	unsigned long flags;

	flags = cpu_disable_interrupt_save();

	__ihk_mc_spinlock_lock_noirq(lock);

	return flags;
}

static inline void __ihk_mc_spinlock_unlock(_ihk_spinlock_t *lock,
		unsigned long flags)
{
	__ihk_mc_spinlock_unlock_noirq(lock);

	cpu_restore_interrupt(flags);
}

typedef struct mcs_rwlock_lock {
	_ihk_spinlock_t slock;

#ifndef ENABLE_UBSAN
} __aligned(64) mcs_rwlock_lock_t;
#else
} mcs_rwlock_lock_t;
#endif

static inline void
mcs_rwlock_writer_lock_noirq(struct mcs_rwlock_lock *lock)
{
	ihk_mc_spinlock_lock_noirq(&lock->slock);
}

static inline void
mcs_rwlock_writer_unlock_noirq(struct mcs_rwlock_lock *lock)
{
	ihk_mc_spinlock_unlock_noirq(&lock->slock);
}

#endif
