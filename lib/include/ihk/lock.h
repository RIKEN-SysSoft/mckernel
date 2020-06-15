/**
 * \file lock.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Declare functions implementing spin lock.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef __HEADER_GENERIC_IHK_LOCK
#define __HEADER_GENERIC_IHK_LOCK

#include <arch-lock.h>


/* Simple read/write spinlock implementation */
#define IHK_RWSPINLOCK_WRITELOCKED	(0xffU << 24)
typedef struct {
	ihk_atomic_t v;
} __attribute__((aligned(4))) ihk_rwspinlock_t;

static void ihk_rwspinlock_init(ihk_rwspinlock_t *lock)
{
	ihk_atomic_set(&lock->v, 0);
}

static inline void __ihk_rwspinlock_read_lock(ihk_rwspinlock_t *lock)
{
	int desired_old_val;
	int new_val;

	/*
	 * Atomically increase number of readers,
	 * but make sure no writer is holding the lock.
	 */
	for (;;) {
		desired_old_val = ihk_atomic_read(&lock->v);
		desired_old_val &= ~(IHK_RWSPINLOCK_WRITELOCKED);
		new_val = desired_old_val + 1;

		/* Only if we have not reached the max number of readers */
		if (likely((uint32_t)new_val < IHK_RWSPINLOCK_WRITELOCKED)) {
			if (likely(cmpxchg(&lock->v.counter, desired_old_val, new_val) ==
					desired_old_val))
				return;
		}
	}
}

static inline int __ihk_rwspinlock_read_trylock(ihk_rwspinlock_t *lock)
{
	int desired_old_val;
	int new_val;

	/*
	 * Atomically try to increase number of readers,
	 * but make sure no writer is holding the lock.
	 */
	desired_old_val = ihk_atomic_read(&lock->v);
	desired_old_val &= ~(IHK_RWSPINLOCK_WRITELOCKED);
	new_val = desired_old_val + 1;

	/* Only if we have not reached the max number of readers */
	if (likely((uint32_t)new_val < IHK_RWSPINLOCK_WRITELOCKED)) {
		if (likely(cmpxchg(&lock->v.counter, desired_old_val, new_val) ==
					desired_old_val))
			return 1;
	}

	return 0;
}


static inline void __ihk_rwspinlock_read_unlock(ihk_rwspinlock_t *lock)
{
	ihk_atomic_dec((ihk_atomic_t *)&lock->v);
}

static inline void __ihk_rwspinlock_write_lock(ihk_rwspinlock_t *lock)
{
	/*
	 * Atomically switch to write-locked state,
	 * but make sure no one else is holding the lock.
	 */
	for (;;) {
		if (likely(cmpxchg(&lock->v.counter,
					0, IHK_RWSPINLOCK_WRITELOCKED) == 0))
			return;
		cpu_pause();
	}
}

static inline void __ihk_rwspinlock_write_unlock(ihk_rwspinlock_t *lock)
{
	smp_store_release(&(lock->v.counter), 0);
}

/* User facing functions */
static inline void ihk_rwspinlock_read_lock_noirq(ihk_rwspinlock_t *lock)
{
	preempt_disable();
	__ihk_rwspinlock_read_lock(lock);
}

static inline int ihk_rwspinlock_read_trylock_noirq(ihk_rwspinlock_t *lock)
{
	int rc;

	preempt_disable();
	rc = __ihk_rwspinlock_read_trylock(lock);
	if (!rc) {
		preempt_enable();
	}

	return rc;
}

static inline void ihk_rwspinlock_write_lock_noirq(ihk_rwspinlock_t *lock)
{
	preempt_disable();
	__ihk_rwspinlock_write_lock(lock);
}

static inline void ihk_rwspinlock_read_unlock_noirq(ihk_rwspinlock_t *lock)
{
	__ihk_rwspinlock_read_unlock(lock);
	preempt_enable();
}

static inline void ihk_rwspinlock_write_unlock_noirq(ihk_rwspinlock_t *lock)
{
	__ihk_rwspinlock_write_unlock(lock);
	preempt_enable();
}


static inline
unsigned long ihk_rwspinlock_read_lock(ihk_rwspinlock_t *lock)
{
	unsigned long irqstate = cpu_disable_interrupt_save();

	ihk_rwspinlock_read_lock_noirq(lock);
	return irqstate;
}

static inline
unsigned long ihk_rwspinlock_write_lock(ihk_rwspinlock_t *lock)
{
	unsigned long irqstate = cpu_disable_interrupt_save();

	ihk_rwspinlock_write_lock_noirq(lock);
	return irqstate;
}

static inline void ihk_rwspinlock_read_unlock(ihk_rwspinlock_t *lock,
	unsigned long irqstate)
{
	ihk_rwspinlock_read_unlock_noirq(lock);
	cpu_restore_interrupt(irqstate);
}

static inline void ihk_rwspinlock_write_unlock(ihk_rwspinlock_t *lock,
	unsigned long irqstate)
{
	ihk_rwspinlock_write_unlock_noirq(lock);
	cpu_restore_interrupt(irqstate);
}



#ifndef ARCH_MCS_LOCK
/* An architecture independent implementation of the
 * Mellor-Crummey Scott (MCS) lock */

typedef struct mcs_lock_node {
#ifndef SPIN_LOCK_IN_MCS
	unsigned long locked;
	struct mcs_lock_node *next;
#endif
	unsigned long irqsave;
#ifdef SPIN_LOCK_IN_MCS
	ihk_spinlock_t spinlock;
#endif
#ifndef ENABLE_UBSAN
} __aligned(64) mcs_lock_node_t;
#else
} mcs_lock_node_t;
#endif

typedef mcs_lock_node_t mcs_lock_t;

static void mcs_lock_init(struct mcs_lock_node *node)
{
#ifdef SPIN_LOCK_IN_MCS
	ihk_mc_spinlock_init(&node->spinlock);
#else
	node->locked = 0;
	node->next = NULL;
#endif // SPIN_LOCK_IN_MCS
}


static void __mcs_lock_lock(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
#ifdef SPIN_LOCK_IN_MCS
	ihk_mc_spinlock_lock_noirq(&lock->spinlock);
#else
	struct mcs_lock_node *pred;

	node->next = NULL;
	node->locked = 0;

	pred = xchg(&lock->next, node);
	if (likely(pred == NULL)) {
		/*
		 * Lock acquired, don't need to set node->locked to 1. Threads
		 * only spin on its own node->locked value for lock acquisition.
		 */
		return;
	}
	WRITE_ONCE(pred->next, node);

	/* Wait until the lock holder passes the lock down. */
	while (!(smp_load_acquire(&node->locked)))
		cpu_pause();
#endif // SPIN_LOCK_IN_MCS
}

static void __mcs_lock_unlock(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
#ifdef SPIN_LOCK_IN_MCS
	ihk_mc_spinlock_unlock_noirq(&lock->spinlock);
#else
	struct mcs_lock_node *next = READ_ONCE(node->next);

	if (likely(!next)) {
		/*
		 * Release the lock by setting it to NULL
		 */
		if (likely(cmpxchg(&lock->next, node, NULL) == node))
			return;

		/* Wait until the next pointer is set */
		while (!(next = READ_ONCE(node->next)))
			cpu_pause();
	}

	/* Pass lock to next waiter. */
	smp_store_release((&next->locked), 1);
#endif // SPIN_LOCK_IN_MCS
}

static void mcs_lock_lock_noirq(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	preempt_disable();
	__mcs_lock_lock(lock, node);
}

static void mcs_lock_unlock_noirq(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	__mcs_lock_unlock(lock, node);
	preempt_enable();
}

static void mcs_lock_lock(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	node->irqsave = cpu_disable_interrupt_save();
	mcs_lock_lock_noirq(lock, node);
}

static void mcs_lock_unlock(struct mcs_lock_node *lock,
		struct mcs_lock_node *node)
{
	mcs_lock_unlock_noirq(lock, node);
	cpu_restore_interrupt(node->irqsave);
}
#endif // ARCH_MCS_LOCK



#ifndef IHK_STATIC_SPINLOCK_FUNCS
void ihk_mc_spinlock_init(ihk_spinlock_t *);
void ihk_mc_spinlock_lock(ihk_spinlock_t *, unsigned long *);
void ihk_mc_spinlock_unlock(ihk_spinlock_t *, unsigned long *);
#endif

/*
 * Linux queued_spin_lock compatible spin_lock, without the queue.
 */
#define _Q_LOCKED_OFFSET    0
#define _Q_LOCKED_VAL       (1U << _Q_LOCKED_OFFSET)

#define linux_spin_lock(lock)                    \
	do {                                         \
		while (!__sync_bool_compare_and_swap(    \
					(unsigned int *)lock, 0,     \
					_Q_LOCKED_VAL)) {            \
			cpu_pause();                         \
		}                                        \
	} while (0)

#define linux_spin_unlock(lock)                               \
	do {                                                      \
		smp_store_release(lock, 0);                           \
	} while (0)

#define linux_spin_lock_irqsave(lock, flags)     \
	do {                                         \
		flags = cpu_disable_interrupt_save();    \
		linux_spin_lock(lock);                   \
	} while (0)

#define linux_spin_unlock_irqrestore(lock, flags) \
	do {                                          \
		linux_spin_unlock(lock);                  \
		cpu_restore_interrupt(flags);             \
	} while (0)


#endif

