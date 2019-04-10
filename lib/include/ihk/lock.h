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

#endif

