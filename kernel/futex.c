/*
 * Kitten LWK futex code adaptation.
 * Copyright (c) 2012 RIKEN AICS
 */

/*
 * Copyright (c) 2008 Sandia National Laboratories
 *
 * Futex code adapted from Linux 2.6.27.9, original copyright below.
 * Simplified to only support address-space (process-private) futexes.
 * Removed demand-paging, cow, etc. complications since LWK doesn't
 * require these.
 */

/*
 *  Fast Userspace Mutexes (which I call "Futexes!").
 *  (C) Rusty Russell, IBM 2002
 *
 *  Generalized futexes, futex requeueing, misc fixes by Ingo Molnar
 *  (C) Copyright 2003 Red Hat Inc, All Rights Reserved
 *
 *  Removed page pinning, fix privately mapped COW pages and other cleanups
 *  (C) Copyright 2003, 2004 Jamie Lokier
 *
 *  Robust futex support started by Ingo Molnar
 *  (C) Copyright 2006 Red Hat Inc, All Rights Reserved
 *  Thanks to Thomas Gleixner for suggestions, analysis and fixes.
 *
 *  PI-futex support started by Ingo Molnar and Thomas Gleixner
 *  Copyright (C) 2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *  Copyright (C) 2006 Timesys Corp., Thomas Gleixner <tglx@timesys.com>
 *
 *  PRIVATE futexes by Eric Dumazet
 *  Copyright (C) 2007 Eric Dumazet <dada1@cosmosbay.com>
 *
 *  Thanks to Ben LaHaise for yelling "hashed waitqueues" loudly
 *  enough at me, Linus for the original (flawed) idea, Matthew
 *  Kirkwood for proof-of-concept implementation.
 *
 *  "The futexes are also cursed."
 *  "But they come in a choice of three flavours!"
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <process.h>
#include <futex.h>
#include <hash.h>
#include <aal/lock.h>
#include <list.h>
#include <cls.h>
#include <kmsg.h>

#if 0
#include <lwk/kernel.h>
#include <lwk/task.h>
#include <lwk/aspace.h>
#include <lwk/futex.h>
#include <lwk/hash.h>
#include <lwk/sched.h>

#ifdef __UACCESS__
#include <arch/uaccess.h>
#endif

#endif

void futex_queue_init(struct futex_queue *queue)
{
	aal_mc_spinlock_init(&queue->lock);
	INIT_LIST_HEAD(&queue->futex_list);
}

static int uaddr_is_valid(uint32_t __user *uaddr)
{
#ifdef __UACCESS__
	return access_ok(VERIFY_WRITE, uaddr, sizeof(uint32_t));
#else
	return 1;
#endif
}

static int futex_init(struct futex *futex, uint32_t __user *uaddr,
                      uint32_t bitset)
{
	if (!uaddr_is_valid(uaddr))
		return -EINVAL;

	futex->uaddr = uaddr;
	futex->bitset = bitset;
	waitq_init(&futex->waitq);
	return 0;
}

static struct futex_queue *get_queue(uint32_t __user *uaddr)
{
	uint64_t hash = hash_64((uint64_t)uaddr, FUTEX_HASHBITS);
	return &cpu_local_var(current)->vm->futex_queues[hash];
}

static struct futex_queue *queue_lock(struct futex *futex, int *irqflags)
{
	struct futex_queue *queue = get_queue(futex->uaddr);
	futex->lock_ptr = &queue->lock;
	*irqflags = aal_mc_spinlock_lock(&queue->lock);
	return queue;
}

static void queue_unlock(struct futex_queue *futex_queue, int irqflags)
{
	aal_mc_spinlock_unlock(&futex_queue->lock, irqflags);
}

static void queue_me(struct futex *futex, struct futex_queue *futex_queue)
{
	list_add_tail(&futex->link, &futex_queue->futex_list);
}

static int unqueue_me(struct futex *futex)
{
	aal_spinlock_t *lock_ptr;
	int irqflags;
	int status = 0;

	/* In the common case we don't take the spinlock, which is nice. */
retry:
	lock_ptr = futex->lock_ptr;
	barrier();
	if (lock_ptr != NULL) {
		irqflags = aal_mc_spinlock_lock(lock_ptr);
		/*
		 * q->lock_ptr can change between reading it and
		 * spin_lock(), causing us to take the wrong lock.  This
		 * corrects the race condition.
		 *
		 * Reasoning goes like this: if we have the wrong lock,
		 * q->lock_ptr must have changed (maybe several times)
		 * between reading it and the spin_lock().  It can
		 * change again after the spin_lock() but only if it was
		 * already changed before the spin_lock().  It cannot,
		 * however, change back to the original value.  Therefore
		 * we can detect whether we acquired the correct lock.
		 */
		if (lock_ptr != futex->lock_ptr) {
			aal_mc_spinlock_unlock(lock_ptr, irqflags);
			goto retry;
		}

		//WARN_ON(list_empty(&futex->link));
		list_del(&futex->link);
		aal_mc_spinlock_unlock(lock_ptr, irqflags);
		status = 1;
	}

	return status;
}

static void lock_two_queues(struct futex_queue *queue1, int *irqflags1,
                            struct futex_queue *queue2, int *irqflags2)
{
	if (queue1 < queue2) 
		*irqflags1 = aal_mc_spinlock_lock(&queue1->lock);
	
	*irqflags2 = aal_mc_spinlock_lock(&queue2->lock);
	
	if (queue1 > queue2)
		*irqflags1 = aal_mc_spinlock_lock(&queue1->lock);
}

static void unlock_two_queues(struct futex_queue *queue1, int irqflags1,
                              struct futex_queue *queue2, int irqflags2)
{
	if (queue1 == queue2) {
		aal_mc_spinlock_unlock(&queue2->lock, irqflags2);
	}
	else {
		aal_mc_spinlock_unlock(&queue2->lock, irqflags2);
		aal_mc_spinlock_unlock(&queue1->lock, irqflags1);
	}
}

/** Puts a task to sleep waiting on a futex. */
static int futex_wait(uint32_t __user *uaddr, uint32_t val, 
                      uint64_t timeout, uint32_t bitset)
{
	DECLARE_WAITQ_ENTRY(wait, cpu_local_var(current));
	int status;
	uint32_t uval;
	struct futex futex;
	struct futex_queue *queue;
	int irqflags;
	uint64_t time_remain = 0;

	if (!bitset)
		return -EINVAL;

	/* This verifies that uaddr is sane */
	if ((status = futex_init(&futex, uaddr, bitset)) != 0)
		return status;

	/* Lock the futex queue corresponding to uaddr */
	queue = queue_lock(&futex, &irqflags);

	/* Get the value from user-space. Since we don't have
 	 * paging, the only options are for this to succeed (with no
 	 * page faults) or fail, returning -EFAULT. There is no way
 	 * for us to be put to sleep, so holding the queue's spinlock
 	 * is fine. */
#ifdef __UACCESS__	
	if ((status = get_user(uval, uaddr)) != 0)
		goto error;
#else
	uval = *uaddr;
	status = 0;
#endif

	/* The user-space value must match the value passed in */
	if (uval != val) {
		status = -EWOULDBLOCK;
		goto error;
	}
	
	/* Add ourself to the futex's waitq and go to sleep */
	cpu_local_var(current)->status = PS_INTERRUPTIBLE;
	waitq_add_entry(&futex.waitq, &wait);

	/* Add ourself to the futex queue and drop our lock on it */
	queue_me(&futex, queue);
	queue_unlock(queue, irqflags);
	
	if (!list_empty(&futex.link)) {
		// We don't have timers for now, let's sleep forever,
		// and pretend we were woken up
		//time_remain = schedule_timeout(timeout);
		schedule();
		time_remain = 10;
	}

	cpu_local_var(current)->status = PS_RUNNING;

	/*
 	 * NOTE: We don't remove ourself from the waitq because
 	 *       we are the only user of it.
 	 */
	
	/* If we were woken (and unqueued), we succeeded, whatever. */
	if (!unqueue_me(&futex))
		return 0;

	if (time_remain == 0)
		return -ETIMEDOUT;
		
	/* We expect that there is a signal pending, but another thread
	 * may have handled it for us already. */
	return -EINTR;

error:
	queue_unlock(queue, irqflags);
	return status;
}

/*
 * The futex_queue's lock must be held when this is called.
 * Afterwards, the futex_queue must not be accessed.
 */
static void wake_futex(struct futex *futex)
{
	list_del_init(&futex->link);
	/*
	 * The lock in waitq_wakeup() is a crucial memory barrier after the
	 * list_del_init() and also before assigning to futex->lock_ptr.
	 */
	waitq_wakeup(&futex->waitq);
	/*
	 * The waiting task can free the futex as soon as this is written,
	 * without taking any locks.  This must come last.
	 *
	 * A memory barrier is required here to prevent the following store
	 * to lock_ptr from getting ahead of the wakeup. Clearing the lock
	 * at the end of waitq_wakeup() does not prevent this store from
	 * moving.
	 */
	barrier();
	futex->lock_ptr = NULL;
}

/** Wakes up nr_wake tasks waiting on a futex. */
static int futex_wake(uint32_t __user *uaddr, int nr_wake, uint32_t bitset)
{
	struct futex_queue *queue;
	struct list_head *head;
	struct futex *this, *next;
	int nr_woke = 0;
	int irqflags;

	if (!bitset)
		return -EINVAL;

	if (!uaddr_is_valid(uaddr))
		return -EINVAL;

	queue = get_queue(uaddr);
	irqflags = aal_mc_spinlock_lock(&queue->lock);
	head = &queue->futex_list;

	list_for_each_entry_safe(this, next, head, link) {
		if ((this->uaddr == uaddr) && (this->bitset & bitset)) {
			wake_futex(this);
			if (++nr_woke >= nr_wake)
				break;
		}
	}

	aal_mc_spinlock_unlock(&queue->lock, irqflags);
	return nr_woke;
}

/** Conditionally wakes up tasks that are waiting on futexes. */
static int futex_wake_op(uint32_t __user *uaddr1, uint32_t __user *uaddr2,
                         int nr_wake1, int nr_wake2, int op)
{
	struct futex_queue *queue1, *queue2;
	int irqflags1 = 0;
	int irqflags2 = 0;
	struct list_head *head;
	struct futex *this, *next;
	int op_result, nr_woke1 = 0, nr_woke2 = 0;

	if (!uaddr_is_valid(uaddr1) || !uaddr_is_valid(uaddr2))
		return -EINVAL;

	queue1 = get_queue(uaddr1);
	queue2 = get_queue(uaddr2);
	lock_two_queues(queue1, &irqflags1, queue2, &irqflags2);

	op_result = futex_atomic_op_inuser(op, (int *)uaddr2);
	if (op_result < 0) {
		unlock_two_queues(queue1, irqflags1, queue2, irqflags2);
		return op_result;
	}

	head = &queue1->futex_list;
	list_for_each_entry_safe(this, next, head, link) {
		if (this->uaddr == uaddr1) {
			wake_futex(this);
			if (++nr_woke1 >= nr_wake1)
				break;
		}
	}

	if (op_result > 0) {
		head = &queue2->futex_list;
		list_for_each_entry_safe(this, next, head, link) {
			if (this->uaddr == uaddr2) {
				wake_futex(this);
				if (++nr_woke2 >= nr_wake2)
					break;
			}
		}
	}

	unlock_two_queues(queue1, irqflags1, queue2, irqflags2);
	return nr_woke1 + nr_woke2;
}

/** Conditionally wakes up or requeues tasks that are waiting on futexes. */
static int futex_cmp_requeue(uint32_t __user *uaddr1, uint32_t __user *uaddr2,
                             int nr_wake, int nr_requeue, uint32_t cmpval)
{
	struct futex_queue *queue1, *queue2;
	int irqflags1, irqflags2;
	struct list_head *head1, *head2;
	struct futex *this, *next;
	uint32_t curval;
	int status, nr_woke = 0;

	if (!uaddr_is_valid(uaddr1) || !uaddr_is_valid(uaddr2))
		return -EINVAL;

	queue1 = get_queue(uaddr1);
	queue2 = get_queue(uaddr2);
	lock_two_queues(queue1, &irqflags1, queue2, &irqflags2);

#ifdef __UACCESS__
	if ((status = get_user(curval, uaddr1)) != 0)
		goto out_unlock;
#else
	curval = *uaddr1;
	status = 0;
#endif

	if (curval != cmpval) {
		status = -EAGAIN;
		goto out_unlock;
	}

	head1 = &queue1->futex_list;
	head2 = &queue2->futex_list;
	list_for_each_entry_safe(this, next, head1, link) {
		if (this->uaddr != uaddr1)
			continue;
		if (++nr_woke <= nr_wake) {
			wake_futex(this);
		} else {
			/* If uaddr1 and uaddr2 hash to the
			 * same futex queue, no need to requeue */
			if (head1 != head2) {
				list_move_tail(&this->link, head2);
				this->lock_ptr = &queue2->lock;
			}
			this->uaddr = uaddr2;

			if (nr_woke - nr_wake >= nr_requeue)
				break;
		}
	}
	status = nr_woke;

out_unlock:
	unlock_two_queues(queue1, irqflags1, queue2, irqflags2);
	return status;
}

int futex(uint32_t __user *uaddr, int op, uint32_t val, uint64_t timeout,
          uint32_t __user *uaddr2, uint32_t val2, uint32_t val3)
{
	int status;

	switch (op) {
		case FUTEX_WAIT:
			val3 = FUTEX_BITSET_MATCH_ANY;
		case FUTEX_WAIT_BITSET:
			status = futex_wait(uaddr, val, timeout, val3);
			break;
		case FUTEX_WAKE:
			val3 = FUTEX_BITSET_MATCH_ANY;
		case FUTEX_WAKE_BITSET:
			status = futex_wake(uaddr, val, val3);
			break;
		case FUTEX_WAKE_OP:
			status = futex_wake_op(uaddr, uaddr2, val, val2, val3);
			break;
		case FUTEX_CMP_REQUEUE:
			status = futex_cmp_requeue(uaddr, uaddr2, val, val2, val3);
			break;
		default:
			kprintf("sys_futex() op=%d not supported (pid: )\n",
			        op, &cpu_local_var(current)->pid);

			status = -ENOSYS;
	}

	return status;
}

