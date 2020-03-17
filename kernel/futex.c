/**
 * \file futex.c
 * Licence details are found in the file LICENSE.
 *  
 * \brief
 * Futex adaptation to McKernel
 *
 * \author Balazs Gerofi  <bgerofi@riken.jp> \par
 * Copyright (C) 2012  RIKEN AICS
 *
 *
 * HISTORY:
 *
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
 *  Requeue-PI support by Darren Hart <dvhltc@us.ibm.com>
 *  Copyright (C) IBM Corporation, 2009
 *  Thanks to Thomas Gleixner for conceptual design and careful reviews.
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
#include <jhash.h>
#include <ihk/lock.h>
#include <ihk/atomic.h>
#include <list.h>
#include <plist.h>
#include <cls.h>
#include <kmsg.h>
#include <timer.h>
#include <ihk/debug.h>
#include <syscall.h>

//#define DEBUG_PRINT_FUTEX

#ifdef DEBUG_PRINT_FUTEX
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#define uti_dkprintf(...) do { ((clv_override && linux_printk) ? (*linux_printk) : kprintf)(__VA_ARGS__); } while (0)
#else
#define uti_dkprintf(...) do { } while (0)
#endif
#define uti_kprintf(...) do { ((clv_override && linux_printk) ? (*linux_printk) : kprintf)(__VA_ARGS__); } while (0)


unsigned long ihk_mc_get_ns_per_tsc(void);

/*
 * Hash buckets are shared by all the futex_keys that hash to the same
 * location.  Each key may have multiple futex_q structures, one for each task
 * waiting on a futex.
 */
struct futex_hash_bucket {
	ihk_spinlock_t lock;
	struct plist_head chain;
};

static struct futex_hash_bucket futex_queues[1<<FUTEX_HASHBITS];

/*
 * We hash on the keys returned from get_futex_key (see below).
 */
static struct futex_hash_bucket *hash_futex(union futex_key *key)
{
	uint32_t hash = jhash2((uint32_t*)&key->both.word,
			  (sizeof(key->both.word)+sizeof(key->both.ptr))/4,
			  key->both.offset);
	return &futex_queues[hash & ((1 << FUTEX_HASHBITS)-1)];
}

/*
 * Return 1 if two futex_keys are equal, 0 otherwise.
 */
static inline int match_futex(union futex_key *key1, union futex_key *key2)
{
	return (key1 && key2
		&& key1->both.word == key2->both.word
		&& key1->both.ptr == key2->both.ptr
		&& key1->both.offset == key2->both.offset);
}

/*
 * Take a reference to the resource addressed by a key.
 * Can be called while holding spinlocks.
 *
 */
static void get_futex_key_refs(union futex_key *key)
{
	/* RIKEN: no swapping in McKernel */
	return;
}

/*
 * Drop a reference to the resource addressed by a key.
 * The hash bucket spinlock must not be held.
 */
static void drop_futex_key_refs(union futex_key *key)
{
	/* RIKEN: no swapping in McKernel */
	return;
}
/**
 * get_futex_key() - Get parameters which are the keys for a futex
 * @uaddr:	virtual address of the futex
 * @fshared:	0 for a PROCESS_PRIVATE futex, 1 for PROCESS_SHARED
 * @key:	address where result is stored.
 *
 * Returns a negative error code or 0
 * The key words are stored in *key on success.
 *
 * For shared mappings, it's (page->index, vma->vm_file->f_path.dentry->d_inode,
 * offset_within_page).  For private mappings, it's (uaddr, current->mm).
 * We can usually work out the index without swapping in the page.
 *
 * lock_page() might sleep, the caller should not hold a spinlock.
 */
static int
get_futex_key(uint32_t *uaddr, int fshared, union futex_key *key, struct cpu_local_var *clv_override)
{
	unsigned long address = (unsigned long)uaddr;
	unsigned long phys;
	struct thread *thread = cpu_local_var_with_override(current, clv_override);
	struct process_vm *mm = thread->vm;

	/*
	 * The futex address must be "naturally" aligned.
	 */
	key->both.offset = address % PAGE_SIZE;
	if (((address % sizeof(uint32_t)) != 0))
		return -EINVAL;
	address -= key->both.offset;

	/*
	 * PROCESS_PRIVATE futexes are fast.
	 * As the mm cannot disappear under us and the 'key' only needs
	 * virtual address, we dont even have to find the underlying vma.
	 * Note : We do have to check 'uaddr' is a valid user address,
	 *        but access_ok() should be faster than find_vma()
	 */
	if (!fshared) {
		key->private.mm = mm;
		key->private.address = address;
		get_futex_key_refs(key);
		return 0;
	}

	key->both.offset |= FUT_OFF_MMSHARED;

retry_v2p:
	/* Just use physical address of page, McKernel does not do swapping */
	if (ihk_mc_pt_virt_to_phys(mm->address_space->page_table, 
				(void *)uaddr, &phys)) { 

		/* Check if we can fault in page */
		if (page_fault_process_vm(mm, uaddr, PF_POPULATE | PF_WRITE | PF_USER)) {
			kprintf("error: get_futex_key() virt to phys translation failed\n");
			return -EFAULT;
		}

		goto retry_v2p;
	}
	key->shared.phys = (void *)phys;
	key->shared.pgoff = 0;

	return 0;
}


static inline
void put_futex_key(int fshared, union futex_key *key)
{
	drop_futex_key_refs(key);
}

static int cmpxchg_futex_value_locked(uint32_t __user *uaddr, uint32_t uval, uint32_t newval)
{
	int curval;

	/* RIKEN: futexes are on not swappable memory */
	curval = futex_atomic_cmpxchg_inatomic((int*)uaddr, (int)uval, (int)newval);

	return curval;
}

/*
 * The hash bucket lock must be held when this is called.
 * Afterwards, the futex_q must not be accessed.
 */
static void wake_futex(struct futex_q *q, struct cpu_local_var *clv_override)
{
	struct thread *p = q->task;

	/*
	 * We set q->lock_ptr = NULL _before_ we wake up the task. If
	 * a non futex wake up happens on another CPU then the task
	 * might exit and p would dereference a non existing task
	 * struct. Prevent this by holding a reference on p across the
	 * wake up.
	 */

	plist_del(&q->list, &q->list.plist);
	/*
	 * The waiting task can free the futex_q as soon as
	 * q->lock_ptr = NULL is written, without taking any locks. A
	 * memory barrier is required here to prevent the following
	 * store to lock_ptr from getting ahead of the plist_del.
	 */
	barrier();
	q->lock_ptr = NULL;


	if (q->uti_futex_resp) { 
		int rc;
		uti_dkprintf("wake_futex(): waking up migrated-to-Linux thread (tid %d),uti_futex_resp=%p\n", p->tid, q->uti_futex_resp);
		/* TODO: Add the case when a Linux thread waking up another Linux thread */
		if (clv_override) {
			uti_dkprintf("%s: ERROR: A Linux thread is waking up migrated-to-Linux thread\n", __FUNCTION__);
		}
		if (p->spin_sleep == 0) {
			uti_dkprintf("%s: INFO: woken up by someone else\n", __FUNCTION__);
		}

		struct ikc_scd_packet pckt;
		struct ihk_ikc_channel_desc *resp_channel = cpu_local_var_with_override(ikc2linux, clv_override);
		pckt.msg = SCD_MSG_FUTEX_WAKE;
		pckt.futex.resp = q->uti_futex_resp;
		pckt.futex.spin_sleep = &p->spin_sleep;
		rc = ihk_ikc_send(resp_channel, &pckt, 0);
		if (rc) {
			uti_dkprintf("%s: ERROR: ihk_ikc_send returned %d, resp_channel=%p\n", __FUNCTION__, rc, resp_channel);
		}
	} else {
		uti_dkprintf("wake_futex(): waking up McKernel thread (tid %d)\n", p->tid);
		sched_wakeup_thread(p, PS_NORMAL);
	}
}

/*
 * Express the locking dependencies for lockdep:
 */
static inline void
double_lock_hb(struct futex_hash_bucket *hb1, struct futex_hash_bucket *hb2)
{
	if (hb1 <= hb2) {
		ihk_mc_spinlock_lock_noirq(&hb1->lock);
		if (hb1 < hb2)
			ihk_mc_spinlock_lock_noirq(&hb2->lock);
	} else { /* hb1 > hb2 */
		ihk_mc_spinlock_lock_noirq(&hb2->lock);
		ihk_mc_spinlock_lock_noirq(&hb1->lock);
	}
}

static inline void
double_unlock_hb(struct futex_hash_bucket *hb1, struct futex_hash_bucket *hb2)
{
	ihk_mc_spinlock_unlock_noirq(&hb1->lock);
	if (hb1 != hb2)
		ihk_mc_spinlock_unlock_noirq(&hb2->lock);
}

/*
 * Wake up waiters matching bitset queued on this futex (uaddr).
 */
static int futex_wake(uint32_t *uaddr, int fshared, int nr_wake, uint32_t bitset, struct cpu_local_var *clv_override)
{
	struct futex_hash_bucket *hb;
	struct futex_q *this, *next;
	struct plist_head *head;
	union futex_key key = FUTEX_KEY_INIT;
	int ret;
	unsigned long irqstate;

	if (!bitset)
		return -EINVAL;

	ret = get_futex_key(uaddr, fshared, &key, clv_override);
	if ((ret != 0))
		goto out;

	hb = hash_futex(&key);
	irqstate = ihk_mc_spinlock_lock(&hb->lock);
	head = &hb->chain;

	plist_for_each_entry_safe(this, next, head, list) {
		if (match_futex (&this->key, &key)) {
			
			/* RIKEN: no pi state... */
			/* Check if one of the bits is set in both bitsets */
			if (!(this->bitset & bitset))
				continue;

			wake_futex(this, clv_override);
			if (++ret >= nr_wake)
				break;
		}
	}

	ihk_mc_spinlock_unlock(&hb->lock, irqstate);
	put_futex_key(fshared, &key);
out:
	return ret;
}

/*
 * Wake up all waiters hashed on the physical page that is mapped
 * to this virtual address:
 */
static int
futex_wake_op(uint32_t *uaddr1, int fshared, uint32_t *uaddr2,
			  int nr_wake, int nr_wake2, int op,
			  struct cpu_local_var *clv_override)
{
	union futex_key key1 = FUTEX_KEY_INIT, key2 = FUTEX_KEY_INIT;
	struct futex_hash_bucket *hb1, *hb2;
	struct plist_head *head;
	struct futex_q *this, *next;
	int ret, op_ret;

retry:
	ret = get_futex_key(uaddr1, fshared, &key1, clv_override);
	if ((ret != 0))
		goto out;
	ret = get_futex_key(uaddr2, fshared, &key2, clv_override);
	if ((ret != 0))
		goto out_put_key1;

	hb1 = hash_futex(&key1);
	hb2 = hash_futex(&key2);

retry_private:
	double_lock_hb(hb1, hb2);
	op_ret = futex_atomic_op_inuser(op, (int*)uaddr2);
	if ((op_ret < 0)) {

		double_unlock_hb(hb1, hb2);

		if ((op_ret != -EFAULT)) {
			ret = op_ret;
			goto out_put_keys;
		}

		/* RIKEN: set ret to 0 as if fault_in_user_writeable() returned it */
		ret = 0;

		if (!fshared)
			goto retry_private;

		put_futex_key(fshared, &key2);
		put_futex_key(fshared, &key1);
		goto retry;
	}

	head = &hb1->chain;

	plist_for_each_entry_safe(this, next, head, list) {
		if (match_futex (&this->key, &key1)) {
			wake_futex(this, clv_override);
			if (++ret >= nr_wake)
				break;
		}
	}

	if (op_ret > 0) {
		head = &hb2->chain;

		op_ret = 0;
		plist_for_each_entry_safe(this, next, head, list) {
			if (match_futex (&this->key, &key2)) {
				wake_futex(this, clv_override);
				if (++op_ret >= nr_wake2)
					break;
			}
		}
		ret += op_ret;
	}

	double_unlock_hb(hb1, hb2);
out_put_keys:
	put_futex_key(fshared, &key2);
out_put_key1:
	put_futex_key(fshared, &key1);
out:
	return ret;
}

/**
 * requeue_futex() - Requeue a futex_q from one hb to another
 * @q:		the futex_q to requeue
 * @hb1:	the source hash_bucket
 * @hb2:	the target hash_bucket
 * @key2:	the new key for the requeued futex_q
 */
static inline
void requeue_futex(struct futex_q *q, struct futex_hash_bucket *hb1,
		   struct futex_hash_bucket *hb2, union futex_key *key2)
{

	/*
	 * If key1 and key2 hash to the same bucket, no need to
	 * requeue.
	 */
	if ((&hb1->chain != &hb2->chain)) {
		plist_del(&q->list, &hb1->chain);
		plist_add(&q->list, &hb2->chain);
		q->lock_ptr = &hb2->lock;
#ifdef CONFIG_DEBUG_PI_LIST
		q->list.plist.spinlock = &hb2->lock;
#endif
	}
	get_futex_key_refs(key2);
	q->key = *key2;
}

/**
 * futex_requeue() - Requeue waiters from uaddr1 to uaddr2
 * uaddr1:	source futex user address
 * uaddr2:	target futex user address
 * nr_wake:	number of waiters to wake (must be 1 for requeue_pi)
 * nr_requeue:	number of waiters to requeue (0-INT_MAX)
 * requeue_pi:	if we are attempting to requeue from a non-pi futex to a
 * 		pi futex (pi to pi requeue is not supported)
 *
 * Requeue waiters on uaddr1 to uaddr2. In the requeue_pi case, try to acquire
 * uaddr2 atomically on behalf of the top waiter.
 *
 * Returns:
 * >=0 - on success, the number of tasks requeued or woken
 *  <0 - on error
 */
static int futex_requeue(uint32_t *uaddr1, int fshared, uint32_t *uaddr2,
			 int nr_wake, int nr_requeue, uint32_t *cmpval,
						 int requeue_pi, struct cpu_local_var *clv_override)
{
	union futex_key key1 = FUTEX_KEY_INIT, key2 = FUTEX_KEY_INIT;
	int drop_count = 0, task_count = 0, ret;
	struct futex_hash_bucket *hb1, *hb2;
	struct plist_head *head1;
	struct futex_q *this, *next;

	ret = get_futex_key(uaddr1, fshared, &key1, clv_override);
	if ((ret != 0))
		goto out;
	ret = get_futex_key(uaddr2, fshared, &key2, clv_override);
	if ((ret != 0))
		goto out_put_key1;

	hb1 = hash_futex(&key1);
	hb2 = hash_futex(&key2);

	double_lock_hb(hb1, hb2);

	if ((cmpval != NULL)) {
		uint32_t curval;

		ret = get_futex_value_locked(&curval, uaddr1);

		if (curval != *cmpval) {
			ret = -EAGAIN;
			goto out_unlock;
		}
	}

	head1 = &hb1->chain;
	plist_for_each_entry_safe(this, next, head1, list) {
		if (task_count - nr_wake >= nr_requeue)
			break;

		if (!match_futex(&this->key, &key1))
			continue;

		/*
		 * Wake nr_wake waiters.  For requeue_pi, if we acquired the
		 * lock, we already woke the top_waiter.  If not, it will be
		 * woken by futex_unlock_pi().
		 */
		/* RIKEN: no requeue_pi at this moment */
		if (++task_count <= nr_wake) {
			wake_futex(this, clv_override);
			continue;
		}

		requeue_futex(this, hb1, hb2, &key2);
		drop_count++;
	}

out_unlock:
	double_unlock_hb(hb1, hb2);

	/*
	 * drop_futex_key_refs() must be called outside the spinlocks. During
	 * the requeue we moved futex_q's from the hash bucket at key1 to the
	 * one at key2 and updated their key pointer.  We no longer need to
	 * hold the references to key1.
	 */
	while (--drop_count >= 0)
		drop_futex_key_refs(&key1);

	put_futex_key(fshared, &key2);
out_put_key1:
	put_futex_key(fshared, &key1);
out:
	return ret ? ret : task_count;
}

/* The key must be already stored in q->key. */
static inline struct futex_hash_bucket *queue_lock(struct futex_q *q)
{
	struct futex_hash_bucket *hb;

	get_futex_key_refs(&q->key);
	hb = hash_futex(&q->key);
	q->lock_ptr = &hb->lock;

	ihk_mc_spinlock_lock_noirq(&hb->lock);
	return hb;
}

static inline void
queue_unlock(struct futex_q *q, struct futex_hash_bucket *hb)
{
	ihk_mc_spinlock_unlock_noirq(&hb->lock);
	drop_futex_key_refs(&q->key);
}

/**
 * queue_me() - Enqueue the futex_q on the futex_hash_bucket
 * @q:	The futex_q to enqueue
 * @hb:	The destination hash bucket
 *
 * The hb->lock must be held by the caller, and is released here. A call to
 * queue_me() is typically paired with exactly one call to unqueue_me().  The
 * exceptions involve the PI related operations, which may use unqueue_me_pi()
 * or nothing if the unqueue is done as part of the wake process and the unqueue
 * state is implicit in the state of woken task (see futex_wait_requeue_pi() for
 * an example).
 */
static inline void queue_me(struct futex_q *q, struct futex_hash_bucket *hb, struct cpu_local_var *clv_override)
{
	int prio;

	/*
	 * The priority used to register this element is
	 * - either the real thread-priority for the real-time threads
	 * (i.e. threads with a priority lower than MAX_RT_PRIO)
	 * - or MAX_RT_PRIO for non-RT threads.
	 * Thus, all RT-threads are woken first in priority order, and
	 * the others are woken last, in FIFO order.
	 *
	 * RIKEN: no priorities at the moment, everyone is 10.
	 */
	prio = 10; 

	plist_node_init(&q->list, prio);
#ifdef CONFIG_DEBUG_PI_LIST
	q->list.plist.spinlock = &hb->lock;
#endif
	plist_add(&q->list, &hb->chain);
	q->task = cpu_local_var_with_override(current, clv_override);
	ihk_mc_spinlock_unlock_noirq(&hb->lock);
}

/**
 * unqueue_me() - Remove the futex_q from its futex_hash_bucket
 * @q:	The futex_q to unqueue
 *
 * The q->lock_ptr must not be held by the caller. A call to unqueue_me() must
 * be paired with exactly one earlier call to queue_me().
 *
 * Returns:
 *   1 - if the futex_q was still queued (and we removed unqueued it)
 *   0 - if the futex_q was already removed by the waking thread
 */
static int unqueue_me(struct futex_q *q)
{
	ihk_spinlock_t *lock_ptr;
	int ret = 0;

	/* In the common case we don't take the spinlock, which is nice. */
retry:
	lock_ptr = q->lock_ptr;
	barrier();
	if (lock_ptr != NULL) {
		ihk_mc_spinlock_lock_noirq(lock_ptr);
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
		if (lock_ptr != q->lock_ptr) {
			ihk_mc_spinlock_unlock_noirq(lock_ptr);
			goto retry;
		}
		plist_del(&q->list, &q->list.plist);

		ihk_mc_spinlock_unlock_noirq(lock_ptr);
		ret = 1;
	}

	drop_futex_key_refs(&q->key);
	return ret;
}

/**
 * futex_wait_queue_me() - queue_me() and wait for wakeup, timeout, or signal
 * @hb:		the futex hash bucket, must be locked by the caller
 * @q:		the futex_q to queue up on
 * @timeout:	the prepared hrtimer_sleeper, or null for no timeout
 */

/* RIKEN: this function has been rewritten so that it returns the remaining
 * time in case we are waken.
 */
static int64_t futex_wait_queue_me(struct futex_hash_bucket *hb, struct futex_q *q,
				   uint64_t timeout, struct cpu_local_var *clv_override)
{
	int64_t time_remain = 0;
	unsigned long irqstate;
	struct thread *thread = cpu_local_var_with_override(current, clv_override);
	/*
	 * The task state is guaranteed to be set before another task can
	 * wake it. 
	 * queue_me() calls spin_unlock() upon completion, serializing
	 * access to the hash list and forcing a memory barrier.
	 */
	xchg4(&(thread->status), PS_INTERRUPTIBLE);

	/* Indicate spin sleep. Note that schedule_timeout() with
	 * idle_halt should use spin sleep because sleep with timeout
	 * is not implemented.
	 */
	if (!idle_halt || timeout) {
		irqstate = ihk_mc_spinlock_lock(&thread->spin_sleep_lock);
		thread->spin_sleep = 1;
		ihk_mc_spinlock_unlock(&thread->spin_sleep_lock, irqstate);
	}

	queue_me(q, hb, clv_override);
	
	if (!plist_node_empty(&q->list)) {
		if (clv_override) {
			uti_dkprintf("%s: tid: %d is trying to sleep\n", __FUNCTION__, thread->tid);
			/* Note that the unit of timeout is nsec */
			time_remain = (*linux_wait_event)(q->uti_futex_resp, timeout);
			
			/* Note that time_remain == 0 indicates contidion evaluated to false after the timeout elapsed */
			if (time_remain < 0) {
				if (time_remain == -ERESTARTSYS) { /* Interrupted by signal */
					uti_dkprintf("%s: DEBUG: wait_event returned -ERESTARTSYS\n", __FUNCTION__);
				} else {
					uti_kprintf("%s: ERROR: wait_event returned %d\n", __FUNCTION__, time_remain);
				}
			}
			uti_dkprintf("%s: tid: %d woken up\n", __FUNCTION__, thread->tid);
		} else {
		
		if (timeout) {
			dkprintf("futex_wait_queue_me(): tid: %d schedule_timeout()\n", thread->tid);
			time_remain = schedule_timeout(timeout);
		}
		else {
			dkprintf("futex_wait_queue_me(): tid: %d schedule()\n", thread->tid);
			spin_sleep_or_schedule();
			time_remain = 0;
		}
		dkprintf("futex_wait_queue_me(): tid: %d woken up\n", thread->tid);
		}
	}
	
	/* This does not need to be serialized */
	thread->status = PS_RUNNING;
	thread->spin_sleep = 0;
	
	return time_remain;
}

/**
 * futex_wait_setup() - Prepare to wait on a futex
 * @uaddr:	the futex userspace address
 * @val:	the expected value
 * @fshared:	whether the futex is shared (1) or not (0)
 * @q:		the associated futex_q
 * @hb:		storage for hash_bucket pointer to be returned to caller
 *
 * Setup the futex_q and locate the hash_bucket.  Get the futex value and
 * compare it with the expected value.  Handle atomic faults internally.
 * Return with the hb lock held and a q.key reference on success, and unlocked
 * with no q.key reference on failure.
 *
 * Returns:
 *  0 - uaddr contains val and hb has been locked
 * <1 - -EFAULT or -EWOULDBLOCK (uaddr does not contain val) and hb is unlcoked
 */
static int futex_wait_setup(uint32_t __user *uaddr, uint32_t val, int fshared,
			    struct futex_q *q, struct futex_hash_bucket **hb,
			    struct cpu_local_var *clv_override)
{
	uint32_t uval;
	int ret;

	/*
	 * Access the page AFTER the hash-bucket is locked.
	 * Order is important:
	 *
	 *   Userspace waiter: val = var; if (cond(val)) futex_wait(&var, val);
	 *   Userspace waker:  if (cond(var)) { var = new; futex_wake(&var); }
	 *
	 * The basic logical guarantee of a futex is that it blocks ONLY
	 * if cond(var) is known to be true at the time of blocking, for
	 * any cond.  If we queued after testing *uaddr, that would open
	 * a race condition where we could block indefinitely with
	 * cond(var) false, which would violate the guarantee.
	 *
	 * A consequence is that futex_wait() can return zero and absorb
	 * a wakeup when *uaddr != val on entry to the syscall.  This is
	 * rare, but normal.
	 */
	q->key = FUTEX_KEY_INIT;
	ret = get_futex_key(uaddr, fshared, &q->key, clv_override);
	if (ret != 0)
		return ret;

	*hb = queue_lock(q);

	ret = get_futex_value_locked(&uval, uaddr);
	if (ret) {
		queue_unlock(q, *hb);
		put_futex_key(fshared, &q->key);
		return ret;
	}

	if (uval != val) {
		queue_unlock(q, *hb);
		ret = -EWOULDBLOCK;
	}

	if (ret)
		put_futex_key(fshared, &q->key);
	return ret;
}

static int futex_wait(uint32_t __user *uaddr, int fshared,
		      uint32_t val, uint64_t timeout, uint32_t bitset, int clockrt,
		      struct cpu_local_var *clv_override)
{
	struct futex_hash_bucket *hb;
	int64_t time_remain;
	struct futex_q lq;
	struct futex_q *q = NULL;
	int ret;

	if (!bitset)
		return -EINVAL;

	if (!clv_override) {
		q = &lq;
	}
	else {
		q = &cpu_local_var_with_override(current,
						 clv_override)->futex_q;
	}

#ifdef PROFILE_ENABLE
	if (cpu_local_var_with_override(current, clv_override)->profile &&
		cpu_local_var_with_override(current, clv_override)->profile_start_ts) {
		cpu_local_var_with_override(current, clv_override)->profile_elapsed_ts +=
			(rdtsc() - cpu_local_var_with_override(current, clv_override)->profile_start_ts);
		cpu_local_var_with_override(current, clv_override)->profile_start_ts = 0;
	}
#endif

	q->bitset = bitset;
	q->requeue_pi_key = NULL;
	q->uti_futex_resp = cpu_local_var_with_override(uti_futex_resp,
							clv_override);

retry:
	/* Prepare to wait on uaddr. */
	ret = futex_wait_setup(uaddr, val, fshared, q, &hb, clv_override);
	if (ret) {
		uti_dkprintf("%s: tid=%d futex_wait_setup returns zero, no need to sleep\n", __FUNCTION__, cpu_local_var_with_override(current, clv_override)->tid);
		goto out;
	}

	/* queue_me and wait for wakeup, timeout, or a signal. */
	time_remain = futex_wait_queue_me(hb, q, timeout, clv_override);

	/* If we were woken (and unqueued), we succeeded, whatever. */
	ret = 0;
	if (!unqueue_me(q)) {
		uti_dkprintf("%s: tid=%d unqueued\n", __FUNCTION__, cpu_local_var_with_override(current, clv_override)->tid);
		goto out_put_key;
	}
	ret = -ETIMEDOUT;

	/* RIKEN: timer expired case (indicated by !time_remain) */
	if (timeout && !time_remain) {
		uti_dkprintf("%s: tid=%d timer expired\n", __FUNCTION__, cpu_local_var_with_override(current, clv_override)->tid);
		goto out_put_key;
	}

	/* RIKEN: futex_wait_queue_me() returns -ERESTARTSYS when waiting on Linux CPU and woken up by signal */
	if (hassigpending(cpu_local_var_with_override(current, clv_override)) || time_remain == -ERESTARTSYS) {
		ret = -EINTR;
		uti_dkprintf("%s: tid=%d woken up by signal\n", __FUNCTION__, cpu_local_var_with_override(current, clv_override)->tid);
		goto out_put_key;
	}

	/* RIKEN: no signals */
	put_futex_key(fshared, &q->key);
	goto retry;

out_put_key:
	put_futex_key(fshared, &q->key);
out:
#ifdef PROFILE_ENABLE
	if (cpu_local_var_with_override(current, clv_override)->profile) {
		cpu_local_var_with_override(current, clv_override)->profile_start_ts = rdtsc();
	}
#endif
	return ret;
}

int futex(uint32_t *uaddr, int op, uint32_t val, uint64_t timeout,
	  uint32_t *uaddr2, uint32_t val2, uint32_t val3, int fshared,
	  struct cpu_local_var *clv_override)
{
	int clockrt, ret = -ENOSYS;
	int cmd = op & FUTEX_CMD_MASK;

	uti_dkprintf("%s: uaddr=%p, op=%x, val=%x, timeout=%ld, uaddr2=%p, val2=%x, val3=%x, fshared=%d, clv=%p\n", __FUNCTION__, uaddr, op, val, timeout, uaddr2, val2, val3, fshared, clv_override);

	clockrt = op & FUTEX_CLOCK_REALTIME;
	if (clockrt && cmd != FUTEX_WAIT_BITSET && cmd != FUTEX_WAIT_REQUEUE_PI)
		return -ENOSYS;

	switch (cmd) {
	case FUTEX_WAIT:
		val3 = FUTEX_BITSET_MATCH_ANY;
	case FUTEX_WAIT_BITSET:
		ret = futex_wait(uaddr, fshared, val, timeout, val3, clockrt, clv_override);
		break;
	case FUTEX_WAKE:
		val3 = FUTEX_BITSET_MATCH_ANY;
	case FUTEX_WAKE_BITSET:
		ret = futex_wake(uaddr, fshared, val, val3, clv_override);
		break;
	case FUTEX_REQUEUE:
		ret = futex_requeue(uaddr, fshared, uaddr2, val, val2, NULL, 0, clv_override);
		break;
	case FUTEX_CMP_REQUEUE:
		ret = futex_requeue(uaddr, fshared, uaddr2, val, val2, &val3, 0, clv_override);
		break;
	case FUTEX_WAKE_OP:
		ret = futex_wake_op(uaddr, fshared, uaddr2, val, val2, val3, clv_override);
		break;
	/* RIKEN: these calls are not supported for now.	
	case FUTEX_LOCK_PI:
		if (futex_cmpxchg_enabled)
			ret = futex_lock_pi(uaddr, fshared, val, timeout, 0);
		break;
	case FUTEX_UNLOCK_PI:
		if (futex_cmpxchg_enabled)
			ret = futex_unlock_pi(uaddr, fshared);
		break;
	case FUTEX_TRYLOCK_PI:
		if (futex_cmpxchg_enabled)
			ret = futex_lock_pi(uaddr, fshared, 0, timeout, 1);
		break;
	case FUTEX_WAIT_REQUEUE_PI:
		val3 = FUTEX_BITSET_MATCH_ANY;
		ret = futex_wait_requeue_pi(uaddr, fshared, val, timeout, val3,
					    clockrt, uaddr2);
		break;
	case FUTEX_CMP_REQUEUE_PI:
		ret = futex_requeue(uaddr, fshared, uaddr2, val, val2, &val3,
				    1);
		break;
	*/
	default:
		kprintf("futex() invalid cmd: %d \n", cmd); 
		ret = -ENOSYS;
	}
	return ret;
}

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

int futex_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(futex_queues); i++) {
		plist_head_init(&futex_queues[i].chain, &futex_queues[i].lock);
		ihk_mc_spinlock_init(&futex_queues[i].lock);
	}

	return 0;
}

