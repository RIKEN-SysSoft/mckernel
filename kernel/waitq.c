/**
 * \file waitq.c
 * Licence details are found in the file LICENSE.
 *  
 * \brief
 * Waitqueue adaptation from Sandia's Kitten OS 
 * (originally taken from Linux)
 *
 * \author Balazs Gerofi  <bgerofi@riken.jp> \par
 * Copyright (C) 2012  RIKEN AICS
 *
 */

#include <waitq.h>
#include <process.h>
#include <cls.h>

int
default_wake_function(waitq_entry_t *entry, unsigned mode,
					  int flags, void *key)
{
	return sched_wakeup_thread(entry->private, PS_NORMAL);
}

int
locked_wake_function(waitq_entry_t *entry, unsigned mode,
					  int flags, void *key)
{
	return sched_wakeup_thread_locked(entry->private, PS_NORMAL);
}

void
waitq_init(waitq_t *waitq)
{
	ihk_mc_spinlock_init(&waitq->lock);
	INIT_LIST_HEAD(&waitq->waitq);
}

void
waitq_init_entry(waitq_entry_t *entry, struct thread *proc)
{
	entry->private = proc;
	entry->func = default_wake_function;
	INIT_LIST_HEAD(&entry->link);
}

int
waitq_active(waitq_t *waitq)
{
	int active;

	ihk_mc_spinlock_lock_noirq(&waitq->lock);
	active = !list_empty(&waitq->waitq);
	ihk_mc_spinlock_unlock_noirq(&waitq->lock);

	return active;
}

void
waitq_add_entry(waitq_t *waitq, waitq_entry_t *entry)
{
	ihk_mc_spinlock_lock_noirq(&waitq->lock);
	waitq_add_entry_locked(waitq, entry);
	ihk_mc_spinlock_unlock_noirq(&waitq->lock);
}


void
waitq_add_entry_locked(waitq_t *waitq, waitq_entry_t *entry)
{
	//BUG_ON(!list_empty(&entry->link));
	list_add_tail(&entry->link, &waitq->waitq);
}


void
waitq_remove_entry(waitq_t *waitq, waitq_entry_t *entry)
{
	ihk_mc_spinlock_lock_noirq(&waitq->lock);
	waitq_remove_entry_locked(waitq, entry);
	ihk_mc_spinlock_unlock_noirq(&waitq->lock);
}


void
waitq_remove_entry_locked(waitq_t *waitq, waitq_entry_t *entry)
{
	//BUG_ON(list_empty(&entry->link));
	list_del_init(&entry->link);
}


void
waitq_prepare_to_wait(waitq_t *waitq, waitq_entry_t *entry, int state)
{
	ihk_mc_spinlock_lock_noirq(&waitq->lock);
	if (list_empty(&entry->link))
		list_add(&entry->link, &waitq->waitq);
	cpu_local_var(current)->status = state;
	ihk_mc_spinlock_unlock_noirq(&waitq->lock);
}

void
waitq_finish_wait(waitq_t *waitq, waitq_entry_t *entry)
{
	cpu_local_var(current)->status = PS_RUNNING;
	waitq_remove_entry(waitq, entry);
}

void
waitq_wakeup(waitq_t *waitq)
{
	struct list_head *tmp;
	waitq_entry_t *entry;
	
	ihk_mc_spinlock_lock_noirq(&waitq->lock);
	list_for_each(tmp, &waitq->waitq) {
		entry = list_entry(tmp, waitq_entry_t, link);
		entry->func(entry, 0, 0, NULL);
	}
	ihk_mc_spinlock_unlock_noirq(&waitq->lock);
}


int
waitq_wake_nr(waitq_t * waitq, int nr)
{
	ihk_mc_spinlock_lock_noirq(&waitq->lock);
	int count = waitq_wake_nr_locked(waitq, nr);
	ihk_mc_spinlock_unlock_noirq(&waitq->lock);

	if (count > 0)
		schedule();
	
	return count;
}


int
waitq_wake_nr_locked( waitq_t * waitq, int nr )
{
	int count = 0;
	waitq_entry_t *entry;

	list_for_each_entry(entry, &waitq->waitq, link) {
		if (++count > nr)
			break;
		
		entry->func(entry, 0, 0, NULL);
	}

	return count - 1;
}

