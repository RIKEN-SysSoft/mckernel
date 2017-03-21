/**
 * \file waitq.h
 * License details are found in the file LICENSE.
 *  
 * \brief
 * Waitqueue adaptation from Sandia's Kitten OS 
 * (originally taken from Linux)
 *
 * \author Balazs Gerofi  <bgerofi@riken.jp> \par
 * Copyright (C) 2012  RIKEN AICS
 *
 */

#ifndef _LWK_WAITQ_H
#define _LWK_WAITQ_H

/* Kitten waitqueue adaptation */

#include <ihk/lock.h>
#include <list.h>

struct thread;
struct waitq_entry;

typedef int (*waitq_func_t)(struct waitq_entry *wait, unsigned mode,
							int flags, void *key);

int default_wake_function(struct waitq_entry *wait, unsigned mode, int flags,
			              void *key);
int locked_wake_function(struct waitq_entry *wait, unsigned mode, int flags,
			              void *key);

typedef struct waitq {
	ihk_spinlock_t lock;
	struct list_head waitq;
} waitq_t;

#define WQ_FLAG_EXCLUSIVE       0x01

typedef struct waitq_entry {
	struct list_head link;
	void *private;
	unsigned int flags;
	waitq_func_t func;
} waitq_entry_t;

#define DECLARE_WAITQ(name)                             \
	waitq_t name = __WAITQ_INITIALIZER(name);

#define __WAITQ_INITIALIZER(name) {			\
	    .lock  = SPIN_LOCK_UNLOCKED,                \
	    .waitq = { &(name).waitq, &(name).waitq }   \
	}

#define DECLARE_WAITQ_ENTRY(name, tsk)                  \
	waitq_entry_t name = {								\
	    .private  = tsk,								\
		.func = default_wake_function,					\
	    .link  = { &(name).link, &(name).link }			\
	}

#define DECLARE_WAITQ_ENTRY_LOCKED(name, tsk)           \
	waitq_entry_t name = {								\
	    .private  = tsk,								\
		.func = locked_wake_function,					\
	    .link  = { &(name).link, &(name).link }			\
	}

extern void waitq_init(waitq_t *waitq);
extern void waitq_init_entry(waitq_entry_t *entry, struct thread *proc);
extern int waitq_active(waitq_t *waitq);
extern void waitq_add_entry(waitq_t *waitq, waitq_entry_t *entry);
extern void waitq_add_entry_locked(waitq_t *waitq, waitq_entry_t *entry);
extern void waitq_prepare_to_wait(waitq_t *waitq, 
                                  waitq_entry_t *entry, int state);
extern void waitq_finish_wait(waitq_t *waitq, waitq_entry_t *entry);
extern void waitq_wakeup(waitq_t *waitq);
extern int waitq_wake_nr(waitq_t *waitq, int nr);
extern int waitq_wake_nr_locked(waitq_t *waitq, int nr);
extern void waitq_remove_entry(waitq_t *waitq, waitq_entry_t *entry);
extern void waitq_remove_entry_locked(waitq_t *waitq, waitq_entry_t *entry);

#define __wait_event(waitq, condition)                                \
do {                                                                  \
	DECLARE_WAITQ_ENTRY(__entry, current);                        \
	for (;;) {                                                    \
		waitq_prepare_to_wait(&waitq, &__entry,               \
				      TASK_UNINTERRUPTIBLE);          \
		if (condition)                                        \
			break;                                        \
		schedule();                                           \
	}                                                             \
	waitq_finish_wait(&waitq, &__entry);                          \
} while (0)

/**
 * wait_event - sleep until a condition becomes true
 * @waitq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @waitq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 */
#define wait_event(waitq, condition)                                  \
do {                                                                  \
	if (condition)                                                \
		break;                                                \
	__wait_event(waitq, condition);                               \
} while (0)

#define __wait_event_interruptible(waitq, condition, ret)             \
do {                                                                  \
	DECLARE_WAITQ_ENTRY(__entry, current);                        \
	for (;;) {                                                    \
		waitq_prepare_to_wait(&waitq, &__entry,               \
				      TASK_INTERRUPTIBLE);            \
		if (condition)                                        \
			break;                                        \
		if (1 /* TODO: !signal_pending(current) */) {         \
			schedule();                                   \
			continue;                                     \
		}                                                     \
		ret = -ERESTARTSYS;                                   \
		break;                                                \
	}                                                             \
	waitq_finish_wait(&waitq, &__entry);                          \
} while (0)

/**
 * wait_event_interruptible - sleep until a condition becomes true
 * @waitq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 *
 * The process is put to sleep (TASK_INTERRUPTIBLE) until the
 * @condition evaluates to true or a signal is received. The
 * @condition is checked each time the waitqueue @waitq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function will return -ERESTARTSYS if it was interrupted by a
 * signal and 0 if @condition evaluated to true.
 */
#define wait_event_interruptible(waitq, condition)                   \
({                                                                   \
	int __ret = 0;                                               \
	if (!(condition))                                            \
		__wait_event_interruptible(waitq, condition, __ret); \
	__ret;                                                       \
})

#endif

