/* futex.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
/**
 * \file futex.h
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
#ifndef _FUTEX_H
#define _FUTEX_H

/** \name Futex Commands
 * @{
 */
#define FUTEX_WAIT		0
#define FUTEX_WAKE		1
#define FUTEX_FD		2
#define FUTEX_REQUEUE		3
#define FUTEX_CMP_REQUEUE	4
#define FUTEX_WAKE_OP		5
#define FUTEX_LOCK_PI		6
#define FUTEX_UNLOCK_PI		7
#define FUTEX_TRYLOCK_PI	8
#define FUTEX_WAIT_BITSET	9
#define FUTEX_WAKE_BITSET	10
#define FUTEX_WAIT_REQUEUE_PI	11
#define FUTEX_CMP_REQUEUE_PI	12
// @}

#define FUTEX_PRIVATE_FLAG	128
#define FUTEX_CLOCK_REALTIME	256
#define FUTEX_CMD_MASK		~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

#define FUTEX_WAIT_PRIVATE	(FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_PRIVATE	(FUTEX_WAKE | FUTEX_PRIVATE_FLAG)
#define FUTEX_REQUEUE_PRIVATE	(FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG)
#define FUTEX_CMP_REQUEUE_PRIVATE (FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_OP_PRIVATE	(FUTEX_WAKE_OP | FUTEX_PRIVATE_FLAG)
#define FUTEX_LOCK_PI_PRIVATE	(FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_UNLOCK_PI_PRIVATE	(FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_TRYLOCK_PI_PRIVATE (FUTEX_TRYLOCK_PI | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAIT_BITSET_PRIVATE	(FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAKE_BITSET_PRIVATE	(FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG)
#define FUTEX_WAIT_REQUEUE_PI_PRIVATE	(FUTEX_WAIT_REQUEUE_PI | \
					 FUTEX_PRIVATE_FLAG)
#define FUTEX_CMP_REQUEUE_PI_PRIVATE	(FUTEX_CMP_REQUEUE_PI | \
					 FUTEX_PRIVATE_FLAG)


/** \name Futex Operations, used for FUTEX_WAKE_OP
 * @{
 */
#define FUTEX_OP_SET		0	/* *(int *)UADDR2 = OPARG; */
#define FUTEX_OP_ADD		1	/* *(int *)UADDR2 += OPARG; */
#define FUTEX_OP_OR		2	/* *(int *)UADDR2 |= OPARG; */
#define FUTEX_OP_ANDN		3	/* *(int *)UADDR2 &= ~OPARG; */
#define FUTEX_OP_XOR		4	/* *(int *)UADDR2 ^= OPARG; */

#define FUTEX_OP_OPARG_SHIFT	8U	/* Use (1 << OPARG) instead of OPARG. */

#define FUTEX_OP_CMP_EQ		0	/* if (oldval == CMPARG) wake */
#define FUTEX_OP_CMP_NE		1	/* if (oldval != CMPARG) wake */
#define FUTEX_OP_CMP_LT		2	/* if (oldval < CMPARG) wake */
#define FUTEX_OP_CMP_LE		3	/* if (oldval <= CMPARG) wake */
#define FUTEX_OP_CMP_GT		4	/* if (oldval > CMPARG) wake */
#define FUTEX_OP_CMP_GE		5	/* if (oldval >= CMPARG) wake */
// @}

/* FUTEX_WAKE_OP will perform atomically
   int oldval = *(int *)UADDR2;
   *(int *)UADDR2 = oldval OP OPARG;
   if (oldval CMP CMPARG)
     wake UADDR2;  */
#define FUTEX_OP(op, oparg, cmp, cmparg) \
  (((op & 0xf) << 28) | ((cmp & 0xf) << 24)		\
   | ((oparg & 0xfff) << 12) | (cmparg & 0xfff))

/*
 * bitset with all bits set for the FUTEX_xxx_BITSET OPs to request a
 * match of any bit.
 */
#define FUTEX_BITSET_MATCH_ANY	0xffffffff

#ifdef __KERNEL__

#include <ihk/lock.h>
#include <list.h>
#include <process.h>
#include <waitq.h>
#include <plist.h>

#ifndef _ASM_X86_FUTEX_H
#define _ASM_X86_FUTEX_H

#ifdef __KERNEL__

#define __user 

/* We don't deal with uaccess at the moment, because x86 can access
 * userspace directly, we rely on glibc and the app developers.
 */
#ifdef __UACCESS__
#include <arch/uaccess.h>
#endif

#include <errno.h>
#include <arch-futex.h>

#if 0
#include <arch/processor.h>
#include <arch/system.h>
#endif

#endif // __KERNEL__
#endif // _ASM_X86_FUTEX_H

#define FUTEX_HASHBITS		8	/* 256 entries in each futex hash tbl */

#define FUT_OFF_INODE    1 /* We set bit 0 if key has a reference on inode */
#define FUT_OFF_MMSHARED 2 /* We set bit 1 if key has a reference on mm */

struct process_vm;

static inline int get_futex_value_locked(uint32_t *dest, uint32_t *from)
{

	*dest = *(volatile uint32_t *)from;

	return 0;
}

/*
 * Hash buckets are shared by all the futex_keys that hash to the same
 * location.  Each key may have multiple futex_q structures, one for each task
 * waiting on a futex.
 */
struct futex_hash_bucket {
	ihk_spinlock_t lock;
	struct plist_head chain;
};

struct futex_hash_bucket *get_futex_queues(void);

union futex_key {
	struct {
		unsigned long pgoff;
		void *phys;
		int offset;
	} shared;
	struct {
		unsigned long address;
		struct process_vm *mm;
		int offset;
	} private;
	struct {
		unsigned long word;
		void *ptr;
		int offset;
	} both;
};

#define FUTEX_KEY_INIT (union futex_key) { .both = { .ptr = NULL } }
#define FUT_OFF_MMSHARED 2

extern int futex_init(void);

struct cpu_local_var;
extern int
futex(
	uint32_t __user *		uaddr,
	int						op,
	uint32_t				val,
	uint64_t				timeout,
	uint32_t __user *		uaddr2,
	uint32_t				val2,
	uint32_t				val3,
	int                     fshared
);


/**
 * struct futex_q - The hashed futex queue entry, one per waiting task
 * @task:		the task waiting on the futex
 * @lock_ptr:		the hash bucket lock
 * @key:		the key the futex is hashed on
 * @requeue_pi_key:	the requeue_pi target futex key
 * @bitset:		bitset for the optional bitmasked wakeup
 *
 * We use this hashed waitqueue, instead of a normal wait_queue_t, so
 * we can wake only the relevant ones (hashed queues may be shared).
 *
 * A futex_q has a woken state, just like tasks have TASK_RUNNING.
 * It is considered woken when plist_node_empty(&q->list) || q->lock_ptr == 0.
 * The order of wakup is always to make the first condition true, then
 * the second.
 *
 * PI futexes are typically woken before they are removed from the hash list via
 * the rt_mutex code. See unqueue_me_pi().
 */
struct futex_q {
	struct plist_node list;

	struct thread *task;
	ihk_spinlock_t *lock_ptr;
	union futex_key key;
	union futex_key *requeue_pi_key;
	uint32_t bitset;

	/* Used to wake-up a thread running on a Linux CPU */
	void *uti_futex_resp;

	/* Used to send IPI directly to the waiter CPU */
	int linux_cpu;

	/* Used to wake-up a thread running on a McKernel from Linux */
	void *th_spin_sleep;
	void *th_status;
	void *th_spin_sleep_lock;
	void *proc_status;
	void *proc_update_lock;
	void *runq_lock;
	void *clv_flags;
	int intr_id;
	int intr_vector;

	unsigned long th_spin_sleep_pa;
	unsigned long th_status_pa;
	unsigned long th_spin_sleep_lock_pa;
	unsigned long proc_status_pa;
	unsigned long proc_update_lock_pa;
	unsigned long runq_lock_pa;
	unsigned long clv_flags_pa;
};

#endif
#endif
