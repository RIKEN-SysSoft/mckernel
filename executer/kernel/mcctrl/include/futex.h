/* This is copy of the necessary part from McKernel, for uti-futex */

#ifndef _FUTEX_H
#define _FUTEX_H

#include <mc_plist.h>
#include <arch-lock.h>

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

#define FUT_OFF_INODE    1 /* We set bit 0 if key has a reference on inode */
#define FUT_OFF_MMSHARED 2 /* We set bit 1 if key has a reference on mm */

#define FUTEX_HASHBITS		8	/* 256 entries in each futex hash tbl */

#define PS_RUNNING           0x1
#define PS_INTERRUPTIBLE     0x2
#define PS_UNINTERRUPTIBLE   0x4
#define PS_ZOMBIE            0x8
#define PS_EXITED            0x10
#define PS_STOPPED           0x20

union futex_key {
	struct {
		unsigned long pgoff;
		void *phys;
		int offset;
	} shared;
	struct {
		unsigned long address;
		void *mm;    // Acctually, process_vm
		int offset;
	} private;
	struct {
		unsigned long word;
		void *ptr;
		int offset;
	} both;
};

#define FUTEX_KEY_INIT ((union futex_key) { .both = { .ptr = NULL } })

#define FUTEX_BITSET_MATCH_ANY	0xffffffff

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
	struct mc_plist_node list;

	void *task;    // Actually, struct thread
	_ihk_spinlock_t *lock_ptr;
	union futex_key key;
	union futex_key *requeue_pi_key;
	uint32_t bitset;

	/* Used to wake-up a thread running on a Linux CPU */
	void *uti_futex_resp;

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
};

long do_futex(int n, unsigned long arg0, unsigned long arg1,
		unsigned long arg2, unsigned long arg3,
		unsigned long arg4, unsigned long arg5,
		struct uti_info *uti_info,
		void *uti_futex_resp);

#endif
