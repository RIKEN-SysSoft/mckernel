#ifndef _LWK_FUTEX_H
#define _LWK_FUTEX_H

/** \name Futex Commands
 * @{
 */
#define FUTEX_WAIT		0
#define FUTEX_WAKE		1
#define FUTEX_CMP_REQUEUE	4
#define FUTEX_WAKE_OP		5
#define FUTEX_WAIT_BITSET	9
#define FUTEX_WAKE_BITSET	10
// @}

#define FUTEX_PRIVATE_FLAG	128
#define FUTEX_CLOCK_REALTIME	256
#define FUTEX_CMD_MASK		~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

/** \name Futex Operations, used for FUTEX_WAKE_OP
 * @{
 */
#define FUTEX_OP_SET		0	/* *(int *)UADDR2 = OPARG; */
#define FUTEX_OP_ADD		1	/* *(int *)UADDR2 += OPARG; */
#define FUTEX_OP_OR		2	/* *(int *)UADDR2 |= OPARG; */
#define FUTEX_OP_ANDN		3	/* *(int *)UADDR2 &= ~OPARG; */
#define FUTEX_OP_XOR		4	/* *(int *)UADDR2 ^= OPARG; */

#define FUTEX_OP_OPARG_SHIFT	8	/* Use (1 << OPARG) instead of OPARG.  */

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

#include <lwk/spinlock.h>
#include <lwk/list.h>
#include <lwk/waitq.h>
#include <arch/futex.h>

#define FUTEX_HASHBITS		8	/* 256 entries in each futex hash tbl */

/** Futex tracking structure.
 *
 * A futex has a woken state, just like tasks have TASK_RUNNING.
 * It is considered woken when list_empty(&futex->link) || futex->lock_ptr == 0.
 * The order of wakup is always to make the first condition true, then
 * wake up futex->waitq, then make the second condition true.
 */
struct futex {
	struct list_head		link;
	struct waitq			waitq;
	spinlock_t *			lock_ptr;
	uint32_t __user *		uaddr;
	uint32_t			bitset;
};

struct futex_queue {
	spinlock_t			lock;
	struct list_head		futex_list;
};

extern void
futex_queue_init(
	struct futex_queue *		queue
);

extern int
futex(
	uint32_t __user *		uaddr,
	int				op,
	uint32_t			val,
	uint64_t			timeout,
	uint32_t __user *		uaddr2,
	uint32_t			val2,
	uint32_t			val3
);

extern long
sys_futex(
	uint32_t __user *		uaddr,
	int				op,
	uint32_t			val,
	struct timespec __user *	utime,
	uint32_t __user *		uaddr2,
	uint32_t			val3
);

#endif
#endif
