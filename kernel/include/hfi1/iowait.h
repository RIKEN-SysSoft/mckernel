#ifndef _HFI1_IOWAIT_H
#define _HFI1_IOWAIT_H
/*
 * Copyright(c) 2015 - 2017 Intel Corporation.
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * BSD LICENSE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  - Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  - Neither the name of Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef __HFI1_ORIG__
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/sched.h>

#include "sdma_txreq.h"

/*
 * typedef (*restart_t)() - restart callback
 * @work: pointer to work structure
 */
typedef void (*restart_t)(struct work_struct *work);
#endif /* __HFI1_ORIG__ */

#define IOWAIT_PENDING_IB  0x0
#define IOWAIT_PENDING_TID 0x1

/*
 * A QP can have multiple Send Engines (SEs).
 *
 * The current use case is for supporting a TID RDMA
 * packet build/xmit mechanism independent from verbs.
 */
#define IOWAIT_SES 2
#define IOWAIT_IB_SE 0
#define IOWAIT_TID_SE 1

struct sdma_txreq;
struct sdma_engine;
/**
 * @iowork: the work struct
 * @tx_head: list of prebuilt packets
 * @iow: the parent iowait structure
 *
 * This structure is the work item (process) specific
 * details associated with the each of the two SEs of the
 * QP.
 *
 * The workstruct and the queued TXs are unique to each
 * SE.
 */
struct iowait;
struct iowait_work {
	char iowork[32]; // struct work_struct iowork;
	struct list_head tx_head;
	struct iowait *iow;
};

/**
 * @list: used to add/insert into QP/PQ wait lists
 * @tx_head: overflow list of sdma_txreq's
 * @sleep: no space callback
 * @wakeup: space callback wakeup
 * @sdma_drained: sdma count drained
 * @lock: lock protected head of wait queue
 * @iowork: workqueue overhead
 * @wait_dma: wait for sdma_busy == 0
 * @wait_pio: wait for pio_busy == 0
 * @sdma_busy: # of packets in flight
 * @count: total number of descriptors in tx_head'ed list
 * @tx_limit: limit for overflow queuing
 * @tx_count: number of tx entry's in tx_head'ed list
 * @flags: wait flags (one per QP)
 * @wait: SE array
 *
 * This is to be embedded in user's state structure
 * (QP or PQ).
 *
 * The sleep and wakeup members are a
 * bit misnamed.   They do not strictly
 * speaking sleep or wake up, but they
 * are callbacks for the ULP to implement
 * what ever queuing/dequeuing of
 * the embedded iowait and its containing struct
 * when a resource shortage like SDMA ring space is seen.
 *
 * Both potentially have locks help
 * so sleeping is not allowed.
 *
 * The wait_dma member along with the iow
 *
 * The lock field is used by waiters to record
 * the seqlock_t that guards the list head.
 * Waiters explicity know that, but the destroy
 * code that unwaits QPs does not.
 */
/* The original size on Linux is 240 B */ 
struct iowait {
	struct list_head list;
	int (*sleep)(
		struct sdma_engine *sde,
		struct iowait_work *wait,
		struct sdma_txreq *tx,
		unsigned seq);
	void (*wakeup)(struct iowait *wait, int reason);
	void (*sdma_drained)(struct iowait *wait);
	seqlock_t *lock;
	char wait_dma[24]; // wait_queue_head_t wait_dma;
	char wait_pio[24]; // wait_queue_head_t wait_pio;
	atomic_t sdma_busy;
	atomic_t pio_busy;
	u32 count;
	u32 tx_limit;
	u32 tx_count;
	unsigned long flags;
	struct iowait_work wait[IOWAIT_SES];
};

#define SDMA_AVAIL_REASON 0

#ifdef __HFI1_ORIG__

void iowait_set_flag(struct iowait *wait, u32 flag);
bool iowait_flag_set(struct iowait *wait, u32 flag);
void iowait_clear_flag(struct iowait *wait, u32 flag);

void iowait_init(
	struct iowait *wait,
	u32 tx_limit,
	void (*func)(struct work_struct *work),
	void (*tidfunc)(struct work_struct *work),
	int (*sleep)(
		struct sdma_engine *sde,
		struct iowait_work *wait,
		struct sdma_txreq *tx,
		unsigned seq),
	void (*wakeup)(struct iowait *wait, int reason),
	void (*sdma_drained)(struct iowait *wait));

/**
 * iowait_schedule() - schedule the default send engine work
 * @wait: wait struct to schedule
 * @wq: workqueue for schedule
 * @cpu: cpu
 */
static inline bool iowait_schedule(
	struct iowait *wait,
	struct workqueue_struct *wq,
	int cpu)
{
	hfi1_cdbg(AIOWRITE, ".");
	return !!queue_work_on(cpu, wq, &wait->wait[IOWAIT_IB_SE].iowork);
}

/**
 * iowait_tid_schedule - schedule the tid SE
 * @wait: the iowait structure
 * @wq: the work queue
 * @cpu: the cpu
 */
static inline bool iowait_tid_schedule(
	struct iowait *wait,
	struct workqueue_struct *wq,
	int cpu)
{
	hfi1_cdbg(AIOWRITE, ".");
	return !!queue_work_on(cpu, wq, &wait->wait[IOWAIT_TID_SE].iowork);
}

/**
 * iowait_sdma_drain() - wait for DMAs to drain
 * @wait: iowait structure
 *
 * This will delay until the iowait sdmas have
 * completed.
 */
static inline void iowait_sdma_drain(struct iowait *wait)
{
	hfi1_cdbg(AIOWRITE, ".");
	wait_event(wait->wait_dma, !atomic_read(&wait->sdma_busy));
}

/**
 * iowait_sdma_pending() - return sdma pending count
 *
 * @wait: iowait structure
 *
 */
static inline int iowait_sdma_pending(struct iowait *wait)
{
	hfi1_cdbg(AIOWRITE, ".");
	return atomic_read(&wait->sdma_busy);
}

/**
 * iowait_sdma_inc - note sdma io pending
 * @wait: iowait structure
 */
static inline void iowait_sdma_inc(struct iowait *wait)
{
	hfi1_cdbg(AIOWRITE, ".");
	atomic_inc(&wait->sdma_busy);
}

#endif
/**
 * iowait_sdma_add - add count to pending
 * @wait: iowait_work structure
 */
static inline void iowait_sdma_add(struct iowait *wait, int count)
{
	hfi1_cdbg(AIOWRITE, ".");
	atomic_add(count, &wait->sdma_busy);
}
#ifdef __HFI1_ORIG__

/**
 * iowait_pio_drain() - wait for pios to drain
 *
 * @wait: iowait structure
 *
 * This will delay until the iowait pios have
 * completed.
 */
static inline void iowait_pio_drain(struct iowait *wait)
{
	hfi1_cdbg(AIOWRITE, ".");
	wait_event_timeout(wait->wait_pio,
			   !atomic_read(&wait->pio_busy),
			   HZ);
}

/**
 * iowait_pio_pending() - return pio pending count
 *
 * @wait: iowait structure
 *
 */
static inline int iowait_pio_pending(struct iowait *w)
{
	hfi1_cdbg(AIOWRITE, ".");
	return atomic_read(&w->pio_busy);
}

/**
 * iowait_drain_wakeup() - trigger iowait_drain() waiter
 * @wait: iowait structure
 *
 * This will trigger any waiters.
 */
static inline void iowait_drain_wakeup(struct iowait *w)
{
	hfi1_cdbg(AIOWRITE, ".");
	wake_up(&w->wait_dma);
	wake_up(&w->wait_pio);
	if (w->sdma_drained)
		w->sdma_drained(w);
}

/**
 * iowait_pio_inc - note pio pending
 * @wait: iowait structure
 */
static inline void iowait_pio_inc(struct iowait *wait)
{
	hfi1_cdbg(AIOWRITE, ".");
	atomic_inc(&wait->pio_busy);
}

/**
 * iowait_pio_dec - note pio complete
 * @wait: iowait structure
 */
static inline int iowait_pio_dec(struct iowait *wait)
{
	hfi1_cdbg(AIOWRITE, ".");
	if (!wait)
		return 0;
	return atomic_dec_and_test(&wait->pio_busy);
}

/**
 * iowait_sdma_dec - note pio complete
 * @wait: iowait structure
 */
static inline int iowait_sdma_dec(struct iowait *wait)
{
	hfi1_cdbg(AIOWRITE, ".");
	if (!wait)
		return 0;
	return atomic_dec_and_test(&wait->sdma_busy);
}

/**
 * iowait_get_txhead() - get packet off of iowait list
 * @wait wait struture
 */
static inline struct sdma_txreq *iowait_get_txhead(struct iowait_work *wait)
{
	struct sdma_txreq *tx = NULL;

	hfi1_cdbg(AIOWRITE, ".");
	if (!list_empty(&wait->tx_head)) {
		tx = list_first_entry(
			&wait->tx_head,
			struct sdma_txreq,
			list);
		list_del_init(&tx->list);
	}
	return tx;
}

static inline u16 iowait_get_desc(struct iowait_work *w)
{
	u16 num_desc = 0;
	struct sdma_txreq *tx = NULL;
	hfi1_cdbg(AIOWRITE, ".");

	if (!list_empty(&w->tx_head)) {
		tx = list_first_entry(
			&w->tx_head,
			struct sdma_txreq,
			list);
		num_desc = tx->num_desc;
	}
	return num_desc;
}

static inline u32 iowait_get_all_desc(struct iowait *w)
{
	u32 num_desc = 0;

	hfi1_cdbg(AIOWRITE, ".");
	num_desc = iowait_get_desc(&w->wait[IOWAIT_IB_SE]);
	num_desc += iowait_get_desc(&w->wait[IOWAIT_TID_SE]);
	return num_desc;
}

/**
 * iowait_packet_queued() - determine if a packet it queued
 * @wait: the wait structure
 */
static inline bool iowait_packet_queued(struct iowait_work *w)
{
	hfi1_cdbg(AIOWRITE, ".");
	return !list_empty(&w->tx_head);
}

#endif /* __HFI1_ORIG__ */
/**
 * inc_wait_count - increment wait counts
 * @w: the log work struct
 * @n: the count
 */
static inline void iowait_inc_wait_count(struct iowait_work *w, u16 n)
{
	hfi1_cdbg(AIOWRITE, ".");
	if (!w)
		return;
	w->iow->tx_count++;
	w->iow->count += n;
}
#ifdef __HFI1_ORIG__

/**
 * iowait_get_tid_work - return iowait_work for tid SE
 * @w: the iowait struct
 */
static inline struct iowait_work *iowait_get_tid_work(struct iowait *w)
{
	hfi1_cdbg(AIOWRITE, ".");
	return &w->wait[IOWAIT_TID_SE];
}

#endif /* __HFI1_ORIG__ */
/**
 * iowait_get_ib_work - return iowait_work for ib SE
 * @w: the iowait struct
 */
static inline struct iowait_work *iowait_get_ib_work(struct iowait *w)
{
	hfi1_cdbg(AIOWRITE, ".");
	return &w->wait[IOWAIT_IB_SE];
}

/**
 * iowait_ioww_to_iow - return iowait given iowait_work
 * @w: the iowait_work struct
 */
static inline struct iowait *iowait_ioww_to_iow(struct iowait_work *w)
{
	hfi1_cdbg(AIOWRITE, ".");
	if (likely(w))
		return w->iow;
	return NULL;
}
#ifdef __HFI1_ORIG__

void iowait_cancel_work(struct iowait *w);
int iowait_set_work_flag(struct iowait_work *w);
#endif /* __HFI1_ORIG__ */

#endif
