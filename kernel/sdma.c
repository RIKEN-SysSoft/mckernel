/*
 * Copyright(c) 2015, 2016 Intel Corporation.
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

#include <hfi1/ihk_hfi1_common.h>
#include <hfi1/user_sdma.h> 
#include <hfi1/sdma.h> 
#include <hfi1/common.h> 

//#define DEBUG_PRINT_SDMA

#ifdef DEBUG_PRINT_SC
#define	dkprintf(...) kprintf(__VA_ARGS__)
#define	ekprintf(...) kprintf(__VA_ARGS__)
#else
#define dkprintf(...) do { if (0) kprintf(__VA_ARGS__); } while (0)
#define	ekprintf(...) kprintf(__VA_ARGS__)
#endif

unsigned long hfi1_cap_mask = HFI1_CAP_MASK_DEFAULT;

/* must be a power of 2 >= 64 <= 32768 */
#define SDMA_DESCQ_CNT 2048
#define SDMA_DESC_INTR 64
#define INVALID_TAIL 0xffff

#define SDMA_TAIL_UPDATE_THRESH 0x1F

/**
 * sdma_select_engine_vl() - select sdma engine
 * @dd: devdata
 * @selector: a spreading factor
 * @vl: this vl
 *
 *
 * This function returns an engine based on the selector and a vl.  The
 * mapping fields are protected by RCU.
 */
struct sdma_engine *sdma_select_engine_vl(
	struct hfi1_devdata *dd,
	u32 selector,
	u8 vl)
{
	struct sdma_vl_map *m;
	struct sdma_map_elem *e;
	struct sdma_engine *rval;

	/* NOTE This should only happen if SC->VL changed after the initial
	 *      checks on the QP/AH
	 *      Default will return engine 0 below
	 */
	if (vl >= HFI1_MAX_VLS_SUPPORTED) {
		rval = NULL;
		goto done;
	}

	m = ACCESS_ONCE(dd->sdma_map);
	if (unlikely(!m)) {
		return &dd->per_sdma[0];
	}
	e = m->map[vl & m->mask];
	rval = e->sde[selector & e->mask];

done:
	rval =  !rval ? &dd->per_sdma[0] : rval;
	// trace_hfi1_sdma_engine_select(dd, selector, vl, rval->this_idx);
	hfi1_cdbg(AIOWRITE, "-");
	return rval;
}

int sdma_select_user_engine_idx(void)
{
	int idx = 0;
	int idx_start = 0;
	int idx_modulo = 16;

	/* Hash on rank if MPI job */
	if (cpu_local_var(current)->proc->nr_processes > 1) {
		idx = idx_start +
			(cpu_local_var(current)->proc->process_rank % idx_modulo);
	}
	/* Otherwise, CPU id */
	else {
		idx = ihk_mc_get_processor_id() % idx_modulo;
	}

	return idx;
}

/*
 * sdma_select_user_engine() - select sdma engine based on user setup
 * @dd: devdata
 * @selector: a spreading factor
 * @vl: this vl
 *
 * This function returns an sdma engine for a user sdma request.
 * User defined sdma engine affinity setting is honored when applicable,
 * otherwise system default sdma engine mapping is used. To ensure correct
 * ordering, the mapping from <selector, vl> to sde must remain unchanged.
 */
struct sdma_engine *sdma_select_user_engine(struct hfi1_devdata *dd,
					    u32 selector, u8 vl)
{
	return &dd->per_sdma[sdma_select_user_engine_idx()];
}

/*
 * return the mode as indicated by the first
 * descriptor in the tx.
 */
static inline u8 ahg_mode(struct sdma_txreq *tx)
{
	return (tx->descp[0].qw[1] & SDMA_DESC1_HEADER_MODE_SMASK)
		>> SDMA_DESC1_HEADER_MODE_SHIFT;
}

/**
 * __sdma_txclean() - clean tx of mappings, descp *kmalloc's
 * @dd: hfi1_devdata for unmapping
 * @tx: tx request to clean
 *
 * This is used in the progress routine to clean the tx or
 * by the ULP to toss an in-process tx build.
 *
 * The code can be called multiple times without issue.
 *
 */
void __sdma_txclean(
	struct hfi1_devdata *dd,
	struct sdma_txreq *tx)
{
	if (tx->num_desc) {
		/* TODO: enable sdma_unmap_desc */
#if 0
		u16 i;
		u8 skip = 0, mode = ahg_mode(tx);

		/* unmap first */
		//sdma_unmap_desc(dd, &tx->descp[0]);
		/* determine number of AHG descriptors to skip */
		if (mode > SDMA_AHG_APPLY_UPDATE1)
			skip = mode >> 1;
		// for (i = 1 + skip; i < tx->num_desc; i++)
		// 	sdma_unmap_desc(dd, &tx->descp[i]);
#endif
		tx->num_desc = 0;
	}
	kfree(tx->coalesce_buf);
	tx->coalesce_buf = NULL;
	/* kmalloc'ed descp */
	if (unlikely(tx->desc_limit > ARRAY_SIZE(tx->descs))) {
		tx->desc_limit = ARRAY_SIZE(tx->descs);
		kfree(tx->descp);
	}
}

static inline void sdma_update_tail(struct sdma_engine *sde, u16 tail)
{
	/* Commit writes to memory and advance the tail on the chip */
	smp_wmb(); /* see get_txhead() */
	writeq(tail, sde->tail_csr);
}

/*
 * add the generation number into
 * the qw1 and return
 */
static inline u64 add_gen(struct sdma_engine *sde, u64 qw1)
{
	u8 generation = (sde->descq_tail >> sde->sdma_shift) & 3;

	qw1 &= ~SDMA_DESC1_GENERATION_SMASK;
	qw1 |= ((u64)generation & SDMA_DESC1_GENERATION_MASK)
			<< SDMA_DESC1_GENERATION_SHIFT;
	return qw1;
}

/*
 * This routine submits the indicated tx
 *
 * Space has already been guaranteed and
 * tail side of ring is locked.
 *
 * The hardware tail update is done
 * in the caller and that is facilitated
 * by returning the new tail.
 *
 * There is special case logic for ahg
 * to not add the generation number for
 * up to 2 descriptors that follow the
 * first descriptor.
 *
 */
static inline u16 submit_tx(struct sdma_engine *sde, struct sdma_txreq *tx)
{
	int i;
	u16 tail;
	struct sdma_desc *descp = tx->descp;
	u8 skip = 0, mode = ahg_mode(tx);
	tail = sde->descq_tail & sde->sdma_mask;
	sde->descq[tail].qw[0] = cpu_to_le64(descp->qw[0]);
	sde->descq[tail].qw[1] = cpu_to_le64(add_gen(sde, descp->qw[1]));
	// trace_hfi1_sdma_descriptor(sde, descp->qw[0], descp->qw[1],
	// 			   tail, &sde->descq[tail]);
	tail = ++sde->descq_tail & sde->sdma_mask;
	descp++;
	if (mode > SDMA_AHG_APPLY_UPDATE1)
		skip = mode >> 1;
	for (i = 1; i < tx->num_desc; i++, descp++) {
		u64 qw1;

		sde->descq[tail].qw[0] = cpu_to_le64(descp->qw[0]);
		if (skip) {
			/* edits don't have generation */
			qw1 = descp->qw[1];
			skip--;
		} else {
			/* replace generation with real one for non-edits */
			qw1 = add_gen(sde, descp->qw[1]);
		}
		sde->descq[tail].qw[1] = cpu_to_le64(qw1);
		// trace_hfi1_sdma_descriptor(sde, descp->qw[0], qw1,
		// 			   tail, &sde->descq[tail]);
		tail = ++sde->descq_tail & sde->sdma_mask;
	}

	tx->next_descq_idx = tail;
#ifdef CONFIG_HFI1_DEBUG_SDMA_ORDER
	tx->sn = sde->tail_sn++;
	// trace_hfi1_sdma_in_sn(sde, tx->sn);
	WARN_ON_ONCE(sde->tx_ring[sde->tx_tail & sde->sdma_mask]);
#endif
	sde->tx_ring[sde->tx_tail++ & sde->sdma_mask] = tx;
	sde->desc_avail -= tx->num_desc;
	return tail;
}

/*
 * Check for progress
 */
static int sdma_check_progress(
	struct sdma_engine *sde,
	struct iowait_work *wait,
	struct sdma_txreq *tx,
	bool pkts_sent)
{
	int ret;

	hfi1_cdbg(AIOWRITE, "+");
	sde->desc_avail = sdma_descq_freecnt(sde);
	if (tx->num_desc <= sde->desc_avail)
		return -EAGAIN;
	/* pulse the head_lock */
	if (wait && iowait_ioww_to_iow(wait)->sleep) {
		unsigned seq;

		seq = raw_seqcount_begin(
			(const seqcount_t *)&sde->head_lock.seqcount);
		ret = wait->iow->sleep(sde, wait, tx, seq, pkts_sent);
		if (ret == -EAGAIN)
			sde->desc_avail = sdma_descq_freecnt(sde);
	} else {
		ret = -EBUSY;
	}
	hfi1_cdbg(AIOWRITE, "-");
	return ret;
}

/**
 * sdma_send_txlist() - submit a list of tx req to ring
 * @sde: sdma engine to use
 * @wait: SE wait structure to use when full (may be NULL)
 * @tx_list: list of sdma_txreqs to submit
 * @count: pointer to a u32 which, after return will contain the total number of
 *         sdma_txreqs removed from the tx_list. This will include sdma_txreqs
 *         whose SDMA descriptors are submitted to the ring and the sdma_txreqs
 *         which are added to SDMA engine flush list if the SDMA engine state is
 *         not running.
 *
 * The call submits the list into the ring.
 *
 * If the iowait structure is non-NULL and not equal to the iowait list
 * the unprocessed part of the list  will be appended to the list in wait.
 *
 * In all cases, the tx_list will be updated so the head of the tx_list is
 * the list of descriptors that have yet to be transmitted.
 *
 * The intent of this call is to provide a more efficient
 * way of submitting multiple packets to SDMA while holding the tail
 * side locking.
 *
 * Return:
 * 0 - Success,
 * -EINVAL - sdma_txreq incomplete, -EBUSY - no space in ring (wait == NULL)
 * -EIOCBQUEUED - tx queued to iowait, -ECOMM bad sdma state
 */
int sdma_send_txlist(struct sdma_engine *sde, struct iowait_work *wait,
		     struct list_head *tx_list, u32 *count_out)
{
	struct sdma_txreq *tx, *tx_next;
	int ret = 0;
	unsigned long flags;
	u16 tail = INVALID_TAIL;
	u32 submit_count = 0, flush_count = 0, total_count;

retry_lock:
	linux_spin_lock_irqsave(&sde->tail_lock, flags);
retry:
	list_for_each_entry_safe(tx, tx_next, tx_list, list) {
		tx->wait = iowait_ioww_to_iow(wait);
		if (unlikely(!__sdma_running(sde))) {
			kprintf("%s: !__sdma_running \n", __FUNCTION__);
			goto unlock_noconn;
		}
		if (unlikely(tx->num_desc > sde->desc_avail)) {
			goto nodesc;
		}
		if (unlikely(tx->tlen)) {
			ret = -EINVAL;
			goto update_tail;
		}
		list_del_init(&tx->list);
		tail = submit_tx(sde, tx);
		submit_count++;
		if (tail != INVALID_TAIL &&
		    (submit_count & SDMA_TAIL_UPDATE_THRESH) == 0) {
			sdma_update_tail(sde, tail);
			tail = INVALID_TAIL;
		}
	}

update_tail:
	total_count = submit_count + flush_count;
	if (wait)
		iowait_sdma_add(iowait_ioww_to_iow(wait), total_count);
	if (tail != INVALID_TAIL)
		sdma_update_tail(sde, tail);
	linux_spin_unlock_irqrestore(&sde->tail_lock, flags);
	*count_out = total_count;
	return ret;

unlock_noconn:
nodesc:
	{
		/*
		 * Either way, we spin.
		 * We never sleep in McKernel so release the lock occasionally
		 * to give a chance to Linux.
		 */
		unsigned long ts = rdtsc();

		while ((tx->num_desc > sde->desc_avail) &&
				(rdtsc() - ts) < 5000000) {
			sde->desc_avail = sdma_descq_freecnt(sde);
			cpu_pause();
		}

		if (tx->num_desc <= sde->desc_avail) {
			ret = 0;
			goto retry;
		}

		dkprintf("%s: releasing lock and reiterating.. \n", __FUNCTION__);
		linux_spin_unlock_irqrestore(&sde->tail_lock, flags);
		cpu_pause();
		ret = 0;
		goto retry_lock;
	}
}

/*
 * _extend_sdma_tx_descs() - helper to extend txreq
 *
 * This is called once the initial nominal allocation
 * of descriptors in the sdma_txreq is exhausted.
 *
 * The code will bump the allocation up to the max
 * of MAX_DESC (64) descriptors. There doesn't seem
 * much point in an interim step. The last descriptor
 * is reserved for coalesce buffer in order to support
 * cases where input packet has >MAX_DESC iovecs.
 *
 */
static int _extend_sdma_tx_descs(struct hfi1_devdata *dd, struct sdma_txreq *tx)
{
	int i;

	/* Handle last descriptor */
	if (unlikely((tx->num_desc == (MAX_DESC - 1)))) {
		/* if tlen is 0, it is for padding, release last descriptor */
		if (!tx->tlen) {
			tx->desc_limit = MAX_DESC;
		} else if (!tx->coalesce_buf) {
			/* allocate coalesce buffer with space for padding */
			tx->coalesce_buf = kmalloc(tx->tlen + sizeof(u32),
						   GFP_ATOMIC);
			if (!tx->coalesce_buf)
				goto enomem;
			tx->coalesce_idx = 0;
		}
		return 0;
	}

	if (unlikely(tx->num_desc == MAX_DESC))
		goto enomem;

	tx->descp = kmalloc_array(
			MAX_DESC,
			sizeof(struct sdma_desc),
			GFP_ATOMIC);
	if (!tx->descp)
		goto enomem;

	/* reserve last descriptor for coalescing */
	tx->desc_limit = MAX_DESC - 1;
	/* copy ones already built */
	for (i = 0; i < tx->num_desc; i++)
		tx->descp[i] = tx->descs[i];
	return 0;
enomem:
	__sdma_txclean(dd, tx);
	return -ENOMEM;
}

/*
 * ext_coal_sdma_tx_descs() - extend or coalesce sdma tx descriptors
 *
 * This is called once the initial nominal allocation of descriptors
 * in the sdma_txreq is exhausted.
 *
 * This function calls _extend_sdma_tx_descs to extend or allocate
 * coalesce buffer. If there is a allocated coalesce buffer, it will
 * copy the input packet data into the coalesce buffer. It also adds
 * coalesce buffer descriptor once when whole packet is received.
 *
 * Return:
 * <0 - error
 * 0 - coalescing, don't populate descriptor
 * 1 - continue with populating descriptor
 */
int ext_coal_sdma_tx_descs(struct hfi1_devdata *dd, struct sdma_txreq *tx,
			   int type, void *kvaddr, struct page *page,
			   unsigned long offset, u16 len)
{
//TODO: ext_coal_sdma_tx_descs
#ifdef __HFI1_ORIG__
	int pad_len, rval;
	dma_addr_t addr;

	rval = _extend_sdma_tx_descs(dd, tx);
	if (rval) {
		__sdma_txclean(dd, tx);
		return rval;
	}

	/* If coalesce buffer is allocated, copy data into it */
	if (tx->coalesce_buf) {
		if (type == SDMA_MAP_NONE) {
			__sdma_txclean(dd, tx);
			return -EINVAL;
		}

		if (type == SDMA_MAP_PAGE) {
			kvaddr = kmap(page);
			kvaddr += offset;
		} else if (WARN_ON(!kvaddr)) {
			__sdma_txclean(dd, tx);
			return -EINVAL;
		}

		memcpy(tx->coalesce_buf + tx->coalesce_idx, kvaddr, len);
		tx->coalesce_idx += len;
		if (type == SDMA_MAP_PAGE)
			kunmap(page);

		/* If there is more data, return */
		if (tx->tlen - tx->coalesce_idx)
			return 0;

		/* Whole packet is received; add any padding */
		pad_len = tx->packet_len & (sizeof(u32) - 1);
		if (pad_len) {
			pad_len = sizeof(u32) - pad_len;
			memset(tx->coalesce_buf + tx->coalesce_idx, 0, pad_len);
			/* padding is taken care of for coalescing case */
			tx->packet_len += pad_len;
			tx->tlen += pad_len;
		}

		/* dma map the coalesce buffer */
		addr = dma_map_single(&dd->pcidev->dev,
				      tx->coalesce_buf,
				      tx->tlen,
				      DMA_TO_DEVICE);

		if (unlikely(dma_mapping_error(&dd->pcidev->dev, addr))) {
			__sdma_txclean(dd, tx);
			return -ENOSPC;
		}

		/* Add descriptor for coalesce buffer */
		tx->desc_limit = MAX_DESC;
		return _sdma_txadd_daddr(dd, SDMA_MAP_SINGLE, tx,
					 addr, tx->tlen);
	}
#endif /* __HFI1_ORIG__ */
	return 1;
}

/* tx not dword sized - pad */
int _pad_sdma_tx_descs(struct hfi1_devdata *dd, struct sdma_txreq *tx)
{
	int rval = 0;

	tx->num_desc++;
	if ((unlikely(tx->num_desc == tx->desc_limit))) {
		rval = _extend_sdma_tx_descs(dd, tx);
		if (rval) {
			__sdma_txclean(dd, tx);
			return rval;
		}
	}
	/* finish the one just added */
	make_tx_sdma_desc(
		tx,
		SDMA_MAP_NONE,
		dd->sdma_pad_phys,
		sizeof(u32) - (tx->packet_len & (sizeof(u32) - 1)));
	_sdma_close_tx(dd, tx);
	return rval;
}

/*
 * Add ahg to the sdma_txreq
 *
 * The logic will consume up to 3
 * descriptors at the beginning of
 * sdma_txreq.
 */
void _sdma_txreq_ahgadd(
	struct sdma_txreq *tx,
	u8 num_ahg,
	u8 ahg_entry,
	u32 *ahg,
	u8 ahg_hlen)
{
	u32 i, shift = 0, desc = 0;
	u8 mode;

	WARN_ON_ONCE(num_ahg > 9 || (ahg_hlen & 3) || ahg_hlen == 4);
	/* compute mode */
	if (num_ahg == 1)
		mode = SDMA_AHG_APPLY_UPDATE1;
	else if (num_ahg <= 5)
		mode = SDMA_AHG_APPLY_UPDATE2;
	else
		mode = SDMA_AHG_APPLY_UPDATE3;
	tx->num_desc++;
	/* initialize to consumed descriptors to zero */
	switch (mode) {
	case SDMA_AHG_APPLY_UPDATE3:
		tx->num_desc++;
		tx->descs[2].qw[0] = 0;
		tx->descs[2].qw[1] = 0;
		/* FALLTHROUGH */
	case SDMA_AHG_APPLY_UPDATE2:
		tx->num_desc++;
		tx->descs[1].qw[0] = 0;
		tx->descs[1].qw[1] = 0;
		break;
	}
	ahg_hlen >>= 2;
	tx->descs[0].qw[1] |=
		(((u64)ahg_entry & SDMA_DESC1_HEADER_INDEX_MASK)
			<< SDMA_DESC1_HEADER_INDEX_SHIFT) |
		(((u64)ahg_hlen & SDMA_DESC1_HEADER_DWS_MASK)
			<< SDMA_DESC1_HEADER_DWS_SHIFT) |
		(((u64)mode & SDMA_DESC1_HEADER_MODE_MASK)
			<< SDMA_DESC1_HEADER_MODE_SHIFT) |
		(((u64)ahg[0] & SDMA_DESC1_HEADER_UPDATE1_MASK)
			<< SDMA_DESC1_HEADER_UPDATE1_SHIFT);
	for (i = 0; i < (num_ahg - 1); i++) {
		if (!shift && !(i & 2))
			desc++;
		tx->descs[desc].qw[!!(i & 2)] |=
			(((u64)ahg[i + 1])
				<< shift);
		shift = (shift + 32) & 63;
	}
}

/**
 * sdma_ahg_alloc - allocate an AHG entry
 * @sde: engine to allocate from
 *
 * Return:
 * 0-31 when successful, -EOPNOTSUPP if AHG is not enabled,
 * -ENOSPC if an entry is not available
 */
int sdma_ahg_alloc(struct sdma_engine *sde)
{
	int nr;
	int oldbit;

	if (!sde) {
		trace_hfi1_ahg_allocate(sde, -EINVAL);
		return -EINVAL;
	}
	while (1) {
		nr = ffz(ACCESS_ONCE(sde->ahg_bits));
		if (nr > 31) {
			trace_hfi1_ahg_allocate(sde, -ENOSPC);
			return -ENOSPC;
		}
		oldbit = test_and_set_bit(nr, &sde->ahg_bits);
		if (!oldbit)
			break;
		cpu_relax();
	}
	trace_hfi1_ahg_allocate(sde, nr);
	return nr;
}

/**
 * sdma_ahg_free - free an AHG entry
 * @sde: engine to return AHG entry
 * @ahg_index: index to free
 *
 * This routine frees the indicate AHG entry.
 */
void sdma_ahg_free(struct sdma_engine *sde, int ahg_index)
{
	if (!sde)
		return;
	trace_hfi1_ahg_deallocate(sde, ahg_index);
	if (ahg_index < 0 || ahg_index > 31)
		return;
	clear_bit(ahg_index, &sde->ahg_bits);
}
