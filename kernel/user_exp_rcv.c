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
#include <hfi1/common.h>
#include <hfi1/hfi.h>
#include <hfi1/chip.h>
#include <hfi1/user_exp_rcv.h>

static int program_rcvarray(struct hfi1_filedata *, uintptr_t, u16, struct tid_group *,
			    u32 *);
static int set_rcvarray_entry(struct hfi1_filedata *, uintptr_t,
			      u32, struct tid_group *,
			      u16);
static int unprogram_rcvarray(struct hfi1_filedata *, u32, struct tid_group **);
static void clear_tid_node(struct hfi1_filedata *, struct tid_rb_node *);

struct tid_rb_node {
	uintptr_t phys;
	u32 len;
	u32 rcventry;
	struct tid_group *grp;
};


/*
 * RcvArray entry allocation for Expected Receives is done by the
 * following algorithm:
 *
 * The context keeps 3 lists of groups of RcvArray entries:
 *   1. List of empty groups - tid_group_list
 *      This list is created during user context creation and
 *      contains elements which describe sets (of 8) of empty
 *      RcvArray entries.
 *   2. List of partially used groups - tid_used_list
 *      This list contains sets of RcvArray entries which are
 *      not completely used up. Another mapping request could
 *      use some of all of the remaining entries.
 *   3. List of full groups - tid_full_list
 *      This is the list where sets that are completely used
 *      up go.
 *
 * An attempt to optimize the usage of RcvArray entries is
 * made by finding all sets of physically contiguous pages in a
 * user's buffer.
 * These physically contiguous sets are further split into
 * sizes supported by the receive engine of the HFI. The
 * resulting sets of pages are stored in struct tid_pageset,
 * which describes the sets as:
 *    * .count - number of pages in this set
 *    * .idx - starting index into struct page ** array
 *                    of this set
 *
 * From this point on, the algorithm deals with the page sets
 * described above. The number of pagesets is divided by the
 * RcvArray group size to produce the number of full groups
 * needed.
 *
 * Groups from the 3 lists are manipulated using the following
 * rules:
 *   1. For each set of 8 pagesets, a complete group from
 *      tid_group_list is taken, programmed, and moved to
 *      the tid_full_list list.
 *   2. For all remaining pagesets:
 *      2.1 If the tid_used_list is empty and the tid_group_list
 *          is empty, stop processing pageset and return only
 *          what has been programmed up to this point.
 *      2.2 If the tid_used_list is empty and the tid_group_list
 *          is not empty, move a group from tid_group_list to
 *          tid_used_list.
 *      2.3 For each group is tid_used_group, program as much as
 *          can fit into the group. If the group becomes fully
 *          used, move it to tid_full_list.
 */
int hfi1_user_exp_rcv_setup(struct hfi1_filedata *fd, struct hfi1_tid_info *tinfo)
{
	int ret = -EFAULT;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	uintptr_t vaddr = tinfo->vaddr;
	u32 tid[20]; /* at most 20 requests with this algorithm */
	u16 tididx = 0;
	u16 order;
	u32 npages;
	struct process_vm *vm = cpu_local_var(current)->vm;
	size_t base_pgsize;
	pte_t *ptep;
	u64 phys;

	if (!tinfo->length)
		return -EINVAL;

	if (tinfo->length / PAGE_SIZE > uctxt->expected_count) {
		kprintf("Expected buffer too big\n");
		return -EINVAL;
	}

	/* Verify that access is OK for the user buffer */
	// TODO: iterate over vm memory ranges for write access
	// return -EFAULT;

	/* Simplified design: vaddr to vaddr + tinfo->length is contiguous
	 * for us, but program_rcvarray only deals with powers of two
	 * -> we need as many requests as there are bits set in length
	 *
	 * Note that we only work with multiples of 4k, so round up and shift
	 */
	npages = (tinfo->length + 4095) >> 12;

	ptep = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
				    (void*)vaddr, 0, 0, &base_pgsize, 0);
	if (unlikely(!ptep || !pte_is_present(ptep))) {
		kprintf("%s: ERRROR: no valid  PTE for 0x%lx\n",
			__FUNCTION__, vaddr);
		return -EFAULT;
	}
	phys = pte_get_phys(ptep);


	for (order = 0; order < 20; order++)
	{
		struct tid_group *grp;

		if (!(npages & (1 << order)))
			continue;

		spin_lock(&fd->tid_lock);
		if (!uctxt->tid_used_list.count) {
			if (!uctxt->tid_group_list.count) {
				goto unlock;
			}

			grp = tid_group_pop(&uctxt->tid_group_list);
		} else {
			grp = tid_group_pop(&uctxt->tid_used_list);
		}

		ret = program_rcvarray(fd, phys, order, grp, tid + (tididx++));
		if (ret < 0) {
			hfi1_cdbg(TID,
				  "Failed to program RcvArray entries %d",
				  ret);
			ret = -EFAULT;
		} else if (WARN_ON(ret == 0)) {
			ret = -EFAULT;
		}

		if (grp->used == grp->size)
			tid_group_add_tail(grp, &uctxt->tid_full_list);
		else
			tid_group_add_tail(grp, &uctxt->tid_used_list);
unlock:
		spin_unlock(&fd->tid_lock);

		phys += 1 << (order+12);
		if (ret < 0)
			break;
	}
	if (ret > 0) {
		// TODO: can we use spin_lock with kernel locks?
		spin_lock(&fd->tid_lock);
		fd->tid_used += tididx;
		spin_unlock(&fd->tid_lock);
		tinfo->tidcnt = tididx;

		if (copy_to_user((void __user *)(unsigned long)tinfo->tidlist,
				 tid, sizeof(tid)*tididx)) {
			/*
			 * On failure to copy to the user level, we need to undo
			 * everything done so far so we don't leak resources.
			 */
			tinfo->tidlist = (unsigned long)&tid;
			hfi1_user_exp_rcv_clear(fd, tinfo);
			tinfo->tidlist = 0;
			ret = -EFAULT;
		}
	}

	return ret > 0 ? 0 : ret;
}

int hfi1_user_exp_rcv_clear(struct hfi1_filedata *fd, struct hfi1_tid_info *tinfo)
{
	int ret = 0;
	u32 *tidinfo;
	unsigned tididx;

	tidinfo = kcalloc(tinfo->tidcnt, sizeof(*tidinfo), GFP_KERNEL);
	if (!tidinfo)
		return -ENOMEM;

	if (copy_from_user(tidinfo, (void __user *)(unsigned long)
			   tinfo->tidlist, sizeof(tidinfo[0]) *
			   tinfo->tidcnt)) {
		ret = -EFAULT;
		goto done;
	}

	spin_lock(&fd->tid_lock);
	for (tididx = 0; tididx < tinfo->tidcnt; tididx++) {
		ret = unprogram_rcvarray(fd, tidinfo[tididx], NULL);
		if (ret) {
			hfi1_cdbg(TID, "Failed to unprogram rcv array %d",
				  ret);
			break;
		}
	}
	fd->tid_used -= tididx;
	spin_unlock(&fd->tid_lock);
	tinfo->tidcnt = tididx;
done:
	kfree(tidinfo);
	return ret;
}

int hfi1_user_exp_rcv_invalid(struct hfi1_filedata *fd, struct hfi1_tid_info *tinfo)
{
#if 0
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	unsigned long *ev = uctxt->dd->events +
		(((uctxt->ctxt - uctxt->dd->first_user_ctxt) *
		  HFI1_MAX_SHARED_CTXTS) + fd->subctxt);
	u32 *array;
	int ret = 0;

	if (!fd->invalid_tids)
		return -EINVAL;

	/*
	 * copy_to_user() can sleep, which will leave the invalid_lock
	 * locked and cause the MMU notifier to be blocked on the lock
	 * for a long time.
	 * Copy the data to a local buffer so we can release the lock.
	 */
	array = kcalloc(uctxt->expected_count, sizeof(*array), GFP_KERNEL);
	if (!array)
		return -EFAULT;

	spin_lock(&fd->invalid_lock);
	if (fd->invalid_tid_idx) {
		memcpy(array, fd->invalid_tids, sizeof(*array) *
		       fd->invalid_tid_idx);
		memset(fd->invalid_tids, 0, sizeof(*fd->invalid_tids) *
		       fd->invalid_tid_idx);
		tinfo->tidcnt = fd->invalid_tid_idx;
		fd->invalid_tid_idx = 0;
		/*
		 * Reset the user flag while still holding the lock.
		 * Otherwise, PSM can miss events.
		 */
		clear_bit(_HFI1_EVENT_TID_MMU_NOTIFY_BIT, ev);
	} else {
		tinfo->tidcnt = 0;
	}
	spin_unlock(&fd->invalid_lock);

	if (tinfo->tidcnt) {
		if (copy_to_user((void __user *)tinfo->tidlist,
				 array, sizeof(*array) * tinfo->tidcnt))
			ret = -EFAULT;
	}
	kfree(array);

	return ret;
#endif
	return 0;
}
/**
 * program_rcvarray() - program an RcvArray group with receive buffers
 * @fd: file data
 * @vaddr: starting user virtual address
 * @grp: RcvArray group
 * @sets: array of struct tid_pageset holding information on physically
 *        contiguous chunks from the user buffer
 * @start: starting index into sets array
 * @count: number of struct tid_pageset's to program
 * @pages: an array of struct page * for the user buffer
 * @ptid: information about the programmed RcvArray entries is to be encoded.
 * @tididx: starting offset into tidlist
 *
 * This function will program up to 'count' number of RcvArray entries from the
 * group 'grp'. To make best use of write-combining writes, the function will
 * perform writes to the unused RcvArray entries which will be ignored by the
 * HW. Each RcvArray entry will be programmed with a physically contiguous
 * buffer chunk from the user's virtual buffer.
 *
 * Return:
 * -EINVAL if the requested count is larger than the size of the group,
 * -ENOMEM or -EFAULT on error from set_rcvarray_entry(), or
 * number of RcvArray entries programmed.
 */
static int program_rcvarray(struct hfi1_filedata *fd, uintptr_t phys,
			    u16 order,
			    struct tid_group *grp,
			    u32 *ptid)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;
	u16 idx;
	u32 tidinfo = 0, rcventry;

	/* Find the first unused entry in the group */
	for (idx = 0; idx < grp->size; idx++) {
		if (!(grp->map & (1 << idx))) {
			break;
		}
	}

	int ret = 0;

	/*
	 * If this entry in the group is used, move to the next one.
	 * If we go past the end of the group, exit the loop.
	 */
	rcv_array_wc_fill(dd, grp->base + idx);

	rcventry = grp->base + idx;

	ret = set_rcvarray_entry(fd, phys, rcventry, grp,
				 order);
	if (ret)
		return ret;

	tidinfo = rcventry2tidinfo(rcventry - uctxt->expected_base);
	*ptid = tidinfo;
	grp->used++;
	grp->map |= 1 << idx++;

	return 1;
}

static int set_rcvarray_entry(struct hfi1_filedata *fd, uintptr_t phys,
			      u32 rcventry, struct tid_group *grp,
			      u16 order)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;
	struct tid_rb_node *node;

	/*
	 * Allocate the node first so we can handle a potential
	 * failure before we've programmed anything.
	 */
	node = kcalloc(1, sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	kprintf("Registering rcventry %d, phys 0x%p, len %u\n", rcventry, phys, 1 << (order+12));

	node->phys = phys;
	node->len = 1 << (order+12);
	node->rcventry = rcventry;
	node->grp = grp;
	// TODO: check node->rcventry - uctxt->expected_base is within
	// [0; uctxt->expected_count[ ?
	fd->entry_to_rb[node->rcventry - uctxt->expected_base] = node;


	hfi1_put_tid(dd, rcventry, PT_EXPECTED, phys, order+1);
#if 0
	trace_hfi1_exp_tid_reg(uctxt->ctxt, fd->subctxt, rcventry, npages,
			       node->mmu.addr, node->phys, phys);
#endif
	return 0;
}

static int unprogram_rcvarray(struct hfi1_filedata *fd, u32 tidinfo,
			      struct tid_group **grp)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct tid_rb_node *node;
	u8 tidctrl = EXP_TID_GET(tidinfo, CTRL);
	u32 tididx = EXP_TID_GET(tidinfo, IDX) << 1, rcventry;

	if (tididx >= uctxt->expected_count) {
		kprintf("Invalid RcvArray entry (%u) index for ctxt %u\n",
			   tididx, uctxt->ctxt);
		return -EINVAL;
	}

	if (tidctrl == 0x3)
		return -EINVAL;

	rcventry = tididx + (tidctrl - 1);

	node = fd->entry_to_rb[rcventry];
	if (!node || node->rcventry != (uctxt->expected_base + rcventry))
		return -EBADF;

	if (grp)
		*grp = node->grp;

	kprintf("Clearing rcventry %d, phys 0x%p, len %u\n", node->rcventry,
		node->phys, node->len);

	fd->entry_to_rb[rcventry] = NULL;
	clear_tid_node(fd, node);

	return 0;
}

static void clear_tid_node(struct hfi1_filedata *fd, struct tid_rb_node *node)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;

#if 0
	trace_hfi1_exp_tid_unreg(uctxt->ctxt, fd->subctxt, node->rcventry,
				 node->npages, node->mmu.addr, node->phys,
				 node->dma_addr);
#endif

	hfi1_put_tid(dd, node->rcventry, PT_INVALID, 0, 0);
	/*
	 * Make sure device has seen the write before we unpin the
	 * pages.
	 */
	flush_wc();

#if 0
	pci_unmap_single(dd->pcidev, node->dma_addr, node->mmu.len,
			 PCI_DMA_FROMDEVICE);
	hfi1_release_user_pages(fd->mm, node->pages, node->npages, true);
	fd->tid_n_pinned -= node->npages;
#endif


	node->grp->used--;
	node->grp->map &= ~(1 << (node->rcventry - node->grp->base));

	if (node->grp->used == node->grp->size - 1)
		tid_group_move(node->grp, &uctxt->tid_full_list,
			       &uctxt->tid_used_list);
	else if (!node->grp->used)
		tid_group_move(node->grp, &uctxt->tid_used_list,
			       &uctxt->tid_group_list);
	kfree(node);
}
