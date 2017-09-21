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

//#define DEBUG_PRINT_USER_EXP_RCV

#ifdef DEBUG_PRINT_USER_EXP_RCV
#define dkprintf(...) kprintf(__VA_ARGS__)
#else
#define dkprintf(...) do { if(0) kprintf(__VA_ARGS__); } while (0)
#endif

static int program_rcvarray(struct hfi1_filedata *, uintptr_t, size_t, u32 *);
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
 */
int hfi1_user_exp_rcv_setup(struct hfi1_filedata *fd, struct hfi1_tid_info *tinfo)
{
	int ret = -EFAULT;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	uintptr_t vaddr_prev, vaddr, vaddr_end;
	u32 *tidlist;
	u16 tididx = 0;
	struct process_vm *vm = cpu_local_var(current)->vm;
	size_t base_pgsize, len = 0;
	pte_t *ptep;
	u64 phys_start = 0, phys_prev = 0, phys;

	if (!tinfo->length)
		return -EINVAL;

	if (tinfo->length / PAGE_SIZE > uctxt->expected_count) {
		kprintf("Expected buffer too big\n");
		return -EINVAL;
	}

	tidlist = kmalloc(sizeof(*tidlist)*uctxt->expected_count,
			  IHK_MC_AP_NOWAIT);
	if (!tidlist)
		return -ENOMEM;

	/* Verify that access is OK for the user buffer */
	// TODO: iterate over vm memory ranges for write access
	// return -EFAULT;

	vaddr_end = tinfo->vaddr + tinfo->length;
	dkprintf("setup start: 0x%llx, length: %zu\n", tinfo->vaddr,
		 tinfo->length);
	for (vaddr = tinfo->vaddr; vaddr < vaddr_end; vaddr += base_pgsize) {
		ptep = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
					    (void*)vaddr, 0, 0, &base_pgsize,
					    0);
		if (unlikely(!ptep || !pte_is_present(ptep))) {
			kprintf("%s: ERRROR: no valid  PTE for 0x%lx\n",
				__FUNCTION__, vaddr);
			ret = -EFAULT;
			break;
		}
		phys = pte_get_phys(ptep);

		if (!phys_prev) {
			/* first pass */
			phys_start = phys;
		} else if (len == MAX_EXPECTED_BUFFER ||
				phys - phys_prev != vaddr - vaddr_prev) {
			/*
			 *  Two ways to get here:
			 *  - Segment has reached max size;
			 *  - Found a new segment;
			 *
			 * Register what we have.
			 */
			ret = program_rcvarray(fd, phys_start, len,
					       tidlist + tididx);
			if (ret <= 0) {
				kprintf("Failed to program RcvArray entries: %d\n",
					ret);
				ret = -EFAULT;
			}

			tididx += ret;
			phys_start = phys;
			len = 0;
		}

		/* Corner case #1: base_pgsize is too big (requested length) */
		if (vaddr + base_pgsize > vaddr_end) {
			base_pgsize = vaddr_end - vaddr;
		}

		/* Corner case #2: base_pgsize is too big (max request size).
		 * This will result in an extra virt to phys lookup,
		 * but should be rare in practice
		 */
		if (len + base_pgsize > MAX_EXPECTED_BUFFER) {
			size_t extra = len + base_pgsize - MAX_EXPECTED_BUFFER;
			phys -= extra;
			vaddr -= extra;
			base_pgsize -= extra;
		}
		phys_prev = phys;
		vaddr_prev = vaddr;
		len += base_pgsize;
		dkprintf("phys 0x%llx, vaddr 0x%llx, len %zu, base_pgsize %zu\n",
			 phys, vaddr, len, base_pgsize);
	}

	/* Register whatever is left */
	ret = program_rcvarray(fd, phys_start, len,
			       tidlist + tididx);
	if (ret <= 0) {
		kprintf("Failed to program RcvArray entries: %d\n",
			ret);
		ret = -EFAULT;
	}
	tididx += ret;

	if (ret > 0) {
		spin_lock(&fd->tid_lock);
		fd->tid_used += tididx;
		spin_unlock(&fd->tid_lock);
		tinfo->tidcnt = tididx;

		if (copy_to_user((void __user *)(unsigned long)tinfo->tidlist,
				 tidlist, sizeof(*tidlist)*tididx)) {
			/*
			 * On failure to copy to the user level, we need to undo
			 * everything done so far so we don't leak resources.
			 */
			tinfo->tidlist = (unsigned long)&tidlist;
			hfi1_user_exp_rcv_clear(fd, tinfo);
			tinfo->tidlist = 0;
			ret = -EFAULT;
		}
	}

	kfree(tidlist);
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

	dkprintf("Clear called, cnt %d\n", tinfo->tidcnt);
	for (tididx = 0; tididx < tinfo->tidcnt; tididx++) {
		ret = unprogram_rcvarray(fd, tidinfo[tididx], NULL);
		if (ret) {
			kprintf("Failed to unprogram rcv array %d\n",
				  ret);
			break;
		}
	}
	fd->tid_used -= tididx;
	tinfo->tidcnt = tididx;
done:
	kfree(tidinfo);
	return ret;
}

/**
 * program_rcvarray() - program an RcvArray group with receive buffers
 */
static int program_rcvarray(struct hfi1_filedata *fd, uintptr_t phys,
			    size_t len, u32 *ptid)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;
	u16 idx = 0;
	s16 order;
	u32 tidinfo = 0, rcventry;
	int ret = -ENOMEM, count = 0;
	struct tid_group *grp = NULL;

	/* lock is taken at loop edges */
	spin_lock(&fd->tid_lock);
	while (len > 0) {
		if (!grp) {
			if (!uctxt->tid_used_list.count) {
				if (!uctxt->tid_group_list.count) {
					spin_unlock(&fd->tid_lock);
					/* return what we have so far */
					return count ? count : -ENOMEM;
				}

				grp = tid_group_pop(&uctxt->tid_group_list);
			} else {
				grp = tid_group_pop(&uctxt->tid_used_list);
			}
		}

		/* Find the first unused entry in the group */
		for (; idx < grp->size; idx++) {
			if (!(grp->map & (1 << idx))) {
				break;
			}
		}
		spin_unlock(&fd->tid_lock);


		/* order is power of two of 4k (2^12) pages */
		order = fls(len) - 13;
		if (order < 0)
			order = 0;
		dkprintf("len %u, order %u\n", len, order);

		rcv_array_wc_fill(dd, grp->base + idx);
		rcventry = grp->base + idx;
		ret = set_rcvarray_entry(fd, phys, rcventry, grp,
					 order);
		if (ret)
			return ret;

		tidinfo = rcventry2tidinfo(rcventry - uctxt->expected_base) |
			EXP_TID_SET(LEN, 1 << order);
		ptid[count++] = tidinfo;
		len -= 1 << (order + 12);
		phys += 1 << (order + 12);


		spin_lock(&fd->tid_lock);
		grp->used++;
		grp->map |= 1 << idx++;

		/* optimization: keep same group if possible. */
		if (grp->used < grp->size && len > 0)
			continue;

		if (grp->used == grp->size)
			tid_group_add_tail(grp, &uctxt->tid_full_list);
		else
			tid_group_add_tail(grp, &uctxt->tid_used_list);
		idx = 0;
		grp = NULL;
	}
	spin_unlock(&fd->tid_lock);

	return count;
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

	dkprintf("Registering rcventry %d, phys 0x%p, len %u\n", rcventry,
		 phys, 1 << (order+12));

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

	if (tidctrl == 0x3) {
		kprintf("tidctrl = 3 for rcventry %d\n",
			tididx + 2 + uctxt->expected_base);
		return -EINVAL;
	}

	rcventry = tididx + (tidctrl - 1);

	node = fd->entry_to_rb[rcventry];
	if (!node || node->rcventry != (uctxt->expected_base + rcventry)) {
		kprintf("bad entry %d\n", rcventry);
		return -EBADF;
	}

	if (grp)
		*grp = node->grp;

	dkprintf("Clearing rcventry %d, phys 0x%p, len %u\n", node->rcventry,
		node->phys, node->len);

	fd->entry_to_rb[rcventry] = NULL;
	clear_tid_node(fd, node);

	return 0;
}

static void clear_tid_node(struct hfi1_filedata *fd, struct tid_rb_node *node)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;


	hfi1_put_tid(dd, node->rcventry, PT_INVALID, 0, 0);
	/*
	 * Make sure device has seen the write before we unpin the
	 * pages.
	 */
	flush_wc();

	spin_lock(&fd->tid_lock);
	node->grp->used--;
	node->grp->map &= ~(1 << (node->rcventry - node->grp->base));

	if (node->grp->used == node->grp->size - 1)
		tid_group_move(node->grp, &uctxt->tid_full_list,
			       &uctxt->tid_used_list);
	else if (!node->grp->used)
		tid_group_move(node->grp, &uctxt->tid_used_list,
			       &uctxt->tid_group_list);
	spin_unlock(&fd->tid_lock);
	kfree(node);
}
