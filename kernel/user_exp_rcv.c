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
#include <hfi1/user_sdma.h> // for hfi1_map_device_addresses

//#define DEBUG_PRINT_USER_EXP_RCV

#ifdef DEBUG_PRINT_USER_EXP_RCV
#define dkprintf(...) kprintf(__VA_ARGS__)
#else
#define dkprintf(...) do { if(0) kprintf(__VA_ARGS__); } while (0)
#endif

static int program_rcvarray(struct hfi1_filedata *, unsigned long, uintptr_t,
		size_t, u32 *);
static int set_rcvarray_entry(struct hfi1_filedata *, unsigned long, uintptr_t,
		u32, struct tid_group *, int, u32);
static int unprogram_rcvarray(struct hfi1_filedata *, u32, struct tid_group **);
static void clear_tid_node(struct hfi1_filedata *, struct tid_rb_node *);
static int tid_rb_invalidate(struct hfi1_filedata *fdata,
		struct tid_rb_node *node);

static int hfi1_rb_tree_insert(struct rb_root *root,
		struct tid_rb_node *new_node);
static void __hfi1_rb_tree_remove(struct tid_rb_node *tid_node);
static struct tid_rb_node *__hfi1_search_rb_overlapping_node(
		struct rb_root *root,
		unsigned long start,
		unsigned long end);

/*
 * RcvArray entry allocation for Expected Receives is done by the
 * following algorithm:
 */
int hfi1_user_exp_rcv_setup(struct hfi1_filedata *fd, struct hfi1_tid_info *tinfo)
{
	int ret = -EFAULT;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	uintptr_t vaddr, vaddr_end, base_vaddr = 0;
	u32 *tidlist;
	u16 tididx = 0;
	struct process_vm *vm = cpu_local_var(current)->vm;
	size_t base_pgsize, len = 0;
	pte_t *ptep;
	u64 phys;

	if (!tinfo->length)
		return -EINVAL;

	if (tinfo->length / PAGE_SIZE > uctxt->expected_count) {
		kprintf("Expected buffer too big\n");
		return -EINVAL;
	}

	/* TODO: sizeof(*tidlist) * uctxt->expected_count); */
	tidlist = kmalloc_cache_alloc(&cpu_local_var(tidlist_cache),
			sizeof(*tidlist) * 2048);

	if (!tidlist)
		return -ENOMEM;

#if 0
	/* Verify that access is OK for the user buffer */
	if (access_ok(vm, VERIFY_WRITE, tinfo->vaddr, tinfo->length))
		return -EFAULT;
#endif

	vaddr_end = tinfo->vaddr + tinfo->length;
	dkprintf("%s: vaddr: 0x%llx, length: %zu (end: 0x%lx)\n",
			__FUNCTION__, tinfo->vaddr, tinfo->length,
			tinfo->vaddr + tinfo->length);

	vaddr = tinfo->vaddr;

	ptep = ihk_mc_pt_lookup_fault_pte(vm,
			(void*)vaddr, 0,
			(void**)&base_vaddr,
			&base_pgsize, 0);
	if (unlikely(!ptep || !pte_is_present(ptep))) {
		kprintf("%s: ERROR: no valid  PTE for 0x%lx\n",
				__FUNCTION__, vaddr);
		return -EFAULT;
	}

	while (vaddr < vaddr_end) {
		phys = pte_get_phys(ptep) + (vaddr - base_vaddr);
		len = (base_vaddr + base_pgsize - vaddr);
		ret = 0;

		/* Are we right at a page border? */
		if (len == 0) {
			ptep = ihk_mc_pt_lookup_fault_pte(vm,
					(void*)vaddr, 0,
					(void**)&base_vaddr,
					&base_pgsize, 0);
			if (unlikely(!ptep || !pte_is_present(ptep))) {
				kprintf("%s: ERROR: no valid  PTE for 0x%lx\n",
						__FUNCTION__, vaddr);
				return -EFAULT;
			}

			phys = pte_get_phys(ptep) + (vaddr - base_vaddr);
			len = (base_vaddr + base_pgsize - vaddr);
		}

		/* Collect max physically contiguous chunk */
		while (len < MAX_EXPECTED_BUFFER &&
				vaddr + len < vaddr_end) {
			uintptr_t __base_vaddr;
			size_t __base_pgsize;
			pte_t *__ptep;
			int contiguous = 0;

			/* Look up next page */
			__ptep = ihk_mc_pt_lookup_fault_pte(vm,
					(void*)vaddr + len, 0,
					(void**)&__base_vaddr,
					&__base_pgsize, 0);
			if (unlikely(!__ptep || !pte_is_present(__ptep))) {
				kprintf("%s: ERRROR: no valid  PTE for 0x%lx\n",
						__FUNCTION__, vaddr + len);
				ret = -EFAULT;
				break;
			}

			/* Contiguous? */
			if (pte_get_phys(__ptep) == pte_get_phys(ptep) + base_pgsize) {
				len += __base_pgsize;
				contiguous = 1;
			}

			base_pgsize = __base_pgsize;
			base_vaddr = __base_vaddr;
			ptep = __ptep;

			if (!contiguous)
				break;
		}

		if (ret == -EFAULT)
			break;

		if (len > vaddr_end - vaddr) {
			len = vaddr_end - vaddr;
		}

		if (len > MAX_EXPECTED_BUFFER) {
			len = MAX_EXPECTED_BUFFER;
		}

		ret = program_rcvarray(fd, vaddr, phys, len, tidlist + tididx);
		if (ret <= 0) {
			kprintf("%s: failed to program RcvArray entries for len: %lu"
					", vaddr: 0x%lx, vaddr_end: 0x%lx, ret: %d\n",
					__FUNCTION__, len, vaddr, vaddr_end, ret);
			panic("program_rcvarray() failed");
			ret = -EFAULT;
		}

		dkprintf("%s: vaddr: 0x%lx -> phys: 0x%llx:%lu programmed\n",
			__FUNCTION__, vaddr, phys, len);

		tididx += ret;
		vaddr += len;
	}

	if (ret > 0) {
		linux_spin_lock(&fd->tid_lock);
		fd->tid_used += tididx;
		linux_spin_unlock(&fd->tid_lock);
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

		dkprintf("%s: range: 0x%llx:%lu -> %d TIDs programmed\n",
			__FUNCTION__, tinfo->vaddr, tinfo->length, tinfo->tidcnt);
	}

	kmalloc_cache_free(tidlist);
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

	/* Technically should never be needed (because mapped previously
	 * on update), but this call is no-op if addresses have been set
	 * previously
	if (hfi1_map_device_addresses(fd) < 0) {
		kprintf("%s: Could not map hfi1 device addresses\n",
			__FUNCTION__);
		return -EINVAL;
	}
	*/

	for (tididx = 0; tididx < tinfo->tidcnt; tididx++) {
		ret = unprogram_rcvarray(fd, tidinfo[tididx], NULL);
		if (ret) {
			kprintf("Failed to unprogram rcv array %d\n",
				  ret);
			break;
		}
	}

	dkprintf("%s: 0x%llx:%lu -> %d TIDs unprogrammed\n",
			__FUNCTION__, tinfo->vaddr, tinfo->length, tinfo->tidcnt);

	linux_spin_lock(&fd->tid_lock);
	fd->tid_used -= tididx;
	linux_spin_unlock(&fd->tid_lock);

	tinfo->tidcnt = tididx;
done:
	kfree(tidinfo);
	return ret;
}


/**
 * program_rcvarray() - program an RcvArray group with receive buffers
 */
static int program_rcvarray(struct hfi1_filedata *fd,
				unsigned long vaddr,
				uintptr_t phys,
			    size_t len, u32 *ptid)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;
	u16 idx = 0;
	u32 tidinfo = 0, rcventry;
	int ret = -ENOMEM, count = 0;
	struct tid_group *grp = NULL;

	/* lock is taken at loop edges */
	linux_spin_lock(&fd->tid_lock);
	while (len > 0) {
		size_t tid_len;
		size_t tid_npages;

		if (!grp) {
			if (!uctxt->tid_used_list.count) {
				if (!uctxt->tid_group_list.count) {
					linux_spin_unlock(&fd->tid_lock);
					/* return what we have so far */
					kprintf("%s: ERROR: no grp?\n", __FUNCTION__);
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
		linux_spin_unlock(&fd->tid_lock);

		tid_len = (len > MAX_EXPECTED_BUFFER) ? MAX_EXPECTED_BUFFER :
			(1 << (fls(len) - 1));
		tid_npages = (tid_len > PAGE_SIZE) ? tid_len >> PAGE_SHIFT : 1;

		rcventry = grp->base + idx;
		rcv_array_wc_fill(dd, rcventry);
		tidinfo = rcventry2tidinfo(rcventry - uctxt->expected_base) |
			EXP_TID_SET(LEN, tid_npages);
		ret = set_rcvarray_entry(fd, vaddr, phys, rcventry,
				grp, tid_npages, tidinfo);
		if (ret) {
			kprintf("%s: set_rcvarray_entry() failed: %d\n",
				__FUNCTION__, ret);
			return ret;
		}

		ptid[count++] = tidinfo;
		len -= tid_len;
		vaddr += tid_len;
		phys += tid_len;

		linux_spin_lock(&fd->tid_lock);
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
	linux_spin_unlock(&fd->tid_lock);

	return count;
}

static int set_rcvarray_entry(struct hfi1_filedata *fd,
		unsigned long vaddr, uintptr_t phys,
		u32 rcventry, struct tid_group *grp,
		int npages, u32 tidinfo)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_devdata *dd = uctxt->dd;
	struct tid_rb_node *node;

	/*
	 * Allocate the node first so we can handle a potential
	 * failure before we've programmed anything.
	 */
	node = kmalloc_cache_alloc(&cpu_local_var(tid_node_cache),
			sizeof(*node));
	if (!node) {
		kprintf("%s: ERROR: allocating node\n", __FUNCTION__);
		return -ENOMEM;
	}

	dkprintf("Registering rcventry %d, phys 0x%p, len %u\n", rcventry,
		 phys, npages << PAGE_SHIFT);

	node->phys = phys;
	node->len = npages << PAGE_SHIFT;
	node->rcventry = rcventry;
	node->grp = grp;
	node->freed = false;
	node->fd = fd;
	node->start = vaddr;
	node->end = vaddr + node->len;
	node->range = NULL;

	// TODO: check node->rcventry - uctxt->expected_base is within
	// [0; uctxt->expected_count[ ?
	fd->entry_to_rb[node->rcventry - uctxt->expected_base] = node;
	hfi1_rb_tree_insert(
			&cpu_local_var(current)->proc->hfi1_reg_tree,
			node);
	dkprintf("%s: node (0x%lx:%lu) programmed, tidinfo: %d\n",
		__FUNCTION__, vaddr, node->len, tidinfo);

	hfi1_put_tid(dd, rcventry, PT_EXPECTED, phys, fls(npages));
#if 0
	trace_hfi1_exp_tid_reg(uctxt->ctxt, fd->subctxt, rcventry, npages,
			       node->mmu.addr, node->phys, phys);
#endif
	return 0;
}


int hfi1_user_exp_rcv_invalid(struct hfi1_filedata *fd, struct hfi1_tid_info *tinfo)
{
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	unsigned long *ev = uctxt->dd->events +
		(((uctxt->ctxt - uctxt->dd->first_dyn_alloc_ctxt) *
		  HFI1_MAX_SHARED_CTXTS) + fd->subctxt);
	int ret = 0;

	if (!fd->invalid_tids)
		return -EINVAL;

	/*
	 * copy_to_user() can sleep, which will leave the invalid_lock
	 * locked and cause the MMU notifier to be blocked on the lock
	 * for a long time.
	 * Copy the data to a local buffer so we can release the lock.
	 *
	 * McKernel: copy to userspace directly.
	 */

	linux_spin_lock(&fd->invalid_lock);
	if (fd->invalid_tid_idx) {
		dkprintf("%s: fd->invalid_tid_idx: %d to be notified\n",
				__FUNCTION__, fd->invalid_tid_idx);

		if (copy_to_user((void __user *)tinfo->tidlist,
					fd->invalid_tids,
					sizeof(*(fd->invalid_tids)) *
					fd->invalid_tid_idx)) {
			ret = -EFAULT;
		}
		else {
			tinfo->tidcnt = fd->invalid_tid_idx;
			memset(fd->invalid_tids, 0, sizeof(*fd->invalid_tids) *
					fd->invalid_tid_idx);
			/*
			 * Reset the user flag while still holding the lock.
			 * Otherwise, PSM can miss events.
			 */
			clear_bit(_HFI1_EVENT_TID_MMU_NOTIFY_BIT, ev);
			dkprintf("%s: fd->invalid_tid_idx: %d notified\n",
					__FUNCTION__, fd->invalid_tid_idx);
			fd->invalid_tid_idx = 0;
		}
	}
	else {
		tinfo->tidcnt = 0;
	}
	linux_spin_unlock(&fd->invalid_lock);

	return ret;
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
	dkprintf("%s: node (0x%lx:%lu), tidinfo: %d\n",
			__FUNCTION__, node->start, node->end - node->start, tidinfo);

	if (!node || node->rcventry != (uctxt->expected_base + rcventry)) {
		kprintf("bad entry %d\n", rcventry);
		return -EBADF;
	}

	if (node->range) {
		struct process_vm *vm = cpu_local_var(current)->vm;
		struct deferred_unmap_range *range = node->range;

		//ihk_mc_spinlock_lock_noirq(&vm->vm_deferred_unmap_lock);

		if (--range->refcnt == 0) {
			list_del(&range->list);
		}
		else {
			range = NULL;
		}
		//ihk_mc_spinlock_unlock_noirq(&vm->vm_deferred_unmap_lock);

		if (range) {
			dkprintf("%s: executing deferred unmap: 0x%lx:%lu-0x%lx\n",
					__FUNCTION__, range->addr, range->len,
					range->addr + range->len);

			ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);
			do_munmap(range->addr, range->len);
			ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);

			kfree(range);
		}
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
	barrier();

	__hfi1_rb_tree_remove(node);

	linux_spin_lock(&fd->tid_lock);
	node->grp->used--;
	node->grp->map &= ~(1 << (node->rcventry - node->grp->base));

	if (node->grp->used == node->grp->size - 1)
		tid_group_move(node->grp, &uctxt->tid_full_list,
			       &uctxt->tid_used_list);
	else if (!node->grp->used)
		tid_group_move(node->grp, &uctxt->tid_used_list,
			       &uctxt->tid_group_list);
	linux_spin_unlock(&fd->tid_lock);
	kmalloc_cache_free(node);
}


int hfi1_user_exp_rcv_overlapping(unsigned long start, unsigned long end)
{
	int ret = 0;
	struct process_vm *vm = cpu_local_var(current)->vm;
	struct tid_rb_node *node;
	struct deferred_unmap_range *range;

	dkprintf("%s: 0x%lx:%lu\n", __FUNCTION__, start, end - start);

	//ihk_mc_spinlock_lock_noirq(&vm->vm_deferred_unmap_lock);

	node = __hfi1_search_rb_overlapping_node(
			&cpu_local_var(current)->proc->hfi1_reg_tree,
			start, end);
	if (!node || node->freed) {
		return 0;
	}

	range = kmalloc(sizeof(*range), IHK_MC_AP_NOWAIT);
	if (!range) {
		kprintf("%s: ERROR: allocating memory\n", __FUNCTION__);
		return -ENOMEM;
	}

	init_deferred_unmap_range(range, vm, (void *)start, end - start);

	while (node) {
		struct hfi1_filedata *fd = node->fd;
		struct hfi1_ctxtdata *uctxt = fd ? fd->uctxt : NULL;

		/* Sanity check */
		if (!uctxt ||
				fd->entry_to_rb[node->rcventry - uctxt->expected_base] != node) {
			kprintf("%s: ERROR: inconsistent TID node\n", __FUNCTION__);
			ret = -EINVAL;
			break;
		}

		dkprintf("%s: node (0x%lx:%lu) deferred and invalidated"
				" in munmap for 0x%lx:%lu-0x%lx\n",
				__FUNCTION__, node->start, node->len, start, end - start, end);
		tid_rb_invalidate(fd, node);
		if (node->range) {
			kprintf("%s: WARNING: node->range is already set for 0x%lx:%lu\n",
				__FUNCTION__, start, end);
		}
		else {
			node->range = range;
		}
		++range->refcnt;

		node = __hfi1_search_rb_overlapping_node(
				&cpu_local_var(current)->proc->hfi1_reg_tree,
				start, end);
	}

	if (range->refcnt == 0) {
		kfree(range);
	}
	else {
		list_add_tail(&range->list, &vm->vm_deferred_unmap_range_list);
		ret = range->refcnt;
	}

	//ihk_mc_spinlock_unlock_noirq(&vm->vm_deferred_unmap_lock);

	return ret;
}

static int hfi1_rb_tree_insert(struct rb_root *root,
		struct tid_rb_node *new_node)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct tid_rb_node *tid_node;

	while (*new) {
		tid_node = rb_entry(*new, struct tid_rb_node, rb_node);
		parent = *new;

		if (new_node->end <= tid_node->start) {
			new = &((*new)->rb_left);
		}
		else if (new_node->start >= tid_node->end) {
			new = &((*new)->rb_right);
		}
		else {
			kprintf("%s: ERROR: overlapping TID nodes, "
					"node (0x%lx:%lu) <=> new (0x%lx:%lu)\n",
					__FUNCTION__,
					tid_node->start, tid_node->len,
					new_node->start, new_node->len);
			return -EINVAL;
		}
	}

	rb_link_node(&new_node->rb_node, parent, new);
	rb_insert_color(&new_node->rb_node, root);
	new_node->rb_root = root;

	return 0;
}

static void __hfi1_rb_tree_remove(struct tid_rb_node *tid_node)
{
	if (!tid_node->rb_root) {
		kprintf("%s: ERROR: node without rb_root??\n",
			__FUNCTION__);
		return;
	}
	rb_erase(&tid_node->rb_node, tid_node->rb_root);
	tid_node->rb_root = NULL;
}

static struct tid_rb_node *__hfi1_search_rb_overlapping_node(
	struct rb_root *root,
	unsigned long start,
	unsigned long end)
{
	struct rb_node *node = root->rb_node;
	struct tid_rb_node *tid_node = NULL;

	while (node) {
		tid_node = rb_entry(node, struct tid_rb_node, rb_node);

		if (end <= tid_node->start) {
			node = node->rb_left;
		}
		else if (start >= tid_node->end) {
			node = node->rb_right;
		}
		else if (tid_node->freed) {
			node = rb_next(node);
		}
		else {
			break;
		}
	}

	return node ? tid_node : NULL;
}

/*
 * Always return 0 from this function.  A non-zero return indicates that the
 * remove operation will be called and that memory should be unpinned.
 * However, the driver cannot unpin out from under PSM.  Instead, retain the
 * memory (by returning 0) and inform PSM that the memory is going away.  PSM
 * will call back later when it has removed the memory from its list.
 *
 * XXX: in McKernel we attach tid nodes to memory ranges that are
 * about to be unmapped. Once we got all of them cleared, the actual
 * unmap is performed.
 */
static int tid_rb_invalidate(struct hfi1_filedata *fdata,
		struct tid_rb_node *node)
{
	struct hfi1_ctxtdata *uctxt = fdata->uctxt;

	if (node->freed)
		return 0;

	node->freed = true;
	__hfi1_rb_tree_remove(node);
	hfi1_rb_tree_insert(
			&cpu_local_var(current)->proc->hfi1_inv_tree,
			node);

	linux_spin_lock(&fdata->invalid_lock);
	if (fdata->invalid_tid_idx < uctxt->expected_count) {
		fdata->invalid_tids[fdata->invalid_tid_idx] =
			rcventry2tidinfo(node->rcventry - uctxt->expected_base);
		fdata->invalid_tids[fdata->invalid_tid_idx] |=
			EXP_TID_SET(LEN, node->len >> PAGE_SHIFT);
		if (!fdata->invalid_tid_idx) {
			unsigned long *ev;

			/*
			 * hfi1_set_uevent_bits() sets a user event flag
			 * for all processes. Because calling into the
			 * driver to process TID cache invalidations is
			 * expensive and TID cache invalidations are
			 * handled on a per-process basis, we can
			 * optimize this to set the flag only for the
			 * process in question.
			 */
			ev = uctxt->dd->events +
				(((uctxt->ctxt - uctxt->dd->first_dyn_alloc_ctxt) *
				  HFI1_MAX_SHARED_CTXTS) + fdata->subctxt);
			set_bit(_HFI1_EVENT_TID_MMU_NOTIFY_BIT, ev);
		}
		fdata->invalid_tid_idx++;
	}
	linux_spin_unlock(&fdata->invalid_lock);
	return 0;
}
