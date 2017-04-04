/**
 * \file xpmem.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Cross Partition Memory (XPMEM) support.
 */
/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (c) 2004-2007 Silicon Graphics, Inc.  All Rights Reserved.
 * Copyright 2010, 2014 Cray Inc. All Rights Reserved
 * Copyright 2015-2016 Los Alamos National Security, LLC. All rights reserved.
 */
/*
 * HISTORY
 */

#include <errno.h>
#include <kmalloc.h>
#include <limits.h>
#include <memobj.h>
#include <mman.h>
#include <string.h>
#include <types.h>
#include <vsprintf.h>
#include <ihk/lock.h>
#include <ihk/mm.h>
#include <xpmem_private.h>


struct xpmem_partition *xpmem_my_part = NULL;  /* pointer to this partition */


#if defined(POSTK_DEBUG_ARCH_DEP_46) || defined(POSTK_DEBUG_ARCH_DEP_62)
int xpmem_open(int num, const char *pathname,
		int flags, ihk_mc_user_context_t *ctx)
{
	int ret;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	int fd;
	struct mckfd *mckfd;
	long irqstate;

	XPMEM_DEBUG("call: syscall_num=%d, pathname=%s, flags=%d", num, pathname, flags);
#else /* POSTK_DEBUG_ARCH_DEP_46 || POSTK_DEBUG_ARCH_DEP_62 */
int xpmem_open(
	ihk_mc_user_context_t *ctx)
{
	const char *pathname = (const char *)ihk_mc_syscall_arg0(ctx);
	int flags = (int)ihk_mc_syscall_arg1(ctx);
	int ret;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct syscall_request request IHK_DMA_ALIGN;
	int fd;
	struct mckfd *mckfd;
	long irqstate;

	XPMEM_DEBUG("call: pathname=%s, flags=%d", pathname, flags);
#endif /* POSTK_DEBUG_ARCH_DEP_46 || POSTK_DEBUG_ARCH_DEP_62 */

	if (!xpmem_my_part) {
		ret = xpmem_init();
		if (ret) {
			return ret;
		}
	}

#ifdef POSTK_DEBUG_ARCH_DEP_62 /* Absorb the difference between open and openat args. */
	fd = syscall_generic_forwarding(num, ctx);
	if(fd < 0){
		XPMEM_DEBUG("syscall_num=%d error: fd=%d", num, fd);
		return fd;
	}
#else /* POSTK_DEBUG_ARCH_DEP_62 */
	request.number = __NR_open;
	request.args[0] = (unsigned long)pathname;
	request.args[1] = flags;
	fd = do_syscall(&request, ihk_mc_get_processor_id(), 0);
	if(fd < 0){
		XPMEM_DEBUG("__NR_open error: fd=%d", fd);
		return fd;
	}
#endif /* POSTK_DEBUG_ARCH_DEP_62 */

	ret = __xpmem_open();
	if (ret) {
		XPMEM_DEBUG("return: ret=%d", ret);
		return ret;
	}

	mckfd = kmalloc(sizeof(struct mckfd), IHK_MC_AP_NOWAIT);
	if(!mckfd) {
		return -ENOMEM;
	}
	XPMEM_DEBUG("kmalloc(): mckfd=0x%p", mckfd);
	memset(mckfd, 0, sizeof(struct mckfd));
	mckfd->fd = fd;
	mckfd->sig_no = -1;
	mckfd->ioctl_cb = xpmem_ioctl;
	mckfd->close_cb = xpmem_close;
	irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);

	if(proc->mckfd == NULL) {
		proc->mckfd = mckfd;
		mckfd->next = NULL;
	} else {
		mckfd->next = proc->mckfd;
		proc->mckfd = mckfd;
	}

	ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);

	ihk_atomic_inc_return(&xpmem_my_part->n_opened);

	XPMEM_DEBUG("return: ret=%d", mckfd->fd);

	return mckfd->fd;
}


static int xpmem_ioctl(
	struct mckfd *mckfd,
	ihk_mc_user_context_t *ctx)
{
	int ret;
	unsigned int cmd = ihk_mc_syscall_arg1(ctx);
	unsigned long arg = ihk_mc_syscall_arg2(ctx);

	XPMEM_DEBUG("call: cmd=0x%x, arg=0x%lx", cmd, arg);

	switch (cmd) {
	case XPMEM_CMD_VERSION: {
		ret = XPMEM_CURRENT_VERSION;

		XPMEM_DEBUG("return: cmd=0x%x, ret=0x%lx", cmd, ret);

		return ret;
	}
	case XPMEM_CMD_MAKE: {
		struct xpmem_cmd_make make_info;
		xpmem_segid_t segid = 0;

		if (copy_from_user(&make_info, (void __user *)arg, 
			sizeof(struct xpmem_cmd_make)))
			return -EFAULT;

		ret = xpmem_make(make_info.vaddr, make_info.size, 
			make_info.permit_type, 
			(void *)make_info.permit_value, &segid);
		if (ret != 0) {
			XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);
			return ret;
		}

		if (copy_to_user(&((struct xpmem_cmd_make __user *)arg)->segid, 
			(void *)&segid, sizeof(xpmem_segid_t))) {
			(void)xpmem_remove(segid);
			return -EFAULT;
		}

		XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);

		return ret;
	}
	case XPMEM_CMD_REMOVE: {
		struct xpmem_cmd_remove remove_info;

		if (copy_from_user(&remove_info, (void __user *)arg, 
			sizeof(struct xpmem_cmd_remove)))
			return -EFAULT;

		ret = xpmem_remove(remove_info.segid);

		XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);

		return ret;
	}
	case XPMEM_CMD_GET: {
		struct xpmem_cmd_get get_info;
//		xpmem_apid_t apid = 0;

		if (copy_from_user(&get_info, (void __user *)arg, 
			sizeof(struct xpmem_cmd_get)))
			return -EFAULT;

//		ret = xpmem_get(get_info.segid, get_info.flags,
//			get_info.permit_type,
//			(void *)get_info.permit_value, &apid); // TODO
		ret = -EINVAL;
		if (ret != 0) {
			XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);
			return ret;
		}

//		if (copy_to_user(&((struct xpmem_cmd_get __user *)arg)->apid, 
//			(void *)&apid, sizeof(xpmem_apid_t))) {
//			(void)xpmem_release(apid);
//			return -EFAULT;
//		}

		XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);

		return ret;
	}
	case XPMEM_CMD_RELEASE: {
		struct xpmem_cmd_release release_info;

		if (copy_from_user(&release_info, (void __user *)arg,
			sizeof(struct xpmem_cmd_release)))
			return -EFAULT;

//		ret = xpmem_release(release_info.apid); // TODO
		ret = -EINVAL;

		XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);

		return ret;
	}
	case XPMEM_CMD_ATTACH: {
		struct xpmem_cmd_attach attach_info;
//		unsigned long at_vaddr = 0;

		if (copy_from_user(&attach_info, (void __user *)arg, 
			sizeof(struct xpmem_cmd_attach)))
			return -EFAULT;

//		ret = xpmem_attach(mckfd, attach_info.apid, attach_info.offset, 
//			attach_info.size, attach_info.vaddr, 
//			attach_info.fd, attach_info.flags, 
//			&at_vaddr); // TODO
		ret = -EINVAL;
		if (ret != 0) {
			XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);
			return ret;
		}

//		if (copy_to_user(
//			&((struct xpmem_cmd_attach __user *)arg)->vaddr, 
//			(void *)&at_vaddr, sizeof(unsigned long))) {
//			(void)xpmem_detach(at_vaddr);
//			return -EFAULT;
//		}

		XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);

		return ret;
	}
	case XPMEM_CMD_DETACH: {
		struct xpmem_cmd_detach detach_info;

		if (copy_from_user(&detach_info, (void __user *)arg, 
			sizeof(struct xpmem_cmd_detach)))
			return -EFAULT;

//		ret = xpmem_detach(detach_info.vaddr); // TODO
		ret = -EINVAL;

		XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);

		return ret;
	}
	default:
		break;
	}

	XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, -EINVAL);

	return -EINVAL;
}


static int xpmem_close(
	struct mckfd *mckfd,
	ihk_mc_user_context_t *ctx)
{
	struct xpmem_thread_group *tg;
	int index;
	struct mcs_rwlock_node_irqsave lock;
	int n_opened;

	XPMEM_DEBUG("call: fd=%d", mckfd->fd);

	n_opened = ihk_atomic_dec_return(&xpmem_my_part->n_opened);
	if (n_opened) {
		XPMEM_DEBUG("return: ret=%d, n_opened=%d", 0, n_opened);
		return 0;
	}
	XPMEM_DEBUG("n_opened=%d", n_opened);

	index = xpmem_tg_hashtable_index(cpu_local_var(current)->proc->pid);

	mcs_rwlock_writer_lock(&xpmem_my_part->tg_hashtable[index].lock, &lock);

	tg = xpmem_tg_ref_by_tgid_all_nolock(
		cpu_local_var(current)->proc->pid);
	if (!tg) {
		mcs_rwlock_writer_unlock(
			&xpmem_my_part->tg_hashtable[index].lock, &lock);
		return 0;
	}

	list_del_init(&tg->tg_hashlist);

	mcs_rwlock_writer_unlock(&xpmem_my_part->tg_hashtable[index].lock, 
		&lock);

	XPMEM_DEBUG("tg->vm=0x%p", tg->vm);

	xpmem_destroy_tg(tg);

	if (!n_opened) {
		xpmem_exit();
	}

	XPMEM_DEBUG("return: ret=%d", 0);

	return 0;
}


static int xpmem_init(void)
{
	int i;

	XPMEM_DEBUG("call: ");

	xpmem_my_part = kmalloc(sizeof(struct xpmem_partition) + 
		sizeof(struct xpmem_hashlist) * XPMEM_TG_HASHTABLE_SIZE, 
		IHK_MC_AP_NOWAIT);
	if (xpmem_my_part == NULL) {
		return -ENOMEM;
	}
	XPMEM_DEBUG("kmalloc(): xpmem_my_part=0x%p", xpmem_my_part);
	memset(xpmem_my_part, 0, sizeof(struct xpmem_partition) + 
		sizeof(struct xpmem_hashlist) * XPMEM_TG_HASHTABLE_SIZE);

	for (i = 0; i < XPMEM_TG_HASHTABLE_SIZE; i++) {
		mcs_rwlock_init(&xpmem_my_part->tg_hashtable[i].lock);
		INIT_LIST_HEAD(&xpmem_my_part->tg_hashtable[i].list);
	}

	ihk_atomic_set(&xpmem_my_part->n_opened, 0);

	XPMEM_DEBUG("return: ret=%d", 0);

	return 0;
}


static void xpmem_exit(void)
{
	XPMEM_DEBUG("call: ");

	if (xpmem_my_part) {
		XPMEM_DEBUG("kfree(): 0x%p", xpmem_my_part);
		kfree(xpmem_my_part);
		xpmem_my_part = NULL;
	}

	XPMEM_DEBUG("return: ");
}


static int __xpmem_open(void)
{
	struct xpmem_thread_group *tg;
	int index;
	struct mcs_rwlock_node_irqsave lock;

	XPMEM_DEBUG("call: ");

	tg = xpmem_tg_ref_by_tgid(cpu_local_var(current)->proc->pid);
	if (!IS_ERR(tg)) {
		xpmem_tg_deref(tg);
		XPMEM_DEBUG("return: ret=%d, tg=0x%p", 0, tg);
		return 0;
	}

	tg = kmalloc(sizeof(struct xpmem_thread_group) + 
		sizeof(struct xpmem_hashlist) * XPMEM_AP_HASHTABLE_SIZE, 
		IHK_MC_AP_NOWAIT);
	if (tg == NULL) {
		return -ENOMEM;
	}
	XPMEM_DEBUG("kmalloc(): tg=0x%p", tg);
	memset(tg, 0, sizeof(struct xpmem_thread_group) + 
		sizeof(struct xpmem_hashlist) * XPMEM_AP_HASHTABLE_SIZE);

	ihk_mc_spinlock_init(&tg->lock);
	tg->tgid = cpu_local_var(current)->proc->pid;
	tg->uid = cpu_local_var(current)->proc->ruid;
	tg->gid = cpu_local_var(current)->proc->rgid;
	ihk_atomic_set(&tg->uniq_segid, 0);
	ihk_atomic_set(&tg->uniq_apid, 0);
	mcs_rwlock_init(&tg->seg_list_lock);
	INIT_LIST_HEAD(&tg->seg_list);
	ihk_atomic_set(&tg->n_pinned, 0);
	INIT_LIST_HEAD(&tg->tg_hashlist);
	tg->vm = cpu_local_var(current)->vm;
	ihk_atomic_set(&tg->n_recall_PFNs, 0);

	for (index = 0; index < XPMEM_AP_HASHTABLE_SIZE; index++) {
		mcs_rwlock_init(&tg->ap_hashtable[index].lock);
		INIT_LIST_HEAD(&tg->ap_hashtable[index].list);
	}

	xpmem_tg_not_destroyable(tg);

	index = xpmem_tg_hashtable_index(tg->tgid);
	mcs_rwlock_writer_lock(&xpmem_my_part->tg_hashtable[index].lock, &lock);

	list_add_tail(&tg->tg_hashlist, 
		&xpmem_my_part->tg_hashtable[index].list);

	mcs_rwlock_writer_unlock(&xpmem_my_part->tg_hashtable[index].lock, 
		&lock);

	tg->group_leader = cpu_local_var(current);

	XPMEM_DEBUG("return: ret=%d", 0);

	return 0;
}


static void xpmem_destroy_tg(
	struct xpmem_thread_group *tg)
{
	XPMEM_DEBUG("call: tg=0x%p", tg);

	XPMEM_DEBUG("tg->vm=0x%p", tg->vm);

	xpmem_tg_destroyable(tg);
	xpmem_tg_deref(tg);

	XPMEM_DEBUG("return: ");
}


static int xpmem_make(
	unsigned long vaddr,
	size_t size,
	int permit_type,
	void *permit_value,
	xpmem_segid_t *segid_p)
{
	xpmem_segid_t segid;
	struct xpmem_thread_group *seg_tg;
	struct xpmem_segment *seg;
	struct mcs_rwlock_node_irqsave lock;

	XPMEM_DEBUG("call: vaddr=0x%lx, size=%lu, permit_type=%d, " 
		"permit_value=0%04lo", 
		vaddr, size, permit_type, 
		(unsigned long)(uintptr_t)permit_value);

	if (permit_type != XPMEM_PERMIT_MODE ||
		((unsigned long)(uintptr_t)permit_value & ~00777) || 
		size == 0) {
		XPMEM_DEBUG("return: ret=%d", -EINVAL);
		return -EINVAL;
	}

	seg_tg = xpmem_tg_ref_by_tgid(cpu_local_var(current)->proc->pid);
	if (IS_ERR(seg_tg)) {
		DBUG_ON(PTR_ERR(seg_tg) != -ENOENT);
		return -XPMEM_ERRNO_NOPROC;
	}

	/*
	 * The start of the segment must be page aligned and it must be a
	 * multiple of pages in size.
	 */
	if (offset_in_page(vaddr) != 0 || offset_in_page(size) != 0) {
		xpmem_tg_deref(seg_tg);
		XPMEM_DEBUG("return: ret=%d", -EINVAL);
		return -EINVAL;
	}

	segid = xpmem_make_segid(seg_tg);
	if (segid < 0) {
		xpmem_tg_deref(seg_tg);
		return segid;
	}

	/* create a new struct xpmem_segment structure with a unique segid */
	seg = kmalloc(sizeof(struct xpmem_segment), IHK_MC_AP_NOWAIT);
	if (seg == NULL) {
		xpmem_tg_deref(seg_tg);
		return -ENOMEM;
	}
	XPMEM_DEBUG("kmalloc(): seg=0x%p", seg);
	memset(seg, 0, sizeof(struct xpmem_segment));

	ihk_mc_spinlock_init(&seg->lock);
	mcs_rwlock_init(&seg->seg_lock);
	seg->segid = segid;
	seg->vaddr = vaddr;
	seg->size = size;
	seg->permit_type = permit_type;
	seg->permit_value = permit_value;
	seg->tg = seg_tg;
	INIT_LIST_HEAD(&seg->ap_list);
	INIT_LIST_HEAD(&seg->seg_list);

	xpmem_seg_not_destroyable(seg);

	/* add seg to its tg's list of segs */
	mcs_rwlock_writer_lock(&seg_tg->seg_list_lock, &lock);
	list_add_tail(&seg->seg_list, &seg_tg->seg_list);
	mcs_rwlock_writer_unlock(&seg_tg->seg_list_lock, &lock);

	xpmem_tg_deref(seg_tg);

	*segid_p = segid;

	XPMEM_DEBUG("return: ret=%d, segid=0x%lx", 0, *segid_p);

	return 0;
}


static xpmem_segid_t xpmem_make_segid(
	struct xpmem_thread_group *seg_tg)
{
	struct xpmem_id segid;
	xpmem_segid_t *segid_p = (xpmem_segid_t *)&segid;
	int uniq;

	XPMEM_DEBUG("call: seg_tg=0x%p, uniq_segid=%d", 
		seg_tg, ihk_atomic_read(&seg_tg->uniq_segid));

	DBUG_ON(sizeof(struct xpmem_id) != sizeof(xpmem_segid_t));

	uniq = ihk_atomic_inc_return(&seg_tg->uniq_segid);
	if (uniq > XPMEM_MAX_UNIQ_ID) {
		ihk_atomic_dec(&seg_tg->uniq_segid);
		return -EBUSY;
	}

	*segid_p = 0;
	segid.tgid = seg_tg->tgid;
	segid.uniq = (unsigned long)uniq;

	DBUG_ON(*segid_p <= 0);

	XPMEM_DEBUG("return: segid=0x%lx, segid.tgid=%d, segid.uniq=%d", 
		segid, segid.tgid, segid.uniq);

	return *segid_p;
}


static int xpmem_remove(
	xpmem_segid_t segid)
{
	struct xpmem_thread_group *seg_tg;
	struct xpmem_segment *seg;

	XPMEM_DEBUG("call: segid=0x%lx", segid);

	if (segid <= 0) {
		XPMEM_DEBUG("return: ret=%d", -EINVAL);
		return -EINVAL;
	}

	seg_tg = xpmem_tg_ref_by_segid(segid);
	if (IS_ERR(seg_tg))
		return PTR_ERR(seg_tg);

	if (cpu_local_var(current)->proc->pid != seg_tg->tgid) {
		xpmem_tg_deref(seg_tg);
		XPMEM_DEBUG("return: ret=%d", -EACCES);
		return -EACCES;
	}

	seg = xpmem_seg_ref_by_segid(seg_tg, segid);
	if (IS_ERR(seg)) {
		xpmem_tg_deref(seg_tg);
		return PTR_ERR(seg);
	}
	DBUG_ON(seg->tg != seg_tg);

	xpmem_remove_seg(seg_tg, seg);
	xpmem_seg_deref(seg);
	xpmem_tg_deref(seg_tg);

	XPMEM_DEBUG("return: ret=%d", 0);

	return 0;
}


static void xpmem_remove_seg(
	struct xpmem_thread_group *seg_tg,
	struct xpmem_segment *seg)
{
	DBUG_ON(ihk_atomic_read(&seg->refcnt) <= 0);
	struct mcs_rwlock_node_irqsave seg_lock;
	struct mcs_rwlock_node_irqsave lock;

	XPMEM_DEBUG("call: tgid=%d, segid=0x%lx", seg_tg->tgid, seg->segid);

	ihk_mc_spinlock_lock(&seg->lock);
	if (seg->flags & XPMEM_FLAG_DESTROYING) {
		ihk_mc_spinlock_unlock_noirq(&seg->lock);
		schedule();
		return;
	}
	seg->flags |= XPMEM_FLAG_DESTROYING;
	ihk_mc_spinlock_unlock_noirq(&seg->lock);

	mcs_rwlock_writer_lock(&seg->seg_lock, &seg_lock);

	/* unpin pages and clear PTEs for each attachment to this segment */
	xpmem_clear_PTEs(seg);

	/* indicate that the segment has been destroyed */
	ihk_mc_spinlock_lock(&seg->lock);
	seg->flags |= XPMEM_FLAG_DESTROYED;
	ihk_mc_spinlock_unlock_noirq(&seg->lock);

	/* Remove segment structure from its tg's list of segs */
	mcs_rwlock_writer_lock(&seg_tg->seg_list_lock, &lock);
	list_del_init(&seg->seg_list);
	mcs_rwlock_writer_unlock(&seg_tg->seg_list_lock, &lock);

	mcs_rwlock_writer_unlock(&seg->seg_lock, &seg_lock);

	xpmem_seg_destroyable(seg);

	XPMEM_DEBUG("return: ");
}


static void xpmem_clear_PTEs(
	struct xpmem_segment *seg)
{
	XPMEM_DEBUG("call: seg=0x%p", seg);

//	xpmem_clear_PTEs_range(seg, seg->vaddr, seg->vaddr + seg->size, 0); // TODO

	XPMEM_DEBUG("return: ");
}


static struct xpmem_thread_group * __xpmem_tg_ref_by_tgid_nolock_internal(
	pid_t tgid,
	int index,
	int return_destroying)
{
	struct xpmem_thread_group *tg;

	XPMEM_DEBUG("call: tgid=%d, index=%d, return_destroying=%d", 
		tgid, index, return_destroying);

	list_for_each_entry(tg, &xpmem_my_part->tg_hashtable[index].list,
		tg_hashlist) {
		if (tg->tgid == tgid) {
			if ((tg->flags & XPMEM_FLAG_DESTROYING) &&
				!return_destroying) {
				continue;
			}

			xpmem_tg_ref(tg);

			XPMEM_DEBUG("return: tg=0x%p", tg);
			return tg;
		}
	}

	XPMEM_DEBUG("return: tg=0x%p", ERR_PTR(-ENOENT));

	return ERR_PTR(-ENOENT);
}


static struct xpmem_thread_group * xpmem_tg_ref_by_segid(
	xpmem_segid_t segid)
{
	struct xpmem_thread_group *tg;

	XPMEM_DEBUG("call: segid=0x%lx", segid);

	tg = xpmem_tg_ref_by_tgid(xpmem_segid_to_tgid(segid));

	XPMEM_DEBUG("return: tg=0x%p", tg);

        return tg;
}


static void xpmem_tg_deref(
	struct xpmem_thread_group *tg)
{
	XPMEM_DEBUG("call: tg=0x%p", tg);

	DBUG_ON(ihk_atomic_read(&tg->refcnt) <= 0);
	if (ihk_atomic_dec_return(&tg->refcnt) != 0) {
		XPMEM_DEBUG("return: tg->refcnt=%d", tg->refcnt);
		return;
	}

	XPMEM_DEBUG("kfree(): tg=0x%p", tg);
	kfree(tg);

	XPMEM_DEBUG("return: ");
}


static struct xpmem_segment * xpmem_seg_ref_by_segid(
	struct xpmem_thread_group *seg_tg,
	xpmem_segid_t segid)
{
	struct xpmem_segment *seg;
	struct mcs_rwlock_node_irqsave lock;

	XPMEM_DEBUG("call: seg_tg=0x%p, segid=0x%lx", seg_tg, segid);

	mcs_rwlock_reader_lock(&seg_tg->seg_list_lock, &lock);

	list_for_each_entry(seg, &seg_tg->seg_list, seg_list) {
		if (seg->segid == segid) {
			if (seg->flags & XPMEM_FLAG_DESTROYING)
				continue;

			xpmem_seg_ref(seg);
			mcs_rwlock_reader_unlock(&seg_tg->seg_list_lock, &lock);
			return seg;
		}
	}

	mcs_rwlock_reader_unlock(&seg_tg->seg_list_lock, &lock);

	return ERR_PTR(-ENOENT);
}


static void xpmem_seg_deref(
	struct xpmem_segment *seg)
{
	XPMEM_DEBUG("call: seg=0x%p", seg);

	DBUG_ON(ihk_atomic_read(&seg->refcnt) <= 0);
	if (ihk_atomic_dec_return(&seg->refcnt) != 0) {
		XPMEM_DEBUG("return: seg->refcnt=%d", seg->refcnt);
		return;
	}

	DBUG_ON(!(seg->flags & XPMEM_FLAG_DESTROYING));

	XPMEM_DEBUG("kfree(): seg=0x%p", seg);
	kfree(seg);

	XPMEM_DEBUG("return: ");
}

