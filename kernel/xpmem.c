/* xpmem.c COPYRIGHT FUJITSU LIMITED 2017 */
/**
 * \file xpmem.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Cross Partition Memory (XPMEM) support.
 * \author Yoichi Umezawa  <yoichi.umezawa.qh@hitachi.com> \par
 * 	Copyright (C) 2016 Yoichi Umezawa
 *
 * Original Copyright follows:
 *
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
#include <page.h>
#include <string.h>
#include <types.h>
#include <vsprintf.h>
#include <ihk/lock.h>
#include <ihk/mm.h>
#include <xpmem_private.h>

struct xpmem_partition *xpmem_my_part = NULL;  /* pointer to this partition */

static int do_xpmem_open(int syscall_num, const char *pathname,
		int flags, ihk_mc_user_context_t *ctx)
{
	int ret;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	int fd;
	struct mckfd *mckfd;
	long irqstate;

	XPMEM_DEBUG("call: syscall_num=%d, pathname=%s, flags=%d",
		syscall_num, pathname, flags);

	if (!xpmem_my_part) {
		ret = xpmem_init();
		if (ret) {
			return ret;
		}
	}

	fd = syscall_generic_forwarding(syscall_num, ctx);
	if(fd < 0){
		XPMEM_DEBUG("syscall_num=%d error: fd=%d", syscall_num, fd);
		return fd;
	}

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
	mckfd->dup_cb = xpmem_dup;
	mckfd->data = (long)proc;
	irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);

	if (proc->mckfd == NULL) {
		proc->mckfd = mckfd;
		mckfd->next = NULL;
	}
	else {
		mckfd->next = proc->mckfd;
		proc->mckfd = mckfd;
	}

	ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);

	ihk_atomic_inc_return(&xpmem_my_part->n_opened);
	XPMEM_DEBUG("n_opened=%d", xpmem_my_part->n_opened);

	XPMEM_DEBUG("return: ret=%d", mckfd->fd);

	return mckfd->fd;
}

int xpmem_open(const char *pathname,
		int flags, ihk_mc_user_context_t *ctx)
{
	return do_xpmem_open(__NR_open, pathname, flags, ctx);
}

int xpmem_openat(const char *pathname,
		int flags, ihk_mc_user_context_t *ctx)
{
	return do_xpmem_open(__NR_openat, pathname, flags, ctx);
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
		xpmem_apid_t apid = 0;

		if (copy_from_user(&get_info, (void __user *)arg, 
			sizeof(struct xpmem_cmd_get)))
			return -EFAULT;

		ret = xpmem_get(get_info.segid, get_info.flags,
			get_info.permit_type,
			(void *)get_info.permit_value, &apid);
		if (ret != 0) {
			XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);
			return ret;
		}

		if (copy_to_user(&((struct xpmem_cmd_get __user *)arg)->apid, 
			(void *)&apid, sizeof(xpmem_apid_t))) {
			(void)xpmem_release(apid);
			return -EFAULT;
		}

		XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);

		return ret;
	}
	case XPMEM_CMD_RELEASE: {
		struct xpmem_cmd_release release_info;

		if (copy_from_user(&release_info, (void __user *)arg,
			sizeof(struct xpmem_cmd_release)))
			return -EFAULT;

		ret = xpmem_release(release_info.apid);

		XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);

		return ret;
	}
	case XPMEM_CMD_ATTACH: {
		struct xpmem_cmd_attach attach_info;
		unsigned long at_vaddr = 0;

		if (copy_from_user(&attach_info, (void __user *)arg, 
			sizeof(struct xpmem_cmd_attach)))
			return -EFAULT;

		ret = xpmem_attach(mckfd, attach_info.apid, attach_info.offset, 
			attach_info.size, attach_info.vaddr, 
			attach_info.fd, attach_info.flags, 
			&at_vaddr);
		if (ret != 0) {
			XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);
			return ret;
		}

		if (copy_to_user(
			&((struct xpmem_cmd_attach __user *)arg)->vaddr, 
			(void *)&at_vaddr, sizeof(unsigned long))) {
			(void)xpmem_detach(at_vaddr);
			return -EFAULT;
		}

		XPMEM_DEBUG("return: cmd=0x%x, ret=%d", cmd, ret);

		return ret;
	}
	case XPMEM_CMD_DETACH: {
		struct xpmem_cmd_detach detach_info;

		if (copy_from_user(&detach_info, (void __user *)arg, 
			sizeof(struct xpmem_cmd_detach)))
			return -EFAULT;

		ret = xpmem_detach(detach_info.vaddr);

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
	int n_opened;

	XPMEM_DEBUG("call: fd=%d, pid=%d, rgid=%d", 
		mckfd->fd, cpu_local_var(current)->proc->pid,
		cpu_local_var(current)->proc->rgid);

	n_opened = ihk_atomic_dec_return(&xpmem_my_part->n_opened);
	XPMEM_DEBUG("n_opened=%d", n_opened);

	if (mckfd->data) {
		/* release my xpmem-objects */
		xpmem_flush(mckfd);
	}

	if (!n_opened) {
		xpmem_exit();
	}

	XPMEM_DEBUG("return: ret=%d", 0);

	return 0;
}

static int xpmem_dup(
	struct mckfd *mckfd,
	ihk_mc_user_context_t *ctx)
{
	mckfd->data = 0;
	ihk_atomic_inc_return(&xpmem_my_part->n_opened);

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
		XPMEM_DEBUG("kfree(): xpmem_my_part=0x%p", xpmem_my_part);
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

	XPMEM_DEBUG("call: vaddr=0x%lx, size=0x%lx, permit_type=%d, " 
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
	if (offset_in_page(vaddr) != 0 ||
			/* Special treatment of -1UL */
			(offset_in_page(size) != 0 && size != 0xffffffffffffffff)) {
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
	seg->segid = segid;
	seg->vaddr = vaddr;
	seg->size = size;
	seg->permit_type = permit_type;
	seg->permit_value = permit_value;
	seg->tg = seg_tg;
	INIT_LIST_HEAD(&seg->ap_list);
	INIT_LIST_HEAD(&seg->seg_list);

	xpmem_seg_not_destroyable(seg);

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
	struct mcs_rwlock_node_irqsave lock;

	XPMEM_DEBUG("call: tgid=%d, segid=0x%lx", seg_tg->tgid, seg->segid);

	ihk_mc_spinlock_lock_noirq(&seg->lock);
	if (seg->flags & XPMEM_FLAG_DESTROYING) {
		ihk_mc_spinlock_unlock_noirq(&seg->lock);
		return;
	}
	seg->flags |= XPMEM_FLAG_DESTROYING;
	ihk_mc_spinlock_unlock_noirq(&seg->lock);

	xpmem_clear_PTEs(seg);

	ihk_mc_spinlock_lock_noirq(&seg->lock);
	seg->flags |= XPMEM_FLAG_DESTROYED;
	ihk_mc_spinlock_unlock_noirq(&seg->lock);

	mcs_rwlock_writer_lock(&seg_tg->seg_list_lock, &lock);
	list_del_init(&seg->seg_list);
	mcs_rwlock_writer_unlock(&seg_tg->seg_list_lock, &lock);

	xpmem_seg_destroyable(seg);

	XPMEM_DEBUG("return: ");
}


static void xpmem_remove_segs_of_tg(
	struct xpmem_thread_group *seg_tg)
{
	struct xpmem_segment *seg;
	struct mcs_rwlock_node_irqsave lock;

	XPMEM_DEBUG("call: tgid=%d", seg_tg->tgid);

	mcs_rwlock_writer_lock(&seg_tg->seg_list_lock, &lock);

	while (!list_empty(&seg_tg->seg_list)) {
		seg = list_entry((&seg_tg->seg_list)->next, 
			struct xpmem_segment, seg_list);
		xpmem_seg_ref(seg);
		mcs_rwlock_writer_unlock(&seg_tg->seg_list_lock, &lock);

		xpmem_remove_seg(seg_tg, seg);

		xpmem_seg_deref(seg);

		mcs_rwlock_writer_lock(&seg_tg->seg_list_lock, &lock);
	}

	mcs_rwlock_writer_unlock(&seg_tg->seg_list_lock, &lock);

	XPMEM_DEBUG("return: ");
}


static int xpmem_get(
	xpmem_segid_t segid,
	int flags,
	int permit_type,
	void *permit_value,
	xpmem_apid_t *apid_p)
{
	xpmem_apid_t apid;
	struct xpmem_access_permit *ap;
	struct xpmem_segment *seg;
	struct xpmem_thread_group *ap_tg, *seg_tg;
	int index;
	struct mcs_rwlock_node_irqsave lock;

	XPMEM_DEBUG("call: segid=0x%lx, flags=%d, permit_type=%d, " 
		"permit_value=0%04lo", 
		segid, flags, permit_type, 
		(unsigned long)(uintptr_t)permit_value);

	if (segid <= 0) {
		return -EINVAL;
	}

	if ((flags & ~(XPMEM_RDONLY | XPMEM_RDWR)) ||
		(flags & (XPMEM_RDONLY | XPMEM_RDWR)) ==
		(XPMEM_RDONLY | XPMEM_RDWR)) {
		return -EINVAL;
	}

	if (permit_type != XPMEM_PERMIT_MODE || permit_value != NULL) {
		return -EINVAL;
	}

	seg_tg = xpmem_tg_ref_by_segid(segid);
	if (IS_ERR(seg_tg)) {
		return PTR_ERR(seg_tg);
	}

	seg = xpmem_seg_ref_by_segid(seg_tg, segid);
	if (IS_ERR(seg)) {
		xpmem_tg_deref(seg_tg);
		return PTR_ERR(seg);
	}

	if (xpmem_check_permit_mode(flags, seg) != 0) {
		xpmem_seg_deref(seg);
		xpmem_tg_deref(seg_tg);
		return -EACCES;
	}

	ap_tg = xpmem_tg_ref_by_tgid(cpu_local_var(current)->proc->pid);
	if (IS_ERR(ap_tg)) {
		DBUG_ON(PTR_ERR(ap_tg) != -ENOENT);
		xpmem_seg_deref(seg);
		xpmem_tg_deref(seg_tg);
		return -XPMEM_ERRNO_NOPROC;
	}

	apid = xpmem_make_apid(ap_tg);
	if (apid < 0) {
		xpmem_tg_deref(ap_tg);
		xpmem_seg_deref(seg);
		xpmem_tg_deref(seg_tg);
		return apid;
	}

	/* create a new xpmem_access_permit structure with a unique apid */
	ap = kmalloc(sizeof(struct xpmem_access_permit), IHK_MC_AP_NOWAIT);
	if (ap == NULL) {
		xpmem_tg_deref(ap_tg);
		xpmem_seg_deref(seg);
		xpmem_tg_deref(seg_tg);
		return -ENOMEM;
	}
	XPMEM_DEBUG("kmalloc(): ap=0x%p", ap);
	memset(ap, 0, sizeof(struct xpmem_access_permit));

	ihk_mc_spinlock_init(&ap->lock);
	ap->apid = apid;
	ap->mode = flags;
	ap->seg = seg;
	ap->tg = ap_tg;
	INIT_LIST_HEAD(&ap->att_list);
	INIT_LIST_HEAD(&ap->ap_list);
	INIT_LIST_HEAD(&ap->ap_hashlist);

	xpmem_ap_not_destroyable(ap);

	/* add ap to its seg's access permit list */
	ihk_mc_spinlock_lock_noirq(&seg->lock);
	list_add_tail(&ap->ap_list, &seg->ap_list);
	ihk_mc_spinlock_unlock_noirq(&seg->lock);

	/* add ap to its hash list */
	index = xpmem_ap_hashtable_index(ap->apid);
	mcs_rwlock_writer_lock(&ap_tg->ap_hashtable[index].lock, &lock);
	list_add_tail(&ap->ap_hashlist, &ap_tg->ap_hashtable[index].list);
	mcs_rwlock_writer_unlock(&ap_tg->ap_hashtable[index].lock, &lock);

	xpmem_tg_deref(ap_tg);

	*apid_p = apid;

	XPMEM_DEBUG("return: ret=%d, apid=0x%lx", 0, *apid_p);

	return 0;
}


static int xpmem_check_permit_mode(
	int flags,
	struct xpmem_segment *seg)
{
	int ret;
	struct xpmem_perm perm;

	XPMEM_DEBUG("call: flags=%d", flags);

	DBUG_ON(seg->permit_type != XPMEM_PERMIT_MODE);

	memset(&perm, 0, sizeof(struct xpmem_perm));
	perm.uid = seg->tg->uid;
	perm.gid = seg->tg->gid;
	perm.mode = (unsigned long)seg->permit_value;

	ret = xpmem_perms(&perm, XPMEM_PERM_IRUSR);
	if (ret == 0 && (flags & XPMEM_RDWR)) {
		ret = xpmem_perms(&perm, XPMEM_PERM_IWUSR);
	}

	XPMEM_DEBUG("return: ret=%d", ret);

	return ret;
}


static int xpmem_perms(
	struct xpmem_perm *perm,
	short flag)
{
	int ret = 0;
	int requested_mode;
	int granted_mode;

	XPMEM_DEBUG("call: uid=%d, gid=%d, mode=0%lo, flag=0%o", 
		perm->uid, perm->gid, perm->mode, flag);

	requested_mode = (flag >> 6) | (flag >> 3) | flag;
	granted_mode = perm->mode;
	if (perm->uid == cpu_local_var(current)->proc->ruid) {
		granted_mode >>= 6;
	}
	else if (perm->gid == cpu_local_var(current)->proc->rgid) {
		granted_mode >>= 3;
	}

	if (requested_mode & ~granted_mode & 0007) {
		ret = -1;
	}

	XPMEM_DEBUG("return: ret=%d", ret);

	return ret;
}


static xpmem_apid_t xpmem_make_apid(
	struct xpmem_thread_group *ap_tg)
{
	struct xpmem_id apid;
	xpmem_apid_t *apid_p = (xpmem_apid_t *)&apid;
	int uniq;

	XPMEM_DEBUG("call: ap_tg=0x%p, uniq_apid=%d", 
		ap_tg, ihk_atomic_read(&ap_tg->uniq_apid));

	DBUG_ON(sizeof(struct xpmem_id) != sizeof(xpmem_apid_t));

	uniq = ihk_atomic_inc_return(&ap_tg->uniq_apid);
	if (uniq > XPMEM_MAX_UNIQ_ID) {
		ihk_atomic_dec(&ap_tg->uniq_apid);
		return -EBUSY;
	}

	*apid_p = 0;
	apid.tgid = ap_tg->tgid;
	apid.uniq = (unsigned int)uniq;

	XPMEM_DEBUG("return: apid=0x%lx, apid.tgid=%d, apid.uniq=%d", 
		apid, apid.tgid, apid.uniq);

	return *apid_p;
}


static int xpmem_release(
	xpmem_apid_t apid)
{
	struct xpmem_thread_group *ap_tg;
	struct xpmem_access_permit *ap;

	XPMEM_DEBUG("call: apid=0x%lx", apid);

	if (apid <= 0) {
		return -EINVAL;
	}

	ap_tg = xpmem_tg_ref_by_apid(apid);
	if (IS_ERR(ap_tg)) {
		return PTR_ERR(ap_tg);
	}

	if (cpu_local_var(current)->proc->pid != ap_tg->tgid) {
		xpmem_tg_deref(ap_tg);
		return -EACCES;
	}

	ap = xpmem_ap_ref_by_apid(ap_tg, apid);
	if (IS_ERR(ap)) {
		xpmem_tg_deref(ap_tg);
		return PTR_ERR(ap);
	}
	DBUG_ON(ap->tg != ap_tg);

	xpmem_release_ap(ap_tg, ap);
	xpmem_ap_deref(ap);
	xpmem_tg_deref(ap_tg);

	XPMEM_DEBUG("return: ret=%d", 0);

	return 0;
}


static void xpmem_release_ap(
	struct xpmem_thread_group *ap_tg,
	struct xpmem_access_permit *ap)
{
	int index;
	struct xpmem_thread_group *seg_tg;
	struct xpmem_attachment *att;
	struct xpmem_segment *seg;
	struct mcs_rwlock_node_irqsave lock;

	XPMEM_DEBUG("call: tgid=%d, apid=0x%lx", ap_tg->tgid, ap->apid);

	ihk_mc_spinlock_lock_noirq(&ap->lock);
	if (ap->flags & XPMEM_FLAG_DESTROYING) {
		ihk_mc_spinlock_unlock_noirq(&ap->lock);
                return;
        }
	ap->flags |= XPMEM_FLAG_DESTROYING;

	while (!list_empty(&ap->att_list)) {
		att = list_entry((&ap->att_list)->next, struct xpmem_attachment,
			att_list);
		xpmem_att_ref(att);
		ihk_mc_spinlock_unlock_noirq(&ap->lock);

		xpmem_detach_att(ap, att);

		xpmem_att_deref(att);

		ihk_mc_spinlock_lock_noirq(&ap->lock);
	}

	ap->flags |= XPMEM_FLAG_DESTROYED;

	ihk_mc_spinlock_unlock_noirq(&ap->lock);

	index = xpmem_ap_hashtable_index(ap->apid);
	mcs_rwlock_writer_lock(&ap_tg->ap_hashtable[index].lock, &lock);
	list_del_init(&ap->ap_hashlist);
	mcs_rwlock_writer_unlock(&ap_tg->ap_hashtable[index].lock, &lock);

	seg = ap->seg;
	seg_tg = seg->tg;

	ihk_mc_spinlock_lock_noirq(&seg->lock);
	list_del_init(&ap->ap_list);
	ihk_mc_spinlock_unlock_noirq(&seg->lock);

	xpmem_seg_deref(seg);
	xpmem_tg_deref(seg_tg);

	xpmem_ap_destroyable(ap);

	XPMEM_DEBUG("return: ");
}


static void xpmem_release_aps_of_tg(
	struct xpmem_thread_group *ap_tg)
{
	struct xpmem_hashlist *hashlist;
	struct xpmem_access_permit *ap;
	struct mcs_rwlock_node_irqsave lock;
	int index;

	XPMEM_DEBUG("call: tgid=%d", ap_tg->tgid);

	for (index = 0; index < XPMEM_AP_HASHTABLE_SIZE; index++) {
		hashlist = &ap_tg->ap_hashtable[index];

		mcs_rwlock_writer_lock(&hashlist->lock, &lock);
		while (!list_empty(&hashlist->list)) {
			ap = list_entry((&hashlist->list)->next,
				struct xpmem_access_permit, ap_hashlist);
			xpmem_ap_ref(ap);
			mcs_rwlock_writer_unlock(&hashlist->lock, &lock);

			xpmem_release_ap(ap_tg, ap);

			xpmem_ap_deref(ap);

			mcs_rwlock_writer_lock(&hashlist->lock, &lock);
		}
		mcs_rwlock_writer_unlock(&hashlist->lock, &lock);
	}

	XPMEM_DEBUG("return: ");
}

static void xpmem_flush(struct mckfd *mckfd)
{
	struct process *proc = (struct process *)mckfd->data;
	struct xpmem_thread_group *tg;
	int index;
	struct mcs_rwlock_node_irqsave lock;

	index = xpmem_tg_hashtable_index(proc->pid);

	mcs_rwlock_writer_lock(&xpmem_my_part->tg_hashtable[index].lock, &lock);

	tg = xpmem_tg_ref_by_tgid_all_nolock(proc->pid);
	if (IS_ERR(tg)) {
		mcs_rwlock_writer_unlock(
			&xpmem_my_part->tg_hashtable[index].lock, &lock);
		return;
	}

	list_del_init(&tg->tg_hashlist);

	mcs_rwlock_writer_unlock(&xpmem_my_part->tg_hashtable[index].lock, 
		&lock);

	XPMEM_DEBUG("tg->vm=0x%p", tg->vm);

	ihk_mc_spinlock_lock_noirq(&tg->lock);
	tg->flags |= XPMEM_FLAG_DESTROYING;
	ihk_mc_spinlock_unlock_noirq(&tg->lock);

	xpmem_release_aps_of_tg(tg);
	xpmem_remove_segs_of_tg(tg);

	ihk_mc_spinlock_lock_noirq(&tg->lock);
	tg->flags |= XPMEM_FLAG_DESTROYED;
	ihk_mc_spinlock_unlock_noirq(&tg->lock);

	xpmem_destroy_tg(tg);
}

static void dump_stack_ranges(struct process_vm *src_vm)
{
	struct vm_range *stack_range = NULL;
	unsigned long stack_vaddr;

	kprintf("%s: dumping stack ranges: src vm: %lx, src_vm->region.stack: %lx-%lx\n",
		__func__,
		(unsigned long)src_vm,
		src_vm->region.stack_start,
		src_vm->region.stack_end);

	for (stack_vaddr = src_vm->region.stack_end; stack_vaddr - 1 >= src_vm->region.stack_start; stack_vaddr = stack_range->start) {
		if (stack_range == NULL) {
			stack_range = lookup_process_memory_range(src_vm, stack_vaddr - 1, stack_vaddr);
		}
		else {
			stack_range = previous_process_memory_range(src_vm, stack_range);
		}

		kprintf("%s: info: src vm: %lx, stack_range: %lx-%lx\n",
			__func__,
			(unsigned long)src_vm,
			stack_range->start,
			stack_range->end);
	}
}	

static int xpmem_attach(
	struct mckfd *mckfd,
	xpmem_apid_t apid,
	off_t offset,
	size_t size,
	unsigned long vaddr,
	int fd,
	int att_flags,
	unsigned long *at_vaddr_p)
{
	int ret;
	unsigned long flags;
	unsigned long prot_flags = PROT_READ | PROT_WRITE;
	unsigned long seg_vaddr;
	unsigned long at_vaddr;
	struct xpmem_thread_group *ap_tg;
	struct xpmem_thread_group *seg_tg;
	struct xpmem_access_permit *ap;
	struct xpmem_segment *seg;
	struct xpmem_attachment *att;
	struct mcs_rwlock_node_irqsave at_lock;
	struct vm_range *vmr;
	struct process_vm *vm = cpu_local_var(current)->vm;
	struct thread *src_thread;
	struct process_vm *src_vm;
	struct vm_range *src_range;
	unsigned long old;
	unsigned long src_vaddr;

	XPMEM_DEBUG("call: apid=0x%lx, offset=0x%lx, size=0x%lx, vaddr=0x%lx, " 
		"fd=%d, att_flags=%d", 
		apid, offset, size, vaddr, fd, att_flags);

	if (apid <= 0) {
		return -EINVAL;
	}

	/* The start of the attachment must be page aligned */
	if (offset_in_page(vaddr) != 0 || offset_in_page(offset) != 0) {
		return -EINVAL;
	}

	/* If the size is not page aligned, fix it */
	if (offset_in_page(size) != 0) {
		size += PAGE_SIZE - offset_in_page(size);
	}

	ap_tg = xpmem_tg_ref_by_apid(apid);
	if (IS_ERR(ap_tg))
		return PTR_ERR(ap_tg);

	ap = xpmem_ap_ref_by_apid(ap_tg, apid);
	if (IS_ERR(ap)) {
		xpmem_tg_deref(ap_tg);
		return PTR_ERR(ap);
	}

	seg = ap->seg;
	xpmem_seg_ref(seg);
	seg_tg = seg->tg;
	xpmem_tg_ref(seg_tg);

	if ((seg->flags & XPMEM_FLAG_DESTROYING) ||
		(seg_tg->flags & XPMEM_FLAG_DESTROYING)) {
		ret = -ENOENT;
		goto out_1;
	}

	ret = xpmem_validate_access(ap, offset, size, XPMEM_RDWR, &seg_vaddr);
	if (ret != 0) {
		goto out_1;
	}
	kprintf("%s: source: vm: %lx, seg_vaddr: %lx-%lx\n",
		__func__, seg_tg->vm, seg_vaddr, seg_vaddr + size);

	/* range check */
	size += offset_in_page(seg_vaddr);

	seg = ap->seg;
	if (cpu_local_var(current)->proc->pid == seg_tg->tgid && vaddr) {
		if ((vaddr + size > seg_vaddr) && (vaddr < seg_vaddr + size)) {
			ret = -EINVAL;
			goto out_1;
		}
	}

	/* create new attach structure */
	att = kmalloc(sizeof(struct xpmem_attachment), IHK_MC_AP_NOWAIT);
	if (att == NULL) {
		ret = -ENOMEM;
		goto out_1;
	}
	XPMEM_DEBUG("kmalloc(): att=0x%p", att);
	memset(att, 0, sizeof(struct xpmem_attachment));

	mcs_rwlock_init(&att->at_lock);
	att->vaddr = seg_vaddr;
	att->min = ULONG_MAX;
	att->max = 0;
	att->at_size = size;
	att->ap = ap;
	INIT_LIST_HEAD(&att->att_list);
	att->vm = vm;

        xpmem_att_not_destroyable(att);
        xpmem_att_ref(att);

	mcs_rwlock_writer_lock(&att->at_lock, &at_lock);

	ihk_mc_spinlock_lock_noirq(&ap->lock);
	list_add_tail(&att->att_list, &ap->att_list);
	if (ap->flags & XPMEM_FLAG_DESTROYING) {
		ihk_mc_spinlock_unlock_noirq(&ap->lock);
		ret = -ENOENT;
		goto out_2;
	}
	ihk_mc_spinlock_unlock_noirq(&ap->lock);

	flags = MAP_SHARED;
	if (vaddr != 0)
		flags |= MAP_FIXED;

	if (flags & MAP_FIXED) {
		struct vm_range *existing_vmr;

		ihk_rwspinlock_read_lock_noirq(&vm->memory_range_lock);

		existing_vmr = lookup_process_memory_range(vm, vaddr, 
			vaddr + size);

		ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);

		for (; existing_vmr && existing_vmr->start < vaddr + size;
			existing_vmr = next_process_memory_range(vm, 
			existing_vmr)) {
			if (xpmem_is_private_data(existing_vmr)) {
				ret = -EINVAL;
				goto out_2;
			}
		}
	}

	flags |= MAP_ANONYMOUS;
	XPMEM_DEBUG("do_mmap(): vaddr=0x%lx, size=0x%lx, prot_flags=0x%lx, " 
		"flags=0x%lx, fd=%d, offset=0x%lx", 
		vaddr, size, prot_flags, flags, mckfd->fd, offset);
	/* The new range uses on-demand paging and is associated with shmobj because of 
	   MAP_ANONYMOUS && !MAP_PRIVATE && MAP_SHARED */
	at_vaddr = do_mmap(vaddr, size, prot_flags, flags, mckfd->fd, offset);
	if (IS_ERR((void *)(uintptr_t)at_vaddr)) {
		ret = at_vaddr;
		goto out_2;
	}
	XPMEM_DEBUG("at_vaddr=0x%lx", at_vaddr);
	att->at_vaddr = at_vaddr;

	ihk_rwspinlock_read_lock_noirq(&vm->memory_range_lock);

	vmr = lookup_process_memory_range(vm, at_vaddr, at_vaddr + 1);

	/* To identify pages of XPMEM attachment for rusage accounting */
	if(vmr->memobj) {
		vmr->memobj->flags |= MF_XPMEM;
	} else {
		ekprintf("%s: vmr->memobj equals to NULL\n", __FUNCTION__);
	}

	ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);

	if (!vmr) {
		ret = -ENOENT;
		goto out_2;
	}
	vmr->private_data = att;

	att->at_vmr = vmr;

	*at_vaddr_p = at_vaddr + offset_in_page(att->vaddr);

	ret = 0;
out_2:
	if (ret != 0) {
		att->flags |= XPMEM_FLAG_DESTROYING;
		ihk_mc_spinlock_lock_noirq(&ap->lock);
		list_del_init(&att->att_list);
		ihk_mc_spinlock_unlock_noirq(&ap->lock);
		xpmem_att_destroyable(att);
	}
	mcs_rwlock_writer_unlock(&att->at_lock, &at_lock);
	xpmem_att_deref(att);

	if (ret) {
		goto out_1;
	}

	/* ref remote process, vm, range */
	src_thread = seg_tg->group_leader;
	hold_thread(src_thread);

	src_vm = seg_tg->vm;
	hold_process_vm(src_vm);

	ihk_rwspinlock_write_lock_noirq(&src_vm->memory_range_lock);

	/* mark source ranges containing attached */
	src_range = NULL;
	for (src_vaddr = seg_vaddr; src_vaddr < seg_vaddr + size; src_vaddr = src_range->end) {
		if (src_range == NULL) {
			src_range = lookup_process_memory_range(src_vm, seg_vaddr, seg_vaddr + 1);
		}
		else {
			src_range = next_process_memory_range(src_vm, src_range);
		}

		if (!src_range) {
			kprintf("%s: source range not found, vm: %lx, vaddr: %lx\n",
				__func__, (unsigned long)src_vm, seg_vaddr);
			ret = -ENOENT;
			dump_stack_ranges(src_vm);
			ihk_rwspinlock_write_unlock_noirq(&src_vm->memory_range_lock);
			goto out_1;
		}
#if 0 /* hugefileobj does not support splitting */
		if (src_range->start < src_vaddr) {
			kprintf("%s: split, vm: %lx, range: %lx-%lx and %lx-%lx\n",
				__func__, seg_tg->vm,
				src_range->start, src_vaddr,
				src_vaddr, src_range->end);
			ret = split_process_memory_range(src_vm, src_range, src_vaddr, &src_range);
			if (ret) {
				ekprintf("%s :split failed with %d\n",
					 __func__, ret);
				ihk_rwspinlock_write_unlock_noirq(&src_vm->memory_range_lock);
				goto out_1;
			}
		}

		if (seg_vaddr + size < src_range->end) {
			kprintf("%s: split, vm: %lx, range: %lx-%lx and %lx-%lx\n",
				__func__, seg_tg->vm,
				src_range->start, seg_vaddr + size,
				seg_vaddr + size, src_range->end);
			ret = split_process_memory_range(src_vm, src_range, seg_vaddr + size, NULL);
			if (ret) {
				ekprintf("%s :split failed with %d\n",
					 __func__, ret);
				ihk_rwspinlock_write_unlock_noirq(&src_vm->memory_range_lock);
				goto out_1;
			}
		}
#endif

		/* first attach "ref"s for source range as well */
		if ((old = ihk_atomic64_cmpxchg(&src_range->xpmem_count.atomic, 0, 2)) != 0) {
			ihk_atomic_add_long(1, &src_range->xpmem_count.l);
		}
		kprintf("%s: ref, source: vm: %lx, range: %lx-%lx, xpmem_count: %d\n",
			__func__, seg_tg->vm, src_range->start, src_range->end,
			ihk_atomic64_read(&src_range->xpmem_count.atomic));

		if (att->min > src_range->start) {
			att->min = src_range->start;
		}
		if (att->max < src_range->end) {
			att->max = src_range->end;
		}
		kprintf("%s: source ranges updated, source: vm: %lx, min-max: %lx-%lx\n",
			__func__, seg_tg->vm, att->min, att->max);
	}

	ihk_rwspinlock_write_unlock_noirq(&src_vm->memory_range_lock);

out_1:
	xpmem_ap_deref(ap);
	xpmem_tg_deref(ap_tg);
	xpmem_seg_deref(seg);
	xpmem_tg_deref(seg_tg);

	XPMEM_DEBUG("return: ret=%d, at_vaddr=0x%lx", ret, *at_vaddr_p);

	return ret;
}

extern int _do_munmap(struct thread *thread, struct process_vm *vm,
		      void *addr, size_t len, int holding_memory_range_lock);

static int xpmem_detach(
	unsigned long at_vaddr)
{
	int ret;
	struct xpmem_access_permit *ap;
	struct xpmem_attachment *att;
	struct mcs_rwlock_node_irqsave at_lock;
	struct vm_range *range;
	struct process_vm *vm = cpu_local_var(current)->vm;
	struct xpmem_segment *seg;
	struct xpmem_thread_group *seg_tg;
	struct thread *src_thread;
	struct process_vm *src_vm;

	XPMEM_DEBUG("call: at_vaddr=0x%lx", at_vaddr);

	ihk_rwspinlock_read_lock_noirq(&vm->memory_range_lock);

	range = lookup_process_memory_range(vm, at_vaddr, at_vaddr + 1);

	if (!range || range->start > at_vaddr) {
		ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);
		return 0;
	}

	att = (struct xpmem_attachment *)range->private_data;
	if (att == NULL) {
		ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);
		return -EINVAL;
	}

	xpmem_att_ref(att);

	mcs_rwlock_writer_lock(&att->at_lock, &at_lock);

	if (att->flags & XPMEM_FLAG_DESTROYING) {
		mcs_rwlock_writer_unlock(&att->at_lock, &at_lock);
		ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);
		xpmem_att_deref(att);
		return 0;
	}
	att->flags |= XPMEM_FLAG_DESTROYING;

	ap = att->ap;
	xpmem_ap_ref(ap);

	if (cpu_local_var(current)->proc->pid != ap->tg->tgid) {
		att->flags &= ~XPMEM_FLAG_DESTROYING;
		xpmem_ap_deref(ap);
		mcs_rwlock_writer_unlock(&att->at_lock, &at_lock);
		ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);
		xpmem_att_deref(att);
		return -EACCES;
	}

	xpmem_unpin_pages(ap->seg, vm, att->at_vaddr, att->at_size);

	range->private_data = NULL;
    /* range->memobj is released in xpmem_vm_munmap() --> xpmem_remove_process_range() -->
	   xpmem_free_process_memory_range() */

	mcs_rwlock_writer_unlock(&att->at_lock, &at_lock);

	XPMEM_DEBUG("xpmem_vm_munmap(): start=0x%lx, len=0x%lx", 
		range->start, att->at_size);
	ret = xpmem_vm_munmap(vm, (void *)range->start, att->at_size);
	if (ret) {
		ekprintf("%s: ERROR: xpmem_vm_munmap() failed %d\n", 
			__FUNCTION__, ret);
	}
	ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);
	DBUG_ON(ret != 0);

	att->flags &= ~XPMEM_FLAG_VALIDPTEs;

	ihk_mc_spinlock_lock_noirq(&ap->lock);
	list_del_init(&att->att_list);
	ihk_mc_spinlock_unlock_noirq(&ap->lock);

	xpmem_att_destroyable(att);

	/* deref remote thread, vm, range */
	seg = ap->seg;
	xpmem_seg_ref(seg);
	seg_tg = seg->tg;
	xpmem_tg_ref(seg_tg);
	src_vm = seg_tg->vm;
	src_thread = seg_tg->group_leader;

	ihk_rwspinlock_write_lock_noirq(&src_vm->memory_range_lock);

#if 0
	{
	unsigned long seg_vaddr;

	seg_vaddr = att->vaddr;
	kprintf("%s: remote-munmap, vm: %lx, range: %lx-%lx\n",
		__func__, (unsigned long)src_vm,
		seg_vaddr, seg_vaddr + att->at_size);

	ret = _do_munmap(src_thread,
			 src_vm,
			 (void *)seg_vaddr,
			 seg_vaddr + att->at_size,
			 1);

	if (ret) {
		kprintf("%s: error: _do_munmap: %lx-%lx, ret: %d\n",
			__func__,
			seg_vaddr, seg_vaddr + att->at_size,
			ret);
		ret = -EINVAL;
		ihk_rwspinlock_write_unlock_noirq(&src_vm->memory_range_lock);
		goto out;
	}

	ihk_rwspinlock_write_unlock_noirq(&src_vm->memory_range_lock);

	release_process_vm(src_vm);
	release_thread(src_thread);
	}
#else /* munmap source ranges containing attached */
	{
	struct vm_range *src_range;
	unsigned long src_vaddr;
	int count;

	/* avoid splitting by unmapping range by range */
	src_range = NULL;
	for (src_vaddr = att->min; src_vaddr < att->max; src_vaddr = src_range->end) {
		if (src_range == NULL) {
			src_range = lookup_process_memory_range(src_vm, src_vaddr, src_vaddr + 1);
			if (!src_range) {
				kprintf("%s: source range not found, vm: %lx, vaddr: %lx\n",
					__func__, (unsigned long)src_vm, src_vaddr);
				ret = -ENOENT;
				ihk_rwspinlock_write_unlock_noirq(&src_vm->memory_range_lock);
				goto out;
			}
		}
		else {
			src_range = next_process_memory_range(src_vm, src_range);
		}

		if ((count = ihk_atomic_add_long_return(-1, &src_range->xpmem_count.l)) == 0) {
			kprintf("%s: remote-munmap, vm: %lx,src_range: %lx-%lx\n",
				__func__, (unsigned long)src_vm,
				src_range->start, src_range->end);

			ret = _do_munmap(src_thread,
					 src_vm,
					 (void *)src_range->start,
					 src_range->end - src_range->start,
					 1);
			if (ret) {
				kprintf("%s: error: _do_munmap: %lx-%lx, ret: %d\n",
					__func__, src_range->start,
					src_range->end, ret);
				ihk_rwspinlock_write_unlock_noirq(&src_vm->memory_range_lock);
	                        goto out;
	                }
		}
		kprintf("%s: deref, src_vm: %lx, src_range: %lx-%lx, xpmem_count: %d\n",
			__func__, (unsigned long)src_vm,
			src_range->start, src_range->end,
			ihk_atomic64_read(&src_range->xpmem_count.atomic));
	}
	ihk_rwspinlock_write_unlock_noirq(&src_vm->memory_range_lock);
	release_process_vm(src_vm);
	release_thread(src_thread);
	}
#endif

	ret = 0;
 out:
	xpmem_seg_deref(seg);
	xpmem_tg_deref(seg_tg);

	xpmem_ap_deref(ap);
	xpmem_att_deref(att);

	XPMEM_DEBUG("return: ret=%d", ret);

	return ret;
}


static int xpmem_vm_munmap(
	struct process_vm *vm,
	void *addr,
	size_t len)
{
	int ret;
	int ro_freed;

	XPMEM_DEBUG("call: vm=0x%p, addr=0x%p, len=0x%lx", vm, addr, len);

	begin_free_pages_pending();

	ret = xpmem_remove_process_range(vm, (intptr_t)addr, 
		(intptr_t)(addr + len), &ro_freed);

	finish_free_pages_pending();

	XPMEM_DEBUG("return: ret=%d", ret);

	return ret;
}


static int xpmem_remove_process_range(
	struct process_vm *vm,
	unsigned long start,
	unsigned long end,
	int *ro_freedp)
{
	int error = 0;
	struct vm_range *range;
	struct vm_range *next;
	int ro_freed = 0;

	XPMEM_DEBUG("call: vm=0x%p, start=0x%lx, end=0x%lx", vm, start, end);

	next = lookup_process_memory_range(vm, start, end);
	while ((range = next) && range->start < end) {
		next = next_process_memory_range(vm, range);

		if (range->start < start) {
			error = split_process_memory_range(vm,
				range, start, &range);
			if (error) {
				ekprintf("%s(%p,%lx,%lx): ERROR: "
					"split failed %d\n",
					__FUNCTION__, vm, start, end, error);
				goto out;
			}
		}

		if (end < range->end) {
			error = split_process_memory_range(vm, range, end,
				NULL);
			if (error) {
				ekprintf("%s(%p,%lx,%lx): ERROR: "
					"split failed %d\n",
					__FUNCTION__, vm, start, end, error);
				goto out;
			}
		}

		if (!(range->flag & VR_PROT_WRITE)) {
			ro_freed = 1;
		}

		if (range->private_data) {
			xpmem_remove_process_memory_range(vm, range);
		}

		error = xpmem_free_process_memory_range(vm, range);
		if (error) {
			ekprintf("%s(%p,%lx,%lx): ERROR: free failed %d\n",
				__FUNCTION__, vm, start, end, error);
			goto out;
		}
	}

	if (ro_freedp) {
		*ro_freedp = ro_freed;
	}

out:
	XPMEM_DEBUG("return: ret=%d, ro_freed=%d", error, ro_freed);

	return error;
}


static int xpmem_free_process_memory_range(
	struct process_vm *vm,
	struct vm_range *range)
{
	int error;
	int i;

	XPMEM_DEBUG("call: vm=0x%p, start=0x%lx, end=0x%lx", 
		vm, range->start, range->end);

	ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);

	error = ihk_mc_pt_clear_range(vm->address_space->page_table, vm,
		(void *)range->start, (void *)range->end);

	ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);

	if (error && (error != -ENOENT)) {
		ekprintf("%s(%p,%lx-%lx): ERROR: "
			"ihk_mc_pt_clear_range(%lx-%lx) failed %d\n",
			__FUNCTION__, vm, range->start, range->end, 
			range->start, range->end, error);
		/* through */
	}

	if (range->memobj) {
		memobj_unref(range->memobj);
	}

	rb_erase(&range->vm_rb_node, &vm->vm_range_tree);
	for (i = 0; i < VM_RANGE_CACHE_SIZE; ++i) {
		if (vm->range_cache[i] == range)
			vm->range_cache[i] = NULL;
	}

	kfree(range);

	XPMEM_DEBUG("return: ret=%d", 0);

	return 0;
}


static void xpmem_detach_att(
	struct xpmem_access_permit *ap,
	struct xpmem_attachment *att)
{
	int ret;
	struct vm_range *range;
	struct process_vm *vm;
	struct mcs_rwlock_node_irqsave at_lock;

	XPMEM_DEBUG("call: apid=0x%lx, att=0x%p", ap->apid, att);

	XPMEM_DEBUG("detaching current->vm=0x%p, att->vm=0x%p", 
		(void *)cpu_local_var(current)->vm, (void *)att->vm);

	vm = cpu_local_var(current)->vm ? cpu_local_var(current)->vm : att->vm;

	ihk_rwspinlock_read_lock_noirq(&vm->memory_range_lock);

	mcs_rwlock_writer_lock(&att->at_lock, &at_lock);

	if (att->flags & XPMEM_FLAG_DESTROYING) {
		mcs_rwlock_writer_unlock(&att->at_lock, &at_lock);
		ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);
		XPMEM_DEBUG("return: XPMEM_FLAG_DESTROYING");
		return;
	}
	att->flags |= XPMEM_FLAG_DESTROYING;

	range = lookup_process_memory_range(cpu_local_var(current)->vm,
		att->at_vaddr, att->at_vaddr + 1);

	if (!range || range->start > att->at_vaddr) {
		ihk_mc_spinlock_lock_noirq(&ap->lock);
		list_del_init(&att->att_list);
		ihk_mc_spinlock_unlock_noirq(&ap->lock);
		mcs_rwlock_writer_unlock(&att->at_lock, &at_lock);
		ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);
		xpmem_att_destroyable(att);
		XPMEM_DEBUG("return: range=%p");
		return;
	}
	XPMEM_DEBUG("lookup_process_memory_range(): at_vaddr=0x%lx, " 
		"start=0x%lx, end=0x%lx", 
		att->at_vaddr, range->start, range->end);

	DBUG_ON(!xpmem_is_private_data(range));
	DBUG_ON((range->end - range->start) != att->at_size);
	DBUG_ON(range->private_data != att);

	xpmem_unpin_pages(ap->seg, vm, att->at_vaddr, att->at_size);

	range->private_data = NULL;
	/* range->memobj is released in xpmem_vm_munmap() --> xpmem_remove_process_range() -->
	   xpmem_free_process_memory_range() */

	att->flags &= ~XPMEM_FLAG_VALIDPTEs;

	ihk_mc_spinlock_lock_noirq(&ap->lock);
	list_del_init(&att->att_list);
	ihk_mc_spinlock_unlock_noirq(&ap->lock);

	mcs_rwlock_writer_unlock(&att->at_lock, &at_lock);

	XPMEM_DEBUG("xpmem_vm_munmap(): start=0x%lx, len=0x%lx", 
		range->start, att->at_size);
	ret = xpmem_vm_munmap(cpu_local_var(current)->vm, (void *)range->start, 
		att->at_size);
	if (ret) {
		ekprintf("%s: ERROR: xpmem_vm_munmap() failed %d\n", 
			__FUNCTION__, ret);
	}

	ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);

	xpmem_att_destroyable(att);

	XPMEM_DEBUG("return: ");
}


static void xpmem_clear_PTEs(
	struct xpmem_segment *seg)
{
	XPMEM_DEBUG("call: segid=0x%lx", seg->segid);

	xpmem_clear_PTEs_range(seg, seg->vaddr, seg->vaddr + seg->size);

	XPMEM_DEBUG("return: ");
}


static void xpmem_clear_PTEs_range(
	struct xpmem_segment *seg,
	unsigned long start,
	unsigned long end)
{
	struct xpmem_access_permit *ap;

	XPMEM_DEBUG("call: segid=0x%lx, start=0x%lx, end=0x%lx", 
		seg->segid, start, end);

	ihk_mc_spinlock_lock_noirq(&seg->lock);

	list_for_each_entry(ap, &seg->ap_list, ap_list) {
		xpmem_ap_ref(ap);
		ihk_mc_spinlock_unlock_noirq(&seg->lock);

		xpmem_clear_PTEs_of_ap(ap, start, end);

		ihk_mc_spinlock_lock_noirq(&seg->lock);
		if (list_empty(&ap->ap_list)) {
			xpmem_ap_deref(ap);
			ap = list_entry(&seg->ap_list, 
				struct xpmem_access_permit, ap_list);
		}
		else {
			xpmem_ap_deref(ap);
		}
	}

	ihk_mc_spinlock_unlock_noirq(&seg->lock);

	XPMEM_DEBUG("return: ");
}


static void xpmem_clear_PTEs_of_ap(
	struct xpmem_access_permit *ap,
	unsigned long start,
	unsigned long end)
{
	struct xpmem_attachment *att;

	XPMEM_DEBUG("call: apid=0x%lx, start=0x%lx, end=0x%lx", 
		ap->apid, start, end);

	ihk_mc_spinlock_lock_noirq(&ap->lock);

	list_for_each_entry(att, &ap->att_list, att_list) {
		if (!(att->flags & XPMEM_FLAG_VALIDPTEs))
			continue;

		xpmem_att_ref(att);
		ihk_mc_spinlock_unlock_noirq(&ap->lock);

		xpmem_clear_PTEs_of_att(att, start, end);

		ihk_mc_spinlock_lock_noirq(&ap->lock);
		if (list_empty(&att->att_list)) {
			xpmem_att_deref(att);
			att = list_entry(&ap->att_list, struct xpmem_attachment,
				att_list);
		}
		else {
			xpmem_att_deref(att);
		}
	}

	ihk_mc_spinlock_unlock_noirq(&ap->lock);

	XPMEM_DEBUG("return: ");
}


static void xpmem_clear_PTEs_of_att(
	struct xpmem_attachment *att,
	unsigned long start,
	unsigned long end)
{
	int ret;
	struct mcs_rwlock_node_irqsave at_lock;

	XPMEM_DEBUG("call: att=0x%p, start=0x%lx, end=0x%lx", 
		att, start, end);

	ihk_rwspinlock_read_lock_noirq(&att->vm->memory_range_lock);
	mcs_rwlock_writer_lock(&att->at_lock, &at_lock);

	if (att->flags & XPMEM_FLAG_VALIDPTEs) {
		struct vm_range *range;
		unsigned long invalidate_start;
		unsigned long invalidate_end;
		unsigned long invalidate_len;
		unsigned long offset_start;
		unsigned long offset_end;
		unsigned long unpin_at;
		unsigned long att_vaddr_end = att->vaddr + att->at_size;

		invalidate_start = max(start, att->vaddr);
		invalidate_end = min(end, att_vaddr_end);
		if (invalidate_start >= att_vaddr_end || 
			invalidate_end <= att->vaddr)
			goto out;

		offset_start = invalidate_start - att->vaddr;
		offset_end = invalidate_end - att->vaddr;

		unpin_at = att->at_vaddr + offset_start;
		invalidate_len = offset_end - offset_start;
		DBUG_ON(offset_in_page(unpin_at) ||
			offset_in_page(invalidate_len));
		XPMEM_DEBUG("unpin_at=0x%lx, invalidate_len=0x%lx\n",
			unpin_at, invalidate_len);

		xpmem_unpin_pages(att->ap->seg, att->vm, unpin_at,
			invalidate_len);

		range = lookup_process_memory_range(att->vm, att->at_vaddr, 
			att->at_vaddr + 1);
		if (!range) {
			ekprintf("%s: ERROR: lookup_process_memory_range() " 
				"failed\n", 
				__FUNCTION__);
			goto out;
		}

		mcs_rwlock_writer_unlock(&att->at_lock, &at_lock);

		XPMEM_DEBUG(
			"xpmem_vm_munmap(): start=0x%lx, len=0x%lx", 
			unpin_at, invalidate_len);
		ret = xpmem_vm_munmap(att->vm, (void *)unpin_at, 
			invalidate_len);
		if (ret) {
			ekprintf("%s: ERROR: xpmem_vm_munmap() failed %d\n", 
				__FUNCTION__, ret);
		}

		mcs_rwlock_writer_lock(&att->at_lock, &at_lock);

		if (offset_start == 0 && att->at_size == invalidate_len)
			att->flags &= ~XPMEM_FLAG_VALIDPTEs;
	}
out:
	mcs_rwlock_writer_unlock(&att->at_lock, &at_lock);
	ihk_rwspinlock_read_unlock_noirq(&att->vm->memory_range_lock);

	XPMEM_DEBUG("return: ");
}


int xpmem_remove_process_memory_range(
	struct process_vm *vm,
	struct vm_range *vmr)
{
	struct vm_range *remaining_vmr;
	u64 remaining_vaddr;
	struct xpmem_access_permit *ap;
	struct xpmem_attachment *att;
	struct mcs_rwlock_node_irqsave at_lock;

	XPMEM_DEBUG("call: vmr=0x%p, att=0x%p", vmr, vmr->private_data);

	att = (struct xpmem_attachment *)vmr->private_data;
	if (att == NULL) {
		return 0;
	}

	XPMEM_DEBUG("cleaning up vmr with range: 0x%lx - 0x%lx", 
		vmr->start, vmr->end);

	xpmem_att_ref(att);

	ihk_rwspinlock_read_lock_noirq(
		&cpu_local_var(current)->vm->memory_range_lock);

	mcs_rwlock_writer_lock(&att->at_lock, &at_lock);

	if (att->flags & XPMEM_FLAG_DESTROYING) {
		mcs_rwlock_writer_unlock(&att->at_lock, &at_lock);
		xpmem_att_deref(att);
		XPMEM_DEBUG("already cleaned up");
		return 0;
	}

	if (vmr->start == att->at_vaddr &&
		((vmr->end - vmr->start) == att->at_size)) {
		att->flags |= XPMEM_FLAG_DESTROYING;

		ap = att->ap;
		xpmem_ap_ref(ap);

		ihk_mc_spinlock_lock_noirq(&ap->lock);
		list_del_init(&att->att_list);
		ihk_mc_spinlock_unlock_noirq(&ap->lock);

		xpmem_ap_deref(ap);

		xpmem_att_destroyable(att);
		goto out;
	}

	if (vmr->start == att->at_vaddr) {
		remaining_vaddr = vmr->end;
	}
	else if (vmr->end == att->at_vaddr + att->at_size) {
		remaining_vaddr = att->at_vaddr;
	}
	else {
		remaining_vaddr = vmr->end;
		remaining_vmr = lookup_process_memory_range(
			cpu_local_var(current)->vm, remaining_vaddr - 1, 
			remaining_vaddr);
		if (!remaining_vmr) {
			ekprintf("%s: ERROR: vm_range is NULL\n", __FUNCTION__);
			goto out;
		}
		else if (remaining_vmr->start > remaining_vaddr || 
			remaining_vmr->private_data != vmr->private_data) {
			ekprintf("%s: ERROR: vm_range: 0x%lx - 0x%lx\n", 
				__FUNCTION__, vmr->start, vmr->end);
			goto out;
		}

		remaining_vmr->private_data = NULL;
		/* This function is always followed by xpmem_free_process_memory_range() 
		 * which in turn calls memobj_put()
		 */
		remaining_vaddr = att->at_vaddr;
	}

	remaining_vmr = lookup_process_memory_range(
		cpu_local_var(current)->vm, remaining_vaddr, 
		remaining_vaddr + 1);
	if (!remaining_vmr) {
		ekprintf("%s: ERROR: vm_range is NULL\n", __FUNCTION__);
		goto out;
	}
	else if (remaining_vmr->start > remaining_vaddr || 
		remaining_vmr->private_data != vmr->private_data) {
		ekprintf("%s: ERROR: vm_range: 0x%lx - 0x%lx\n", 
			__FUNCTION__, vmr->start, vmr->end);
		goto out;
	}

	att->at_vaddr = remaining_vmr->start;
	att->at_size = remaining_vmr->end - remaining_vmr->start;

	vmr->private_data = NULL;
	/* This function is always followed by [xpmem_]free_process_memory_range()
	 * which in turn calls memobj_put()
	 */

out:
	mcs_rwlock_writer_unlock(&att->at_lock, &at_lock);

	ihk_rwspinlock_read_unlock_noirq(
		&cpu_local_var(current)->vm->memory_range_lock);

	xpmem_att_deref(att);

	XPMEM_DEBUG("return: ret=%d", 0);

	return 0;
}


int xpmem_fault_process_memory_range(
	struct process_vm *vm,
	struct vm_range *vmr,
	unsigned long vaddr,
	uint64_t reason)
{
	int ret = 0;
	unsigned long seg_vaddr = 0;
	pte_t *pte = NULL;
	pte_t *old_pte = NULL;
	struct xpmem_thread_group *ap_tg;
	struct xpmem_thread_group *seg_tg;
	struct xpmem_access_permit *ap;
	struct xpmem_attachment *att;
	struct xpmem_segment *seg;
	size_t pgsize;
	struct mcs_rwlock_node_irqsave at_lock = { 0 };
	int att_locked = 0;

	XPMEM_DEBUG("call: vmr=0x%p, vaddr=0x%lx, reason=0x%lx", 
		vmr, vaddr, reason);

	att = (struct xpmem_attachment *)vmr->private_data;
	if (att == NULL) {
		return -EFAULT;
	}

	xpmem_att_ref(att);
	ap = att->ap;
	xpmem_ap_ref(ap);
	ap_tg = ap->tg;
	xpmem_tg_ref(ap_tg);
	if ((ap->flags & XPMEM_FLAG_DESTROYING) ||
		(ap_tg->flags & XPMEM_FLAG_DESTROYING)) {
		xpmem_att_deref(att);
		xpmem_ap_deref(ap);
		xpmem_tg_deref(ap_tg);
		return -EFAULT;
	}
	DBUG_ON(cpu_local_var(current)->proc->pid != ap_tg->tgid);
	DBUG_ON(ap->mode != XPMEM_RDWR);

	seg = ap->seg;
	xpmem_seg_ref(seg);
	seg_tg = seg->tg;
	xpmem_tg_ref(seg_tg);

	if ((seg->flags & XPMEM_FLAG_DESTROYING) ||
		(seg_tg->flags & XPMEM_FLAG_DESTROYING)) {
		kprintf("%s: error: destroying, seg->flag: %lx, seg_tg->flags: %lx\n",
			__func__, seg->flags, seg_tg->flags);
		ret = -ENOENT;
		goto out_2;
	}

	mcs_rwlock_writer_lock(&att->at_lock, &at_lock);
	att_locked = 1;

	if ((att->flags & XPMEM_FLAG_DESTROYING) ||
		(ap_tg->flags & XPMEM_FLAG_DESTROYING) ||
		(seg_tg->flags & XPMEM_FLAG_DESTROYING)) {
		goto out_2;
	}

	if (vaddr < att->at_vaddr || vaddr + 1 > att->at_vaddr + att->at_size) {
		goto out_2;
	}

	seg_vaddr = (att->vaddr & PAGE_MASK) + (vaddr - att->at_vaddr);
	XPMEM_DEBUG("vaddr=%lx, seg_vaddr=%lx", vaddr, seg_vaddr);

	ret = xpmem_ensure_valid_page(seg, seg_vaddr);
	if (ret != 0) {
		kprintf("%s: xpmem_ensure_valid_page failed with %d\n",
			__func__, ret);
		goto out_2;
	}

	pte = xpmem_vaddr_to_pte(seg_tg->vm, seg_vaddr, &pgsize);

	att->flags |= XPMEM_FLAG_VALIDPTEs;

out_2:
	xpmem_ap_deref(ap);
	xpmem_tg_deref(ap_tg);

	if (pte && !pte_is_null(pte)) {
		old_pte = xpmem_vaddr_to_pte(cpu_local_var(current)->vm, vaddr, 
			&pgsize);
		if (old_pte && !pte_is_null(old_pte)) {
			if (*old_pte != *pte) {
				ret = -EFAULT;
				ekprintf("%s: ERROR: pte mismatch: " 
					"0x%lx != 0x%lx\n", 
					__FUNCTION__, *old_pte, *pte);
			}

			ihk_atomic_dec(&seg->tg->n_pinned);
			goto out_1;
		}

		ret = xpmem_remap_pte(vm, vmr, vaddr, reason, seg, seg_vaddr);
		if (ret) {
			ekprintf("%s: ERROR: xpmem_remap_pte() failed %d\n", 
				__FUNCTION__, ret);
		}
	}

	flush_tlb_single(vaddr);

out_1:
	if (att_locked) {
		mcs_rwlock_writer_unlock(&att->at_lock, &at_lock);
	}

	xpmem_tg_deref(seg_tg);
	xpmem_seg_deref(seg);
	xpmem_att_deref(att);

	XPMEM_DEBUG("return: ret=%d", ret);

	return ret;
}


static int xpmem_remap_pte(
	struct process_vm *vm,
	struct vm_range *vmr,
	unsigned long vaddr,
	uint64_t reason,
	struct xpmem_segment *seg,
	unsigned long seg_vaddr)
{
	int ret;
	struct xpmem_thread_group *seg_tg = seg->tg;
	struct vm_range *seg_vmr;
	pte_t *seg_pte;
	void *seg_pgaddr;
	size_t seg_pgsize;
	int seg_p2align;
	uintptr_t seg_phys;
	pte_t *att_pte;
	void *att_pgaddr;
	size_t att_pgsize;
	int att_p2align;
	enum ihk_mc_pt_attribute att_attr;

	XPMEM_DEBUG("call: vmr=0x%p, vaddr=0x%lx, reason=0x%lx, segid=0x%lx, " 
		"seg_vaddr=0x%lx", 
		vmr, vaddr, reason, seg->segid, seg_vaddr);

	ihk_rwspinlock_read_lock_noirq(&seg_tg->vm->memory_range_lock);

	seg_vmr = lookup_process_memory_range(seg_tg->vm, seg_vaddr, 
		seg_vaddr + 1);

	ihk_rwspinlock_read_unlock_noirq(&seg_tg->vm->memory_range_lock);

	if (!seg_vmr) {
		ret = -EFAULT;
		ekprintf("%s: ERROR: lookup_process_memory_range() failed\n", 
			__FUNCTION__);
		goto out;
	}

	if (seg_tg->vm->proc->straight_va &&
			seg_vaddr >= seg_tg->vm->proc->straight_va &&
			seg_vaddr < (seg_tg->vm->proc->straight_va +
				seg_tg->vm->proc->straight_len)) {
		seg_phys = (((unsigned long)seg_vaddr & PAGE_MASK) -
				(unsigned long)seg_tg->vm->proc->straight_va) +
			seg_tg->vm->proc->straight_pa;
		dkprintf("%s: 0x%lx in PID %d is straight -> phys: 0x%lx\n",
				__func__, (unsigned long)seg_vaddr & PAGE_MASK,
				seg_tg->tgid, seg_phys);
	}
	else {

		seg_pte = ihk_mc_pt_lookup_pte(seg_tg->vm->address_space->page_table, 
				(void *)seg_vaddr, seg_vmr->pgshift, &seg_pgaddr, &seg_pgsize, 
				&seg_p2align);
		if (!seg_pte) {
			ret = -EFAULT;
			ekprintf("%s: ERROR: ihk_mc_pt_lookup_pte() failed\n", 
					__FUNCTION__);
			goto out;
		}
		XPMEM_DEBUG("seg_pte=0x%016lx, seg_pgaddr=0x%p, seg_pgsize=%lu, " 
				"seg_p2align=%d", 
				*seg_pte, seg_pgaddr, seg_pgsize, seg_p2align);

		seg_phys = pte_get_phys(seg_pte);
		XPMEM_DEBUG("seg_phys=0x%lx", seg_phys);
	}

	att_pte = ihk_mc_pt_lookup_pte(vm->address_space->page_table, 
		(void *)vaddr, vmr->pgshift, &att_pgaddr, &att_pgsize, 
		&att_p2align);
	XPMEM_DEBUG("att_pte=%p, att_pgaddr=0x%p, att_pgsize=%lu, " 
		"att_p2align=%d", 
		att_pte, att_pgaddr, att_pgsize, att_p2align);

	att_attr = arch_vrflag_to_ptattr(vmr->flag, reason, att_pte);
	XPMEM_DEBUG("att_attr=0x%lx", att_attr);

	if (att_pte) {
		ret = ihk_mc_pt_set_pte(vm->address_space->page_table, att_pte, 
			att_pgsize, seg_phys, att_attr);
		if (ret) {
			ret = -EFAULT;
			ekprintf("%s: ERROR: ihk_mc_pt_set_pte() failed %d\n", 
				__FUNCTION__, ret);
			goto out;
		}
		// memory_stat_rss_add() is called by the process hosting the memory area
	}
	else {
		ret = ihk_mc_pt_set_range(vm->address_space->page_table, vm, 
			att_pgaddr, att_pgaddr + att_pgsize, seg_phys, att_attr,
								  vmr->pgshift, vmr, 0);
		if (ret) {
			ret = -EFAULT;
			ekprintf("%s: ERROR: ihk_mc_pt_set_range() failed %d\n",
				 __FUNCTION__, ret);
			goto out;
		}
		// memory_stat_rss_add() is called by the process hosting the memory area
	}

out:
	XPMEM_DEBUG("return: ret=%d", ret);

	return ret;
}


static int xpmem_ensure_valid_page(
	struct xpmem_segment *seg,
	unsigned long vaddr)
{
	int ret;
	struct xpmem_thread_group *seg_tg = seg->tg;

	XPMEM_DEBUG("call: segid=0x%lx, vaddr=0x%lx", seg->segid, vaddr);

	if (seg->flags & XPMEM_FLAG_DESTROYING)
		return -ENOENT;

	ret = xpmem_pin_page(seg_tg, seg_tg->group_leader, seg_tg->vm, vaddr);

	XPMEM_DEBUG("return: ret=%d", ret);

	return ret;
}


static pte_t * xpmem_vaddr_to_pte(
	struct process_vm *vm,
	unsigned long vaddr,
	size_t *pgsize)
{
	pte_t *pte = NULL;
	struct vm_range *range;
	int pgshift;
	void *base;
	size_t size;
	int p2align;

	range = lookup_process_memory_range(vm, vaddr, vaddr + 1);
	if (range) {
		pgshift = range->pgshift;
	}
	else {
		goto out;
	}

	pte = ihk_mc_pt_lookup_pte(vm->address_space->page_table, 
		(void *)vaddr, pgshift, &base, &size, &p2align);
	if (pte) {
		*pgsize = size;
	}
	else {
		*pgsize = PAGE_SIZE;
	}

out:

        return pte;
}

static int xpmem_pin_page(
	struct xpmem_thread_group *tg,
	struct thread *src_thread,
	struct process_vm *src_vm,
	unsigned long vaddr)
{
	int ret;
	struct vm_range *range;

	XPMEM_DEBUG("call: tgid=%d, vaddr=0x%lx", tg->tgid, vaddr);

	ihk_rwspinlock_read_lock_noirq(&src_vm->memory_range_lock);

	range = lookup_process_memory_range(src_vm, vaddr, vaddr + 1);

	ihk_rwspinlock_read_unlock_noirq(&src_vm->memory_range_lock);

	if (!range || range->start > vaddr) {
		if (range) {
			kprintf("%s: error: invalid range->start, "
				"src vm: %lx, range: %lx, vaddr: %lx, range: %lx-%lx\n",
				__func__,
				(unsigned long)src_vm,
				range,
				vaddr,
				range->start,
				range->end);
		} else {
			kprintf("%s: error: src range not found, "
				"src vm: %lx, range: %lx, vaddr: %lx\n",
				__func__,
				(unsigned long)src_vm,
				range,
				vaddr);
		}

		dump_stack_ranges(src_vm);
		return -ENOENT;
	}

	if (xpmem_is_private_data(range)) {
		return -ENOENT;
	}

	ret = page_fault_process_vm(src_vm, (void *)vaddr, 
		PF_POPULATE | PF_WRITE | PF_USER);
	if (!ret) {
		ihk_atomic_inc(&tg->n_pinned);
	}
	else {
		return -ENOENT;
	}

	XPMEM_DEBUG("return: ret=%d", ret);

        return ret;
}


static void xpmem_unpin_pages(
	struct xpmem_segment *seg,
	struct process_vm *vm,
	unsigned long vaddr,
	size_t size)
{
	int n_pgs = (((offset_in_page(vaddr) + (size)) + (PAGE_SIZE - 1)) >> 
		PAGE_SHIFT);
	int n_pgs_unpinned = 0;
	size_t vsize = 0;
	pte_t *pte = NULL;

	XPMEM_DEBUG("call: segid=0x%lx, vaddr=0x%lx, size=0x%lx", 
		seg->segid, vaddr, size);

	XPMEM_DEBUG("n_pgs=%d", n_pgs);

	vaddr &= PAGE_MASK;

	while (n_pgs > 0) {
		pte = xpmem_vaddr_to_pte(vm, vaddr, &vsize);
		if (pte && !pte_is_null(pte)) {
			n_pgs_unpinned++;
			vaddr += PAGE_SIZE;
			n_pgs--;
		}
		else {
			vsize = ((vaddr + vsize) & (~(vsize - 1)));
			n_pgs -= (vsize - vaddr) / PAGE_SIZE;
			vaddr = vsize;
		}
	}

	XPMEM_DEBUG("sub: tg->n_pinned=%d, n_pgs_unpinned=%d", 
		seg->tg->n_pinned, n_pgs_unpinned);
	ihk_atomic_sub(n_pgs_unpinned, &seg->tg->n_pinned);

	XPMEM_DEBUG("return: ");
}


static struct xpmem_thread_group *__xpmem_tg_ref_by_tgid_nolock_internal(
	pid_t tgid,
	int index,
	int return_destroying)
{
	struct xpmem_thread_group *tg;

	list_for_each_entry(tg, &xpmem_my_part->tg_hashtable[index].list,
		tg_hashlist) {
		if (tg->tgid == tgid) {
			if ((tg->flags & XPMEM_FLAG_DESTROYING) &&
				!return_destroying) {
				continue;
			}

			xpmem_tg_ref(tg);

			return tg;
		}
	}

	return ERR_PTR(-ENOENT);
}


static struct xpmem_thread_group *xpmem_tg_ref_by_segid(
	xpmem_segid_t segid)
{
	struct xpmem_thread_group *tg;

	tg = xpmem_tg_ref_by_tgid(xpmem_segid_to_tgid(segid));

        return tg;
}


static struct xpmem_thread_group *xpmem_tg_ref_by_apid(
	xpmem_apid_t apid)
{
	struct xpmem_thread_group *tg;

	tg = xpmem_tg_ref_by_tgid(xpmem_apid_to_tgid(apid));

	return tg;
}


static void xpmem_tg_deref(
	struct xpmem_thread_group *tg)
{
	DBUG_ON(ihk_atomic_read(&tg->refcnt) <= 0);
	if (ihk_atomic_dec_return(&tg->refcnt) != 0) {
		XPMEM_DEBUG("return: tg->refcnt=%d, tg->n_pinned=%d", 
			tg->refcnt, tg->n_pinned);
		return;
	}

	XPMEM_DEBUG("kfree(): tg=0x%p", tg);
	kfree(tg);
}


static struct xpmem_segment * xpmem_seg_ref_by_segid(
	struct xpmem_thread_group *seg_tg,
	xpmem_segid_t segid)
{
	struct xpmem_segment *seg;
	struct mcs_rwlock_node_irqsave lock;

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


static void xpmem_seg_deref(struct xpmem_segment *seg)
{
	DBUG_ON(ihk_atomic_read(&seg->refcnt) <= 0);
	if (ihk_atomic_dec_return(&seg->refcnt) != 0) {
		XPMEM_DEBUG("return: seg->refcnt=%d", seg->refcnt);
		return;
	}

	DBUG_ON(!(seg->flags & XPMEM_FLAG_DESTROYING));

	XPMEM_DEBUG("kfree(): seg=0x%p", seg);
	kfree(seg);
}


static struct xpmem_access_permit * xpmem_ap_ref_by_apid(
	struct xpmem_thread_group *ap_tg,
	xpmem_apid_t apid)
{
	int index;
	struct xpmem_access_permit *ap;
	struct mcs_rwlock_node_irqsave lock;

	index = xpmem_ap_hashtable_index(apid);
	mcs_rwlock_reader_lock(&ap_tg->ap_hashtable[index].lock, &lock);

	list_for_each_entry(ap, &ap_tg->ap_hashtable[index].list,
		ap_hashlist) {
		if (ap->apid == apid) {
			if (ap->flags & XPMEM_FLAG_DESTROYING) {
				break;
			}

			xpmem_ap_ref(ap);
			mcs_rwlock_reader_unlock(
				&ap_tg->ap_hashtable[index].lock, &lock);
			return ap;
		}
	}

	mcs_rwlock_reader_unlock(&ap_tg->ap_hashtable[index].lock, &lock);

	return ERR_PTR(-ENOENT);
}


static void xpmem_ap_deref(struct xpmem_access_permit *ap)
{
	DBUG_ON(ihk_atomic_read(&ap->refcnt) <= 0);
	if (ihk_atomic_dec_return(&ap->refcnt) != 0) {
		XPMEM_DEBUG("return: ap->refcnt=%d", ap->refcnt);
		return;
	}

	DBUG_ON(!(ap->flags & XPMEM_FLAG_DESTROYING));

	XPMEM_DEBUG("kfree(): ap=0x%p", ap);
	kfree(ap);
}


static void xpmem_att_deref(struct xpmem_attachment *att)
{
	DBUG_ON(ihk_atomic_read(&att->refcnt) <= 0);
	if (ihk_atomic_dec_return(&att->refcnt) != 0) {
		XPMEM_DEBUG("return: att->refcnt=%d", att->refcnt);
		return;
	}

	DBUG_ON(!(att->flags & XPMEM_FLAG_DESTROYING));

	XPMEM_DEBUG("kfree(): att=0x%p", att);
	kfree(att);
}


static int xpmem_validate_access(
	struct xpmem_access_permit *ap,
	off_t offset,
	size_t size,
	int mode,
	unsigned long *vaddr)
{
	XPMEM_DEBUG("call: apid=0x%lx, offset=0x%lx, size=0x%lx, mode=%d",  
		ap->apid, offset, size, mode);

	if (cpu_local_var(current)->proc->pid != ap->tg->tgid ||
		(mode == XPMEM_RDWR && ap->mode == XPMEM_RDONLY)) {
		return -EACCES;
	}

	if (offset < 0 || size == 0 || offset + size > ap->seg->size) {
		return -EINVAL;
	}

	*vaddr = ap->seg->vaddr + offset;
	kprintf("%s: vm: %lx, src_vaddr: %lx, seg->vaddr: %lx, offset: %lx\n",
		__func__, (unsigned long)ap->seg->tg->vm,
		*vaddr, ap->seg->vaddr, offset);

	XPMEM_DEBUG("return: ret=%d, vaddr=0x%lx", 0, *vaddr);

	return 0;
}

