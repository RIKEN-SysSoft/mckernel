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
#include <process.h>
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
	unsigned long at_lock;
	struct process_vm *vm = cpu_local_var(current)->vm;

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

	ihk_rwspinlock_init(&att->at_lock);
	att->vaddr = seg_vaddr;
	att->at_size = size;
	att->ap = ap;
	INIT_LIST_HEAD(&att->att_list);
	att->vm = vm;

        xpmem_att_not_destroyable(att);
        xpmem_att_ref(att);

	at_lock = ihk_rwspinlock_write_lock(&att->at_lock);

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

		for (; existing_vmr && existing_vmr->start < vaddr + size;
			existing_vmr = next_process_memory_range(vm, 
			existing_vmr)) {
			if (xpmem_is_private_data(existing_vmr)) {
				ret = -EINVAL;
				ihk_rwspinlock_read_unlock_noirq(
					&vm->memory_range_lock);
				goto out_2;
			}
		}

		ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);
	}

	flags |= MAP_ANONYMOUS;
	XPMEM_DEBUG("do_mmap(): vaddr=0x%lx, size=0x%lx, prot_flags=0x%lx, " 
		"flags=0x%lx, fd=%d, offset=0x%lx", 
		vaddr, size, prot_flags, flags, mckfd->fd, offset);
	/* The new range is associated with shmobj because of
	 * MAP_ANONYMOUS && !MAP_PRIVATE && MAP_SHARED. Note that MAP_FIXED
	 * support prevents us from reusing segment vm_range when segment vm
	 * and attach vm is the same.
	 */
	at_vaddr = do_mmap(vaddr, size, prot_flags, flags, mckfd->fd,
			offset, VR_XPMEM, att);
	if (IS_ERR((void *)(uintptr_t)at_vaddr)) {
		ret = at_vaddr;
		goto out_2;
	}
	XPMEM_DEBUG("at_vaddr=0x%lx", at_vaddr);

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
	ihk_rwspinlock_write_unlock(&att->at_lock, at_lock);
	xpmem_att_deref(att);
out_1:
	xpmem_ap_deref(ap);
	xpmem_tg_deref(ap_tg);
	xpmem_seg_deref(seg);
	xpmem_tg_deref(seg_tg);

	XPMEM_DEBUG("return: ret=%d, at_vaddr=0x%lx", ret, *at_vaddr_p);

	return ret;
}

static int xpmem_detach(
	unsigned long at_vaddr)
{
	int ret;
	struct xpmem_access_permit *ap;
	struct xpmem_attachment *att;
	unsigned long at_lock;
	struct vm_range *range;
	struct process_vm *vm = cpu_local_var(current)->vm;

	XPMEM_DEBUG("call: at_vaddr=0x%lx", at_vaddr);

	ihk_rwspinlock_write_lock_noirq(&vm->memory_range_lock);

	range = lookup_process_memory_range(vm, at_vaddr, at_vaddr + 1);

	if (!range || range->start > at_vaddr) {
		ihk_rwspinlock_write_unlock_noirq(&vm->memory_range_lock);
		return 0;
	}

	att = (struct xpmem_attachment *)range->private_data;
	if (att == NULL) {
		ihk_rwspinlock_write_unlock_noirq(&vm->memory_range_lock);
		return -EINVAL;
	}

	xpmem_att_ref(att);

	at_lock = ihk_rwspinlock_write_lock(&att->at_lock);

	if (att->flags & XPMEM_FLAG_DESTROYING) {
		ihk_rwspinlock_write_unlock(&att->at_lock, at_lock);
		ihk_rwspinlock_write_unlock_noirq(&vm->memory_range_lock);
		xpmem_att_deref(att);
		return 0;
	}
	att->flags |= XPMEM_FLAG_DESTROYING;

	ap = att->ap;
	xpmem_ap_ref(ap);

	if (cpu_local_var(current)->proc->pid != ap->tg->tgid) {
		att->flags &= ~XPMEM_FLAG_DESTROYING;
		xpmem_ap_deref(ap);
		ihk_rwspinlock_write_unlock(&att->at_lock, at_lock);
		ihk_rwspinlock_write_unlock_noirq(&vm->memory_range_lock);
		xpmem_att_deref(att);
		return -EACCES;
	}

	xpmem_unpin_pages(ap->seg, vm, att->at_vaddr, att->at_size);

	range->private_data = NULL;
    /* range->memobj is released in xpmem_vm_munmap() --> xpmem_remove_process_range() -->
	   xpmem_free_process_memory_range() */

	ihk_rwspinlock_write_unlock(&att->at_lock, at_lock);

	XPMEM_DEBUG("xpmem_vm_munmap(): start=0x%lx, len=0x%lx", 
		range->start, att->at_size);
	ret = xpmem_vm_munmap(vm, (void *)range->start, att->at_size);
	if (ret) {
		ekprintf("%s: ERROR: xpmem_vm_munmap() failed %d\n", 
			__FUNCTION__, ret);
	}
	ihk_rwspinlock_write_unlock_noirq(&vm->memory_range_lock);
	DBUG_ON(ret != 0);

	att->flags &= ~XPMEM_FLAG_VALIDPTEs;

	ihk_mc_spinlock_lock_noirq(&ap->lock);
	list_del_init(&att->att_list);
	ihk_mc_spinlock_unlock_noirq(&ap->lock);

	xpmem_att_destroyable(att);

	xpmem_ap_deref(ap);
	xpmem_att_deref(att);

	XPMEM_DEBUG("return: ret=%d", 0);

	return 0;
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
	unsigned long at_lock;

	XPMEM_DEBUG("call: apid=0x%lx, att=0x%p", ap->apid, att);

	XPMEM_DEBUG("detaching att->vm=0x%p", (void *)att->vm);

	at_lock = ihk_rwspinlock_write_lock(&att->at_lock);

	if (att->flags & XPMEM_FLAG_DESTROYING) {
		ihk_rwspinlock_write_unlock(&att->at_lock, at_lock);
		XPMEM_DEBUG("return: XPMEM_FLAG_DESTROYING");
		return;
	}
	att->flags |= XPMEM_FLAG_DESTROYING;

	vm = att->vm;
	ihk_rwspinlock_read_lock_noirq(&vm->memory_range_lock);

	range = lookup_process_memory_range(vm,
		att->at_vaddr, att->at_vaddr + 1);

	if (!range || range->start > att->at_vaddr) {
		ihk_mc_spinlock_lock_noirq(&ap->lock);
		list_del_init(&att->att_list);
		ihk_mc_spinlock_unlock_noirq(&ap->lock);
		ihk_rwspinlock_write_unlock(&att->at_lock, at_lock);
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

	ihk_rwspinlock_write_unlock(&att->at_lock, at_lock);

	XPMEM_DEBUG("xpmem_vm_munmap(): start=0x%lx, len=0x%lx", 
		range->start, att->at_size);
	ret = xpmem_vm_munmap(vm, (void *)range->start, att->at_size);
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
	unsigned long at_lock;

	XPMEM_DEBUG("call: att=0x%p, start=0x%lx, end=0x%lx", 
		att, start, end);

	ihk_rwspinlock_read_lock_noirq(&att->vm->memory_range_lock);
	at_lock = ihk_rwspinlock_write_lock(&att->at_lock);

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

		ihk_rwspinlock_write_unlock(&att->at_lock, at_lock);

		XPMEM_DEBUG(
			"xpmem_vm_munmap(): start=0x%lx, len=0x%lx", 
			unpin_at, invalidate_len);
		ret = xpmem_vm_munmap(att->vm, (void *)unpin_at, 
			invalidate_len);
		if (ret) {
			ekprintf("%s: ERROR: xpmem_vm_munmap() failed %d\n", 
				__FUNCTION__, ret);
		}

		at_lock = ihk_rwspinlock_write_lock(&att->at_lock);

		if (offset_start == 0 && att->at_size == invalidate_len)
			att->flags &= ~XPMEM_FLAG_VALIDPTEs;
	}
out:
	ihk_rwspinlock_write_unlock(&att->at_lock, at_lock);
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
	unsigned long at_lock;

	XPMEM_DEBUG("call: vmr=0x%p, att=0x%p", vmr, vmr->private_data);

	att = (struct xpmem_attachment *)vmr->private_data;
	if (att == NULL) {
		return 0;
	}

	XPMEM_DEBUG("cleaning up vmr with range: 0x%lx - 0x%lx", 
		vmr->start, vmr->end);

	xpmem_att_ref(att);

	at_lock = ihk_rwspinlock_write_lock(&att->at_lock);

	if (att->flags & XPMEM_FLAG_DESTROYING) {
		XPMEM_DEBUG("already cleaned up");
		goto out;
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
			vm, remaining_vaddr - 1,
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
		vm, remaining_vaddr,
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
	ihk_rwspinlock_write_unlock(&att->at_lock, at_lock);

	xpmem_att_deref(att);

	XPMEM_DEBUG("return: ret=%d", 0);

	return 0;
}


static int _xpmem_fault_process_memory_range(
	struct process_vm *vm,
	struct vm_range *vmr,
	unsigned long vaddr,
	uint64_t reason,
	int page_in_remote)
{
	int ret = 0;
	unsigned long seg_vaddr;
	struct xpmem_thread_group *ap_tg;
	struct xpmem_thread_group *seg_tg;
	struct xpmem_access_permit *ap;
	struct xpmem_attachment *att;
	struct xpmem_segment *seg;
	pte_t *att_pte;
	void *att_pgaddr;
	size_t att_pgsize;
	int att_p2align;
	pte_t *seg_pte;
	size_t seg_pgsize;
	uintptr_t seg_phys;
	uintptr_t seg_phys_plus_off;
	enum ihk_mc_pt_attribute att_attr;

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
		ret = -ENOENT;
		goto out;
	}

	if ((att->flags & XPMEM_FLAG_DESTROYING) ||
		(ap_tg->flags & XPMEM_FLAG_DESTROYING) ||
		(seg_tg->flags & XPMEM_FLAG_DESTROYING)) {
		goto out;
	}

	if (vaddr < att->at_vaddr || vaddr + 1 > att->at_vaddr + att->at_size) {
		goto out;
	}

	/* page-in remote pages on page-fault or (on attach and
	 * xpmem_remote_on_demand isn't specified)
	 */
	seg_vaddr = att->vaddr + (vaddr - att->at_vaddr);
	XPMEM_DEBUG("vaddr=%lx, seg_vaddr=%lx", vaddr, seg_vaddr);

	ret = xpmem_ensure_valid_page(seg, seg_vaddr, page_in_remote);
	if (ret != 0) {
		goto out;
	}

	if (is_remote_vm(seg_tg->vm)) {
		ihk_rwspinlock_read_lock_noirq(&seg_tg->vm->memory_range_lock);
	}

	if (seg_tg->vm->proc->straight_va &&
	    seg_vaddr >= seg_tg->vm->proc->straight_va &&
	    seg_vaddr < (seg_tg->vm->proc->straight_va +
			 seg_tg->vm->proc->straight_len)) {
		seg_phys = (((unsigned long)seg_vaddr & PAGE_MASK) -
			    (unsigned long)seg_tg->vm->proc->straight_va) +
			seg_tg->vm->proc->straight_pa;
		seg_pgsize = (1UL << 29);
		dkprintf("%s: 0x%lx in PID %d is straight -> phys: 0x%lx\n",
			 __func__, (unsigned long)seg_vaddr & PAGE_MASK,
			 seg_tg->tgid, seg_phys);
	}
	else {
		seg_pte = xpmem_vaddr_to_pte(seg_tg->vm, seg_vaddr, &seg_pgsize);

		/* map only resident remote pages on attach and
		 * xpmem_remote_on_demand is specified
		 */
		if (!seg_pte || pte_is_null(seg_pte)) {
			ret = page_in_remote ? -EFAULT : 0;
			if (is_remote_vm(seg_tg->vm)) {
				ihk_rwspinlock_read_unlock_noirq(&seg_tg->vm->memory_range_lock);
			}
			goto out;
		}

		seg_phys = pte_get_phys(seg_pte);
	}

	/* clear lower bits of the contiguous-PTE tail entries */
	seg_phys_plus_off = (seg_phys & ~(seg_pgsize - 1)) |
		(seg_vaddr & (seg_pgsize - 1));
	XPMEM_DEBUG("seg_vaddr: %lx, seg_phys: %lx, seg_phys_plus_off: %lx",
		    seg_vaddr, seg_phys, seg_phys_plus_off);

	if (is_remote_vm(seg_tg->vm)) {
		ihk_rwspinlock_read_unlock_noirq(&seg_tg->vm->memory_range_lock);
	}

	/* find largest page-size fitting vm range and segment page */
	att_pte = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
		(void *)vaddr, vmr->pgshift, &att_pgaddr, &att_pgsize,
		&att_p2align);

	while ((unsigned long)att_pgaddr < vmr->start ||
	       vmr->end < (uintptr_t)att_pgaddr + att_pgsize ||
	       att_pgsize > seg_pgsize) {
		att_pte = NULL;
		ret = arch_get_smaller_page_size(NULL, att_pgsize,
						 &att_pgsize, &att_p2align);
		if (ret) {
			ekprintf("%s: arch_get_smaller_page_size failed: "
				 " range: %lx-%lx, pgsize: %lx, ret: %d\n",
				 __func__, vmr->start, vmr->end, att_pgsize,
				 ret);
			goto out;
		}
		att_pgaddr = (void *)(vaddr & ~(att_pgsize - 1));
	}

	arch_adjust_allocate_page_size(vm->address_space->page_table,
				       vaddr, att_pte, &att_pgaddr,
				       &att_pgsize);

	XPMEM_DEBUG("att_pte=%p, att_pgaddr=0x%p, att_pgsize=%lu, "
		"att_p2align=%d",
		att_pte, att_pgaddr, att_pgsize, att_p2align);

	/* last arg is not used */
	att_attr = arch_vrflag_to_ptattr(vmr->flag, reason, NULL);
	XPMEM_DEBUG("att_attr=0x%lx", att_attr);

	if (att_pte && !pte_is_null(att_pte)) {
		unsigned long att_phys = pte_get_phys(att_pte);
		unsigned long seg_phys_aligned =
			seg_phys_plus_off & ~(att_pgsize - 1);

		if (att_phys != seg_phys_aligned) {
			ret = -EFAULT;
			ekprintf("%s: ERROR: pte mismatch: "
				 "0x%lx != 0x%lx\n",
				 __func__, att_phys, seg_phys_aligned);
		}

		if (page_in_remote) {
			ihk_atomic_dec(&seg->tg->n_pinned);
		}
		goto out;
	}

	XPMEM_DEBUG("att_pgaddr: %lx, att_pgsize: %lx, "
		    "seg_vaddr: %lx, seg_pgsize: %lx, seg_phys: %lx\n",
		    att_pgaddr, att_pgsize, seg_vaddr,
		    seg_pgsize, seg_phys);
	if (att_pte && !pgsize_is_contiguous(att_pgsize)) {
		ret = ihk_mc_pt_set_pte(vm->address_space->page_table,
					att_pte, att_pgsize,
					seg_phys_plus_off,
					att_attr);
		if (ret) {
			ret = -EFAULT;
			ekprintf("%s: ERROR: ihk_mc_pt_set_pte() failed %d\n",
				__func__, ret);
			goto out;
		}
	}
	else {
		ret = ihk_mc_pt_set_range(vm->address_space->page_table, vm,
					  att_pgaddr, att_pgaddr + att_pgsize,
					  seg_phys_plus_off,
					  att_attr, vmr->pgshift, vmr, 1);
		if (ret) {
			ret = -EFAULT;
			ekprintf("%s: ERROR: ihk_mc_pt_set_range() failed %d\n",
				 __func__, ret);
			goto out;
		}
	}

	att->flags |= XPMEM_FLAG_VALIDPTEs;
	flush_tlb_single(vaddr);

out:
	xpmem_ap_deref(ap);
	xpmem_tg_deref(ap_tg);
	xpmem_tg_deref(seg_tg);
	xpmem_seg_deref(seg);
	xpmem_att_deref(att);

	XPMEM_DEBUG("return: ret=%d", ret);

	return ret;
}

int xpmem_fault_process_memory_range(
	struct process_vm *vm,
	struct vm_range *vmr,
	unsigned long vaddr,
	uint64_t reason)
{
	int ret;
	unsigned long at_lock;
	struct xpmem_attachment *att;

	att = (struct xpmem_attachment *)vmr->private_data;
	if (att == NULL) {
		return -EFAULT;
	}
	at_lock = ihk_rwspinlock_read_lock(&att->at_lock);
	ret = _xpmem_fault_process_memory_range(vm, vmr, vaddr, reason, 1);
	ihk_rwspinlock_read_unlock(&att->at_lock, at_lock);
	return ret;
}

int xpmem_update_process_page_table(
	struct process_vm *vm, struct vm_range *vmr)
{
	int ret = 0;
	unsigned long vaddr;
	pte_t *pte;
	size_t pgsize;
	struct xpmem_thread_group *ap_tg;
	struct xpmem_thread_group *seg_tg;
	struct xpmem_access_permit *ap;
	struct xpmem_attachment *att;
	struct xpmem_segment *seg;

	XPMEM_DEBUG("call: vmr=0x%p", vmr);

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
		ret = -EFAULT;
		goto out_1;
	}

	DBUG_ON(cpu_local_var(current)->proc->pid != ap_tg->tgid);
	DBUG_ON(ap->mode != XPMEM_RDWR);

	seg = ap->seg;
	xpmem_seg_ref(seg);
	seg_tg = seg->tg;
	xpmem_tg_ref(seg_tg);

	if ((seg->flags & XPMEM_FLAG_DESTROYING) ||
		(seg_tg->flags & XPMEM_FLAG_DESTROYING)) {
		ret = -ENOENT;
		goto out_2;
	}

	att->at_vaddr = vmr->start;
	att->at_vmr = vmr;

	if ((att->flags & XPMEM_FLAG_DESTROYING) ||
		(ap_tg->flags & XPMEM_FLAG_DESTROYING) ||
		(seg_tg->flags & XPMEM_FLAG_DESTROYING)) {
		goto out_2;
	}

	for (vaddr = vmr->start; vaddr < vmr->end; vaddr += pgsize) {
		XPMEM_DEBUG("vmr: %lx-%lx, vaddr: %lx",
			    vmr->start, vmr->end, vaddr);

		ret = _xpmem_fault_process_memory_range(vm, vmr, vaddr,
							0,
							!xpmem_remote_on_demand);
		if (ret) {
			ekprintf("%s: ERROR: "
				 "_xpmem_fault_process_memory_range() "
				 "failed %d\n", __func__, ret);
		}

		pte = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
					       (void *)vaddr, vmr->pgshift,
					       NULL, &pgsize, NULL);

		/* when segment page is not resident and
		 * xpmem_remote_on_demand is specified
		 */
		if (!pte || pte_is_null(pte)) {
			pgsize = PAGE_SIZE;
		}
	}

out_2:
	xpmem_tg_deref(seg_tg);
	xpmem_seg_deref(seg);

out_1:
	xpmem_att_deref(att);
	xpmem_ap_deref(ap);
	xpmem_tg_deref(ap_tg);

	XPMEM_DEBUG("return: ret=%d", ret);

	return ret;
}

static int xpmem_ensure_valid_page(
	struct xpmem_segment *seg,
	unsigned long vaddr,
	int page_in)
{
	int ret;
	struct xpmem_thread_group *seg_tg = seg->tg;

	XPMEM_DEBUG("call: segid=0x%lx, vaddr=0x%lx", seg->segid, vaddr);

	if (seg->flags & XPMEM_FLAG_DESTROYING)
		return -ENOENT;

	ret = xpmem_pin_page(seg_tg, seg_tg->group_leader, seg_tg->vm, vaddr,
			     page_in);

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
	unsigned long vaddr,
	int page_in)
{
	int ret = 0;
	struct vm_range *range;

	XPMEM_DEBUG("call: tgid=%d, vaddr=0x%lx", tg->tgid, vaddr);

	if (is_remote_vm(src_vm)) {
		ihk_rwspinlock_read_lock_noirq(&src_vm->memory_range_lock);
	}

	range = lookup_process_memory_range(src_vm, vaddr, vaddr + 1);

	if (!range || range->start > vaddr) {
		ret = -ENOENT;
		goto out;
	}

	if (xpmem_is_private_data(range)) {
		ret = -ENOENT;
		goto out;
	}

	ihk_atomic_inc(&tg->n_pinned);

	/* Page-in remote area */
	if (page_in) {
		/* skip read lock for the case src_vm is local
		 * because write lock is taken in do_mmap.
		 */
		ret = page_fault_process_memory_range(src_vm, range,
						      vaddr,
						      PF_POPULATE | PF_WRITE |
						      PF_USER);
		if (ret) {
			goto out;
		}
	}

out:
	if (is_remote_vm(src_vm)) {
		ihk_rwspinlock_read_unlock_noirq(&src_vm->memory_range_lock);
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
	int n_pgs_unpinned = 0;
	size_t vsize = 0;
	unsigned long end = vaddr + size;
	pte_t *pte = NULL;

	XPMEM_DEBUG("call: segid=0x%lx, vaddr=0x%lx, size=0x%lx", 
		seg->segid, vaddr, size);

	vaddr &= PAGE_MASK;

	while (vaddr < end) {
		pte = xpmem_vaddr_to_pte(vm, vaddr, &vsize);
		if (pte && !pte_is_null(pte)) {
			n_pgs_unpinned++;
			vaddr += vsize;
		}
		else {
			vaddr = ((vaddr + vsize) & (~(vsize - 1)));
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

	XPMEM_DEBUG("return: ret=%d, vaddr=0x%lx", 0, *vaddr);

	return 0;
}

static int is_remote_vm(struct process_vm *vm)
{
	int ret = 0;

	if (cpu_local_var(current)->proc->vm != vm) {
		/* vm is not mine */
		ret = 1;
	}

	return ret;
}

