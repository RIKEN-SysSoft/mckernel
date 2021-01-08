/**
 * \file xpmem_private.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Private Cross Partition Memory (XPMEM) structures and macros.
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
 * Copyright 2009, 2010, 2014 Cray Inc. All Rights Reserved
 * Copyright (c) 2014-2016 Los Alamos National Security, LCC. All rights
 *                         reserved.
 */
/*
 * HISTORY
 */

#ifndef _XPMEM_PRIVATE_H
#define _XPMEM_PRIVATE_H

#include <mc_xpmem.h>
#include <xpmem.h>
#include <ihk/debug.h>

#define XPMEM_CURRENT_VERSION           0x00026003

//#define DEBUG_PRINT_XPMEM

#ifdef DEBUG_PRINT_XPMEM
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif
#define XPMEM_DEBUG(format, a...) dkprintf("[%d] %s: "format"\n", cpu_local_var(current)->proc->rgid, __func__, ##a)

//#define USE_DBUG_ON

#ifdef USE_DBUG_ON
#define DBUG_ON(condition) do { if (condition) kprintf("[%d] BUG: func=%s\n", cpu_local_var(current)->proc->rgid, __func__); } while (0)
#else
#define DBUG_ON(condition)
#endif

#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)

/*
 * Both the xpmem_segid_t and xpmem_apid_t are of type __s64 and designed
 * to be opaque to the user. Both consist of the same underlying fields.
 *
 * The 'uniq' field is designed to give each segid or apid a unique value.
 * Each type is only unique with respect to itself.
 *
 * An ID is never less than or equal to zero.
 */
struct xpmem_id {
	pid_t tgid;		/* thread group that owns ID */
	unsigned int uniq;	/* this value makes the ID unique */
};

typedef union {
	struct xpmem_id xpmem_id;
	xpmem_segid_t segid;
	xpmem_apid_t apid;
} xpmem_id_t;

/* Shift INT_MAX by one so we can tell when we overflow. */
#define XPMEM_MAX_UNIQ_ID	(INT_MAX >> 1)

static inline pid_t xpmem_segid_to_tgid(xpmem_segid_t segid)
{
	DBUG_ON(segid <= 0);
	return ((xpmem_id_t *)&segid)->xpmem_id.tgid;
}

static inline pid_t xpmem_apid_to_tgid(xpmem_apid_t apid)
{
	DBUG_ON(apid <= 0);
	return ((xpmem_id_t *)&apid)->xpmem_id.tgid;
}

/*
 * Hash Tables
 *
 * XPMEM utilizes hash tables to enable faster lookups of list entries.
 * These hash tables are implemented as arrays. A simple modulus of the hash
 * key yields the appropriate array index. A hash table's array element (i.e.,
 * hash table bucket) consists of a hash list and the lock that protects it.
 *
 * XPMEM has the following two hash tables:
 *
 * table                bucket                                  key
 * part->tg_hashtable   list of struct xpmem_thread_group       tgid
 * tg->ap_hashtable     list of struct xpmem_access_permit      apid.uniq
 */
struct xpmem_hashlist {
        mcs_rwlock_lock_t lock;	/* lock for hash list */
        struct list_head list;	/* hash list */
};

#define XPMEM_TG_HASHTABLE_SIZE 8
#define XPMEM_AP_HASHTABLE_SIZE 8

static inline int xpmem_tg_hashtable_index(pid_t tgid)
{
	int index;

	index = (unsigned int)tgid % XPMEM_TG_HASHTABLE_SIZE;

	XPMEM_DEBUG("return: tgid=%lu, index=%d", tgid, index);

	return index;
}

static inline int xpmem_ap_hashtable_index(xpmem_apid_t apid)
{
	int index;

        DBUG_ON(apid <= 0);

	index = ((xpmem_id_t *)&apid)->xpmem_id.uniq % XPMEM_AP_HASHTABLE_SIZE;

	XPMEM_DEBUG("return: apid=0x%lx, index=%d", apid, index);

	return index;
}

/*
 * general internal driver structures
 */
struct xpmem_thread_group {
	ihk_spinlock_t lock;	/* tg lock */
	pid_t tgid;		/* tg's tgid */
	uid_t uid;		/* tg's uid */
	gid_t gid;		/* tg's gid */
	volatile int flags;	/* tg attributes and state */
	ihk_atomic_t uniq_segid;	/* segid uniq */
	ihk_atomic_t uniq_apid;	/* apid uniq */
	mcs_rwlock_lock_t seg_list_lock;	/* tg's list of segs lock */
	struct list_head seg_list;	/* tg's list of segs */
	ihk_atomic_t refcnt;	/* references to tg */
	ihk_atomic_t n_pinned;	/* #of pages pinned by this tg */
	struct list_head tg_hashlist;	/* tg hash list */
	struct thread *group_leader;	/* thread group leader */
	struct process_vm *vm;		/* tg's process_vm */
	struct xpmem_hashlist ap_hashtable[];	/* locks + ap hash lists */
};

struct xpmem_segment {
	ihk_spinlock_t lock;	/* seg lock */
	xpmem_segid_t segid;	/* unique segid */
	unsigned long vaddr;	/* starting address */
	size_t size;		/* size of seg */
	int permit_type;	/* permission scheme */
	void *permit_value;	/* permission data */
	volatile int flags;	/* seg attributes and state */
	ihk_atomic_t refcnt;	/* references to seg */
	struct xpmem_thread_group *tg;	/* creator tg */
	struct list_head ap_list;	/* local access permits of seg */
	struct list_head seg_list;	/* tg's list of segs */
};

struct xpmem_access_permit {
	ihk_spinlock_t lock;	/* access permit lock */
	xpmem_apid_t apid;	/* unique apid */
	int mode;		/* read/write mode */
	volatile int flags;	/* access permit attributes and state */
	ihk_atomic_t refcnt;	/* references to access permit */
	struct xpmem_segment *seg;	/* seg permitted to be accessed */
	struct xpmem_thread_group *tg;	/* access permit's tg */
	struct list_head att_list;	/* atts of this access permit's seg */
	struct list_head ap_list;	/* access permits linked to seg */
	struct list_head ap_hashlist;	/* access permit hash list */
};

struct xpmem_partition {
	ihk_atomic_t n_opened;	/* # of /dev/xpmem opened */
	struct xpmem_hashlist tg_hashtable[];	/* locks + tg hash lists */
};

#define XPMEM_FLAG_DESTROYING		0x00040 /* being destroyed */
#define XPMEM_FLAG_DESTROYED		0x00080 /* 'being destroyed' finished */

#define XPMEM_FLAG_VALIDPTEs		0x00200 /* valid PTEs exist */

struct xpmem_perm {
	uid_t uid;
	gid_t gid;
	unsigned long mode;
};

#define XPMEM_PERM_IRUSR 00400
#define XPMEM_PERM_IWUSR 00200

extern struct xpmem_partition *xpmem_my_part;

static int xpmem_ioctl(struct mckfd *mckfd, ihk_mc_user_context_t *ctx);
static int xpmem_close(struct mckfd *mckfd, ihk_mc_user_context_t *ctx);
static int xpmem_dup(struct mckfd *mckfd, ihk_mc_user_context_t *ctx);

static int xpmem_init(void);
static void xpmem_exit(void);
static int __xpmem_open(void);
static void xpmem_destroy_tg(struct xpmem_thread_group *);

static int xpmem_make(unsigned long, size_t, int, void *, xpmem_segid_t *);
static xpmem_segid_t xpmem_make_segid(struct xpmem_thread_group *);

static int xpmem_remove(xpmem_segid_t);
static void xpmem_remove_seg(struct xpmem_thread_group *,
        struct xpmem_segment *);
static void xpmem_remove_segs_of_tg(struct xpmem_thread_group *seg_tg);

static int xpmem_get(xpmem_segid_t, int, int, void *, xpmem_apid_t *);
static int xpmem_check_permit_mode(int, struct xpmem_segment *);
static int xpmem_perms(struct xpmem_perm *, short);
static xpmem_apid_t xpmem_make_apid(struct xpmem_thread_group *);

static int xpmem_release(xpmem_apid_t);
static void xpmem_release_ap(struct xpmem_thread_group *,
	struct xpmem_access_permit *);
static void xpmem_release_aps_of_tg(struct xpmem_thread_group *ap_tg);
static void xpmem_flush(struct mckfd *);

static int xpmem_attach(struct mckfd *, xpmem_apid_t, off_t, size_t, 
	unsigned long, int, int, unsigned long *);

static int xpmem_detach(unsigned long);
static int xpmem_vm_munmap(struct process_vm *vm, void *addr, size_t len);
static int xpmem_remove_process_range(struct process_vm *vm, 
	unsigned long start, unsigned long end, int *ro_freedp);
static int xpmem_free_process_memory_range(struct process_vm *vm,
	struct vm_range *range);
static void xpmem_detach_att(struct xpmem_access_permit *, 
	struct xpmem_attachment *);
static void xpmem_clear_PTEs(struct xpmem_segment *);
static void xpmem_clear_PTEs_range(struct xpmem_segment *, unsigned long,
	unsigned long);
static void xpmem_clear_PTEs_of_ap(struct xpmem_access_permit *, unsigned long, 
	unsigned long);
static void xpmem_clear_PTEs_of_att(struct xpmem_attachment *, unsigned long, 
	unsigned long);

static int xpmem_remap_pte(struct process_vm *, struct vm_range *,
	unsigned long, uint64_t, struct xpmem_segment *, unsigned long);

static int xpmem_ensure_valid_page(struct xpmem_segment *, unsigned long);
static pte_t * xpmem_vaddr_to_pte(struct process_vm *, unsigned long, 
	size_t *pgsize);
static int xpmem_pin_page(struct xpmem_thread_group *, struct thread *,
	struct process_vm *, unsigned long);
static void xpmem_unpin_pages(struct xpmem_segment *, struct process_vm *, 
	unsigned long, size_t);

static struct xpmem_thread_group *__xpmem_tg_ref_by_tgid_nolock_internal(
	pid_t tgid, int index, int return_destroying);

static inline struct xpmem_thread_group *__xpmem_tg_ref_by_tgid(
	pid_t tgid,
	int return_destroying)
{
	struct xpmem_thread_group *tg;
	int index;
	struct mcs_rwlock_node_irqsave lock;

	XPMEM_DEBUG("call: tgid=%d, return_destroying=%d", 
		tgid, return_destroying);

	index = xpmem_tg_hashtable_index(tgid);
	XPMEM_DEBUG("xpmem_my_part=%p\n", xpmem_my_part);
	XPMEM_DEBUG("xpmem_my_part->tg_hashtable=%p\n", xpmem_my_part->tg_hashtable);
	mcs_rwlock_reader_lock(&xpmem_my_part->tg_hashtable[index].lock, &lock);
	tg = __xpmem_tg_ref_by_tgid_nolock_internal(tgid, index, 
		return_destroying);
        mcs_rwlock_reader_unlock(&xpmem_my_part->tg_hashtable[index].lock, 
		&lock);

	XPMEM_DEBUG("return: tg=0x%p", tg);

        return tg;
}

static inline struct xpmem_thread_group *__xpmem_tg_ref_by_tgid_nolock(
	pid_t tgid,
	int return_destroying)
{
	struct xpmem_thread_group *tg;

	XPMEM_DEBUG("call: tgid=%d, return_destroying=%d", 
		tgid, return_destroying);

        tg = __xpmem_tg_ref_by_tgid_nolock_internal(tgid, 
		xpmem_tg_hashtable_index(tgid), return_destroying);

	XPMEM_DEBUG("return: tg=0x%p", tg);

        return tg;
}

#define xpmem_tg_ref_by_tgid(t)             __xpmem_tg_ref_by_tgid(t, 0)
#define xpmem_tg_ref_by_tgid_all(t)         __xpmem_tg_ref_by_tgid(t, 1)
#define xpmem_tg_ref_by_tgid_nolock(t)      __xpmem_tg_ref_by_tgid_nolock(t, 0)
#define xpmem_tg_ref_by_tgid_all_nolock(t)  __xpmem_tg_ref_by_tgid_nolock(t, 1)

static struct xpmem_thread_group *xpmem_tg_ref_by_segid(xpmem_segid_t);
static struct xpmem_thread_group *xpmem_tg_ref_by_apid(xpmem_apid_t);
static void xpmem_tg_deref(struct xpmem_thread_group *tg);
static struct xpmem_segment *xpmem_seg_ref_by_segid(struct xpmem_thread_group *,
	xpmem_segid_t);
static void xpmem_seg_deref(struct xpmem_segment *seg);
static struct xpmem_access_permit * xpmem_ap_ref_by_apid(
	struct xpmem_thread_group *ap_tg, xpmem_apid_t apid);
static void xpmem_ap_deref(struct xpmem_access_permit *ap);
static void xpmem_att_deref(struct xpmem_attachment *att);
static int xpmem_validate_access(struct xpmem_access_permit *, off_t, size_t,
	int, unsigned long *);
static int is_remote_vm(struct process_vm *vm);

/*
 * Inlines that mark an internal driver structure as being destroyable or not.
 * The idea is to set the refcnt to 1 at structure creation time and then
 * drop that reference at the time the structure is to be destroyed.
 */
static inline void xpmem_tg_not_destroyable(
	struct xpmem_thread_group *tg)
{
	ihk_atomic_set(&tg->refcnt, 1);

	XPMEM_DEBUG("return: tg->refcnt=%d", tg->refcnt);
}

static inline void xpmem_tg_destroyable(
	struct xpmem_thread_group *tg)
{
	XPMEM_DEBUG("call: ");

	xpmem_tg_deref(tg);

	XPMEM_DEBUG("return: ");
}

static inline void xpmem_seg_not_destroyable(
	struct xpmem_segment *seg)
{
	ihk_atomic_set(&seg->refcnt, 1);

	XPMEM_DEBUG("return: seg->refcnt=%d", seg->refcnt);
}

static inline void xpmem_seg_destroyable(
	struct xpmem_segment *seg)
{
	XPMEM_DEBUG("call: ");

	xpmem_seg_deref(seg);

	XPMEM_DEBUG("return: ");
}

static inline void xpmem_ap_not_destroyable(
	struct xpmem_access_permit *ap)
{
	ihk_atomic_set(&ap->refcnt, 1);

	XPMEM_DEBUG("return: ap->refcnt=%d", ap->refcnt);
}

static inline void xpmem_ap_destroyable(
	struct xpmem_access_permit *ap)
{
	XPMEM_DEBUG("call: ");

	xpmem_ap_deref(ap);

	XPMEM_DEBUG("return: ");
}

static inline void xpmem_att_not_destroyable(
	struct xpmem_attachment *att)
{
	ihk_atomic_set(&att->refcnt, 1);

	XPMEM_DEBUG("return: att->refcnt=%d", att->refcnt);
}

static inline void xpmem_att_destroyable(
	struct xpmem_attachment *att)
{
	XPMEM_DEBUG("call: ");

	xpmem_att_deref(att);

	XPMEM_DEBUG("return: ");
}

/*
 * Inlines that increment the refcnt for the specified structure.
 */
static inline void xpmem_tg_ref(
	struct xpmem_thread_group *tg)
{
	DBUG_ON(ihk_atomic_read(&tg->refcnt) <= 0);
	ihk_atomic_inc(&tg->refcnt);

	XPMEM_DEBUG("return: tg->refcnt=%d", tg->refcnt);
}

static inline void xpmem_seg_ref(
	struct xpmem_segment *seg)
{
	DBUG_ON(ihk_atomic_read(&seg->refcnt) <= 0);
	ihk_atomic_inc(&seg->refcnt);

	XPMEM_DEBUG("return: seg->refcnt=%d", seg->refcnt);
}

static inline void xpmem_ap_ref(
	struct xpmem_access_permit *ap)
{
	DBUG_ON(ihk_atomic_read(&ap->refcnt) <= 0);
	ihk_atomic_inc(&ap->refcnt);

	XPMEM_DEBUG("return: ap->refcnt=%d", ap->refcnt);
}

static inline void xpmem_att_ref(
	struct xpmem_attachment *att)
{
	DBUG_ON(ihk_atomic_read(&att->refcnt) <= 0);
	ihk_atomic_inc(&att->refcnt);

	XPMEM_DEBUG("return: att->refcnt=%d", att->refcnt);
}

static inline int xpmem_is_private_data(
	struct vm_range *vmr)
{
        return (vmr->private_data != NULL);
}

#endif /* _XPMEM_PRIVATE_H */

