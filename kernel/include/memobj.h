/**
 * \file memobj.h
 *  License details are found in the file LICENSE.
 * \brief
 *  defines and declares for memory object
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 */
/*
 * HISTORY:
 */

#ifndef HEADER_MEMOBJ_H
#define HEADER_MEMOBJ_H

#include <ihk/types.h>
#include <ihk/atomic.h>
#include <ihk/lock.h>
#include <errno.h>
#include <list.h>

/* begin types.h */
typedef int32_t key_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;
typedef int64_t time_t;
typedef int32_t pid_t;
/* end types.h */

enum {
	/* for memobj.flags */
	MF_HAS_PAGER	= 0x0001,
	MF_SHMDT_OK	= 0x0002,
	MF_IS_REMOVABLE	= 0x0004,
	MF_PREFETCH = 0x0008,
	MF_ZEROFILL = 0x0010,
	MF_REG_FILE = 0x1000,
	MF_DEV_FILE = 0x2000,
	MF_PREMAP   = 0x8000,
	MF_HOST_RELEASED = 0x80000000,
	MF_END
};

#define MEMOBJ_READY              0
#define MEMOBJ_TO_BE_PREFETCHED   1

struct memobj {
	struct memobj_ops *ops;
	uint32_t flags;
	uint32_t status;
	size_t size;
	ihk_spinlock_t lock;

	/* For pre-mapped memobjects */
	void **pages;
	int nr_pages;
};

typedef void memobj_release_func_t(struct memobj *obj);
typedef void memobj_ref_func_t(struct memobj *obj);
typedef int memobj_get_page_func_t(struct memobj *obj, off_t off, int p2align, uintptr_t *physp, unsigned long *flag);
typedef uintptr_t memobj_copy_page_func_t(struct memobj *obj, uintptr_t orgphys, int p2align);
typedef int memobj_flush_page_func_t(struct memobj *obj, uintptr_t phys, size_t pgsize);
typedef int memobj_invalidate_page_func_t(struct memobj *obj, uintptr_t phys, size_t pgsize);
typedef int memobj_lookup_page_func_t(struct memobj *obj, off_t off, int p2align, uintptr_t *physp, unsigned long *flag);

struct memobj_ops {
	memobj_release_func_t *		release;
	memobj_ref_func_t *		ref;
	memobj_get_page_func_t *	get_page;
	memobj_copy_page_func_t *	copy_page;
	memobj_flush_page_func_t *	flush_page;
	memobj_invalidate_page_func_t *	invalidate_page;
	memobj_lookup_page_func_t *	lookup_page;
};

static inline void memobj_release(struct memobj *obj)
{
	if (obj->ops->release) {
		(*obj->ops->release)(obj);
	}
}

static inline void memobj_ref(struct memobj *obj)
{
	if (obj->ops->ref) {
		(*obj->ops->ref)(obj);
	}
}

static inline int memobj_get_page(struct memobj *obj, off_t off,
		int p2align, uintptr_t *physp, unsigned long *pflag)
{
	if (obj->ops->get_page) {
		return (*obj->ops->get_page)(obj, off, p2align, physp, pflag);
	}
	return -ENXIO;
}

static inline uintptr_t memobj_copy_page(struct memobj *obj,
		uintptr_t orgphys, int p2align)
{
	if (obj->ops->copy_page) {
		return (*obj->ops->copy_page)(obj, orgphys, p2align);
	}
	return -ENXIO;
}

static inline int memobj_flush_page(struct memobj *obj, uintptr_t phys, size_t pgsize)
{
	if (obj->ops->flush_page) {
		return (*obj->ops->flush_page)(obj, phys, pgsize);
	}
	return 0;
}

static inline int memobj_invalidate_page(struct memobj *obj, uintptr_t phys,
		size_t pgsize)
{
	if (obj->ops->invalidate_page) {
		return (*obj->ops->invalidate_page)(obj, phys, pgsize);
	}
	return 0;
}

static inline int memobj_lookup_page(struct memobj *obj, off_t off,
		int p2align, uintptr_t *physp, unsigned long *pflag)
{
	if (obj->ops->lookup_page) {
		return (*obj->ops->lookup_page)(obj, off, p2align, physp, pflag);
	}
	return -ENXIO;
}

static inline void memobj_lock(struct memobj *obj)
{
	ihk_mc_spinlock_lock_noirq(&obj->lock);
}

static inline void memobj_unlock(struct memobj *obj)
{
	ihk_mc_spinlock_unlock_noirq(&obj->lock);
}

static inline int memobj_has_pager(struct memobj *obj)
{
	return !!(obj->flags & MF_HAS_PAGER);
}

static inline int memobj_is_removable(struct memobj *obj)
{
	return !!(obj->flags & MF_IS_REMOVABLE);
}

int fileobj_create(int fd, struct memobj **objp, int *maxprotp);
struct shmid_ds;
int shmobj_create(struct shmid_ds *ds, struct memobj **objp);
int zeroobj_create(struct memobj **objp);
int devobj_create(int fd, size_t len, off_t off, struct memobj **objp, int *maxprotp,
	int prot, int populate_flags);

#endif /* HEADER_MEMOBJ_H */
