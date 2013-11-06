#ifndef HEADER_MEMOBJ_H
#define HEADER_MEMOBJ_H

#include <ihk/types.h>
#include <ihk/atomic.h>
#include <ihk/lock.h>
#include <list.h>

struct memobj {
	struct memobj_ops *	ops;
	ihk_spinlock_t		lock;
};

typedef void memobj_release_func_t(struct memobj *obj);
typedef void memobj_ref_func_t(struct memobj *obj);
typedef int memobj_get_page_func_t(struct memobj *obj, off_t off, int p2align, uintptr_t *physp);
typedef uintptr_t memobj_copy_page_func_t(struct memobj *obj, uintptr_t orgphys, int p2align);
typedef int memobj_flush_page_func_t(struct memobj *obj, uintptr_t phys, size_t pgsize);

struct memobj_ops {
	memobj_release_func_t *		release;
	memobj_ref_func_t *		ref;
	memobj_get_page_func_t *	get_page;
	memobj_copy_page_func_t *	copy_page;
	memobj_flush_page_func_t *	flush_page;
};

static inline void memobj_release(struct memobj *obj)
{
	(*obj->ops->release)(obj);
}

static inline void memobj_ref(struct memobj *obj)
{
	(*obj->ops->ref)(obj);
}

static inline int memobj_get_page(struct memobj *obj, off_t off,
		int p2align, uintptr_t *physp)
{
	return (*obj->ops->get_page)(obj, off, p2align, physp);
}

static inline uintptr_t memobj_copy_page(struct memobj *obj,
		uintptr_t orgphys, int p2align)
{
	return (*obj->ops->copy_page)(obj, orgphys, p2align);
}

static inline int memobj_flush_page(struct memobj *obj, uintptr_t phys, size_t pgsize)
{
	return (*obj->ops->flush_page)(obj, phys, pgsize);
}

static inline void memobj_lock(struct memobj *obj)
{
	ihk_mc_spinlock_lock_noirq(&obj->lock);
}

static inline void memobj_unlock(struct memobj *obj)
{
	ihk_mc_spinlock_unlock_noirq(&obj->lock);
}

int fileobj_create(int fd, struct memobj **objp, int *maxprotp);

#endif /* HEADER_MEMOBJ_H */
