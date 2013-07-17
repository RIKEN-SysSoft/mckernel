#ifndef HEADER_MEMOBJ_H
#define HEADER_MEMOBJ_H

#include <ihk/types.h>
#include <ihk/atomic.h>
#include <ihk/lock.h>
#include <list.h>

struct memobj {
	struct list_head	list;
	ihk_atomic_t		ref;
	uintptr_t		handle;
	struct list_head	page_list;
	ihk_spinlock_t		page_list_lock;
};

int memobj_create(int fd, int flags, int prot, struct memobj **objp, int *maxprotp);
void memobj_ref(struct memobj *obj);
void memobj_release(struct memobj *obj);
int memobj_get_page(struct memobj *obj, off_t off, size_t pgsize, uintptr_t *physp);

#endif /* HEADER_MEMOBJ_H */
