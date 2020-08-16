/**
 * \file shmobj.c
 *  License details are found in the file LICENSE.
 * \brief
 *  shared memory object
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2014 - 2015  RIKEN AICS
 */
/*
 * HISTORY:
 */

#include <ihk/atomic.h>
#include <ihk/lock.h>
#include <ihk/mm.h>
#include <errno.h>
#include <kmalloc.h>
#include <list.h>
#include <memobj.h>
#include <memory.h>
#include <page.h>
#include <shm.h>
#include <string.h>
#include <rusage_private.h>
#include <ihk/debug.h>


static LIST_HEAD(shmobj_list_head);
static ihk_spinlock_t shmobj_list_lock_body = SPIN_LOCK_UNLOCKED;

static memobj_free_func_t shmobj_free;
static memobj_get_page_func_t shmobj_get_page;
static memobj_invalidate_page_func_t shmobj_invalidate_page;
static memobj_lookup_page_func_t shmobj_lookup_page;

static struct memobj_ops shmobj_ops = {
	.free =	&shmobj_free,
	.get_page =	&shmobj_get_page,
	.lookup_page =	&shmobj_lookup_page,
};

static struct shmobj *to_shmobj(struct memobj *memobj)
{
	return (struct shmobj *)memobj;
}

static struct memobj *to_memobj(struct shmobj *shmobj)
{
	return &shmobj->memobj;
}

/***********************************************************************
 * page_list
 */
static void page_list_init(struct shmobj *obj)
{
	INIT_LIST_HEAD(&obj->page_list);
	ihk_mc_spinlock_init(&obj->page_list_lock);
	return;
}

static void page_list_lock(struct shmobj *obj)
{
	ihk_mc_spinlock_lock_noirq(&obj->page_list_lock);
}

static void page_list_unlock(struct shmobj *obj)
{
	ihk_mc_spinlock_unlock_noirq(&obj->page_list_lock);
}

static void page_list_insert(struct shmobj *obj, struct page *page)
{
	list_add(&page->list, &obj->page_list);
	return;
}

static void page_list_remove(struct shmobj *obj, struct page *page)
{
	list_del(&page->list);
	return;
}

static struct page *page_list_lookup(struct shmobj *obj, off_t off)
{
	struct page *page;

	list_for_each_entry(page, &obj->page_list, list) {
		if (page->offset == off) {
			goto out;
		}
	}
	page = NULL;

out:
	return page;
}

static struct page *page_list_first(struct shmobj *obj)
{
	if (list_empty(&obj->page_list)) {
		return NULL;
	}

	return list_first_entry(&obj->page_list, struct page, list);
}

/***********************************************************************
 * shmobj_list
 */
void shmobj_list_lock(void)
{
	ihk_mc_spinlock_lock_noirq(&shmobj_list_lock_body);
	return;
}

void shmobj_list_unlock(void)
{
	ihk_mc_spinlock_unlock_noirq(&shmobj_list_lock_body);
	return;
}

/***********************************************************************
 * shmlock_users
 */
ihk_spinlock_t shmlock_users_lock_body = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(shmlock_users);

void shmlock_user_free(struct shmlock_user *user)
{
	if (user->locked) {
		panic("shmlock_user_free()");
	}
	list_del(&user->chain);
	kfree(user);
}

int shmlock_user_get(uid_t ruid, struct shmlock_user **userp)
{
	struct shmlock_user *user;

	list_for_each_entry(user, &shmlock_users, chain) {
		if (user->ruid == ruid) {
			break;
		}
	}
	if (&user->chain == &shmlock_users) {
		user = kmalloc(sizeof(*user), IHK_MC_AP_NOWAIT);
		if (!user) {
			return -ENOMEM;
		}
		user->ruid = ruid;
		user->locked = 0;
		list_add(&user->chain, &shmlock_users);
	}
	*userp = user;
	return 0;
}

/***********************************************************************
 * operations
 */
int the_seq = 0;
int shmobj_create(struct shmid_ds *ds, struct memobj **objp)
{
	struct shmobj *obj = NULL;
	int error;
	int pgshift;
	size_t pgsize;

	dkprintf("shmobj_create(%p %#lx,%p)\n", ds, ds->shm_segsz, objp);
	pgshift = ds->init_pgshift;
	if (!pgshift) {
		pgshift = PAGE_SHIFT;
	}
	pgsize = (size_t)1 << pgshift;

	obj = kmalloc(sizeof(*obj), IHK_MC_AP_NOWAIT);
	if (!obj) {
		error = -ENOMEM;
		ekprintf("shmobj_create(%p %#lx,%p):kmalloc failed. %d\n",
				ds, ds->shm_segsz, objp, error);
		goto out;
	}

	memset(obj, 0, sizeof(*obj));
	obj->memobj.ops = &shmobj_ops;
	obj->memobj.flags = MF_SHM;
	obj->memobj.size = ds->shm_segsz;
	ihk_atomic_set(&obj->memobj.refcnt, 1);
	obj->ds = *ds;
	obj->ds.shm_perm.seq = the_seq++;
	obj->ds.init_pgshift = 0;
	obj->index = -1;
	obj->pgshift = pgshift;
	obj->real_segsz = (obj->ds.shm_segsz + pgsize - 1) & ~(pgsize - 1);
	page_list_init(obj);

	error = 0;
	*objp = to_memobj(obj);
	obj = NULL;

out:
	if (obj) {
		kfree(obj);
	}
	dkprintf("shmobj_create_indexed(%p %#lx,%p):%d %p\n",
			ds, ds->shm_segsz, objp, error, *objp);
	return error;
}

int shmobj_create_indexed(struct shmid_ds *ds, struct shmobj **objp)
{
	int error;
	struct memobj *obj;

	error = shmobj_create(ds, &obj);
	if (!error) {
		obj->flags |= MF_SHMDT_OK | MF_IS_REMOVABLE;
		*objp = to_shmobj(obj);
	}
	return error;
}

static void shmobj_destroy(struct shmobj *obj)
{
	extern struct shm_info the_shm_info;
	struct shmlock_user *user;
	size_t size;
	int npages;

	dkprintf("shmobj_destroy(%p [%d %o])\n", obj, obj->index, obj->ds.shm_perm.mode);
	if (obj->user) {
		user = obj->user;
		obj->user = NULL;
		shmlock_users_lock();
		size = obj->real_segsz;
		user->locked -= size;
		if (!user->locked) {
			shmlock_user_free(user);
		}
		shmlock_users_unlock();
	}

	/* zap page_list */
	npages = (size_t)1 << (obj->pgshift - PAGE_SHIFT);
	for (;;) {
		struct page *page;
		void *page_va;
		uintptr_t phys;

		/* no lock required as obj is inaccessible */
		page = page_list_first(obj);
		if (!page) {
			break;
		}
		page_list_remove(obj, page);
		phys = page_to_phys(page);
		page_va = phys_to_virt(phys);

		if (ihk_atomic_read(&page->count) != 1) {
			kprintf("%s: WARNING: page count for phys 0x%lx is invalid\n",
					__FUNCTION__, page->phys);
		} else if (page_unmap(page)) {
			/* Other call sites of page_unmap are:
			 * (1) MADV_REMOVE --> ... --> ihk_mc_pt_free_range()
			 * (2) do_munmap --> ... --> free_process_memory_range()
			 * (3) terminate() --> ... --> free_process_memory_range()
			 */

			size_t free_pgsize = 1UL << obj->pgshift;
			size_t free_size = 1UL << obj->pgshift;

			ihk_mc_free_pages_user(page_va, npages);
			dkprintf("%lx-,%s: calling memory_stat_rss_sub(),phys=%lx,size=%ld,pgsize=%ld\n",
				 phys, __func__, phys, free_size,
				 free_pgsize);
			memory_stat_rss_sub(free_size, free_pgsize);
			kfree(page);
		}

#if 0
		dkprintf("shmobj_destroy(%p):"
				"release page. %p %#lx %d %d",
				obj, page, page_to_phys(page),
				page->mode, page->count);
		count = ihk_atomic_sub_return(1, &page->count);
		if (!((page->mode == PM_MAPPED) && (count == 0))) {
			ekprintf("shmobj_destroy(%p): "
					"page %p phys %#lx mode %#x"
					" count %d off %#lx\n",
					obj, page,
					page_to_phys(page),
					page->mode, count,
					page->offset);
			panic("shmobj_release");
		}

		page->mode = PM_NONE;
		ihk_mc_free_pages(phys_to_virt(page_to_phys(page)), npages);
#endif
	}
	if (obj->index < 0) {
		kfree(obj);
	}
	else {
		int i = obj->index / 64;
		unsigned long x = 1UL << (obj->index % 64);

		list_del(&obj->chain);
		--the_shm_info.used_ids;
		shmid_index[i] &= ~x;
		kfree(obj);
	}
	return;
}

static void shmobj_free(struct memobj *memobj)
{
	struct shmobj *obj = to_shmobj(memobj);
	extern time_t time(void);

	dkprintf("%s(%p)\n", __func__, memobj);

	shmobj_list_lock();
	if (!(obj->ds.shm_perm.mode & SHM_DEST)) {
		ekprintf("%s called without going through rmid?", __func__);
	}

	shmobj_destroy(obj);
	shmobj_list_unlock();

	dkprintf("%s(%p)\n", __func__, memobj);
	return;
}

static int shmobj_get_page(struct memobj *memobj, off_t off, int p2align,
               uintptr_t *physp, unsigned long *pflag, uintptr_t virt_addr)
{
	struct shmobj *obj = to_shmobj(memobj);
	int error;
	struct page *page;
	int npages;
	void *virt = NULL;
	uintptr_t phys = -1;

	dkprintf("shmobj_get_page(%p,%#lx,%d,%p)\n",
			memobj, off, p2align, physp);
	memobj_ref(memobj);
	if (off & ~PAGE_MASK) {
		error = -EINVAL;
		ekprintf("shmobj_get_page(%p,%#lx,%d,%p):invalid argument. %d\n",
				memobj, off, p2align, physp, error);
		goto out;
	}
	if (p2align != (obj->pgshift - PAGE_SHIFT)) {
		error = -ENOMEM;
		ekprintf("shmobj_get_page(%p,%#lx,%d,%p):pgsize mismatch. %d\n",
				memobj, off, p2align, physp, error);
		goto out;
	}
	if (obj->real_segsz <= off) {
		error = -ERANGE;
		ekprintf("shmobj_get_page(%p,%#lx,%d,%p):beyond the end. %d\n",
				memobj, off, p2align, physp, error);
		goto out;
	}
	if ((obj->real_segsz - off) < (PAGE_SIZE << p2align)) {
		error = -ENOSPC;
		ekprintf("shmobj_get_page(%p,%#lx,%d,%p):too large. %d\n",
				memobj, off, p2align, physp, error);
		goto out;
	}

	page_list_lock(obj);
	page = page_list_lookup(obj, off);
	if (!page) {
		npages = 1 << p2align;
		virt = ihk_mc_alloc_aligned_pages_user(npages, p2align,
				IHK_MC_AP_NOWAIT, virt_addr);
		if (!virt) {
			page_list_unlock(obj);
			error = -ENOMEM;
			ekprintf("shmobj_get_page(%p,%#lx,%d,%p):"
					"alloc failed. %d\n",
					memobj, off, p2align, physp, error);
			goto out;
		}
		phys = virt_to_phys(virt);
		page = phys_to_page_insert_hash(phys);

		if (page->mode != PM_NONE) {
			ekprintf("shmobj_get_page(%p,%#lx,%d,%p):"
					"page %p %#lx %d %d %#lx\n",
					memobj, off, p2align, physp,
					page, page_to_phys(page), page->mode,
					page->count, page->offset);
			panic("shmobj_get_page()");
		}
		memset(virt, 0, npages*PAGE_SIZE);
		page->mode = PM_MAPPED;
		page->offset = off;

		/* Page contents should survive over unmap */
		ihk_atomic_set(&page->count, 1);

		ihk_atomic64_set(&page->mapped, 0);
		page_list_insert(obj, page);
		virt = NULL;
		dkprintf("shmobj_get_page(%p,%#lx,%d,%p):alloc page. %p %#lx\n",
				memobj, off, p2align, physp, page, phys);
	}
	page_list_unlock(obj);

	ihk_atomic_inc(&page->count);

	error = 0;
	*physp = page_to_phys(page);

out:
	memobj_unref(memobj);
	if (virt) {
		ihk_mc_free_pages_user(virt, npages);
	}
	dkprintf("shmobj_get_page(%p,%#lx,%d,%p):%d\n",
			memobj, off, p2align, physp, error);
	return error;
}

static int shmobj_lookup_page(struct memobj *memobj, off_t off, int p2align,
		uintptr_t *physp, unsigned long *pflag)
{
	struct shmobj *obj = to_shmobj(memobj);
	int error;
	struct page *page;
	uintptr_t phys = NOPHYS;

	dkprintf("shmobj_lookup_page(%p,%#lx,%d,%p)\n",
			memobj, off, p2align, physp);
	memobj_ref(&obj->memobj);
	if (off & ~PAGE_MASK) {
		error = -EINVAL;
		ekprintf("shmobj_lookup_page(%p,%#lx,%d,%p):invalid argument. %d\n",
				memobj, off, p2align, physp, error);
		goto out;
	}
	if (p2align != (obj->pgshift - PAGE_SHIFT)) {
		error = -ENOMEM;
		ekprintf("shmobj_lookup_page(%p,%#lx,%d,%p):pgsize mismatch. %d\n",
				memobj, off, p2align, physp, error);
		goto out;
	}
	if (obj->real_segsz <= off) {
		error = -ERANGE;
		ekprintf("shmobj_lookup_page(%p,%#lx,%d,%p):beyond the end. %d\n",
				memobj, off, p2align, physp, error);
		goto out;
	}
	if ((obj->real_segsz - off) < (PAGE_SIZE << p2align)) {
		error = -ENOSPC;
		ekprintf("shmobj_lookup_page(%p,%#lx,%d,%p):too large. %d\n",
				memobj, off, p2align, physp, error);
		goto out;
	}

	page_list_lock(obj);
	page = page_list_lookup(obj, off);
	page_list_unlock(obj);
	if (!page) {
		error = -ENOENT;
		dkprintf("shmobj_lookup_page(%p,%#lx,%d,%p):page not found. %d\n",
				memobj, off, p2align, physp, error);
		goto out;
	}
	phys = page_to_phys(page);

	error = 0;
	if (physp) {
		*physp = phys;
	}

out:
	memobj_unref(&obj->memobj);
	dkprintf("shmobj_lookup_page(%p,%#lx,%d,%p):%d %#lx\n",
			memobj, off, p2align, physp, error, phys);
	return error;
} /* shmobj_lookup_page() */
