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
#include <ihk/debug.h>
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

#define	dkprintf(...)	do { if (0) kprintf(__VA_ARGS__); } while (0)
#define	ekprintf(...)	kprintf(__VA_ARGS__)
#define	fkprintf(...)	kprintf(__VA_ARGS__)

static LIST_HEAD(shmobj_list_head);
static ihk_spinlock_t shmobj_list_lock_body = SPIN_LOCK_UNLOCKED;

static memobj_release_func_t shmobj_release;
static memobj_ref_func_t shmobj_ref;
static memobj_get_page_func_t shmobj_get_page;
static memobj_invalidate_page_func_t shmobj_invalidate_page;

static struct memobj_ops shmobj_ops = {
	.release =	&shmobj_release,
	.ref =		&shmobj_ref,
	.get_page =	&shmobj_get_page,
	.invalidate_page =	&shmobj_invalidate_page,
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
	return;
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
 * operations
 */
int the_seq = 0;
int shmobj_create(struct shmid_ds *ds, struct memobj **objp)
{
	struct shmobj *obj = NULL;
	int error;

	dkprintf("shmobj_create(%p %#lx,%p)\n", ds, ds->shm_segsz, objp);
	obj = kmalloc(sizeof(*obj), IHK_MC_AP_NOWAIT);
	if (!obj) {
		error = -ENOMEM;
		ekprintf("shmobj_create(%p %#lx,%p):kmalloc failed. %d\n",
				ds, ds->shm_segsz, objp, error);
		goto out;
	}

	memset(obj, 0, sizeof(*obj));
	obj->memobj.ops = &shmobj_ops;
	obj->ds = *ds;
	obj->ds.shm_perm.seq = the_seq++;
	obj->ds.shm_nattch = 1;
	obj->index = -1;
	obj->pgshift = PAGE_SHIFT;
	obj->real_segsz = (obj->ds.shm_segsz + PAGE_SIZE - 1) & PAGE_MASK;
	page_list_init(obj);
	ihk_mc_spinlock_init(&obj->memobj.lock);

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

void shmobj_destroy(struct shmobj *obj)
{
	extern struct shm_info the_shm_info;
	extern struct list_head kds_free_list;
	extern int the_maxi;

	dkprintf("shmobj_destroy(%p [%d %o])\n", obj, obj->index, obj->ds.shm_perm.mode);
	/* zap page_list */
	for (;;) {
		struct page *page;
		int count;

		page = page_list_first(obj);
		if (!page) {
			break;
		}
		page_list_remove(obj, page);

		dkprintf("shmobj_destroy(%p):"
				"release page. %p %#lx %d %d",
				obj, page, page_to_phys(page),
				page->mode, page->count);
		count = ihk_atomic_sub_return(1, &page->count);
		if (!((page->mode == PM_MAPPED) && (count == 0))) {
			fkprintf("shmobj_destroy(%p): "
					"page %p phys %#lx mode %#x"
					" count %d off %#lx\n",
					obj, page,
					page_to_phys(page),
					page->mode, count,
					page->offset);
			panic("shmobj_release");
		}

		/* XXX:NYI: large pages */
		page->mode = PM_NONE;
		free_pages(phys_to_virt(page_to_phys(page)), 1);
	}
	if (obj->index < 0) {
		kfree(obj);
	}
	else {
		list_del(&obj->chain);
		--the_shm_info.used_ids;

		list_add(&obj->chain, &kds_free_list);
		for (;;) {
			struct shmobj *p;

			list_for_each_entry(p, &kds_free_list, chain) {
				if (p->index == the_maxi) {
					break;
				}
			}
			if (&p->chain == &kds_free_list) {
				break;
			}

			list_del(&p->chain);
			kfree(p);
			--the_maxi;
		}
	}
	return;
}

static void shmobj_release(struct memobj *memobj)
{
	struct shmobj *obj = to_shmobj(memobj);
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct shmobj *freeobj = NULL;
	long newref;
	extern time_t time(void);

	dkprintf("shmobj_release(%p)\n", memobj);
	memobj_lock(&obj->memobj);
	if (obj->index >= 0) {
		obj->ds.shm_dtime = time();
		obj->ds.shm_lpid = proc->pid;
		dkprintf("shmobj_release:drop shm_nattach %p %d\n", obj, obj->ds.shm_nattch);
	}
	newref = --obj->ds.shm_nattch;
	if (newref <= 0) {
		if (newref < 0) {
			fkprintf("shmobj_release(%p):ref %ld\n",
					memobj, newref);
			panic("shmobj_release:freeing free shmobj");
		}
		if (obj->ds.shm_perm.mode & SHM_DEST) {
			freeobj = obj;
		}
	}
	memobj_unlock(&obj->memobj);

	if (freeobj) {
		shmobj_list_lock();
		shmobj_destroy(freeobj);
		shmobj_list_unlock();
	}
	dkprintf("shmobj_release(%p): %ld\n", memobj, newref);
	return;
}

static void shmobj_ref(struct memobj *memobj)
{
	struct shmobj *obj = to_shmobj(memobj);
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	long newref;
	extern time_t time(void);

	dkprintf("shmobj_ref(%p)\n", memobj);
	memobj_lock(&obj->memobj);
	newref = ++obj->ds.shm_nattch;
	if (obj->index >= 0) {
		obj->ds.shm_atime = time();
		obj->ds.shm_lpid = proc->pid;
	}
	memobj_unlock(&obj->memobj);
	dkprintf("shmobj_ref(%p): newref %ld\n", memobj, newref);
	return;
}

static int shmobj_get_page(struct memobj *memobj, off_t off, int p2align,
		uintptr_t *physp, unsigned long *pflag)
{
	struct shmobj *obj = to_shmobj(memobj);
	int error;
	struct page *page;
	int npages;
	void *virt = NULL;
	uintptr_t phys = -1;

	dkprintf("shmobj_get_page(%p,%#lx,%d,%p)\n",
			memobj, off, p2align, physp);
	memobj_lock(&obj->memobj);
	if (off & ~PAGE_MASK) {
		error = -EINVAL;
		ekprintf("shmobj_get_page(%p,%#lx,%d,%p):invalid argument. %d\n",
				memobj, off, p2align, physp, error);
		goto out;
	}
	if (p2align != PAGE_P2ALIGN) {		/* XXX:NYI:large pages */
		error = -ENOMEM;
		ekprintf("shmobj_get_page(%p,%#lx,%d,%p):large page. %d\n",
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

	page = page_list_lookup(obj, off);
	if (!page) {
		npages = 1 << p2align;
		virt = ihk_mc_alloc_pages(npages, IHK_MC_AP_NOWAIT);
		if (!virt) {
			error = -ENOMEM;
			ekprintf("shmobj_get_page(%p,%#lx,%d,%p):"
					"alloc failed. %d\n",
					memobj, off, p2align, physp, error);
			goto out;
		}
		phys = virt_to_phys(virt);
		page = phys_to_page(phys);
		if (page->mode != PM_NONE) {
			fkprintf("shmobj_get_page(%p,%#lx,%d,%p):"
					"page %p %#lx %d %d %#lx\n",
					memobj, off, p2align, physp,
					page, page_to_phys(page), page->mode,
					page->count, page->offset);
			panic("shmobj_get_page()");
		}
		memset(virt, 0, npages*PAGE_SIZE);
		page->mode = PM_MAPPED;
		page->offset = off;
		ihk_atomic_set(&page->count, 1);
		page_list_insert(obj, page);
		virt = NULL;
		dkprintf("shmobj_get_page(%p,%#lx,%d,%p):alloc page. %p %#lx\n",
				memobj, off, p2align, physp, page, phys);
	}

	ihk_atomic_inc(&page->count);

	error = 0;
	*physp = page_to_phys(page);

out:
	memobj_unlock(&obj->memobj);
	if (virt) {
		ihk_mc_free_pages(virt, npages);
	}
	dkprintf("shmobj_get_page(%p,%#lx,%d,%p):%d\n",
			memobj, off, p2align, physp, error);
	return error;
}

static int shmobj_invalidate_page(struct memobj *memobj, uintptr_t phys,
		size_t pgsize)
{
	struct shmobj *obj = to_shmobj(memobj);
	int error;
	struct page *page;

	dkprintf("shmobj_invalidate_page(%p,%#lx,%#lx)\n", memobj, phys, pgsize);

	if (!(page = phys_to_page(phys))
			|| !(page = page_list_lookup(obj, page->offset))) {
		error = 0;
		goto out;
	}

	if (ihk_atomic_read(&page->count) == 1) {
		if (page_unmap(page)) {
			ihk_mc_free_pages(phys_to_virt(phys), pgsize/PAGE_SIZE);
		}
	}

	error = 0;
out:
	dkprintf("shmobj_invalidate_page(%p,%#lx,%#lx):%d\n", memobj, phys, pgsize, error);
	return error;
}
