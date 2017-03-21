/**
 * \file zeroobj.c
 *  License details are found in the file LICENSE.
 * \brief
 *  read-only zeroed page object
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2014  RIKEN AICS
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
#include <string.h>

#define	dkprintf(...)	do { if (0) kprintf(__VA_ARGS__); } while (0)
#define	ekprintf(...)	kprintf(__VA_ARGS__)
#define	fkprintf(...)	kprintf(__VA_ARGS__)

struct zeroobj {
	struct memobj		memobj;		/* must be first */
	struct list_head	page_list;
};

static ihk_spinlock_t the_zeroobj_lock = SPIN_LOCK_UNLOCKED;
static struct zeroobj *the_zeroobj = NULL;	/* singleton */

static memobj_get_page_func_t zeroobj_get_page;

static struct memobj_ops zeroobj_ops = {
	.get_page =	&zeroobj_get_page,
};

static struct zeroobj *to_zeroobj(struct memobj *memobj)
{
	return (struct zeroobj *)memobj;
}

static struct memobj *to_memobj(struct zeroobj *zeroobj)
{
	return &zeroobj->memobj;
}

/***********************************************************************
 * page_list
 */
static void page_list_init(struct zeroobj *obj)
{
	INIT_LIST_HEAD(&obj->page_list);
	return;
}

static void page_list_insert(struct zeroobj *obj, struct page *page)
{
	list_add(&page->list, &obj->page_list);
	return;
}

static struct page *page_list_first(struct zeroobj *obj)
{
	if (list_empty(&obj->page_list)) {
		return NULL;
	}

	return list_first_entry(&obj->page_list, struct page, list);
}

/***********************************************************************
 * zeroobj
 */
static int alloc_zeroobj(void)
{
	int error;
	struct zeroobj *obj = NULL;
	void *virt = NULL;
	uintptr_t phys;
	struct page *page;

	dkprintf("alloc_zeroobj()\n");
	ihk_mc_spinlock_lock_noirq(&the_zeroobj_lock);
	if (the_zeroobj) {
		error = 0;
		dkprintf("alloc_zeroobj():already. %d\n", error);
		goto out;
	}

	obj = kmalloc(sizeof(*obj), IHK_MC_AP_NOWAIT);
	if (!obj) {
		error = -ENOMEM;
		ekprintf("alloc_zeroobj():kmalloc failed. %d\n", error);
		goto out;
	}

	memset(obj, 0, sizeof(*obj));
	obj->memobj.ops = &zeroobj_ops;
	obj->memobj.size = 0;
	page_list_init(obj);
	ihk_mc_spinlock_init(&obj->memobj.lock);

	virt = ihk_mc_alloc_pages(1, IHK_MC_AP_NOWAIT);	/* XXX:NYI:large page */
	if (!virt) {
		error = -ENOMEM;
		ekprintf("alloc_zeroobj():alloc pages failed. %d\n", error);
		goto out;
	}
	phys = virt_to_phys(virt);
	page = phys_to_page_insert_hash(phys);

	if (page->mode != PM_NONE) {
		fkprintf("alloc_zeroobj():"
				"page %p %#lx %d %d %#lx\n",
				page, page_to_phys(page), page->mode,
				page->count, page->offset);
		panic("alloc_zeroobj:dup alloc");
	}

	memset(virt, 0, PAGE_SIZE);
	page->mode = PM_MAPPED;
	page->offset = 0;
	ihk_atomic_set(&page->count, 1);
	page_list_insert(obj, page);
	virt = NULL;

	error = 0;
	the_zeroobj = obj;
	obj = NULL;

out:
	ihk_mc_spinlock_unlock_noirq(&the_zeroobj_lock);
	if (virt) {
		ihk_mc_free_pages(virt, 1);
	}
	if (obj) {
		kfree(obj);
	}
	dkprintf("alloc_zeroobj():%d %p\n", error, the_zeroobj);
	return error;
}

int zeroobj_create(struct memobj **objp)
{
	int error;

	dkprintf("zeroobj_create(%p)\n", objp);
	if (!the_zeroobj) {
		error = alloc_zeroobj();
		if (error) {
			goto out;
		}
	}

	error = 0;
	*objp = to_memobj(the_zeroobj);

out:
	dkprintf("zeroobj_create(%p):%d %p\n", objp, error, *objp);
	return error;
}

static int zeroobj_get_page(struct memobj *memobj, off_t off, int p2align,
		uintptr_t *physp, unsigned long *pflag)
{
	int error;
	struct zeroobj *obj = to_zeroobj(memobj);
	struct page *page;

	/* Don't bother about zero page, page fault handler will
	 * allocate and clear pages */
	return 0;

	dkprintf("zeroobj_get_page(%p,%#lx,%d,%p)\n",
			memobj, off, p2align, physp);
	if (off & ~PAGE_MASK) {
		error = -EINVAL;
		ekprintf("zeroobj_get_page(%p,%#lx,%d,%p):invalid argument. %d\n",
				memobj, off, p2align, physp, error);
		goto out;
	}
	if (p2align != PAGE_P2ALIGN) {		/* XXX:NYI:large pages */
		error = -ENOMEM;
		dkprintf("zeroobj_get_page(%p,%#lx,%d,%p):large page. %d\n",
				memobj, off, p2align, physp, error);
		goto out;
	}

	page = page_list_first(obj);
	if (!page) {
		error = -ENOMEM;
		ekprintf("zeroobj_get_page(%p,%#lx,%d,%p):page not found. %d\n",
				memobj, off, p2align, physp, error);
		goto out;
	}

	ihk_atomic_inc(&page->count);

	error = 0;
	*physp = page_to_phys(page);

out:
	dkprintf("zeroobj_get_page(%p,%#lx,%d,%p):%d\n",
			memobj, off, p2align, physp, error);
	return error;
}
