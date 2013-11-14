/**
 * \file fileobj.c
 *  License details are found in the file LICENSE.
 * \brief
 *  file back-ended pager client
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 */
/*
 * HISTORY:
 */

#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <ihk/lock.h>
#include <ihk/mm.h>
#include <ihk/types.h>
#include <cls.h>
#include <errno.h>
#include <kmalloc.h>
#include <kmsg.h>
#include <memobj.h>
#include <memory.h>
#include <page.h>
#include <pager.h>
#include <string.h>
#include <syscall.h>

#define	dkprintf(...)
#define	ekprintf(...)	kprintf(__VA_ARGS__)

static ihk_spinlock_t fileobj_list_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(fileobj_list);

struct fileobj {
	struct memobj		memobj;		/* must be first */
	long			sref;
	long			cref;
	uintptr_t		handle;
	struct list_head	page_list;
	struct list_head	list;
};

static memobj_release_func_t fileobj_release;
static memobj_ref_func_t fileobj_ref;
static memobj_get_page_func_t fileobj_get_page;
static memobj_copy_page_func_t fileobj_copy_page;
static memobj_flush_page_func_t fileobj_flush_page;

static struct memobj_ops fileobj_ops = {
	.release =	&fileobj_release,
	.ref =		&fileobj_ref,
	.get_page =	&fileobj_get_page,
	.copy_page =	&fileobj_copy_page,
	.flush_page =	&fileobj_flush_page,
};

static struct fileobj *to_fileobj(struct memobj *memobj)
{
	return (struct fileobj *)memobj;
}

static struct memobj *to_memobj(struct fileobj *fileobj)
{
	return &fileobj->memobj;
}

/***********************************************************************
 * page_list
 */
static void page_list_init(struct fileobj *obj)
{
	INIT_LIST_HEAD(&obj->page_list);
	return;
}

static void page_list_insert(struct fileobj *obj, struct page *page)
{
	list_add(&page->list, &obj->page_list);
	return;
}

static void page_list_remove(struct fileobj *obj, struct page *page)
{
	list_del(&page->list);
}

static struct page *page_list_lookup(struct fileobj *obj, off_t off)
{
	struct page *page;

	list_for_each_entry(page, &obj->page_list, list) {
		if ((page->mode != PM_WILL_PAGEIO)
				&& (page->mode != PM_PAGEIO)
				&& (page->mode != PM_DONE_PAGEIO)
				&& (page->mode != PM_PAGEIO_EOF)
				&& (page->mode != PM_PAGEIO_ERROR)
				&& (page->mode != PM_MAPPED)) {
			kprintf("page_list_lookup(%p,%lx): mode %x\n",
					obj, off, page->mode);
			panic("page_list_lookup:invalid obj page");
		}
		if (page->offset == off) {
			goto out;
		}
	}
	page = NULL;

out:
	return page;
}

static struct page *page_list_first(struct fileobj *obj)
{
	if (list_empty(&obj->page_list)) {
		return NULL;
	}

	return list_first_entry(&obj->page_list, struct page, list);
}

/***********************************************************************
 * obj_list
 */
static void obj_list_insert(struct fileobj *obj)
{
	list_add(&obj->list, &fileobj_list);
}

static void obj_list_remove(struct fileobj *obj)
{
	list_del(&obj->list);
}

/* return NULL or locked fileobj */
static struct fileobj *obj_list_lookup(uintptr_t handle)
{
	struct fileobj *obj;
	struct fileobj *p;

	obj = NULL;
	list_for_each_entry(p, &fileobj_list, list) {
		if (p->handle == handle) {
			memobj_lock(&p->memobj);
			if (p->cref > 0) {
				obj = p;
				break;
			}
			memobj_unlock(&p->memobj);
		}
	}

	return obj;
}

/***********************************************************************
 * fileobj
 */
int fileobj_create(int fd, struct memobj **objp, int *maxprotp)
{
	ihk_mc_user_context_t ctx;
	struct pager_create_result result;	// XXX: assumes contiguous physical
	int error;
	struct fileobj *newobj  = NULL;
	struct fileobj *obj;

	dkprintf("fileobj_create(%d)\n", fd);
	newobj = kmalloc(sizeof(*newobj), IHK_MC_AP_NOWAIT);
	if (!newobj) {
		error = -ENOMEM;
		kprintf("fileobj_create(%d):kmalloc failed. %d\n", fd, error);
		goto out;
	}

	ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_CREATE;
	ihk_mc_syscall_arg1(&ctx) = fd;
	ihk_mc_syscall_arg2(&ctx) = virt_to_phys(&result);

	error = syscall_generic_forwarding(__NR_mmap, &ctx);
	if (error) {
		kprintf("fileobj_create(%d):create failed. %d\n", fd, error);
		goto out;
	}

	memset(newobj, 0, sizeof(*newobj));
	newobj->memobj.ops = &fileobj_ops;
	newobj->handle = result.handle;
	newobj->sref = 1;
	newobj->cref = 1;
	page_list_init(newobj);
	ihk_mc_spinlock_init(&newobj->memobj.lock);

	ihk_mc_spinlock_lock_noirq(&fileobj_list_lock);
	obj = obj_list_lookup(result.handle);
	if (!obj) {
		obj_list_insert(newobj);
		obj = newobj;
		newobj = NULL;
	}
	else {
		++obj->sref;
		++obj->cref;
		memobj_unlock(&obj->memobj);	/* locked by obj_list_lookup() */
	}

	ihk_mc_spinlock_unlock_noirq(&fileobj_list_lock);

	error = 0;
	*objp = to_memobj(obj);
	*maxprotp = result.maxprot;

out:
	if (newobj) {
		kfree(newobj);
	}
	dkprintf("fileobj_create(%d):%d %p %x\n", fd, error, *objp, *maxprotp);
	return error;
}

static void fileobj_ref(struct memobj *memobj)
{
	struct fileobj *obj = to_fileobj(memobj);

	dkprintf("fileobj_ref(%p %lx):\n", obj, obj->handle);
	memobj_lock(&obj->memobj);
	++obj->cref;
	memobj_unlock(&obj->memobj);
	return;
}

static void fileobj_release(struct memobj *memobj)
{
	struct fileobj *obj = to_fileobj(memobj);
	long free_sref = 0;
	uintptr_t free_handle;
	struct fileobj *free_obj = NULL;

	dkprintf("fileobj_release(%p %lx)\n", obj, obj->handle);

	memobj_lock(&obj->memobj);
	--obj->cref;
	free_sref = obj->sref - 1;	/* surplus sref */
	if (obj->cref <= 0) {
		free_sref = obj->sref;
		free_obj = obj;
	}
	obj->sref -= free_sref;
	free_handle = obj->handle;
	memobj_unlock(&obj->memobj);

	if (free_obj) {
		ihk_mc_spinlock_lock_noirq(&fileobj_list_lock);
		/* zap page_list */
		for (;;) {
			struct page *page;

			page = page_list_first(obj);
			if (!page) {
				break;
			}
			page_list_remove(obj, page);

			if (!((page->mode == PM_WILL_PAGEIO)
					|| (page->mode == PM_DONE_PAGEIO)
					|| (page->mode == PM_PAGEIO_EOF)
					|| (page->mode == PM_PAGEIO_ERROR)
					|| ((page->mode == PM_MAPPED)
						&& (page->count <= 0)))) {
				kprintf("fileobj_release(%p %lx): "
					       "mode %x, count %d, off %lx\n",
					       obj, obj->handle, page->mode,
					       page->count, page->offset);
				panic("fileobj_release");
			}

			page->mode = PM_NONE;
			free_pages(phys_to_virt(page_to_phys(page)), 1);
		}
		obj_list_remove(free_obj);
		ihk_mc_spinlock_unlock_noirq(&fileobj_list_lock);
		kfree(free_obj);
	}

	if (free_sref) {
		int error;
		ihk_mc_user_context_t ctx;

		ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_RELEASE;
		ihk_mc_syscall_arg1(&ctx) = free_handle;
		ihk_mc_syscall_arg2(&ctx) = free_sref;

		error = syscall_generic_forwarding(__NR_mmap, &ctx);
		if (error) {
			kprintf("fileobj_release(%p %lx):"
					"release %ld failed. %d\n",
					obj, free_handle, free_sref, error);
			/* through */
		}
	}

	dkprintf("fileobj_release(%p %lx):free %ld %p\n",
			obj, free_handle, free_sref, free_obj);
	return;
}

struct pageio_args {
	struct fileobj *	fileobj;
	off_t			objoff;
	size_t			pgsize;
};

/*
 * fileobj_do_pageio():
 * - args0 will be freed with kfree()
 * - args0->fileobj will be released
 */
static void fileobj_do_pageio(void *args0)
{
	struct pageio_args *args = args0;
	struct fileobj *obj = args->fileobj;
	off_t off = args->objoff;
	size_t pgsize = args->pgsize;
	struct page *page;
	ihk_mc_user_context_t ctx;
	ssize_t ss;

	memobj_lock(&obj->memobj);
	page = page_list_lookup(obj, off);
	if (!page) {
		goto out;
	}

	while (page->mode == PM_PAGEIO) {
		memobj_unlock(&obj->memobj);
		cpu_pause();
		memobj_lock(&obj->memobj);
	}

	if (page->mode == PM_WILL_PAGEIO) {
		page->mode = PM_PAGEIO;
		memobj_unlock(&obj->memobj);

		ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_READ;
		ihk_mc_syscall_arg1(&ctx) = obj->handle;
		ihk_mc_syscall_arg2(&ctx) = off;
		ihk_mc_syscall_arg3(&ctx) = pgsize;
		ihk_mc_syscall_arg4(&ctx) = page_to_phys(page);

		ss = syscall_generic_forwarding(__NR_mmap, &ctx);

		memobj_lock(&obj->memobj);
		if (page->mode != PM_PAGEIO) {
			kprintf("fileobj_do_pageio(%p,%lx,%lx):"
					"invalid mode %x\n",
					obj, off, pgsize, page->mode);
			panic("fileobj_do_pageio:invalid page mode");
		}

		if (ss == 0) {
			dkprintf("fileobj_do_pageio(%p,%lx,%lx):EOF? %ld\n",
					obj, off, pgsize, ss);
			page->mode = PM_PAGEIO_EOF;
			goto out;
		}
		else if (ss != pgsize) {
			kprintf("fileobj_do_pageio(%p,%lx,%lx):"
					"read failed. %ld\n",
					obj, off, pgsize, ss);
			page->mode = PM_PAGEIO_ERROR;
			goto out;
		}

		page->mode = PM_DONE_PAGEIO;
	}
out:
	memobj_unlock(&obj->memobj);
	fileobj_release(&obj->memobj);		/* got fileobj_get_page() */
	kfree(args0);
	dkprintf("fileobj_do_pageio(%p,%lx,%lx):\n", obj, off, pgsize);
	return;
}

static int fileobj_get_page(struct memobj *memobj, off_t off, int p2align, uintptr_t *physp)
{
	struct process *proc = cpu_local_var(current);
	struct fileobj *obj = to_fileobj(memobj);
	int error;
	void *virt = NULL;
	int npages;
	uintptr_t phys = -1;
	struct page *page;
	struct pageio_args *args = NULL;

	dkprintf("fileobj_get_page(%p,%lx,%x,%p)\n", obj, off, p2align, physp);

	memobj_lock(&obj->memobj);
	if (p2align != PAGE_P2ALIGN) {
		error = -ENOMEM;
		goto out;
	}

	page = page_list_lookup(obj, off);
	if (!page || (page->mode == PM_WILL_PAGEIO)
			|| (page->mode == PM_PAGEIO)) {
		args = kmalloc(sizeof(*args), IHK_MC_AP_NOWAIT);
		if (!args) {
			error = -ENOMEM;
			kprintf("fileobj_get_page(%p,%lx,%x,%p):"
					"kmalloc failed. %d\n",
					obj, off, p2align, physp, error);
			goto out;
		}

		if (!page) {
			npages = 1 << p2align;
			virt = ihk_mc_alloc_pages(npages, IHK_MC_AP_NOWAIT);
			if (!virt) {
				error = -ENOMEM;
				kprintf("fileobj_get_page(%p,%lx,%x,%p):"
						"alloc failed. %d\n",
						obj, off, p2align, physp,
						error);
				goto out;
			}
			phys = virt_to_phys(virt);
			page = phys_to_page(phys);
			if (page->mode != PM_NONE) {
				panic("fileobj_get_page:invalid new page");
			}
			page->mode = PM_WILL_PAGEIO;
			page->offset = off;
			page_list_insert(obj, page);
		}

		++obj->cref;	/* for fileobj_do_pageio() */

		args->fileobj = obj;
		args->objoff = off;
		args->pgsize = PAGE_SIZE << p2align;

		proc->pgio_fp = &fileobj_do_pageio;
		proc->pgio_arg = args;

		error = -ERESTART;
		virt = NULL;
		args = NULL;
		goto out;
	}
	else if (page->mode == PM_DONE_PAGEIO) {
		page->mode = PM_MAPPED;
		page->count = 0;
	}
	else if (page->mode == PM_PAGEIO_EOF) {
		error = -ERANGE;
		goto out;
	}
	else if (page->mode == PM_PAGEIO_ERROR) {
		error = -EIO;
		goto out;
	}

	++page->count;

	error = 0;
	*physp = page_to_phys(page);
	virt = NULL;
out:
	memobj_unlock(&obj->memobj);
	if (virt) {
		ihk_mc_free_pages(virt, npages);
	}
	if (args) {
		kfree(args);
	}
	dkprintf("fileobj_get_page(%p,%lx,%x,%p): %d %lx\n",
			obj, off, p2align, physp, error, phys);
	return error;
}

static uintptr_t fileobj_copy_page(
		struct memobj *memobj, uintptr_t orgpa, int p2align)
{
	struct page *orgpage = phys_to_page(orgpa);
	size_t pgsize = PAGE_SIZE << p2align;
	int npages = 1 << p2align;
	void *newkva = NULL;
	uintptr_t newpa = -1;
	void *orgkva;

	dkprintf("fileobj_copy_page(%p,%lx,%d)\n", memobj, orgpa, p2align);
	if (p2align != PAGE_P2ALIGN) {
		panic("p2align");
	}

	memobj_lock(memobj);
	for (;;) {
		if (orgpage->mode != PM_MAPPED) {
			kprintf("fileobj_copy_page(%p,%lx,%d):"
					"invalid cow page. %x\n",
					memobj, orgpa, p2align, orgpage->mode);
			panic("fileobj_copy_page:invalid cow page");
		}
		if (orgpage->count == 1) {	// XXX: private only
			list_del(&orgpage->list);
			orgpage->mode = PM_NONE;
			newpa = orgpa;
			break;
		}
		if (orgpage->count <= 0) {
			kprintf("fileobj_copy_page(%p,%lx,%d):"
					"orgpage count corrupted. %x\n",
					memobj, orgpa, p2align, orgpage->count);
			panic("fileobj_copy_page:orgpage count corrupted");
		}
		if (newkva) {
			orgkva = phys_to_virt(orgpa);
			memcpy(newkva, orgkva, pgsize);
			--orgpage->count;
			newpa = virt_to_phys(newkva);
			newkva = NULL;	/* avoid ihk_mc_free_pages() */
			break;
		}

		memobj_unlock(memobj);
		newkva = ihk_mc_alloc_aligned_pages(npages, p2align,
				IHK_MC_AP_NOWAIT);
		if (!newkva) {
			kprintf("fileobj_copy_page(%p,%lx,%d):"
					"alloc page failed\n",
					memobj, orgpa, p2align);
			goto out;
		}
		memobj_lock(memobj);
	}
	memobj_unlock(memobj);

out:
	if (newkva) {
		ihk_mc_free_pages(newkva, npages);
	}
	dkprintf("fileobj_copy_page(%p,%lx,%d): %lx\n",
			memobj, orgpa, p2align, newpa);
	return newpa;
}

static int fileobj_flush_page(struct memobj *memobj, uintptr_t phys,
		size_t pgsize)
{
	struct fileobj *obj = to_fileobj(memobj);
	struct page *page;
	ihk_mc_user_context_t ctx;
	ssize_t ss;

	page = phys_to_page(phys);
	memobj_unlock(&obj->memobj);

	ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_WRITE;
	ihk_mc_syscall_arg1(&ctx) = obj->handle;
	ihk_mc_syscall_arg2(&ctx) = page->offset;
	ihk_mc_syscall_arg3(&ctx) = pgsize;
	ihk_mc_syscall_arg4(&ctx) = phys;

	ss = syscall_generic_forwarding(__NR_mmap, &ctx);
	if (ss != pgsize) {
		dkprintf("fileobj_flush_page(%p,%lx,%lx): %ld (%lx)\n",
				memobj, phys, pgsize, ss, ss);
		/* through */
	}

	memobj_lock(&obj->memobj);
	return 0;
}
