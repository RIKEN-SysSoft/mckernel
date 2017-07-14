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

#define	dkprintf(...)	do { if (0) kprintf(__VA_ARGS__); } while (0)
#define	ekprintf(...)	kprintf(__VA_ARGS__)

mcs_rwlock_lock_t fileobj_list_lock;
static LIST_HEAD(fileobj_list);

#define FILEOBJ_PAGE_HASH_SHIFT 9
#define FILEOBJ_PAGE_HASH_SIZE (1 << FILEOBJ_PAGE_HASH_SHIFT)
#define FILEOBJ_PAGE_HASH_MASK (FILEOBJ_PAGE_HASH_SIZE - 1)

struct fileobj {
	struct memobj memobj;		/* must be first */
	long sref;
	long cref;
	uintptr_t handle;
	struct list_head list;
	struct list_head page_hash[FILEOBJ_PAGE_HASH_SIZE];
	mcs_rwlock_lock_t page_hash_locks[FILEOBJ_PAGE_HASH_SIZE];
};

static memobj_release_func_t fileobj_release;
static memobj_ref_func_t fileobj_ref;
static memobj_get_page_func_t fileobj_get_page;
static memobj_flush_page_func_t fileobj_flush_page;
static memobj_invalidate_page_func_t fileobj_invalidate_page;
static memobj_lookup_page_func_t fileobj_lookup_page;

static struct memobj_ops fileobj_ops = {
	.release =	&fileobj_release,
	.ref =		&fileobj_ref,
	.get_page =	&fileobj_get_page,
	.copy_page =	NULL,
	.flush_page =	&fileobj_flush_page,
	.invalidate_page =	&fileobj_invalidate_page,
	.lookup_page =	&fileobj_lookup_page,
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
static void fileobj_page_hash_init(struct fileobj *obj)
{
	int i;
	for (i = 0; i < FILEOBJ_PAGE_HASH_SIZE; ++i) {
		mcs_rwlock_init(&obj->page_hash_locks[i]);
		INIT_LIST_HEAD(&obj->page_hash[i]);
	}
	return;
}

/* NOTE: caller must hold page_hash_locks[hash] */
static void __fileobj_page_hash_insert(struct fileobj *obj,
		struct page *page, int hash)
{
	list_add(&page->list, &obj->page_hash[hash]);
}

/* NOTE: caller must hold page_hash_locks[hash] */
static void __fileobj_page_hash_remove(struct page *page)
{
	list_del(&page->list);
}

/* NOTE: caller must hold page_hash_locks[hash] */
static struct page *__fileobj_page_hash_lookup(struct fileobj *obj,
		int hash, off_t off)
{
	struct page *page;

	list_for_each_entry(page, &obj->page_hash[hash], list) {
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

static struct page *fileobj_page_hash_first(struct fileobj *obj)
{
	int i;

	for (i = 0; i < FILEOBJ_PAGE_HASH_SIZE; ++i) {
		if (!list_empty(&obj->page_hash[i])) {
			break;
		}
	}

	if (i != FILEOBJ_PAGE_HASH_SIZE) {
		return list_first_entry(&obj->page_hash[i], struct page, list);
	}
	else {
		return NULL;
	}
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
	struct pager_create_result result __attribute__((aligned(64)));	
	int error;
	struct fileobj *newobj  = NULL;
	struct fileobj *obj;
	struct mcs_rwlock_node node;

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
	memset(&result, 0, sizeof(result));

	error = syscall_generic_forwarding(__NR_mmap, &ctx);
	if (error) {
		dkprintf("fileobj_create(%d):create failed. %d\n", fd, error);
		goto out;
	}

	memset(newobj, 0, sizeof(*newobj));
	newobj->memobj.ops = &fileobj_ops;
	newobj->memobj.flags = MF_HAS_PAGER | MF_REG_FILE;
	newobj->handle = result.handle;
	newobj->sref = 1;
	newobj->cref = 1;
	fileobj_page_hash_init(newobj);
	ihk_mc_spinlock_init(&newobj->memobj.lock);

	mcs_rwlock_writer_lock_noirq(&fileobj_list_lock, &node);
	obj = obj_list_lookup(result.handle);
	if (!obj) {
		obj_list_insert(newobj);
		obj = newobj;
		to_memobj(obj)->size = result.size;
		to_memobj(obj)->flags |= result.flags;
		to_memobj(obj)->status = MEMOBJ_READY;
		if (to_memobj(obj)->flags & MF_PREFETCH) {
			to_memobj(obj)->status = MEMOBJ_TO_BE_PREFETCHED;
		}

		/* XXX: KNL specific optimization for OFP runs */
		if ((to_memobj(obj)->flags & MF_PREMAP) &&
				(to_memobj(obj)->flags & MF_ZEROFILL)) {
			struct memobj *mo = to_memobj(obj);
			int nr_pages = (result.size + (PAGE_SIZE - 1))
				>> PAGE_SHIFT;
			int j = 0;
			int node = ihk_mc_get_nr_numa_nodes() / 2;
			dkprintf("%s: MF_PREMAP, start node: %d\n",
				__FUNCTION__, node);

			mo->pages = kmalloc(nr_pages * sizeof(void *), IHK_MC_AP_NOWAIT);
			if (!mo->pages) {
				kprintf("%s: WARNING: failed to allocate pages\n",
						__FUNCTION__);
				goto error_cleanup;
			}

			mo->nr_pages = nr_pages;
			memset(mo->pages, 0, nr_pages * sizeof(*mo->pages));

			if (cpu_local_var(current)->proc->mpol_flags & MPOL_SHM_PREMAP) {
				/* Get the actual pages NUMA interleaved */
				for (j = 0; j < nr_pages; ++j) {
					mo->pages[j] = ihk_mc_alloc_aligned_pages_node_user(1,
							PAGE_P2ALIGN, IHK_MC_AP_NOWAIT, node);
					if (!mo->pages[j]) {
						kprintf("%s: ERROR: allocating pages[%d]\n",
								__FUNCTION__, j);
						goto error_cleanup;
					}

					memset(mo->pages[j], 0, PAGE_SIZE);

					++node;
					if (node == ihk_mc_get_nr_numa_nodes()) {
						node = ihk_mc_get_nr_numa_nodes() / 2;
					}
				}
				dkprintf("%s: allocated %d pages interleaved\n",
						__FUNCTION__, nr_pages);
			}
error_cleanup:
			/* TODO: cleanup allocated portion */
			;
		}

		newobj = NULL;
		dkprintf("%s: new obj 0x%lx cref: %d, %s\n",
			__FUNCTION__,
			obj,
			obj->cref,
			to_memobj(obj)->flags & MF_ZEROFILL ? "zerofill" : "");
	}
	else {
		++obj->sref;
		++obj->cref;
		memobj_unlock(&obj->memobj);	/* locked by obj_list_lookup() */
		dkprintf("%s: existing obj 0x%lx cref: %d, %s\n",
			__FUNCTION__,
			obj,
			obj->cref,
			to_memobj(obj)->flags & MF_ZEROFILL ? "zerofill" : "");
	}

	mcs_rwlock_writer_unlock_noirq(&fileobj_list_lock, &node);

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
	struct mcs_rwlock_node node;

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
	if (obj->memobj.flags & MF_HOST_RELEASED) {
		free_sref = 0; // don't call syscall_generic_forwarding
	}

	if (free_obj) {
		dkprintf("%s: release obj 0x%lx cref: %d, free_obj: 0x%lx, %s\n",
				__FUNCTION__,
				obj,
				obj->cref,
				free_obj,
				to_memobj(obj)->flags & MF_ZEROFILL ? "zerofill" : "");
		mcs_rwlock_writer_lock_noirq(&fileobj_list_lock, &node);
		/* zap page_list */
		for (;;) {
			struct page *page;
			void *page_va;

			page = fileobj_page_hash_first(obj);
			if (!page) {
				break;
			}
			__fileobj_page_hash_remove(page);
			page_va = phys_to_virt(page_to_phys(page));

			if (ihk_atomic_read(&page->count) != 1) {
				kprintf("%s: WARNING: page count %d for phys 0x%lx is invalid, flags: 0x%lx\n",
					__FUNCTION__,
					ihk_atomic_read(&page->count),
					page->phys,
					to_memobj(free_obj)->flags);
			}
			else if (page_unmap(page)) {
				ihk_mc_free_pages_user(page_va, 1);
			}
#if 0
			count = ihk_atomic_sub_return(1, &page->count);

			if (!((page->mode == PM_WILL_PAGEIO)
					|| (page->mode == PM_DONE_PAGEIO)
					|| (page->mode == PM_PAGEIO_EOF)
					|| (page->mode == PM_PAGEIO_ERROR)
					|| ((page->mode == PM_MAPPED)
						&& (count <= 0)))) {
				kprintf("fileobj_release(%p %lx): "
					       "mode %x, count %d, off %lx\n",
					       obj, obj->handle, page->mode,
					       count, page->offset);
				panic("fileobj_release");
			}

			page->mode = PM_NONE;
#endif
		}

		/* Pre-mapped? */
		if (to_memobj(free_obj)->flags & MF_PREMAP) {
			int i;

			for (i = 0; i < to_memobj(free_obj)->nr_pages; ++i) {
				if (to_memobj(free_obj)->pages[i])
					ihk_mc_free_pages_user(to_memobj(free_obj)->pages[i], 1);
			}

			kfree(to_memobj(free_obj)->pages);
		}

		obj_list_remove(free_obj);
		mcs_rwlock_writer_unlock_noirq(&fileobj_list_lock, &node);
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
	struct mcs_rwlock_node mcs_node;
	int hash = (off >> PAGE_SHIFT) & FILEOBJ_PAGE_HASH_MASK;	

	mcs_rwlock_writer_lock_noirq(&obj->page_hash_locks[hash],
			&mcs_node);
	page = __fileobj_page_hash_lookup(obj, hash, off);
	if (!page) {
		goto out;
	}

	while (page->mode == PM_PAGEIO) {
		mcs_rwlock_writer_unlock_noirq(&obj->page_hash_locks[hash],
				&mcs_node);
		cpu_pause();
		mcs_rwlock_writer_lock_noirq(&obj->page_hash_locks[hash],
				&mcs_node);
	}

	if (page->mode == PM_WILL_PAGEIO) {
		if (to_memobj(obj)->flags & MF_ZEROFILL) {
			void *virt = phys_to_virt(page_to_phys(page));
			memset(virt, 0, PAGE_SIZE);
#ifdef PROFILE_ENABLE
			profile_event_add(PROFILE_page_fault_file_clr, PAGE_SIZE);
#endif // PROFILE_ENABLE
		}
		else {
			page->mode = PM_PAGEIO;
			mcs_rwlock_writer_unlock_noirq(&obj->page_hash_locks[hash],
					&mcs_node);

			ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_READ;
			ihk_mc_syscall_arg1(&ctx) = obj->handle;
			ihk_mc_syscall_arg2(&ctx) = off;
			ihk_mc_syscall_arg3(&ctx) = pgsize;
			ihk_mc_syscall_arg4(&ctx) = page_to_phys(page);

			dkprintf("%s: __NR_mmap for handle 0x%lx\n",
					__FUNCTION__, obj->handle);
			ss = syscall_generic_forwarding(__NR_mmap, &ctx);

			mcs_rwlock_writer_lock_noirq(&obj->page_hash_locks[hash],
					&mcs_node);
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
		}

		page->mode = PM_DONE_PAGEIO;
	}
out:
	mcs_rwlock_writer_unlock_noirq(&obj->page_hash_locks[hash],
			&mcs_node);
	fileobj_release(&obj->memobj);		/* got fileobj_get_page() */
	kfree(args0);
	dkprintf("fileobj_do_pageio(%p,%lx,%lx):\n", obj, off, pgsize);
	return;
}

static int fileobj_get_page(struct memobj *memobj, off_t off,
		int p2align, uintptr_t *physp, unsigned long *pflag)
{
	struct thread *proc = cpu_local_var(current);
	struct fileobj *obj = to_fileobj(memobj);
	int error = -1;
	void *virt = NULL;
	int npages;
	uintptr_t phys = -1;
	struct page *page;
	struct pageio_args *args = NULL;
	struct mcs_rwlock_node mcs_node;
	int hash = (off >> PAGE_SHIFT) & FILEOBJ_PAGE_HASH_MASK;	

	dkprintf("fileobj_get_page(%p,%lx,%x,%p)\n", obj, off, p2align, physp);
	if (p2align != PAGE_P2ALIGN) {
		return -ENOMEM;
	}

#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_page_fault_file, PAGE_SIZE);
#endif // PROFILE_ENABLE

	if (memobj->flags & MF_PREMAP) {
		int page_ind = off >> PAGE_SHIFT;

		if (!memobj->pages[page_ind]) {
			virt = ihk_mc_alloc_pages_user(1, IHK_MC_AP_NOWAIT | IHK_MC_AP_USER);

			if (!virt) {
				error = -ENOMEM;
				kprintf("fileobj_get_page(%p,%lx,%x,%p):"
						"alloc failed. %d\n",
						obj, off, p2align, physp,
						error);
				goto out_nolock;
			}

			/* Update the array but see if someone did it already and use
			 * that if so */
			if (!__sync_bool_compare_and_swap(&memobj->pages[page_ind],
						NULL, virt)) {
				ihk_mc_free_pages_user(virt, 1);
			}
			else {
				dkprintf("%s: MF_ZEROFILL: off: %lu -> 0x%lx allocated\n",
						__FUNCTION__, off, virt_to_phys(virt));
			}
		}

		virt = memobj->pages[page_ind];
		error = 0;
		*physp = virt_to_phys(virt);
		dkprintf("%s: MF_ZEROFILL: off: %lu -> 0x%lx resolved\n",
				__FUNCTION__, off, virt_to_phys(virt));
		virt = NULL;
		goto out_nolock;
	}

	mcs_rwlock_writer_lock_noirq(&obj->page_hash_locks[hash],
			&mcs_node);
	page = __fileobj_page_hash_lookup(obj, hash, off);
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

			virt = ihk_mc_alloc_pages_user(npages, IHK_MC_AP_NOWAIT |
					(to_memobj(obj)->flags & MF_ZEROFILL) ? IHK_MC_AP_USER : 0);

			if (!virt) {
				error = -ENOMEM;
				kprintf("fileobj_get_page(%p,%lx,%x,%p):"
						"alloc failed. %d\n",
						obj, off, p2align, physp,
						error);
				goto out;
			}
			phys = virt_to_phys(virt);
			page = phys_to_page_insert_hash(phys);
			if (page->mode != PM_NONE) {
				panic("fileobj_get_page:invalid new page");
			}
			page->offset = off;
			ihk_atomic_set(&page->count, 1);
			__fileobj_page_hash_insert(obj, page, hash);
			page->mode = PM_WILL_PAGEIO;
		}

		memobj_lock(&obj->memobj);
		++obj->cref;	/* for fileobj_do_pageio() */
		memobj_unlock(&obj->memobj);

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
	}
	else if (page->mode == PM_PAGEIO_EOF) {
		error = -ERANGE;
		goto out;
	}
	else if (page->mode == PM_PAGEIO_ERROR) {
		error = -EIO;
		goto out;
	}

	ihk_atomic_inc(&page->count);

	error = 0;
	*physp = page_to_phys(page);
	virt = NULL;
out:
	mcs_rwlock_writer_unlock_noirq(&obj->page_hash_locks[hash],
			&mcs_node);
out_nolock:
	if (virt) {
		ihk_mc_free_pages_user(virt, npages);
	}
	if (args) {
		kfree(args);
	}
	dkprintf("fileobj_get_page(%p,%lx,%x,%p): %d %lx\n",
			obj, off, p2align, physp, error, phys);
	return error;
}

static int fileobj_flush_page(struct memobj *memobj, uintptr_t phys,
		size_t pgsize)
{
	struct fileobj *obj = to_fileobj(memobj);
	struct page *page;
	ihk_mc_user_context_t ctx;
	ssize_t ss;

	if (to_memobj(obj)->flags & MF_ZEROFILL) {
		return 0;
	}

	if (memobj->flags |= MF_HOST_RELEASED) {
		return 0;
	}

	page = phys_to_page(phys);
	if (!page) {
		kprintf("%s: warning: tried to flush non-existing page for phys addr: 0x%lx\n", 
			__FUNCTION__, phys);
		return 0;
	}
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

static int fileobj_invalidate_page(struct memobj *memobj, uintptr_t phys,
		size_t pgsize)
{
	dkprintf("fileobj_invalidate_page(%p,%#lx,%#lx)\n",
			memobj, phys, pgsize);

	/* TODO: keep track of reverse mappings so that invalidation
	 * can be performed */
	kprintf("%s: WARNING: file mapping invalidation not supported\n",
		__FUNCTION__);
	return 0;
}

static int fileobj_lookup_page(struct memobj *memobj, off_t off,
		int p2align, uintptr_t *physp, unsigned long *pflag)
{
	struct fileobj *obj = to_fileobj(memobj);
	int error = -1;
	struct page *page;
	struct mcs_rwlock_node mcs_node;
	int hash = (off >> PAGE_SHIFT) & FILEOBJ_PAGE_HASH_MASK;

	dkprintf("fileobj_lookup_page(%p,%lx,%x,%p)\n", obj, off, p2align, physp);

	if (p2align != PAGE_P2ALIGN) {
		return -ENOMEM;
	}

	mcs_rwlock_reader_lock_noirq(&obj->page_hash_locks[hash],
			&mcs_node);

	page = __fileobj_page_hash_lookup(obj, hash, off);
	if (!page) {
		goto out;
	}

	*physp = page_to_phys(page);
	error = 0;

out:
	mcs_rwlock_reader_unlock_noirq(&obj->page_hash_locks[hash],
			&mcs_node);

	dkprintf("fileobj_lookup_page(%p,%lx,%x,%p): %d \n",
			obj, off, p2align, physp, error);
	return error;
}

