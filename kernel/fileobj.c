/* fileobj.c COPYRIGHT FUJITSU LIMITED 2015-2017 */
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
#include <rusage_private.h>
#include <ihk/debug.h>
#include <mman.h>

//#define DEBUG_PRINT_FILEOBJ

#ifdef DEBUG_PRINT_FILEOBJ
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

mcs_lock_t fileobj_list_lock;
static LIST_HEAD(fileobj_list);

#define FILEOBJ_PAGE_HASH_SHIFT 9
#define FILEOBJ_PAGE_HASH_SIZE (1 << FILEOBJ_PAGE_HASH_SHIFT)
#define FILEOBJ_PAGE_HASH_MASK (FILEOBJ_PAGE_HASH_SIZE - 1)

struct fileobj {
	struct memobj memobj;		/* must be first */
	uint64_t sref;
	uintptr_t handle;
	struct list_head list;
	struct list_head page_hash[FILEOBJ_PAGE_HASH_SIZE];
	mcs_lock_t page_hash_locks[FILEOBJ_PAGE_HASH_SIZE];
};

static memobj_free_func_t fileobj_free;
static memobj_get_page_func_t fileobj_get_page;
static memobj_flush_page_func_t fileobj_flush_page;
static memobj_invalidate_page_func_t fileobj_invalidate_page;
static memobj_lookup_page_func_t fileobj_lookup_page;

static struct memobj_ops fileobj_ops = {
	.free =	&fileobj_free,
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
		mcs_lock_init(&obj->page_hash_locks[i]);
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
	struct fileobj *p;

	list_for_each_entry(p, &fileobj_list, list) {
		if (p->handle == handle) {
			/* for the interval between last put and fileobj_free
			 * taking list_lock
			 */
			if (memobj_ref(&p->memobj) <= 1) {
				ihk_atomic_dec(&p->memobj.refcnt);
				continue;
			}
			return p;
		}
	}

	return NULL;
}

/***********************************************************************
 * fileobj
 */
int fileobj_create(int fd, struct memobj **objp, int *maxprotp, int flags,
		   uintptr_t virt_addr)
{
	ihk_mc_user_context_t ctx;
	struct pager_create_result result __attribute__((aligned(64)));	
	int error;
	struct fileobj *newobj  = NULL;
	struct fileobj *obj;
	struct mcs_lock_node node;

	dkprintf("%s(%d)\n", __func__, fd);

	ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_CREATE;
	ihk_mc_syscall_arg1(&ctx) = fd;
	ihk_mc_syscall_arg2(&ctx) = virt_to_phys(&result);
	memset(&result, 0, sizeof(result));

	error = syscall_generic_forwarding(__NR_mmap, &ctx);

	if (error) {
		/* -ESRCH doesn't mean an error but requesting a fall
		 * back to treat the file as a device file
		 */
		if (error != -ESRCH) {
			kprintf("%s(%d):create failed. %d\n",
				__func__, fd, error);
		}
		goto out;
	}

	if (result.flags & MF_HUGETLBFS) {
		return hugefileobj_pre_create(&result, objp, maxprotp);
	}

	mcs_lock_lock(&fileobj_list_lock, &node);
	obj = obj_list_lookup(result.handle);
	if (obj)
		goto found;
	mcs_lock_unlock(&fileobj_list_lock, &node);

	// not found: alloc new object and lookup again
	newobj = kmalloc(sizeof(*newobj), IHK_MC_AP_NOWAIT);
	if (!newobj) {
		error = -ENOMEM;
		kprintf("%s(%d):kmalloc failed. %d\n", __func__, fd, error);
		goto out;
	}
	memset(newobj, 0, sizeof(*newobj));
	newobj->memobj.ops = &fileobj_ops;
	newobj->memobj.flags = MF_HAS_PAGER | MF_REG_FILE |
		((flags & MAP_PRIVATE) ? MF_PRIVATE : 0);
	newobj->handle = result.handle;

	fileobj_page_hash_init(newobj);

	mcs_lock_lock_noirq(&fileobj_list_lock, &node);
	obj = obj_list_lookup(result.handle);
	if (!obj) {
		obj_list_insert(newobj);
		obj = newobj;
		to_memobj(obj)->size = result.size;
		to_memobj(obj)->flags |= result.flags;
		to_memobj(obj)->status = MEMOBJ_READY;
		ihk_atomic_set(&to_memobj(obj)->refcnt, 1);
		obj->sref = 1;
		if (to_memobj(obj)->flags & MF_PREFETCH) {
			to_memobj(obj)->status = MEMOBJ_TO_BE_PREFETCHED;
		}

		if (result.path[0]) {
			newobj->memobj.path = kmalloc(PATH_MAX, IHK_MC_AP_NOWAIT);
			if (!newobj->memobj.path) {
				error = -ENOMEM;
				kprintf("%s: error: allocating path\n", __FUNCTION__);
				mcs_lock_unlock_noirq(&fileobj_list_lock, &node);
				goto out;
			}
			strncpy(newobj->memobj.path, result.path, PATH_MAX);
		}

		dkprintf("%s: %s\n", __FUNCTION__, obj->memobj.path);

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
							PAGE_P2ALIGN, IHK_MC_AP_NOWAIT, node, virt_addr);
					if (!mo->pages[j]) {
						kprintf("%s: ERROR: allocating pages[%d]\n",
								__FUNCTION__, j);
						goto error_cleanup;
					}
					// Track change in memobj->pages[] for MF_PREMAP pages (MPOL_SHM_PREMAP case)
					dkprintf("%lx+,%s: MF_PREMAP&&MPOL_SHM_PREMAP,memory_stat_rss_add,phys=%lx,size=%ld,pgsize=%ld\n", virt_to_phys(mo->pages[j]), __FUNCTION__, virt_to_phys(mo->pages[j]), PAGE_SIZE, PAGE_SIZE);
					rusage_memory_stat_mapped_file_add(PAGE_SIZE, PAGE_SIZE);

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
		dkprintf("%s: new obj 0x%lx %s\n",
			__FUNCTION__,
			obj,
			to_memobj(obj)->flags & MF_ZEROFILL ? "zerofill" : "");
	}
	else {
found:
		obj->sref++;
		dkprintf("%s: existing obj 0x%lx, %s\n",
			__FUNCTION__,
			obj,
			to_memobj(obj)->flags & MF_ZEROFILL ? "zerofill" : "");
	}

	mcs_lock_unlock_noirq(&fileobj_list_lock, &node);

	error = 0;
	*objp = to_memobj(obj);
	*maxprotp = result.maxprot;

out:
	if (newobj) {
		kfree(newobj);
	}
	dkprintf("%s(%d):%d %p %x\n", __func__, fd, error, *objp, *maxprotp);
	return error;
}

static void fileobj_free(struct memobj *memobj)
{
	struct fileobj *obj = to_fileobj(memobj);
	struct mcs_lock_node node;
	int error;
	ihk_mc_user_context_t ctx;


	dkprintf("%s: free obj 0x%lx, %s\n", __func__,
		 obj, to_memobj(obj)->flags & MF_ZEROFILL ? "zerofill" : "");

	mcs_lock_lock_noirq(&fileobj_list_lock, &node);
	obj_list_remove(obj);
	mcs_lock_unlock_noirq(&fileobj_list_lock, &node);

	/* zap page_list */
	for (;;) {
		struct page *page;
		void *page_va;
		uintptr_t phys;

		page = fileobj_page_hash_first(obj);
		if (!page) {
			break;
		}
		__fileobj_page_hash_remove(page);
		phys = page_to_phys(page);
		page_va = phys_to_virt(phys);
		/* Count must be one because set to one on the first
		 * get_page() invoking fileobj_do_pageio and incremented by
		 * the second get_page() reaping the pageio and decremented
		 * by clear_range().
		 */
		if (ihk_atomic_read(&page->count) != 1) {
			kprintf("%s: WARNING: page count is %d for phys 0x%lx is invalid, flags: 0x%lx\n",
				__func__, ihk_atomic_read(&page->count),
				page->phys, to_memobj(obj)->flags);
		}
		else if (page_unmap(page)) {
			ihk_mc_free_pages_user(page_va, 1);
			/* Track change in page->count for !MF_PREMAP pages.
			 * It is decremented here or in clear_range()
			 */
			dkprintf("%lx-,%s: calling memory_stat_rss_sub(),phys=%lx,size=%ld,pgsize=%ld\n",
				 phys, __func__, phys, PAGE_SIZE, PAGE_SIZE);
			rusage_memory_stat_mapped_file_sub(PAGE_SIZE,
							   PAGE_SIZE);
			kfree(page);
		}
	}

	/* Pre-mapped zerofilled? */
	if (to_memobj(obj)->flags & MF_PREMAP &&
			to_memobj(obj)->flags & MF_ZEROFILL) {
		int i;

		for (i = 0; i < to_memobj(obj)->nr_pages; ++i) {
			if (to_memobj(obj)->pages[i]) {
				dkprintf("%s: pages[i]=%p\n", __func__, i,
					 to_memobj(obj)->pages[i]);
				// Track change in fileobj->pages[] for MF_PREMAP pages
				// Note that page_unmap() isn't called for MF_PREMAP in
				// free_process_memory_range() --> ihk_mc_pt_free_range()
				dkprintf("%lx-,%s: memory_stat_rss_sub,phys=%lx,size=%ld,pgsize=%ld\n",
					 virt_to_phys(to_memobj(obj)->pages[i]),
					 __func__,
					 virt_to_phys(to_memobj(obj)->pages[i]),
					 PAGE_SIZE, PAGE_SIZE);
				rusage_memory_stat_mapped_file_sub(PAGE_SIZE,
								   PAGE_SIZE);
				ihk_mc_free_pages_user(to_memobj(obj)->pages[i],
						       1);
			}
		}

		kfree(to_memobj(obj)->pages);
	}

	if (to_memobj(obj)->path) {
		dkprintf("%s: %s\n", __func__, to_memobj(obj)->path);
		kfree(to_memobj(obj)->path);
	}

	/* linux side
	 * sref is necessary because handle is used as key, so there could
	 * be a new mckernel pager with the same handle being created as
	 * this one is being destroyed
	 */
	ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_RELEASE;
	ihk_mc_syscall_arg1(&ctx) = obj->handle;
	ihk_mc_syscall_arg2(&ctx) = obj->sref;

	error = syscall_generic_forwarding(__NR_mmap, &ctx);
	if (error) {
		dkprintf("%s(%p %lx): free failed. %d\n", __func__,
			obj, obj->handle, error);
		/* through */
	}

	dkprintf("%s(%p %lx):free\n", __func__, obj, obj->handle);
	kfree(obj);
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
	struct mcs_lock_node mcs_node;
	int hash = (off >> PAGE_SHIFT) & FILEOBJ_PAGE_HASH_MASK;	
	int attempts = 0;

	mcs_lock_lock(&obj->page_hash_locks[hash], &mcs_node);
	page = __fileobj_page_hash_lookup(obj, hash, off);
	if (!page) {
		goto out;
	}

	while (page->mode == PM_PAGEIO) {
		PROCESS_BACKLOG(cpu_local_var(current)->proc);
		mcs_lock_unlock(&obj->page_hash_locks[hash], &mcs_node);
		++attempts;
		if (attempts > 49) {
			dkprintf("%s: %s:%lu PM_PAGEIO loop %d -> schedule()\n",
				__func__, to_memobj(obj)->path, off, attempts);
			schedule();
		}
		cpu_pause();
		mcs_lock_lock(&obj->page_hash_locks[hash], &mcs_node);
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
			mcs_lock_unlock(&obj->page_hash_locks[hash], &mcs_node);

			ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_READ;
			ihk_mc_syscall_arg1(&ctx) = obj->handle;
			ihk_mc_syscall_arg2(&ctx) = off;
			ihk_mc_syscall_arg3(&ctx) = pgsize;
			ihk_mc_syscall_arg4(&ctx) = page_to_phys(page);

			dkprintf("%s: __NR_mmap for handle 0x%lx\n",
					__FUNCTION__, obj->handle);
			ss = syscall_generic_forwarding(__NR_mmap, &ctx);

			mcs_lock_lock(&obj->page_hash_locks[hash], &mcs_node);
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
	mcs_lock_unlock(&obj->page_hash_locks[hash], &mcs_node);
	memobj_unref(&obj->memobj);		/* got fileobj_get_page() */
	kfree(args0);
	dkprintf("fileobj_do_pageio(%p,%lx,%lx):\n", obj, off, pgsize);
	return;
}

static int fileobj_get_page(struct memobj *memobj, off_t off,
               int p2align, uintptr_t *physp, unsigned long *pflag, uintptr_t virt_addr)
{
	struct thread *proc = cpu_local_var(current);
	struct fileobj *obj = to_fileobj(memobj);
	int error = -1;
	void *virt = NULL;
	int npages;
	uintptr_t phys = -1;
	struct page *page;
	struct pageio_args *args = NULL;
	struct mcs_lock_node mcs_node;
	int hash = (off >> PAGE_SHIFT) & FILEOBJ_PAGE_HASH_MASK;	

	dkprintf("fileobj_get_page(%p,%lx,%x,%x,%p)\n", obj, off, p2align, virt_addr, physp);
	if (p2align != PAGE_P2ALIGN) {
		return -ENOMEM;
	}

#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_page_fault_file, PAGE_SIZE);
#endif // PROFILE_ENABLE

	if (memobj->flags & MF_PREMAP &&
			memobj->flags & MF_ZEROFILL) {
		int page_ind = off >> PAGE_SHIFT;

		if (!memobj->pages[page_ind]) {
			virt = ihk_mc_alloc_pages_user(1, IHK_MC_AP_NOWAIT | IHK_MC_AP_USER, virt_addr);

			if (!virt) {
				error = -ENOMEM;
				kprintf("fileobj_get_page(%p,%lx,%x,%x,%x,%p):"
						"alloc failed. %d\n",
						obj, off, p2align, virt_addr, physp,
						error);
				goto out_nolock;
			}

			/* Update the array but see if someone did it already and use
			 * that if so */
			if (cmpxchg(&memobj->pages[page_ind], NULL, virt) != NULL) {
				ihk_mc_free_pages_user(virt, 1);
			}
			else {
				dkprintf("%s: MF_ZEROFILL: off: %lu -> 0x%lx allocated\n",
						__FUNCTION__, off, virt_to_phys(virt));
				// Track change in memobj->pages[] for MF_PREMAP pages (!MPOL_SHM_PREMAP case)
				dkprintf("%lx+,%s: MF_PREMAP&&!MPOL_SHM_PREMAP,memory_stat_rss_add,phys=%lx,size=%ld,pgsize=%ld\n", virt_to_phys(virt), __FUNCTION__, virt_to_phys(virt), PAGE_SIZE, PAGE_SIZE);
				rusage_memory_stat_mapped_file_add(PAGE_SIZE, PAGE_SIZE);
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

	mcs_lock_lock(&obj->page_hash_locks[hash], &mcs_node);
	page = __fileobj_page_hash_lookup(obj, hash, off);
	if (!page || (page->mode == PM_WILL_PAGEIO)
			|| (page->mode == PM_PAGEIO)) {
		args = kmalloc(sizeof(*args), IHK_MC_AP_NOWAIT);
		if (!args) {
			error = -ENOMEM;
			kprintf("fileobj_get_page(%p,%lx,%x,%x,%p):"
					"kmalloc failed. %d\n",
					obj, off, p2align, virt_addr, physp, error);
			goto out;
		}

		if (!page) {
			npages = 1 << p2align;

			virt = ihk_mc_alloc_pages_user(npages, (IHK_MC_AP_NOWAIT |
					((to_memobj(obj)->flags & MF_ZEROFILL) ?
						IHK_MC_AP_USER : 0)),
					virt_addr);
			if (!virt) {
				error = -ENOMEM;
				kprintf("fileobj_get_page(%p,%lx,%x,%x,%p):"
						"alloc failed. %d\n",
						obj, off, p2align, virt_addr, physp,
						error);
				goto out;
			}
			phys = virt_to_phys(virt);
			page = phys_to_page_insert_hash(phys);
			// Track change in page->count for !MF_PREMAP pages. 
			// Add when setting the PTE for a page with count of one in ihk_mc_pt_set_range().
			dkprintf("%s: phys_to_page_insert_hash(),phys=%lx,virt=%lx,size=%lx,pgsize=%lx\n", __FUNCTION__, phys, virt, npages * PAGE_SIZE, PAGE_SIZE);

			if (page->mode != PM_NONE) {
				panic("fileobj_get_page:invalid new page");
			}
			page->offset = off;
			ihk_atomic_set(&page->count, 1);
			ihk_atomic64_set(&page->mapped, 0);
			__fileobj_page_hash_insert(obj, page, hash);
			page->mode = PM_WILL_PAGEIO;
		}

		memobj_ref(&obj->memobj);

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
		dkprintf("%s: PM_DONE_PAGEIO-->PM_MAPPED,obj=%lx,off=%lx,phys=%lx\n", __FUNCTION__, obj, off, page_to_phys(page));
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
	dkprintf("%s: mode=%d,count=%d,obj=%lx,off=%lx,phys=%lx\n", __FUNCTION__, page->mode, page->count, obj, off, page_to_phys(page));

	error = 0;
	*physp = page_to_phys(page);
	virt = NULL;
out:
	mcs_lock_unlock(&obj->page_hash_locks[hash], &mcs_node);
out_nolock:
	if (virt) {
		ihk_mc_free_pages_user(virt, npages);
	}
	if (args) {
		kfree(args);
	}
	dkprintf("fileobj_get_page(%p,%lx,%x,%x,%p): %d %lx\n",
			obj, off, p2align, virt_addr, physp, error, phys);
	return error;
}

static int fileobj_flush_page(struct memobj *memobj, uintptr_t phys,
		size_t pgsize)
{
	struct fileobj *obj = to_fileobj(memobj);
	struct page *page;
	ihk_mc_user_context_t ctx;
	ssize_t ss;

	dkprintf("%s: phys=%lx,to_memobj(obj)->flags=%x,memobj->flags=%x,page=%p\n", __FUNCTION__, phys, to_memobj(obj)->flags, memobj->flags, phys_to_page(phys));
	if (to_memobj(obj)->flags & MF_ZEROFILL) {
		return 0;
	}

	page = phys_to_page(phys);
	if (!page) {
		kprintf("%s: warning: tried to flush non-existing page for phys addr: 0x%lx\n", 
			__FUNCTION__, phys);
		return 0;
	}

	ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_WRITE;
	ihk_mc_syscall_arg1(&ctx) = obj->handle;
	ihk_mc_syscall_arg2(&ctx) = page->offset;
	ihk_mc_syscall_arg3(&ctx) = pgsize;
	ihk_mc_syscall_arg4(&ctx) = phys;

	dkprintf("%s: syscall_generic_forwarding\n", __FUNCTION__);
	ss = syscall_generic_forwarding(__NR_mmap, &ctx);
	if (ss != pgsize) {
		dkprintf("fileobj_flush_page(%p,%lx,%lx): %ld (%lx)\n",
				memobj, phys, pgsize, ss, ss);
		/* through */
	}

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
	struct mcs_lock_node mcs_node;
	int hash = (off >> PAGE_SHIFT) & FILEOBJ_PAGE_HASH_MASK;

	dkprintf("fileobj_lookup_page(%p,%lx,%x,%p)\n", obj, off, p2align, physp);

	if (p2align != PAGE_P2ALIGN) {
		return -ENOMEM;
	}

	mcs_lock_lock(&obj->page_hash_locks[hash], &mcs_node);

	page = __fileobj_page_hash_lookup(obj, hash, off);
	if (!page) {
		goto out;
	}

	*physp = page_to_phys(page);
	error = 0;

out:
	mcs_lock_unlock(&obj->page_hash_locks[hash], &mcs_node);

	dkprintf("fileobj_lookup_page(%p,%lx,%x,%p): %d \n",
			obj, off, p2align, physp, error);
	return error;
}

