#include <memobj.h>
#include <ihk/mm.h>
#include <kmsg.h>
#include <kmalloc.h>
#include <string.h>
#include <ihk/debug.h>

#if DEBUG_HUGEFILEOBJ
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

struct hugefileobj {
	struct memobj memobj;
	size_t pgsize;
	uintptr_t handle;
	unsigned int pgshift;
	size_t nr_pages;
	void **pages;
	ihk_spinlock_t lock;
	struct list_head obj_list;
};

static ihk_spinlock_t hugefileobj_list_lock;
static LIST_HEAD(hugefileobj_list);

static struct hugefileobj *to_hugefileobj(struct memobj *memobj)
{
	return (struct hugefileobj *)memobj;
}

static struct memobj *to_memobj(struct hugefileobj *obj)
{
	return &obj->memobj;
}

static struct hugefileobj *hugefileobj_lookup(uintptr_t handle)
{
	struct hugefileobj *p;

	list_for_each_entry(p, &hugefileobj_list, obj_list) {
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

static int hugefileobj_get_page(struct memobj *memobj, off_t off,
				int p2align, uintptr_t *physp,
				unsigned long *pflag, uintptr_t virt_addr)
{
	struct hugefileobj *obj = to_hugefileobj(memobj);
	off_t pgind;
	int ret = 0;
	int npages;

	if (p2align != obj->pgshift - PTL1_SHIFT) {
		kprintf("%s: p2align %d but expected %d\n",
			__func__, p2align, obj->pgshift - PTL1_SHIFT);
		return -ENOMEM;
	}

	pgind = off >> obj->pgshift;
	npages = obj->pgsize >> PAGE_SHIFT;
	ihk_mc_spinlock_lock_noirq(&obj->lock);
	if (!obj->pages[pgind]) {
		obj->pages[pgind] = ihk_mc_alloc_aligned_pages_user(npages,
				p2align, IHK_MC_AP_NOWAIT | IHK_MC_AP_USER,
				virt_addr);
		if (!obj->pages[pgind]) {
			kprintf("%s: error: could not allocate page for off: "
				"%lu, page size: %lu\n", __func__, off,
				obj->pgsize);
			ret = -EIO;
			goto out;
		}

		memset(obj->pages[pgind], 0, obj->pgsize);
#ifndef ENABLE_FUGAKU_HACKS
		dkprintf("%s: obj: 0x%lx, allocated page for off: %lu"
#else
		kprintf("%s: obj: 0x%lx, allocated page for off: %lu"
#endif
				" (ind: %d), page size: %lu\n",
				__func__, obj, off, pgind, obj->pgsize);
	}

	*physp = virt_to_phys(obj->pages[pgind]);

out:
	ihk_mc_spinlock_unlock_noirq(&obj->lock);

	return ret;
}

static void __hugefileobj_free(struct memobj *memobj)
{
	struct hugefileobj *obj = to_hugefileobj(memobj);

	ihk_mc_spinlock_lock_noirq(&obj->lock);
	kfree(memobj->path);
	memobj->path = NULL;

	if (obj->pages) {
		int i;

		for (i = 0; i < obj->nr_pages; ++i) {
			if (obj->pages[i]) {
				ihk_mc_free_pages_user(obj->pages[i],
						obj->pgsize >> PAGE_SHIFT);
				dkprintf("%s: obj: 0x%lx, freed page at "
					 "ind: %d\n", __func__, obj, i);
			}
		}

		kfree(obj->pages);
	}

	ihk_mc_spinlock_unlock_noirq(&obj->lock);
	kfree(obj);
}

static void hugefileobj_free(struct memobj *memobj)
{
	struct hugefileobj *obj = to_hugefileobj(memobj);

	ihk_mc_spinlock_lock_noirq(&hugefileobj_list_lock);
	list_del(&obj->obj_list);
	ihk_mc_spinlock_unlock_noirq(&hugefileobj_list_lock);

	__hugefileobj_free(memobj);
}

struct memobj_ops hugefileobj_ops = {
	.free = hugefileobj_free,
	.get_page = hugefileobj_get_page,
};

void hugefileobj_cleanup(void)
{
	struct hugefileobj *obj;

	while (true) {
		ihk_mc_spinlock_lock_noirq(&hugefileobj_list_lock);
		if (list_empty(&hugefileobj_list)) {
			ihk_mc_spinlock_unlock_noirq(&hugefileobj_list_lock);
			break;
		}
		obj = list_first_entry(&hugefileobj_list, struct hugefileobj,
				       obj_list);
		list_del(&obj->obj_list);
		ihk_mc_spinlock_unlock_noirq(&hugefileobj_list_lock);

		__hugefileobj_free(to_memobj(obj));
	}
}

int hugefileobj_pre_create(struct pager_create_result *result,
			   struct memobj **objp, int *maxprotp)
{
	struct hugefileobj *obj;
	int ret = 0;

	ihk_mc_spinlock_lock_noirq(&hugefileobj_list_lock);
	obj = hugefileobj_lookup(result->handle);
	if (obj) {
		dkprintf("%s: found obj: 0x%lx %s (ino: %lu)\n",
			 __func__,
			 obj->memobj,
			 obj->memobj.path ? obj->memobj.path : "(unknown)",
			 obj->handle);

		*maxprotp = result->maxprot;
		*objp = to_memobj(obj);
		ret = 0;

		goto out_unlock;
	}

	obj = kmalloc(sizeof(*obj), IHK_MC_AP_NOWAIT);
	if (!obj) {
		kprintf("%s: error: allocating hugefileobj\n", __func__);
		ret = -ENOMEM;
		goto out_unlock;
	}

	obj->handle = result->handle;
	obj->pgsize = (1UL << result->pgshift);
	obj->pgshift = result->pgshift;
	obj->pages = NULL;
	obj->nr_pages = 0;
	ihk_mc_spinlock_init(&obj->lock);
	obj->memobj.flags = result->flags;
	obj->memobj.status = MEMOBJ_READY;
	obj->memobj.ops = &hugefileobj_ops;

	/* keep mapping around when process is gone */
	ihk_atomic_set(&obj->memobj.refcnt, 2);

	if (result->path[0]) {
		obj->memobj.path = kmalloc(PATH_MAX, IHK_MC_AP_NOWAIT);
		if (!obj->memobj.path) {
			kprintf("%s: error: allocating path\n", __func__);
			kfree(obj);
			ret = -ENOMEM;
			goto out_unlock;
		}
		strncpy(obj->memobj.path, result->path, PATH_MAX);
	}

	list_add(&obj->obj_list, &hugefileobj_list);
	dkprintf("%s: created obj: 0x%lx %s (ino: %lu)\n",
		__func__,
		obj->memobj,
		obj->memobj.path ? obj->memobj.path : "(unknown)",
		obj->handle);

	*maxprotp = result->maxprot;
	*objp = to_memobj(obj);
	ret = 0;

out_unlock:
	ihk_mc_spinlock_unlock_noirq(&hugefileobj_list_lock);

	return ret;
}

int hugefileobj_create(struct memobj *memobj, size_t len, off_t off,
		       int *pgshiftp, uintptr_t virt_addr)
{
	struct hugefileobj *obj = to_hugefileobj(memobj);
	int nr_pages;
	int ret;

	dkprintf("%s: obj: 0x%lx, VA: 0x%lx, path: \"%s\","
			" len: %lu, off: %lu, pgshift: %d\n",
			__func__,
			obj,
			virt_addr,
			memobj->path ? memobj->path : "(unknown)",
			len,
			off,
			obj->pgshift);

	nr_pages = (off + len) >> obj->pgshift;

	ihk_mc_spinlock_lock_noirq(&obj->lock);
	/* Expand or allocate if needed */
	if (obj->nr_pages < nr_pages) {
		void **pages = kmalloc(nr_pages * sizeof(void *),
				       IHK_MC_AP_NOWAIT);

		if (!pages) {
			ret = -ENOMEM;
			goto out;
		}

		if (obj->nr_pages) {
			memcpy(pages, obj->pages,
			       obj->nr_pages * sizeof(void *));
		}

		memset(pages + (obj->nr_pages * sizeof(void *)), 0,
				(nr_pages - obj->nr_pages) * sizeof(void *));

		if (obj->nr_pages) {
			kfree(obj->pages);
		}

		obj->nr_pages = nr_pages;
		obj->pages = pages;
#ifndef ENABLE_FUGAKU_HACKS
		dkprintf("%s: obj: 0x%lx, VA: 0x%lx, page array allocated"
#else
		kprintf("%s: obj: 0x%lx, VA: 0x%lx, page array allocated"
#endif
				" for %d pages, pagesize: %lu\n",
				__func__,
				obj,
				virt_addr,
				nr_pages,
				obj->pgsize);

#ifdef ENABLE_FUGAKU_HACKS
		if (!hugetlbfs_on_demand) {
			int pgind;
			int npages;

#ifndef ENABLE_FUGAKU_HACKS
			for (pgind = 0; pgind < obj->nr_pages; ++pgind) {
#else
			/* Map in only the last 8 pages */
			for (pgind = ((obj->nr_pages > 8) ? (obj->nr_pages - 8) : 0);
					pgind < obj->nr_pages; ++pgind) {
#endif
				if (obj->pages[pgind]) {
					continue;
				}

				npages = obj->pgsize >> PAGE_SHIFT;
				obj->pages[pgind] = ihk_mc_alloc_aligned_pages_user(npages,
						obj->pgshift - PTL1_SHIFT,
						IHK_MC_AP_NOWAIT | IHK_MC_AP_USER, 0);
				if (!obj->pages[pgind]) {
					kprintf("%s: error: could not allocate page for off: %lu"
							", page size: %lu\n", __func__, off, obj->pgsize);
					continue;
				}

				memset(obj->pages[pgind], 0, obj->pgsize);
				dkprintf("%s: obj: 0x%lx, pre-allocated page for off: %lu"
						" (ind: %d), page size: %lu\n",
						__func__, obj, off, pgind, obj->pgsize);
			}
		}
#endif
	}

	obj->memobj.size = len;
	*pgshiftp = obj->pgshift;
	ret = 0;

out:
	ihk_mc_spinlock_unlock_noirq(&obj->lock);

	return ret;
}
