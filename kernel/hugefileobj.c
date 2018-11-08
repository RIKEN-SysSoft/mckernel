#include <memobj.h>
#include <ihk/mm.h>
#include <kmsg.h>
#include <kmalloc.h>
#include <string.h>
#include <debug.h>

#if DEBUG_HUGEFILEOBJ
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

struct hugefilechunk {
	struct list_head list;
	off_t pgoff;
	int npages;
	void *mem;
};

struct hugefileobj {
	struct memobj memobj;
	size_t pgsize;
	uintptr_t handle;
	unsigned int pgshift;
	struct list_head chunk_list;
	ihk_spinlock_t chunk_lock;
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
	struct hugefilechunk *chunk;
	off_t pgoff;

	if (p2align != obj->pgshift - PTL1_SHIFT) {
		kprintf("%s: p2align %d but expected %d\n",
			__func__, p2align, obj->pgshift - PTL1_SHIFT);
		return -ENOMEM;
	}

	pgoff = off >> obj->pgshift;
	ihk_mc_spinlock_lock_noirq(&obj->chunk_lock);
	list_for_each_entry(chunk, &obj->chunk_list, list) {
		if (pgoff >= chunk->pgoff + chunk->npages)
			continue;
		if (pgoff >= chunk->pgoff)
			break;
		kprintf("%s: no segment found for pgoff %lx (obj %p)\n",
			__func__, pgoff, obj);
		chunk = NULL;
		break;
	}
	ihk_mc_spinlock_unlock_noirq(&obj->chunk_lock);
	if (!chunk)
		return -EIO;

	*physp = virt_to_phys(chunk->mem + (off - chunk->pgoff * PAGE_SIZE));

	return 0;
}

static void hugefileobj_free(struct memobj *memobj)
{
	struct hugefileobj *obj = to_hugefileobj(memobj);
	struct hugefilechunk *chunk, *next;

	dkprintf("Destroying hugefileobj %p\n", memobj);

	ihk_mc_spinlock_lock_noirq(&hugefileobj_list_lock);
	list_del(&obj->obj_list);
	ihk_mc_spinlock_unlock_noirq(&hugefileobj_list_lock);

	kfree(memobj->path);
	/* don't bother with chunk_lock, memobj refcounting makes this safe */
	list_for_each_entry_safe(chunk, next, &obj->chunk_list, list) {
		ihk_mc_free_pages_user(chunk->mem, chunk->npages);
		kfree(chunk);
	}
	kfree(memobj);
}

struct memobj_ops hugefileobj_ops = {
	.free = hugefileobj_free,
	.get_page = hugefileobj_get_page,

};

void hugefileobj_cleanup(void)
{
	struct hugefileobj *obj;
	int refcnt;

	while (true) {
		ihk_mc_spinlock_lock_noirq(&hugefileobj_list_lock);
		if (list_empty(&hugefileobj_list)) {
			ihk_mc_spinlock_unlock_noirq(&hugefileobj_list_lock);
			break;
		}
		obj = list_first_entry(&hugefileobj_list, struct hugefileobj,
				       obj_list);
		ihk_mc_spinlock_unlock_noirq(&hugefileobj_list_lock);

		if ((refcnt = memobj_unref(to_memobj(obj))) != 0) {
			kprintf("%s: obj %p had refcnt %ld > 1, destroying anyway\n",
				__func__, obj, refcnt + 1);
			hugefileobj_free(to_memobj(obj));
		}
	}
}

int hugefileobj_pre_create(struct pager_create_result *result,
			   struct memobj **objp, int *maxprotp)
{
	struct hugefileobj *obj;

	ihk_mc_spinlock_lock_noirq(&hugefileobj_list_lock);
	obj = hugefileobj_lookup(result->handle);
	if (obj)
		goto out_unlock;

	obj = kmalloc(sizeof(*obj), IHK_MC_AP_NOWAIT);
	if (!obj)
		return -ENOMEM;

	obj->handle = result->handle;
	obj->pgsize = result->size;
	obj->pgshift = 0;
	INIT_LIST_HEAD(&obj->chunk_list);
	ihk_mc_spinlock_init(&obj->chunk_lock);
	obj->memobj.flags = result->flags;
	obj->memobj.status = MEMOBJ_TO_BE_PREFETCHED;
	obj->memobj.ops = &hugefileobj_ops;
	/* keep mapping around when process is gone */
	ihk_atomic_set(&obj->memobj.refcnt, 2);
	if (result->path[0]) {
		obj->memobj.path = kmalloc(PATH_MAX, IHK_MC_AP_NOWAIT);
		if (!obj->memobj.path) {
			kfree(obj);
			return -ENOMEM;
		}
		strncpy(obj->memobj.path, result->path, PATH_MAX);
	}

	list_add(&obj->obj_list, &hugefileobj_list);
out_unlock:
	ihk_mc_spinlock_unlock_noirq(&hugefileobj_list_lock);

	*maxprotp = result->maxprot;
	*objp = to_memobj(obj);

	return 0;
}

int hugefileobj_create(struct memobj *memobj, size_t len, off_t off,
		       int *pgshiftp, uintptr_t virt_addr)
{
	struct hugefileobj *obj = to_hugefileobj(memobj);
	struct hugefilechunk *chunk = NULL, *old_chunk = NULL;
	int p2align;
	unsigned int pgshift;
	int npages, npages_left;
	void *v;
	off_t pgoff, next_pgoff;
	int error;

	error = arch_get_smaller_page_size(NULL, obj->pgsize + 1, NULL,
					   &p2align);
	if (error)
		return error;
	pgshift = p2align + PTL1_SHIFT;
	if (1 << pgshift != obj->pgsize) {
		dkprintf("invalid hugefileobj pagesize: %d\n",
			obj->pgsize);
		return -EINVAL;
	}

	if (len & ((1 << pgshift) - 1)) {
		dkprintf("invalid hugetlbfs mmap size %d (pagesize %d)\n",
			len, 1 << pgshift);
		obj->pgshift = 0;
		return -EINVAL;
	}
	if (off & ((1 << pgshift) - 1)) {
		dkprintf("invalid hugetlbfs mmap offset %d (pagesize %d)\n",
			off, 1 << pgshift);
		obj->pgshift = 0;
		return -EINVAL;
	}


	ihk_mc_spinlock_lock_noirq(&obj->chunk_lock);
	if (obj->pgshift && obj->pgshift != pgshift) {
		kprintf("pgshift changed between two calls on same inode?! had %d now %d\n",
			obj->pgshift, pgshift);
		ihk_mc_spinlock_unlock_noirq(&obj->chunk_lock);
		return -EINVAL;
	}
	obj->pgshift = pgshift;

	/* Prealloc upfront, we need to fail here if not enough memory. */
	if (!list_empty(&obj->chunk_list))
		old_chunk = list_first_entry(&obj->chunk_list,
					     struct hugefilechunk, list);
	pgoff = off >> PAGE_SHIFT;
	npages_left = len >> PAGE_SHIFT;
	npages = npages_left;
	while (npages_left) {
		while (old_chunk &&
				pgoff >= old_chunk->pgoff + old_chunk->npages) {
			if (list_is_last(&old_chunk->list, &obj->chunk_list)) {
				old_chunk = NULL;
				break;
			}
			old_chunk = list_entry(old_chunk->list.next,
					       struct hugefilechunk, list);
		}
		if (old_chunk) {
			next_pgoff = old_chunk->pgoff + old_chunk->npages;
			if (pgoff >= old_chunk->pgoff && pgoff < next_pgoff) {
				npages_left -= next_pgoff - pgoff;
				pgoff = next_pgoff;
				continue;
			}
		}
		if (!chunk) {
			chunk = kmalloc(sizeof(*chunk), IHK_MC_AP_NOWAIT);
		}
		if (!chunk) {
			kprintf("could not allocate hugefileobj chunk\n");
			return -ENOMEM;
		}
		if (npages > npages_left)
			npages = npages_left;
		v = ihk_mc_alloc_aligned_pages_user(npages, p2align,
				IHK_MC_AP_NOWAIT | IHK_MC_AP_USER, virt_addr);
		if (!v) {
			if (npages == 1) {
				dkprintf("could not allocate more pages wth pgshift %d\n",
					 pgshift);
				kfree(chunk);
				/* caller will cleanup the rest */
				return -ENOMEM;
			}
			/* exponential backoff, try less aggressive? */
			npages /= 2;
			continue;
		}
		memset(v, 0, npages * PAGE_SIZE);
		chunk->npages = npages;
		chunk->mem = v;
		chunk->pgoff = pgoff;
		/* ordered list: insert before next (bigger) element */
		if (old_chunk)
			list_add(&chunk->list, old_chunk->list.prev);
		else
			list_add(&chunk->list, obj->chunk_list.prev);
		pgoff += npages;
		npages_left -= npages;
	}
	obj->memobj.size = len;

	ihk_mc_spinlock_unlock_noirq(&obj->chunk_lock);

	*pgshiftp = pgshift;

	return 0;
}
