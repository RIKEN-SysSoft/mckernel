#include <ihk/atomic.h>
#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <ihk/lock.h>
#include <ihk/mm.h>
#include <ihk/types.h>
#include <errno.h>
#include <kmalloc.h>
#include <kmsg.h>
#include <memobj.h>
#include <memory.h>
#include <page.h>
#include <pager.h>
#include <string.h>
#include <syscall.h>

#define	dkprintf(...)	kprintf(__VA_ARGS__)
#define	ekprintf(...)	kprintf(__VA_ARGS__)

static ihk_spinlock_t memobj_list_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(memobj_list);

int memobj_create(int fd, int flags, int prot, struct memobj **objpp, int *maxprotp)
{
	ihk_mc_user_context_t ctx;
	struct pager_create_result result;
	int error;
	struct memobj *memobj  = NULL;
	struct memobj *obj;

	kprintf("memobj_create(%d,%x,%x)\n", fd, flags, prot);
	memobj = kmalloc(sizeof(*memobj), IHK_MC_AP_NOWAIT);
	if (memobj == NULL) {
		error = -ENOMEM;
		kprintf("memobj_create(%d,%x,%x):kmalloc failed. %d\n", fd, flags, prot, error);
		goto out;
	}

retry:
	ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_CREATE;
	ihk_mc_syscall_arg1(&ctx) = fd;
	ihk_mc_syscall_arg2(&ctx) = flags;
	ihk_mc_syscall_arg3(&ctx) = prot;
	ihk_mc_syscall_arg4(&ctx) = virt_to_phys(&result);

	error = syscall_generic_forwarding(__NR_mmap, &ctx);
	if (error == -EALREADY) {
		kprintf("memobj_create(%d,%x,%x,%p):create failed. %d\n",
				fd, flags, prot, objpp, error);
		ihk_mc_spinlock_lock_noirq(&memobj_list_lock);
		list_for_each_entry(obj, &memobj_list, list) {
			if (obj->handle == result.handle) {
				memobj_ref(obj);
				ihk_mc_spinlock_unlock_noirq(&memobj_list_lock);
				kfree(memobj);
				memobj = obj;
				goto found;
			}
		}
		ihk_mc_spinlock_unlock_noirq(&memobj_list_lock);
		goto retry;
	}
	else if (error) {
		kprintf("memobj_create(%d,%x,%x,%p):create failed. %d\n",
				fd, flags, prot, objpp, error);
		goto out;
	}

	memset(memobj, 0, sizeof(*memobj));
	ihk_atomic_set(&memobj->ref, 1);
	memobj->handle = result.handle;
	INIT_LIST_HEAD(&memobj->page_list);
	ihk_mc_spinlock_init(&memobj->page_list_lock);

	ihk_mc_spinlock_lock_noirq(&memobj_list_lock);
	list_add(&memobj->list, &memobj_list);
	ihk_mc_spinlock_unlock_noirq(&memobj_list_lock);

found:
	error = 0;
	*objpp = memobj;
	*maxprotp = result.maxprot;
	memobj = NULL;

out:
	kprintf("memobj_create(%d,%x,%x):%d %p %x\n", fd, flags, prot, error, *objpp, *maxprotp);
	return error;
}

void memobj_ref(struct memobj *obj)
{
	kprintf("memobj_ref(%p):\n", obj);
	ihk_atomic_inc(&obj->ref);
	return;
}

void memobj_release(struct memobj *obj)
{
	ihk_mc_user_context_t ctx;
	int error;

	kprintf("memobj_release(%p)\n", obj);
	ihk_mc_spinlock_lock_noirq(&memobj_list_lock);
	if (!ihk_atomic_dec_and_test(&obj->ref)) {
		ihk_mc_spinlock_unlock_noirq(&memobj_list_lock);
		kprintf("memobj_release(%p):keep\n", obj);
		return;
	}
	list_del(&obj->list);
	ihk_mc_spinlock_unlock_noirq(&memobj_list_lock);

	ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_RELEASE;
	ihk_mc_syscall_arg1(&ctx) = obj->handle;

	error = syscall_generic_forwarding(__NR_mmap, &ctx);
	if (error) {
		kprintf("memobj_release(%p):release failed. %d\n", obj, error);
		/* through */
	}

	kfree(obj);
	kprintf("memobj_release(%p):free\n", obj);
	return;
}

int memobj_get_page(struct memobj *obj, off_t off, size_t pgsize, uintptr_t *physp)
{
	int error;
	void *virt = NULL;
	uintptr_t phys = -1;
	ihk_mc_user_context_t ctx;
	struct page *page;

	kprintf("memobj_get_page(%p,%lx,%lx,%p)\n", obj, off, pgsize, physp);
	if (pgsize != PAGE_SIZE) {
		error = -ENOMEM;
		goto out;
	}

retry:
	for (;;) {
		ihk_mc_spinlock_lock_noirq(&obj->page_list_lock);
		list_for_each_entry(page, &obj->page_list, list) {
			if ((page->mode != PM_PAGEIO) && (page->mode != PM_MAPPED)) {
				panic("memobj_get_page:invalid obj page");
			}
			if (page->offset == off) {
				if (page->mode == PM_PAGEIO) {
					ihk_mc_spinlock_unlock_noirq(&obj->page_list_lock);
					goto retry;
				}
				++page->count;
				phys = page_to_phys(page);
				ihk_mc_spinlock_unlock_noirq(&obj->page_list_lock);
				goto found;
			}
		}

		if (virt != NULL) {
			page = phys_to_page(phys);
			break;
		}
		ihk_mc_spinlock_unlock_noirq(&obj->page_list_lock);

		virt = ihk_mc_alloc_pages(1, IHK_MC_AP_NOWAIT);
		if (virt == NULL) {
			error = -ENOMEM;
			goto out;
		}
		phys = virt_to_phys(virt);
	}

	if (page->mode != PM_NONE) {
		panic("memobj_get_page:invalid new page");
	}
	page->mode = PM_PAGEIO;
	page->offset = off;
	list_add(&page->list, &obj->page_list);
	ihk_mc_spinlock_unlock_noirq(&obj->page_list_lock);

	ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_READ;
	ihk_mc_syscall_arg1(&ctx) = obj->handle;
	ihk_mc_syscall_arg2(&ctx) = off;
	ihk_mc_syscall_arg3(&ctx) = pgsize;
	ihk_mc_syscall_arg4(&ctx) = phys;

	error = syscall_generic_forwarding(__NR_mmap, &ctx);
	if (error) {
		kprintf("memobj_get_page(%p,%lx,%lx,%p):read failed. %d\n",
				obj, off, pgsize, physp, error);
		ihk_mc_spinlock_lock_noirq(&obj->page_list_lock);
		if (page->mode != PM_PAGEIO) {
			panic("memobj_get_page:invalid io page");
		}
		list_del(&page->list);
		ihk_mc_spinlock_unlock_noirq(&obj->page_list_lock);
		page->mode = PM_NONE;
		goto out;
	}

	ihk_mc_spinlock_lock_noirq(&obj->page_list_lock);
	if (page->mode != PM_PAGEIO) {
		panic("memobj_get_page:invalid io page");
	}
	page->mode = PM_MAPPED;
	page->count = 1;
	ihk_mc_spinlock_unlock_noirq(&obj->page_list_lock);
	virt = NULL;

found:
	error = 0;
	*physp = phys;

out:
	if (virt != NULL) {
		ihk_mc_free_pages(virt, 1);
	}
	kprintf("memobj_get_page(%p,%lx,%lx,%p): %d %lx\n",
			obj, off, pgsize, physp, error, phys);
	return error;
}
