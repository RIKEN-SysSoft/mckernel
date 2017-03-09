/**
 * \file devobj.c
 *  License details are found in the file LICENSE.
 * \brief
 *  memory mapped device pager client
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2014  RIKEN AICS
 */
/*
 * HISTORY:
 */

#if 0
#include <ihk/cpu.h>
#endif
#include <ihk/debug.h>
#include <ihk/lock.h>
#if 0
#include <ihk/mm.h>
#include <ihk/types.h>
#include <cls.h>
#include <errno.h>
#endif
#include <kmalloc.h>
#if 0
#include <kmsg.h>
#endif
#include <memobj.h>
#if 0
#include <memory.h>
#endif
#include <page.h>	/* for allocate_pages() */
#include <pager.h>
#include <string.h>
#include <syscall.h>
#include <process.h>

//#define DEBUG_PRINT_DEVOBJ

#ifdef DEBUG_PRINT_DEVOBJ
#define	dkprintf(...) kprintf(__VA_ARGS__)
#define	ekprintf(...) kprintf(__VA_ARGS__)
#else
#define dkprintf(...) do { if (0) kprintf(__VA_ARGS__); } while (0)
#define	ekprintf(...) kprintf(__VA_ARGS__)
#endif


struct devobj {
	struct memobj	memobj;		/* must be first */
	long		ref;
	uintptr_t	handle;
	off_t		pfn_pgoff;
	uintptr_t *	pfn_table;
	size_t		npages;
};

static memobj_release_func_t devobj_release;
static memobj_ref_func_t devobj_ref;
static memobj_get_page_func_t devobj_get_page;

static struct memobj_ops devobj_ops = {
	.release =	&devobj_release,
	.ref =		&devobj_ref,
	.get_page =	&devobj_get_page,
};

static struct devobj *to_devobj(struct memobj *memobj)
{
	return (struct devobj *)memobj;
}

static struct memobj *to_memobj(struct devobj *devobj)
{
	return &devobj->memobj;
}

/***********************************************************************
 * devobj
 */
int devobj_create(int fd, size_t len, off_t off, struct memobj **objp, int *maxprotp,
	int prot, int populate_flags)
{
	ihk_mc_user_context_t ctx;
	struct pager_map_result result;	// XXX: assumes contiguous physical
	int error;
	struct devobj *obj  = NULL;
	const size_t npages = (len + PAGE_SIZE - 1) / PAGE_SIZE;
	const size_t pfn_npages = (npages / (PAGE_SIZE / sizeof(uintptr_t))) + 1;

	dkprintf("%s: fd: %d, len: %lu, off: %lu \n", __FUNCTION__, fd, len, off);

	obj = kmalloc(sizeof(*obj), IHK_MC_AP_NOWAIT);
	if (!obj) {
		error = -ENOMEM;
		kprintf("%s: error: fd: %d, len: %lu, off: %lu kmalloc failed.\n", 
			__FUNCTION__, fd, len, off);
		goto out;
	}
	memset(obj, 0, sizeof(*obj));

	obj->pfn_table = ihk_mc_alloc_pages(pfn_npages, IHK_MC_AP_NOWAIT);
	if (!obj->pfn_table) {
		error = -ENOMEM;
		kprintf("%s: error: fd: %d, len: %lu, off: %lu allocating PFN failed.\n", 
			__FUNCTION__, fd, len, off);
		goto out;
	}
	memset(obj->pfn_table, 0, pfn_npages * PAGE_SIZE);

	ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_MAP;
	ihk_mc_syscall_arg1(&ctx) = fd;
	ihk_mc_syscall_arg2(&ctx) = len;
	ihk_mc_syscall_arg3(&ctx) = off;
	ihk_mc_syscall_arg4(&ctx) = virt_to_phys(&result);
	ihk_mc_syscall_arg5(&ctx) = prot | populate_flags;

	error = syscall_generic_forwarding(__NR_mmap, &ctx);
	if (error) {
		kprintf("%s: error: fd: %d, len: %lu, off: %lu map failed.\n", 
			__FUNCTION__, fd, len, off);
		goto out;
	}

	dkprintf("%s: fd: %d, len: %lu, off: %lu, handle: %p, maxprot: %x\n", 
		__FUNCTION__, fd, len, off, result.handle, result.maxprot);

	obj->memobj.ops = &devobj_ops;
	obj->memobj.flags = MF_HAS_PAGER | MF_DEV_FILE;
	obj->memobj.size = len;
	obj->handle = result.handle;
	obj->ref = 1;
	obj->pfn_pgoff = off / PAGE_SIZE;
	obj->npages = npages;
	ihk_mc_spinlock_init(&obj->memobj.lock);

	error = 0;
	*objp = to_memobj(obj);
	*maxprotp = result.maxprot;
	obj = NULL;

out:
	if (obj) {
		if (obj->pfn_table) {
			ihk_mc_free_pages(obj->pfn_table, pfn_npages);
		}
		kfree(obj);
	}
	dkprintf("%s: ret: %d, fd: %d, len: %lu, off: %lu, handle: %p, maxprot: %x \n", 
		__FUNCTION__, error, fd, len, off, result.handle, result.maxprot);
	return error;
}

static void devobj_ref(struct memobj *memobj)
{
	struct devobj *obj = to_devobj(memobj);

	dkprintf("devobj_ref(%p %lx):\n", obj, obj->handle);
	memobj_lock(&obj->memobj);
	++obj->ref;
	memobj_unlock(&obj->memobj);
	return;
}

static void devobj_release(struct memobj *memobj)
{
	struct devobj *obj = to_devobj(memobj);
	struct devobj *free_obj = NULL;
	uintptr_t handle;
	const size_t pfn_npages =
		(obj->npages / (PAGE_SIZE / sizeof(uintptr_t))) + 1;

	dkprintf("devobj_release(%p %lx)\n", obj, obj->handle);

	memobj_lock(&obj->memobj);
	--obj->ref;
	if (obj->ref <= 0) {
		free_obj = obj;
	}
	handle = obj->handle;
	memobj_unlock(&obj->memobj);

	if (free_obj) {
		if (!(free_obj->memobj.flags & MF_HOST_RELEASED)) {
			int error;
			ihk_mc_user_context_t ctx;

			ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_UNMAP;
			ihk_mc_syscall_arg1(&ctx) = handle;
			ihk_mc_syscall_arg2(&ctx) = 1;

			error = syscall_generic_forwarding(__NR_mmap, &ctx);
			if (error) {
				kprintf("devobj_release(%p %lx):"
						"release failed. %d\n",
						free_obj, handle, error);
				/* through */
			}
		}

		if (obj->pfn_table) {
			ihk_mc_free_pages(obj->pfn_table, pfn_npages);
		}
		kfree(free_obj);
	}

	dkprintf("devobj_release(%p %lx):free %p\n",
			obj, handle, free_obj);
	return;
}

static int devobj_get_page(struct memobj *memobj, off_t off, int p2align, uintptr_t *physp, unsigned long *flag)
{
	const off_t pgoff = off / PAGE_SIZE;
	struct devobj *obj = to_devobj(memobj);
	int error;
	uintptr_t pfn;
	uintptr_t attr;
	ihk_mc_user_context_t ctx;
	int ix;

	dkprintf("devobj_get_page(%p %lx,%lx,%d)\n", memobj, obj->handle, off, p2align);

	if ((pgoff < obj->pfn_pgoff) || ((obj->pfn_pgoff + obj->npages) <= pgoff)) {
		error = -EFBIG;
		kprintf("%s: error: out of range: off: %lu, page off: %lu obj->npages: %d\n", __FUNCTION__, off, pgoff, obj->npages);
		goto out;
	}
	ix = pgoff - obj->pfn_pgoff;
	dkprintf("ix: %ld\n", ix);

	memobj_lock(&obj->memobj);
	pfn = obj->pfn_table[ix];
#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_page_fault_dev_file, PAGE_SIZE);
#endif // PROFILE_ENABLE
	if (!(pfn & PFN_VALID)) {
		memobj_unlock(&obj->memobj);

		ihk_mc_syscall_arg0(&ctx) = PAGER_REQ_PFN;
		ihk_mc_syscall_arg1(&ctx) = obj->handle;
		ihk_mc_syscall_arg2(&ctx) = pgoff << PAGE_SHIFT;
		ihk_mc_syscall_arg3(&ctx) = virt_to_phys(&pfn);

		error = syscall_generic_forwarding(__NR_mmap, &ctx);
		if (error) {
			kprintf("devobj_get_page(%p %lx,%lx,%d):PAGER_REQ_PFN failed. %d\n", memobj, obj->handle, off, p2align, error);
			goto out;
		}

		if (pfn & PFN_PRESENT) {
			/* convert remote physical into local physical */
			dkprintf("devobj_get_page(%p %lx,%lx,%d):PFN_PRESENT before %#lx\n", memobj, obj->handle, off, p2align, pfn);
			attr = pfn & ~PFN_PFN;

			/* TODO: do an arch dependent PTE to mapping flag conversion 
			 * instead of this inline check, also, we rely on having the
			 * same PAT config as Linux here.. */
			if ((pfn & PFL1_PWT) && !(pfn & PFL1_PCD)) {
				*flag |= VR_WRITE_COMBINED;
			}

			pfn = ihk_mc_map_memory(NULL, (pfn & PFN_PFN), PAGE_SIZE);
			pfn &= PFN_PFN;
			pfn |= attr;
			dkprintf("devobj_get_page(%p %lx,%lx,%d):PFN_PRESENT after %#lx\n", memobj, obj->handle, off, p2align, pfn);
		}

		memobj_lock(&obj->memobj);
		obj->pfn_table[ix] = pfn;
	}
	memobj_unlock(&obj->memobj);

	if (!(pfn & PFN_PRESENT)) {
		kprintf("devobj_get_page(%p %lx,%lx,%d):not present. %lx\n", memobj, obj->handle, off, p2align, pfn);
		error = -EFAULT;
		goto out;
	}

	error = 0;
	*physp = pfn & PFN_PFN;

out:
	dkprintf("devobj_get_page(%p %lx,%lx,%d): %d %lx\n", memobj, obj->handle, off, p2align, error, *physp);
	return error;
}
