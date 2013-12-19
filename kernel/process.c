/**
 * \file process.c
 *  License details are found in the file LICENSE.
 * \brief
 *  process, thread, and, virtual memory management
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * 	Copyright (C) 2011 - 2012  Taku Shimosawa
 * \author Balazs Gerofi  <bgerofi@riken.jp> \par
 * 	Copyright (C) 2012  RIKEN AICS
 * \author Masamichi Takagi  <m-takagi@ab.jp.nec.com> \par
 * 	Copyright (C) 2012 - 2013  NEC Corporation
 * \author Balazs Gerofi  <bgerofi@is.s.u-tokyo.ac.jp> \par
 * 	Copyright (C) 2013  The University of Tokyo
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 * \author Tomoki Shirasawa  <tomoki.shirasawa.kk@hitachi-solutions.com> \par
 * 	Copyright (C) 2013  Hitachi, Ltd.
 */
/*
 * HISTORY:
 */

#include <process.h>
#include <string.h>
#include <errno.h>
#include <kmalloc.h>
#include <cls.h>
#include <ihk/debug.h>
#include <page.h>
#include <cpulocal.h>
#include <auxvec.h>
#include <timer.h>
#include <mman.h>

//#define DEBUG_PRINT_PROCESS

#ifdef DEBUG_PRINT_PROCESS
#define dkprintf(...) kprintf(__VA_ARGS__)
#define ekprintf(...) kprintf(__VA_ARGS__)
#else
#define dkprintf(...)
#define ekprintf(...) kprintf(__VA_ARGS__)
#endif


#define USER_STACK_NR_PAGES 8192
#define KERNEL_STACK_NR_PAGES 24

extern long do_arch_prctl(unsigned long code, unsigned long address);

static int init_process_vm(struct process *owner, struct process_vm *vm)
{
	void *pt = ihk_mc_pt_create(IHK_MC_AP_NOWAIT);

	if(pt == NULL)
		return -ENOMEM;

	ihk_mc_spinlock_init(&vm->memory_range_lock);
	ihk_mc_spinlock_init(&vm->page_table_lock);

	ihk_atomic_set(&vm->refcount, 1);
	INIT_LIST_HEAD(&vm->vm_range_list);
	vm->page_table = pt;
	hold_process(owner);
	vm->owner_process = owner;
	
	return 0;
}

struct process *create_process(unsigned long user_pc)
{
	struct process *proc;

	proc = ihk_mc_alloc_pages(KERNEL_STACK_NR_PAGES, IHK_MC_AP_NOWAIT);
	if (!proc)
		return NULL;

	memset(proc, 0, sizeof(struct process));
	ihk_atomic_set(&proc->refcount, 2);	/* one for exit, another for wait */

	proc->sighandler = kmalloc(sizeof(struct sig_handler), IHK_MC_AP_NOWAIT);
	if(!proc->sighandler){
		ihk_mc_free_pages(proc, KERNEL_STACK_NR_PAGES);
		return NULL;
	}
	proc->sigshared = kmalloc(sizeof(struct sig_shared), IHK_MC_AP_NOWAIT);
	if(!proc->sigshared){
		ihk_mc_free_pages(proc->sighandler, KERNEL_STACK_NR_PAGES);
		ihk_mc_free_pages(proc, KERNEL_STACK_NR_PAGES);
		return NULL;
	}
	memset(proc->sighandler, '\0', sizeof(struct sig_handler));
	ihk_atomic_set(&proc->sighandler->use, 1);
	ihk_mc_spinlock_init(&proc->sighandler->lock);
	ihk_atomic_set(&proc->sigshared->use, 1);
	ihk_mc_spinlock_init(&proc->sigshared->lock);
	INIT_LIST_HEAD(&proc->sigshared->sigpending);
	ihk_mc_spinlock_init(&proc->sigpendinglock);
	INIT_LIST_HEAD(&proc->sigpending);

	ihk_mc_init_user_process(&proc->ctx, &proc->uctx,
	                         ((char *)proc) + 
							 KERNEL_STACK_NR_PAGES * PAGE_SIZE, user_pc, 0);

	proc->vm = (struct process_vm *)(proc + 1);

	if(init_process_vm(proc, proc->vm) != 0){
		kfree(proc->sighandler);
		ihk_mc_free_pages(proc, KERNEL_STACK_NR_PAGES);
		return NULL;
	}

	ihk_mc_spinlock_init(&proc->spin_sleep_lock);
	proc->spin_sleep = 0;

	return proc;
}

struct process *clone_process(struct process *org, unsigned long pc,
                              unsigned long sp)
{
	struct process *proc;

	if((proc = ihk_mc_alloc_pages(KERNEL_STACK_NR_PAGES, IHK_MC_AP_NOWAIT)) == NULL){
		return NULL;
	}

	memset(proc, 0, sizeof(struct process));
	ihk_atomic_set(&proc->refcount, 2);	/* one for exit, another for wait */

	/* NOTE: sp is the user mode stack! */
	ihk_mc_init_user_process(&proc->ctx, &proc->uctx,
	                         ((char *)proc) + 
							 KERNEL_STACK_NR_PAGES * PAGE_SIZE, pc, sp);

	memcpy(proc->uctx, org->uctx, sizeof(*org->uctx));
	ihk_mc_modify_user_context(proc->uctx, IHK_UCR_STACK_POINTER, sp);
	ihk_mc_modify_user_context(proc->uctx, IHK_UCR_PROGRAM_COUNTER, pc);
	
	ihk_atomic_inc(&org->vm->refcount);
	proc->vm = org->vm;
	proc->rlimit_stack = org->rlimit_stack;

	proc->sighandler = org->sighandler;
	ihk_atomic_inc(&org->sighandler->use);

	proc->sigshared = org->sigshared;
	ihk_atomic_inc(&org->sigshared->use);

	ihk_mc_spinlock_init(&proc->sigpendinglock);
	INIT_LIST_HEAD(&proc->sigpending);

	ihk_mc_spinlock_init(&proc->spin_sleep_lock);
	proc->spin_sleep = 0;

	return proc;
}

int update_process_page_table(struct process *process,
                          struct vm_range *range, uint64_t phys,
			  enum ihk_mc_pt_attribute flag)
{
	unsigned long p, pa = phys;
	unsigned long pp;
	unsigned long flags = ihk_mc_spinlock_lock(&process->vm->page_table_lock);
	enum ihk_mc_pt_attribute attr;

	attr = flag | PTATTR_USER | PTATTR_FOR_USER;
	attr |= (range->flag & VR_PROT_WRITE)? PTATTR_WRITABLE: 0;

	p = range->start;
	while (p < range->end) {
#ifdef USE_LARGE_PAGES
		/* Use large PTE if both virtual and physical addresses are large page 
		 * aligned and more than LARGE_PAGE_SIZE is left from the range */
		if ((p & (LARGE_PAGE_SIZE - 1)) == 0 && 
				(pa & (LARGE_PAGE_SIZE - 1)) == 0 &&
				(range->end - p) >= LARGE_PAGE_SIZE) {

			if (ihk_mc_pt_set_large_page(process->vm->page_table, (void *)p,
					pa, attr) != 0) {
				goto err;
			}

			dkprintf("large page set for 0x%lX -> 0x%lX\n", p, pa);

			pa += LARGE_PAGE_SIZE;
			p += LARGE_PAGE_SIZE;
		}
		else {
#endif		
			if(ihk_mc_pt_set_page(process->vm->page_table, (void *)p,
			      pa, attr) != 0){
				goto err;
			}

			pa += PAGE_SIZE;
			p += PAGE_SIZE;
#ifdef USE_LARGE_PAGES
		}
#endif
	}
	ihk_mc_spinlock_unlock(&process->vm->page_table_lock, flags);
	return 0;

err:
	pp = range->start;
	pa = phys;
	while(pp < p){
#ifdef USE_LARGE_PAGES
		if ((p & (LARGE_PAGE_SIZE - 1)) == 0 && 
				(pa & (LARGE_PAGE_SIZE - 1)) == 0 &&
				(range->end - p) >= LARGE_PAGE_SIZE) {
			ihk_mc_pt_clear_large_page(process->vm->page_table, (void *)pp);
			pa += LARGE_PAGE_SIZE;
			pp += LARGE_PAGE_SIZE;
		}
		else{
#endif
			ihk_mc_pt_clear_page(process->vm->page_table, (void *)pp);
			pa += PAGE_SIZE;
			pp += PAGE_SIZE;
#ifdef USE_LARGE_PAGES
		}
#endif
	}

	ihk_mc_spinlock_unlock(&process->vm->page_table_lock, flags);
	return -ENOMEM;
}

int split_process_memory_range(struct process *proc, struct vm_range *range,
		uintptr_t addr, struct vm_range **splitp)
{
	int error;
	struct vm_range *newrange = NULL;

	dkprintf("split_process_memory_range(%p,%lx-%lx,%lx,%p)\n",
			proc, range->start, range->end, addr, splitp);

	newrange = kmalloc(sizeof(struct vm_range), IHK_MC_AP_NOWAIT);
	if (!newrange) {
		ekprintf("split_process_memory_range(%p,%lx-%lx,%lx,%p):"
				"kmalloc failed\n",
				proc, range->start, range->end, addr, splitp);
		error = -ENOMEM;
		goto out;
	}

	newrange->start = addr;
	newrange->end = range->end;
	newrange->flag = range->flag;

	if (range->memobj) {
		memobj_ref(range->memobj);
		newrange->memobj = range->memobj;
		newrange->objoff = range->objoff + (addr - range->start);
	}
	else {
		newrange->memobj = NULL;
		newrange->objoff = 0;
	}

	range->end = addr;

	list_add(&newrange->list, &range->list);

	error = 0;
	if (splitp != NULL) {
		*splitp = newrange;
	}

out:
	dkprintf("split_process_memory_range(%p,%lx-%lx,%lx,%p): %d %p %lx-%lx\n",
			proc, range->start, range->end, addr, splitp,
			error, newrange,
			newrange? newrange->start: 0, newrange? newrange->end: 0);
	return error;
}

int join_process_memory_range(struct process *proc,
		struct vm_range *surviving, struct vm_range *merging)
{
	int error;

	dkprintf("join_process_memory_range(%p,%lx-%lx,%lx-%lx)\n",
			proc, surviving->start, surviving->end,
			merging->start, merging->end);

	if ((surviving->end != merging->start)
			|| (surviving->flag != merging->flag)
			|| (surviving->memobj != merging->memobj)) {
		error = -EINVAL;
		goto out;
	}
	if (surviving->memobj != NULL) {
		size_t len;
		off_t endoff;

		len = surviving->end - surviving->start;
		endoff = surviving->objoff + len;
		if (endoff != merging->objoff) {
			return -EINVAL;
		}
	}

	surviving->end = merging->end;

	if (merging->memobj) {
		memobj_release(merging->memobj);
	}
	list_del(&merging->list);
	ihk_mc_free(merging);

	error = 0;
out:
	dkprintf("join_process_memory_range(%p,%lx-%lx,%p): %d\n",
			proc, surviving->start, surviving->end, merging, error);
	return error;
}

int free_process_memory_range(struct process_vm *vm, struct vm_range *range)
{
	const intptr_t start0 = range->start;
	const intptr_t end0 = range->end;
	int error;
	intptr_t start;
	intptr_t end;
#ifdef USE_LARGE_PAGES
	struct vm_range *neighbor;
	intptr_t lpstart;
	intptr_t lpend;
#endif /* USE_LARGE_PAGES */

	dkprintf("free_process_memory_range(%p,%lx-%lx)\n",
			vm, start0, end0);

	start = range->start;
	end = range->end;
	if (!(range->flag & (VR_REMOTE | VR_IO_NOCACHE | VR_RESERVED))) {
#ifdef USE_LARGE_PAGES
		lpstart = start & LARGE_PAGE_MASK;
		lpend = (end + LARGE_PAGE_SIZE - 1) & LARGE_PAGE_MASK;


		if (lpstart < start) {
			neighbor = previous_process_memory_range(vm, range);
			if ((neighbor == NULL) || (neighbor->end <= lpstart)) {
				start = lpstart;
			}
		}

		if (end < lpend) {
			neighbor = next_process_memory_range(vm, range);
			if ((neighbor == NULL) || (lpend <= neighbor->start)) {
				end = lpend;
			}
		}
#endif /* USE_LARGE_PAGES */

		ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
		if (range->memobj) {
			memobj_lock(range->memobj);
		}
		error = ihk_mc_pt_free_range(vm->page_table,
				(void *)start, (void *)end,
				(range->flag & VR_PRIVATE)? NULL: range->memobj);
		if (range->memobj) {
			memobj_unlock(range->memobj);
		}
		ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
		if (error && (error != -ENOENT)) {
			ekprintf("free_process_memory_range(%p,%lx-%lx):"
					"ihk_mc_pt_free_range(%lx-%lx,%p) failed. %d\n",
					vm, start0, end0, start, end, range->memobj, error);
			/* through */
		}
	}
	else {
		ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
		error = ihk_mc_pt_clear_range(vm->page_table,
				(void *)start, (void *)end);
		ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
		if (error && (error != -ENOENT)) {
			ekprintf("free_process_memory_range(%p,%lx-%lx):"
					"ihk_mc_pt_clear_range(%lx-%lx) failed. %d\n",
					vm, start0, end0, start, end, error);
			/* through */
		}
	}

	if (range->memobj) {
		memobj_release(range->memobj);
	}
	list_del(&range->list);
	ihk_mc_free(range);

	dkprintf("free_process_memory_range(%p,%lx-%lx): 0\n",
			vm, start0, end0);
	return 0;
}

int remove_process_memory_range(struct process *process,
		unsigned long start, unsigned long end, int *ro_freedp)
{
	struct process_vm * const vm = process->vm;
	struct vm_range *range;
	struct vm_range *next;
	int error;
	struct vm_range *freerange;
	int ro_freed = 0;

	dkprintf("remove_process_memory_range(%p,%lx,%lx)\n",
			process, start, end);

	list_for_each_entry_safe(range, next, &vm->vm_range_list, list) {
		if ((range->end <= start) || (end <= range->start)) {
			/* no overlap */
			continue;
		}
		freerange = range;

		if (freerange->start < start) {
			error = split_process_memory_range(process,
					freerange, start, &freerange);
			if (error) {
				ekprintf("remove_process_memory_range(%p,%lx,%lx):"
						"split failed %d\n",
						process, start, end, error);
				return error;
			}
		}

		if (end < freerange->end) {
			error = split_process_memory_range(process,
					freerange, end, NULL);
			if (error) {
				ekprintf("remove_process_memory_range(%p,%lx,%lx):"
						"split failed %d\n",
						process, start, end, error);
				return error;
			}
		}

		if (!(freerange->flag & VR_PROT_WRITE)) {
			ro_freed = 1;
		}

		error = free_process_memory_range(process->vm, freerange);
		if (error) {
			ekprintf("remove_process_memory_range(%p,%lx,%lx):"
					"free failed %d\n",
					process, start, end, error);
			return error;
		}

	}

	if (ro_freedp) {
		*ro_freedp = ro_freed;
	}
	dkprintf("remove_process_memory_range(%p,%lx,%lx): 0 %d\n",
			process, start, end, ro_freed);
	return 0;
}

static void insert_vm_range_list(struct process_vm *vm, struct vm_range *newrange)
{
	struct list_head *next;
	struct vm_range *range;

	next = &vm->vm_range_list;
	list_for_each_entry(range, &vm->vm_range_list, list) {
		if ((newrange->start < range->end) && (range->start < newrange->end)) {
			ekprintf("insert_vm_range_list(%p,%lx-%lx %lx):overlap %lx-%lx %lx\n",
					vm, newrange->start, newrange->end, newrange->flag,
					range->start, range->end, range->flag);
			panic("insert_vm_range_list\n");
		}

		if (newrange->end <= range->start) {
			next = &range->list;
			break;
		}
	}

	list_add_tail(&newrange->list, next);
	return;
}

enum ihk_mc_pt_attribute vrflag_to_ptattr(unsigned long flag)
{
	enum ihk_mc_pt_attribute attr;

	attr = PTATTR_USER | PTATTR_FOR_USER;

	if (flag & VR_REMOTE) {
		attr |= IHK_PTA_REMOTE;
	}
	else if (flag & VR_IO_NOCACHE) {
		attr |= PTATTR_UNCACHABLE;
	}

	if ((flag & VR_PROT_MASK) != VR_PROT_NONE) {
		attr |= PTATTR_ACTIVE;
	}

	if (flag & VR_PROT_WRITE) {
		attr |= PTATTR_WRITABLE;
	}

	return attr;
}


int add_process_memory_range(struct process *process,
                             unsigned long start, unsigned long end,
                             unsigned long phys, unsigned long flag,
			     struct memobj *memobj, off_t offset)
{
	struct vm_range *range;
	int rc;
#if 0
	extern void __host_update_process_range(struct process *process,
						struct vm_range *range);
#endif

	if ((start < process->vm->region.user_start)
			|| (process->vm->region.user_end < end)) {
		kprintf("range(%#lx - %#lx) is not in user avail(%#lx - %#lx)\n",
				start, end, process->vm->region.user_start,
				process->vm->region.user_end);
		return -EINVAL;
	}

	range = kmalloc(sizeof(struct vm_range), IHK_MC_AP_NOWAIT);
	if (!range) {
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&range->list);
	range->start = start;
	range->end = end;
	range->flag = flag;
	range->memobj = memobj;
	range->objoff = offset;

    if(range->flag & VR_DEMAND_PAGING) {
	dkprintf("range: 0x%lX - 0x%lX => physicall memory area is allocated on demand (%ld) [%lx]\n",
	        range->start, range->end, range->end - range->start,
		range->flag);
    } else {
	dkprintf("range: 0x%lX - 0x%lX => 0x%lX - 0x%lX (%ld) [%lx]\n",
	        range->start, range->end, range->phys, range->phys + 
	        range->end - range->start, range->end - range->start,
		range->flag);
    }

	if (flag & VR_REMOTE) {
		rc = update_process_page_table(process, range, phys, IHK_PTA_REMOTE);
	} else if (flag & VR_IO_NOCACHE) {
		rc = update_process_page_table(process, range, phys, PTATTR_UNCACHABLE);
	} else if(flag & VR_DEMAND_PAGING){
	  //demand paging no need to update process table now
	  dkprintf("demand paging do not update process page table\n");
      rc = 0;
	} else if ((range->flag & VR_PROT_MASK) == VR_PROT_NONE) {
		rc = 0;
	} else {
		rc = update_process_page_table(process, range, phys, 0);
	}
	if(rc != 0){
		kfree(range);
		return rc;
	}

#if 0 // disable __host_update_process_range() in add_process_memory_range(), because it has no effect on the actual mapping on the MICs side. 
	if (!(flag & VR_REMOTE)) {
		__host_update_process_range(process, range);
	}
#endif
	
	insert_vm_range_list(process->vm, range);
	
	/* Clear content! */
	if (!(flag & (VR_REMOTE | VR_DEMAND_PAGING))
			&& ((flag & VR_PROT_MASK) != VR_PROT_NONE)) {
		memset((void*)phys_to_virt(phys), 0, end - start);
	}

	return 0;
}

struct vm_range *lookup_process_memory_range(
		struct process_vm *vm, uintptr_t start, uintptr_t end)
{
	struct vm_range *range = NULL;

	dkprintf("lookup_process_memory_range(%p,%lx,%lx)\n", vm, start, end);

	if (end <= start) {
		goto out;
	}

	list_for_each_entry(range, &vm->vm_range_list, list) {
		if (end <= range->start) {
			break;
		}
		if ((start < range->end) && (range->start < end)) {
			goto out;
		}
	}

	range = NULL;
out:
	dkprintf("lookup_process_memory_range(%p,%lx,%lx): %p %lx-%lx\n",
			vm, start, end, range,
			range? range->start: 0, range? range->end: 0);
	return range;
}

struct vm_range *next_process_memory_range(
		struct process_vm *vm, struct vm_range *range)
{
	struct vm_range *next;

	dkprintf("next_process_memory_range(%p,%lx-%lx)\n",
			vm, range->start, range->end);

	if (list_is_last(&range->list, &vm->vm_range_list)) {
		next = NULL;
	}
	else {
		next = list_entry(range->list.next, struct vm_range, list);
	}

	dkprintf("next_process_memory_range(%p,%lx-%lx): %p %lx-%lx\n",
			vm, range->start, range->end, next,
			next? next->start: 0, next? next->end: 0);
	return next;
}

struct vm_range *previous_process_memory_range(
		struct process_vm *vm, struct vm_range *range)
{
	struct vm_range *prev;

	dkprintf("previous_process_memory_range(%p,%lx-%lx)\n",
			vm, range->start, range->end);

	if (list_first_entry(&vm->vm_range_list, struct vm_range, list) == range) {
		prev = NULL;
	}
	else {
		prev = list_entry(range->list.prev, struct vm_range, list);
	}

	dkprintf("previous_process_memory_range(%p,%lx-%lx): %p %lx-%lx\n",
			vm, range->start, range->end, prev,
			prev? prev->start: 0, prev? prev->end: 0);
	return prev;
}

int change_prot_process_memory_range(struct process *proc,
		struct vm_range *range, unsigned long protflag)
{
	unsigned long newflag;
	int error;
	enum ihk_mc_pt_attribute oldattr;
	enum ihk_mc_pt_attribute newattr;
	enum ihk_mc_pt_attribute clrattr;
	enum ihk_mc_pt_attribute setattr;

	dkprintf("change_prot_process_memory_range(%p,%lx-%lx,%lx)\n",
			proc, range->start, range->end, protflag);

	newflag = (range->flag & ~VR_PROT_MASK) | (protflag & VR_PROT_MASK);
	if (range->flag == newflag) {
		/* nothing to do */
		error = 0;
		goto out;
	}

	oldattr = vrflag_to_ptattr(range->flag);
	newattr = vrflag_to_ptattr(newflag);

	clrattr = oldattr & ~newattr;
	setattr = newattr & ~oldattr;

	ihk_mc_spinlock_lock_noirq(&proc->vm->page_table_lock);
	error = ihk_mc_pt_change_attr_range(proc->vm->page_table,
			(void *)range->start, (void *)range->end,
			clrattr, setattr);
	ihk_mc_spinlock_unlock_noirq(&proc->vm->page_table_lock);
	if (error && (error != -ENOENT)) {
		ekprintf("change_prot_process_memory_range(%p,%lx-%lx,%lx):"
				"ihk_mc_pt_change_attr_range failed: %d\n",
				proc, range->start, range->end, protflag, error);
		goto out;
	}

	if (((range->flag & VR_PROT_MASK) == PROT_NONE)
			&& !(range->flag & VR_DEMAND_PAGING)) {
		ihk_mc_spinlock_lock_noirq(&proc->vm->page_table_lock);
		error = ihk_mc_pt_alloc_range(proc->vm->page_table,
				(void *)range->start, (void *)range->end,
				newattr);
		ihk_mc_spinlock_unlock_noirq(&proc->vm->page_table_lock);
		if (error) {
			ekprintf("change_prot_process_memory_range(%p,%lx-%lx,%lx):"
					"ihk_mc_pt_alloc_range failed: %d\n",
					proc, range->start, range->end, protflag, error);
			goto out;
		}
	}

	range->flag = newflag;
	error = 0;
out:
	dkprintf("change_prot_process_memory_range(%p,%lx-%lx,%lx): %d\n",
			proc, range->start, range->end, protflag, error);
	return error;
}

static int page_fault_process_memory_range(struct process_vm *vm,
		struct vm_range *range, uintptr_t fault_addr)
{
	int error;
	int npages;
	void *virt = NULL;
	void *ptepgaddr;
	size_t ptepgsize;
	int ptep2align;
	void *pgaddr;
	size_t pgsize;
	int p2align;
	uintptr_t phys;
	enum ihk_mc_pt_attribute attr;
	pte_t *ptep;
	off_t off;
	struct page *page = NULL;

	dkprintf("[%d]page_fault_process_memory_range(%p,%lx-%lx %lx,%lx)\n",
			ihk_mc_get_processor_id(), vm, range->start,
			range->end, range->flag, fault_addr);

	ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);

	/* (1) check PTE */
	ptep = ihk_mc_pt_lookup_pte(vm->page_table, (void *)fault_addr,
			&ptepgaddr, &ptepgsize, &ptep2align);
	if (ptep && !pte_is_null(ptep)) {
		if (!pte_is_present(ptep)) {
			error = -EFAULT;
			kprintf("[%d]page_fault_process_memory_range"
					"(%p,%lx-%lx %lx,%lx):"
					"disabled page. %d\n",
					ihk_mc_get_processor_id(), vm,
					range->start, range->end,
					range->flag, fault_addr, error);
			goto out;
		}

		error = 0;
		kprintf("[%d]page_fault_process_memory_range"
				"(%p,%lx-%lx %lx,%lx):already mapped. %d\n",
				ihk_mc_get_processor_id(), vm, range->start,
				range->end, range->flag, fault_addr, error);
		goto out;
	}

	/* (2) select page size */
#ifdef USE_LARGE_PAGES
	if (!ptep) {
		/* get largest page size */
		error = arch_get_smaller_page_size(NULL, -1, &ptepgsize, &ptep2align);
		if (error) {
			kprintf("[%d]page_fault_process_memory_range"
					"(%p,%lx-%lx %lx,%lx):"
					"get pgsize failed. %d\n",
					ihk_mc_get_processor_id(), vm,
					range->start, range->end,
					range->flag, fault_addr, error);
			goto out;
		}
	}
#else
	if (!ptep || (ptepgsize != PAGE_SIZE)) {
		ptep = NULL;
		ptepgsize = PAGE_SIZE;
		ptep2align = PAGE_P2ALIGN;
	}
#endif
	pgsize = ptepgsize;
	p2align = ptep2align;

	/* (3) get physical page */
	for (;;) {
		pgaddr = (void *)(fault_addr & ~(pgsize - 1));

		if ((range->start <= (uintptr_t)pgaddr)
				&& (((uintptr_t)pgaddr + pgsize) <= range->end)) {
			npages = pgsize / PAGE_SIZE;
			if (range->memobj) {
				off = range->objoff + ((uintptr_t)pgaddr - range->start);
				error = memobj_get_page(range->memobj, off, p2align, &phys);
				if (!error) {
					page = phys_to_page(phys);
					break;
				}
				else if (error == -ERESTART) {
					goto out;
				}
				else if (error != -ENOMEM) {
					kprintf("[%d]page_fault_process_memory_range"
							"(%p,%lx-%lx %lx,%lx):"
							"get page failed. %d\n",
							ihk_mc_get_processor_id(), vm,
							range->start, range->end,
							range->flag, fault_addr, error);
					goto out;
				}
			}
			else {
				virt = ihk_mc_alloc_aligned_pages(npages,
						p2align, IHK_MC_AP_NOWAIT);
				if (virt) {
					phys = virt_to_phys(virt);
					memset(virt, 0, pgsize);
					break;
				}
			}
		}

		/* (4) if failed, select smaller page size, and retry */
		ptep = NULL;
		error = arch_get_smaller_page_size(
				vm, pgsize, &pgsize, &p2align);
		if (error) {
			kprintf("[%d]page_fault_process_memory_range"
					"(%p,%lx-%lx %lx,%lx):"
					"get pgsize failed. %d\n",
					ihk_mc_get_processor_id(), vm,
					range->start, range->end,
					range->flag, fault_addr, error);
			goto out;
		}
	}

	/* (5) mapping */
	attr = vrflag_to_ptattr(range->flag);
	if (range->memobj && (range->flag & VR_PRIVATE) && (range->flag & VR_PROT_WRITE)) {
		/* for copy-on-write */
		attr &= ~PTATTR_WRITABLE;
	}
	if (ptep) {
		error = ihk_mc_pt_set_pte(vm->page_table, ptep, pgsize, phys, attr);
		if (error) {
			kprintf("[%d]page_fault_process_memory_range"
					"(%p,%lx-%lx %lx,%lx):"
					"set pte failed. %d\n",
					ihk_mc_get_processor_id(), vm,
					range->start, range->end,
					range->flag, fault_addr, error);
			goto out;
		}
	}
	else {
		error = ihk_mc_pt_set_range(vm->page_table, pgaddr,
				pgaddr+pgsize, phys, attr);
		if (error) {
			kprintf("[%d]page_fault_process_memory_range"
					"(%p,%lx-%lx %lx,%lx):"
					"set range failed. %d\n",
					ihk_mc_get_processor_id(), vm,
					range->start, range->end,
					range->flag, fault_addr, error);
			goto out;
		}
	}
	virt = NULL;	/* avoid ihk_mc_free_pages() */
	page = NULL;	/* avoid page_unmap() */

	error = 0;
out:
	ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
	if (page) {
		int need_free;

		memobj_lock(range->memobj);
		need_free = page_unmap(page);
		memobj_unlock(range->memobj);

		if (need_free) {
			ihk_mc_free_pages(phys_to_virt(phys), npages);
		}
	}
	if (virt != NULL) {
		ihk_mc_free_pages(virt, npages);
	}
	dkprintf("[%d]page_fault_process_memory_range(%p,%lx-%lx %lx,%lx): %d\n",
			ihk_mc_get_processor_id(), vm, range->start,
			range->end, range->flag, fault_addr, error);
	return error;
}

static int protection_fault_process_memory_range(struct process_vm *vm, struct vm_range *range, uintptr_t fault_addr)
{
	int error;
	pte_t *ptep;
	void *pgaddr;
	size_t pgsize;
	int pgp2align;
	int npages;
	uintptr_t oldpa;
	void *oldkva;
	void *newkva;
	uintptr_t newpa;
	struct page *oldpage;
	enum ihk_mc_pt_attribute attr;

	dkprintf("protection_fault_process_memory_range(%p,%lx-%lx %lx,%lx)\n",
			vm, range->start, range->end, range->flag, fault_addr);

	if (!range->memobj) {
		error = -EFAULT;
		kprintf("protection_fault_process_memory_range"
				"(%p,%lx-%lx %lx,%lx):no memobj. %d\n",
				vm, range->start, range->end, range->flag,
				fault_addr, error);
		goto out;
	}

	ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
	ptep = ihk_mc_pt_lookup_pte(vm->page_table, (void *)fault_addr, &pgaddr, &pgsize, &pgp2align);
	if (!ptep || !pte_is_present(ptep)) {
		error = 0;
		kprintf("protection_fault_process_memory_range"
				"(%p,%lx-%lx %lx,%lx):page not found. %d\n",
				vm, range->start, range->end, range->flag,
				fault_addr, error);
		flush_tlb();
		goto out;
	}
	if (pgsize != PAGE_SIZE) {
		panic("protection_fault_process_memory_range:NYI:cow large page");
	}
	npages = 1 << pgp2align;

	oldpa = pte_get_phys(ptep);
	oldkva = phys_to_virt(oldpa);
	oldpage = phys_to_page(oldpa);

	if (oldpage) {
		newpa = memobj_copy_page(range->memobj, oldpa, pgp2align);
		newkva = phys_to_virt(newpa);
	}
	else {
		newkva = ihk_mc_alloc_aligned_pages(npages, pgp2align,
				IHK_MC_AP_NOWAIT);
		if (!newkva) {
			error = -ENOMEM;
			kprintf("protection_fault_process_memory_range"
					"(%p,%lx-%lx %lx,%lx):"
					"alloc page failed. %d\n",
					vm, range->start, range->end,
					range->flag, fault_addr, error);
			goto out;
		}

		memcpy(newkva, oldkva, pgsize);
		newpa = virt_to_phys(newkva);
	}

	attr = vrflag_to_ptattr(range->flag);
	error = ihk_mc_pt_set_pte(vm->page_table, ptep, pgsize, newpa, attr);
	if (error) {
		kprintf("protection_fault_process_memory_range"
				"(%p,%lx-%lx %lx,%lx):set pte failed. %d\n",
				vm, range->start, range->end, range->flag,
				fault_addr, error);
		panic("protection_fault_process_memory_range:ihk_mc_pt_set_pte failed.");
		ihk_mc_free_pages(newkva, npages);
		goto out;
	}
	flush_tlb_single(fault_addr);

	error = 0;
out:
	ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
	dkprintf("protection_fault_process_memory_range"
			"(%p,%lx-%lx %lx,%lx): %d\n",
			vm, range->start, range->end, range->flag,
			fault_addr, error);
	return error;
}

static int do_page_fault_process(struct process *proc, void *fault_addr0, uint64_t reason)
{
	struct process_vm *vm = proc->vm;
	int error;
	const uintptr_t fault_addr = (uintptr_t)fault_addr0;
	struct vm_range *range;

	dkprintf("[%d]do_page_fault_process(%p,%lx,%lx)\n",
			ihk_mc_get_processor_id(), proc, fault_addr0, reason);

	ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);

	range = lookup_process_memory_range(vm, fault_addr, fault_addr+1);
	if (range == NULL) {
		error = -EFAULT;
		kprintf("[%d]do_page_fault_process(%p,%lx,%lx):"
				"out of range. %d\n",
				ihk_mc_get_processor_id(), proc,
				fault_addr0, reason, error);
		goto out;
	}

	if (((range->flag & VR_PROT_MASK) == VR_PROT_NONE)
			|| ((reason & PF_WRITE)
				&& !(range->flag & VR_PROT_WRITE))) {
		error = -EFAULT;
		kprintf("[%d]do_page_fault_process(%p,%lx,%lx):"
				"access denied. %d\n",
				ihk_mc_get_processor_id(), proc,
				fault_addr0, reason, error);
		goto out;
	}

	if (reason & PF_PROT) {
		error = protection_fault_process_memory_range(vm, range, fault_addr);
		if (error) {
			kprintf("[%d]do_page_fault_process(%p,%lx,%lx):"
					"protection range failed. %d\n",
					ihk_mc_get_processor_id(), proc,
					fault_addr0, reason, error);
			goto out;
		}
	}
	else {
		error = page_fault_process_memory_range(vm, range, fault_addr);
		if (error == -ERESTART) {
			goto out;
		}
		if (error) {
			kprintf("[%d]do_page_fault_process(%p,%lx,%lx):"
					"fault range failed. %d\n",
					ihk_mc_get_processor_id(), proc,
					fault_addr0, reason, error);
			goto out;
		}
	}

	error = 0;
out:
	ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);
	dkprintf("[%d]do_page_fault_process(%p,%lx,%lx): %d\n",
			ihk_mc_get_processor_id(), proc, fault_addr0,
			reason, error);
	return error;
}

int page_fault_process(struct process *proc, void *fault_addr, uint64_t reason)
{
	int error;

	if (proc != cpu_local_var(current)) {
		panic("page_fault_process: other process");
	}

	for (;;) {
		error = do_page_fault_process(proc, fault_addr, reason);
		if (error != -ERESTART) {
			break;
		}

		if (proc->pgio_fp) {
			(*proc->pgio_fp)(proc->pgio_arg);
			proc->pgio_fp = NULL;
		}
	}

	return error;
}

int init_process_stack(struct process *process, struct program_load_desc *pn,
                        int argc, char **argv, 
                        int envc, char **env)
{
	int s_ind = 0;
	int arg_ind;
	unsigned long size;
	unsigned long end = process->vm->region.user_end;
	unsigned long start;
	int rc;
	unsigned long vrflag;
	char *stack;
	int error;
	unsigned long *p;
	unsigned long minsz;

	/* create stack range */
	minsz = PAGE_SIZE;
	size = process->rlimit_stack.rlim_cur & PAGE_MASK;
	if (size > (USER_END / 2)) {
		size = USER_END / 2;
	}
	else if (size < minsz) {
		size = minsz;
	}
	start = end - size;

	vrflag = VR_STACK | VR_DEMAND_PAGING;
	vrflag |= VR_PROT_READ | VR_PROT_WRITE | VR_PROT_EXEC;
	vrflag |= VRFLAG_PROT_TO_MAXPROT(vrflag);
#define	NOPHYS	((uintptr_t)-1)
	if ((rc = add_process_memory_range(process, start, end, NOPHYS,
					vrflag, NULL, 0)) != 0) {
		return rc;
	}

	/* map physical pages for initial stack frame */
	stack = ihk_mc_alloc_pages(minsz >> PAGE_SHIFT, IHK_MC_AP_NOWAIT);
	if (!stack) {
		return -ENOMEM;
	}
	memset(stack, 0, minsz);
	error = ihk_mc_pt_set_range(process->vm->page_table,
			(void *)(end-minsz), (void *)end,
			virt_to_phys(stack), vrflag_to_ptattr(vrflag));
	if (error) {
		kprintf("init_process_stack:"
				"set range %lx-%lx %lx failed. %d\n",
				(end-minsz), end, stack, error);
		ihk_mc_free_pages(stack, minsz >> PAGE_SHIFT);
		return error;
	}

	/* set up initial stack frame */
	p = (unsigned long *)(stack + minsz);
	s_ind = -1;
	p[s_ind--] = 0;     /* AT_NULL */
	p[s_ind--] = 0;
	p[s_ind--] = pn->at_entry; /* AT_ENTRY */
	p[s_ind--] = AT_ENTRY;
	p[s_ind--] = pn->at_phnum; /* AT_PHNUM */
	p[s_ind--] = AT_PHNUM;
	p[s_ind--] = pn->at_phent;  /* AT_PHENT */
	p[s_ind--] = AT_PHENT;
	p[s_ind--] = pn->at_phdr;  /* AT_PHDR */
	p[s_ind--] = AT_PHDR;	
	p[s_ind--] = 0;     /* envp terminating NULL */
	/* envp */
	for (arg_ind = envc - 1; arg_ind > -1; --arg_ind) {
		p[s_ind--] = (unsigned long)env[arg_ind];
	}
	
	p[s_ind--] = 0; /* argv terminating NULL */
	/* argv */
	for (arg_ind = argc - 1; arg_ind > -1; --arg_ind) {
		p[s_ind--] = (unsigned long)argv[arg_ind];
	}
	/* argc */
	p[s_ind] = argc;

	ihk_mc_modify_user_context(process->uctx, IHK_UCR_STACK_POINTER,
	                           end + sizeof(unsigned long) * s_ind);
	process->vm->region.stack_end = end;
	process->vm->region.stack_start = start;
	return 0;
}


unsigned long extend_process_region(struct process *proc,
                                    unsigned long start, unsigned long end,
                                    unsigned long address, unsigned long flag)
{
	unsigned long aligned_end, aligned_new_end;
	void *p;
	int rc;

	if (!address || address < start || address >= USER_END) {
		return end;
	}

	aligned_end = ((end + PAGE_SIZE - 1) & PAGE_MASK);

	if (aligned_end >= address) {
		return address;
	}

	aligned_new_end = (address + PAGE_SIZE - 1) & PAGE_MASK;

#ifdef USE_LARGE_PAGES
	if (aligned_new_end - aligned_end >= LARGE_PAGE_SIZE) {
	  if(flag & VR_DEMAND_PAGING){panic("demand paging for large page is not available!");}
		unsigned long p_aligned;
		unsigned long old_aligned_end = aligned_end;

		if ((aligned_end & (LARGE_PAGE_SIZE - 1)) != 0) {

			aligned_end = (aligned_end + (LARGE_PAGE_SIZE - 1)) & LARGE_PAGE_MASK;
			/* Fill in the gap between old_aligned_end and aligned_end
			 * with regular pages */
			if((p = allocate_pages((aligned_end - old_aligned_end) >> PAGE_SHIFT,
                                 IHK_MC_AP_NOWAIT)) == NULL){
				return end;
			}
			if((rc = add_process_memory_range(proc, old_aligned_end,
                                        aligned_end, virt_to_phys(p), flag)) != 0){
				free_pages(p, (aligned_end - old_aligned_end) >> PAGE_SHIFT);
				return end;
			}
			
			dkprintf("filled in gap for LARGE_PAGE_SIZE aligned start: 0x%lX -> 0x%lX\n",
					old_aligned_end, aligned_end);
		}
	
		/* Add large region for the actual mapping */
		aligned_new_end = (aligned_new_end + (aligned_end - old_aligned_end) +
				(LARGE_PAGE_SIZE - 1)) & LARGE_PAGE_MASK;
		address = aligned_new_end;

		if((p = allocate_pages((aligned_new_end - aligned_end + LARGE_PAGE_SIZE) >> PAGE_SHIFT,
                            IHK_MC_AP_NOWAIT)) == NULL){
			return end;
		}

		p_aligned = ((unsigned long)p + (LARGE_PAGE_SIZE - 1)) & LARGE_PAGE_MASK;

		if (p_aligned > (unsigned long)p) {
			free_pages(p, (p_aligned - (unsigned long)p) >> PAGE_SHIFT);
		}
		free_pages(
			(void *)(p_aligned + aligned_new_end - aligned_end),
			(LARGE_PAGE_SIZE - (p_aligned - (unsigned long)p)) >> PAGE_SHIFT);

		if((rc = add_process_memory_range(proc, aligned_end,
                               aligned_new_end, virt_to_phys((void *)p_aligned),
                               flag)) != 0){
			free_pages(p, (aligned_new_end - aligned_end + LARGE_PAGE_SIZE) >> PAGE_SHIFT);
			return end;
		}

		dkprintf("largePTE area: 0x%lX - 0x%lX (s: %lu) -> 0x%lX - \n",
				aligned_end, aligned_new_end, 
				(aligned_new_end - aligned_end), 
				virt_to_phys((void *)p_aligned));

		return address;
	}
#endif
	if(flag & VR_DEMAND_PAGING){
	  // demand paging no need to allocate page now
	  kprintf("demand page do not allocate page\n");
	  p=0;
	}else{

	p = allocate_pages((aligned_new_end - aligned_end) >> PAGE_SHIFT, IHK_MC_AP_NOWAIT);

	if (!p) {
		return end;
	}
    }	
	if((rc = add_process_memory_range(proc, aligned_end, aligned_new_end,
                                      (p==0?0:virt_to_phys(p)), flag, NULL, 0)) != 0){
		free_pages(p, (aligned_new_end - aligned_end) >> PAGE_SHIFT);
		return end;
	}
	
	return address;
}

// Original version retained because dcfa (src/mccmd/client/ibmic/main.c) calls this 
int remove_process_region(struct process *proc,
                          unsigned long start, unsigned long end)
{
	if ((start & (PAGE_SIZE - 1)) || (end & (PAGE_SIZE - 1))) {
		return -EINVAL;
	}

	ihk_mc_spinlock_lock_noirq(&proc->vm->page_table_lock);
	/* We defer freeing to the time of exit */
	// XXX: check error
	ihk_mc_pt_clear_range(proc->vm->page_table, (void *)start, (void *)end);
	ihk_mc_spinlock_unlock_noirq(&proc->vm->page_table_lock);

	return 0;
}

void flush_process_memory(struct process *proc)
{
	struct process_vm *vm = proc->vm;
	struct vm_range *range;
	struct vm_range *next;
	int error;

	dkprintf("flush_process_memory(%p)\n", proc);
	ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);
	list_for_each_entry_safe(range, next, &vm->vm_range_list, list) {
		if (range->memobj) {
			// XXX: temporary of temporary
			error = free_process_memory_range(vm, range);
			if (error) {
				ekprintf("flush_process_memory(%p):"
						"free range failed. %lx-%lx %d\n",
						proc, range->start, range->end, error);
				/* through */
			}
		}
	}
	ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);
	dkprintf("flush_process_memory(%p):\n", proc);
	return;
}

void free_process_memory(struct process *proc)
{
	struct vm_range *range, *next;
	struct process_vm *vm = proc->vm;
	int error;

	if (vm == NULL) {
		return;
	}

	proc->vm = NULL;
	if (!ihk_atomic_dec_and_test(&vm->refcount)) {
		return;
	}

	ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);
	list_for_each_entry_safe(range, next, &vm->vm_range_list, list) {
		error = free_process_memory_range(vm, range);
		if (error) {
			ekprintf("free_process_memory(%p):"
					"free range failed. %lx-%lx %d\n",
					proc, range->start, range->end, error);
			/* through */
		}
	}
	ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);

	ihk_mc_pt_destroy(vm->page_table);
	free_process(vm->owner_process);
}

void hold_process(struct process *proc)
{
	if (proc->status & (PS_ZOMBIE | PS_EXITED)) {
		panic("hold_process: already exited process");
	}

	ihk_atomic_inc(&proc->refcount);
	return;
}

void destroy_process(struct process *proc)
{
	struct sig_pending *pending;
	struct sig_pending *next;
	if(ihk_atomic_dec_and_test(&proc->sighandler->use)){
		kfree(proc->sighandler);
	}
	if(ihk_atomic_dec_and_test(&proc->sigshared->use)){
		list_for_each_entry_safe(pending, next, &proc->sigshared->sigpending, list){
			list_del(&pending->list);
			kfree(pending);
		}
		list_del(&proc->sigshared->sigpending);
		kfree(proc->sigshared);
	}
	list_for_each_entry_safe(pending, next, &proc->sigpending, list){
		list_del(&pending->list);
		kfree(pending);
	}
	ihk_mc_free_pages(proc, KERNEL_STACK_NR_PAGES);
}

void free_process(struct process *proc)
{
	if (!ihk_atomic_dec_and_test(&proc->refcount)) {
		return;
	}

	destroy_process(proc);
}

static void idle(void)
{
	//unsigned int	flags;
	//flags = ihk_mc_spinlock_lock(&cpu_status_lock);
	//ihk_mc_spinlock_unlock(&cpu_status_lock, flags);
	cpu_local_var(status) = CPU_STATUS_IDLE;

	while (1) {
		cpu_enable_interrupt();
		schedule();
		//cpu_local_var(status) = CPU_STATUS_IDLE;
		cpu_halt();
	}
}

void sched_init(void)
{
	struct process *idle_process = &cpu_local_var(idle);

	memset(idle_process, 0, sizeof(struct process));
	memset(&cpu_local_var(idle_vm), 0, sizeof(struct process_vm));

	idle_process->vm = &cpu_local_var(idle_vm);

	ihk_mc_init_context(&idle_process->ctx, NULL, idle);
	idle_process->pid = 0;
	idle_process->tid = ihk_mc_get_processor_id();

	INIT_LIST_HEAD(&cpu_local_var(runq));
	cpu_local_var(runq_len) = 0;
	ihk_mc_spinlock_init(&cpu_local_var(runq_lock));

#ifdef TIMER_CPU_ID
	if (ihk_mc_get_processor_id() == TIMER_CPU_ID) {
		init_timers();
		wake_timers_loop();
	}
#endif
}

void schedule(void)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	struct process *next, *prev, *proc, *tmp = NULL;
	int switch_ctx = 0;
	unsigned long irqstate;
	struct process *last;

	irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));

	next = NULL;
	prev = v->current;

	/* All runnable processes are on the runqueue */
	if (prev && prev != &cpu_local_var(idle)) {
		list_del(&prev->sched_list);
		--v->runq_len;	
		
		/* Round-robin if not exited yet */
		if (!(prev->status & (PS_ZOMBIE | PS_EXITED))) {
			list_add_tail(&prev->sched_list, &(v->runq));
			++v->runq_len;
		}

		if (!v->runq_len) {
			v->status = CPU_STATUS_IDLE;
		}
	}

	/* Pick a new running process */
	list_for_each_entry_safe(proc, tmp, &(v->runq), sched_list) {
		if (proc->status == PS_RUNNING) {
			next = proc;
			break;
		}
	}

	/* No process? Run idle.. */
	if (!next) {
		next = &cpu_local_var(idle);
	}

	if (prev != next) {
		switch_ctx = 1;
		v->current = next;
	}
	
	if (switch_ctx) {
		dkprintf("[%d] schedule: %d => %d \n",
		        ihk_mc_get_processor_id(),
		        prev ? prev->tid : 0, next ? next->tid : 0);

		ihk_mc_load_page_table(next->vm->page_table);
		
		dkprintf("[%d] schedule: tlsblock_base: 0x%lX\n", 
		         ihk_mc_get_processor_id(), next->thread.tlsblock_base); 

		/* Set up new TLS.. */
		do_arch_prctl(ARCH_SET_FS, next->thread.tlsblock_base);
		
		ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
		
		if (prev) {
			last = ihk_mc_switch_context(&prev->ctx, &next->ctx, prev);
		} 
		else {
			last = ihk_mc_switch_context(NULL, &next->ctx, prev);
		}

		if ((last != NULL) && (last->status & (PS_ZOMBIE | PS_EXITED))) {
			free_process_memory(last);
			free_process(last);
		}
	}
	else {
		ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
	}
}


int sched_wakeup_process(struct process *proc, int valid_states)
{
	int status;
	int spin_slept = 0;
	unsigned long irqstate;
	struct cpu_local_var *v = get_cpu_local_var(proc->cpu_id);
	
	irqstate = ihk_mc_spinlock_lock(&(proc->spin_sleep_lock));
	if (proc->spin_sleep) {
		dkprintf("sched_wakeup_process() spin wakeup: cpu_id: %d\n", 
				proc->cpu_id);

		spin_slept = 1;
		proc->spin_sleep = 0;
		status = 0;	
	}
	ihk_mc_spinlock_unlock(&(proc->spin_sleep_lock), irqstate);
	
	if (spin_slept)
		return status;

	irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
	
	if (proc->status & valid_states) {
		xchg4((int *)(&proc->status), PS_RUNNING);
		status = 0;
	} 
	else {
		status = -EINVAL;
	}

	ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);

	if (!status && (proc->cpu_id != ihk_mc_get_processor_id())) {
		ihk_mc_interrupt_cpu(get_x86_cpu_local_variable(proc->cpu_id)->apic_id,
		                     0xd1);
	}

	return status;
}



/* Runq lock must be held here */
void __runq_add_proc(struct process *proc, int cpu_id)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	list_add_tail(&proc->sched_list, &v->runq);
	++v->runq_len;
	proc->cpu_id = cpu_id;
	proc->status = PS_RUNNING;
	get_cpu_local_var(cpu_id)->status = CPU_STATUS_RUNNING;

	dkprintf("runq_add_proc(): tid %d added to CPU[%d]'s runq\n", 
             proc->tid, cpu_id);
}

void runq_add_proc(struct process *proc, int cpu_id)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	unsigned long irqstate;
	
	irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
	__runq_add_proc(proc, cpu_id);
	ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);

	/* Kick scheduler */
	if (cpu_id != ihk_mc_get_processor_id())
		ihk_mc_interrupt_cpu(
		         get_x86_cpu_local_variable(cpu_id)->apic_id, 0xd1);
}

/* NOTE: shouldn't remove a running process! */
void runq_del_proc(struct process *proc, int cpu_id)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	unsigned long irqstate;
	
	irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
	list_del(&proc->sched_list);
	--v->runq_len;
	
	if (!v->runq_len)
		get_cpu_local_var(cpu_id)->status = CPU_STATUS_IDLE;

	ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
}

