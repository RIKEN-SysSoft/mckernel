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
#define dkprintf(...) do { if (0) kprintf(__VA_ARGS__); } while (0)
#define ekprintf(...) kprintf(__VA_ARGS__)
#endif

extern long do_arch_prctl(unsigned long code, unsigned long address);
extern long alloc_debugreg(struct process *proc);
extern void save_debugreg(unsigned long *debugreg);
extern void restore_debugreg(unsigned long *debugreg);
extern void clear_debugreg(void);
extern void clear_single_step(struct process *proc);
static void insert_vm_range_list(struct process_vm *vm, 
		struct vm_range *newrange);
static int copy_user_ranges(struct process *proc, struct process *org);
extern void release_fp_regs(struct process *proc);
extern void save_fp_regs(struct process *proc);
extern void restore_fp_regs(struct process *proc);
void settid(struct process *proc, int mode, int newcpuid, int oldcpuid);
extern void __runq_add_proc(struct process *proc, int cpu_id);
extern void terminate_host(int pid);
extern void lapic_timer_enable(unsigned int clocks);
extern void lapic_timer_disable();

int refcount_fork_tree_node(struct fork_tree_node *ftn)
{
	return ihk_atomic_read(&ftn->refcount);
}

void hold_fork_tree_node(struct fork_tree_node *ftn)
{
	ihk_atomic_inc(&ftn->refcount);
	dkprintf("hold ftn(%d): %d\n", 
			ftn->pid, ihk_atomic_read(&ftn->refcount));
}

void release_fork_tree_node(struct fork_tree_node *ftn)
{
	dkprintf("release ftn(%d): %d\n", 
			ftn->pid, ihk_atomic_read(&ftn->refcount));
	
	if (!ihk_atomic_dec_and_test(&ftn->refcount)) {
		return;
	}
	
	dkprintf("dealloc ftn(%d): %d\n", 
			ftn->pid, ihk_atomic_read(&ftn->refcount));
	
	/* Dealloc */
	kfree(ftn);
}


void init_fork_tree_node(struct fork_tree_node *ftn, 
		struct fork_tree_node *parent, struct process *owner)
{
	ihk_mc_spinlock_init(&ftn->lock);
	/* Only the process/thread holds a reference at this point */
	ihk_atomic_set(&ftn->refcount, 1);
	
	ftn->owner = owner;

	/* These will be filled out when changing status */
	ftn->pid = -1;
	ftn->exit_status = -1;
	ftn->status = PS_RUNNING;

	ftn->group_exit_status = 0;
	ftn->ptrace = 0;
	ftn->signal_flags = 0;

	ftn->parent = NULL;
	if (parent) {
		ftn->parent = parent;
		ftn->pgid = parent->pgid;
		ftn->ruid = parent->ruid;
		ftn->euid = parent->euid;
		ftn->suid = parent->suid;
		ftn->fsuid = parent->fsuid;
		ftn->rgid = parent->rgid;
		ftn->egid = parent->egid;
		ftn->sgid = parent->sgid;
		ftn->fsgid = parent->fsgid;
	}
	INIT_LIST_HEAD(&ftn->children);
	INIT_LIST_HEAD(&ftn->siblings_list);

	INIT_LIST_HEAD(&ftn->ptrace_children);
	INIT_LIST_HEAD(&ftn->ptrace_siblings_list);
	
	waitq_init(&ftn->waitpid_q);
}

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
	memset(&vm->cpu_set, 0, sizeof(cpu_set_t));
	ihk_mc_spinlock_init(&vm->cpu_set_lock);
	vm->exiting = 0;

	return 0;
}

struct process *create_process(unsigned long user_pc)
{
	struct process *proc;

	proc = ihk_mc_alloc_pages(KERNEL_STACK_NR_PAGES, IHK_MC_AP_NOWAIT);
	if (!proc)
		return NULL;

	memset(proc, 0, sizeof(struct process));
	ihk_atomic_set(&proc->refcount, 2);	
	if (1) {
		struct ihk_mc_cpu_info *infop;
		int i;

		infop = ihk_mc_get_cpu_info();
		for (i = 0; i < infop->ncpus; ++i) {
			CPU_SET(i, &proc->cpu_set);
		}
	}

	proc->sched_policy = SCHED_NORMAL;

	proc->sighandler = kmalloc(sizeof(struct sig_handler), IHK_MC_AP_NOWAIT);
	if(!proc->sighandler){
		goto err_free_process;
	}
	proc->sigshared = kmalloc(sizeof(struct sig_shared), IHK_MC_AP_NOWAIT);
	if(!proc->sigshared){
		goto err_free_sighandler;
	}
	memset(proc->sighandler, '\0', sizeof(struct sig_handler));
	ihk_atomic_set(&proc->sighandler->use, 1);
	ihk_mc_spinlock_init(&proc->sighandler->lock);
	ihk_atomic_set(&proc->sigshared->use, 1);
	ihk_mc_spinlock_init(&proc->sigshared->lock);
	INIT_LIST_HEAD(&proc->sigshared->sigpending);
	ihk_mc_spinlock_init(&proc->sigpendinglock);
	INIT_LIST_HEAD(&proc->sigpending);

	proc->sigstack.ss_sp = NULL;
	proc->sigstack.ss_flags = SS_DISABLE;
	proc->sigstack.ss_size = 0;

	ihk_mc_init_user_process(&proc->ctx, &proc->uctx,
	                         ((char *)proc) + 
							 KERNEL_STACK_NR_PAGES * PAGE_SIZE, user_pc, 0);

	proc->vm = (struct process_vm *)(proc + 1);

	proc->ftn = kmalloc(sizeof(struct fork_tree_node), IHK_MC_AP_NOWAIT);
	if (!proc->ftn) {
		goto err_free_sigshared;
	}

	init_fork_tree_node(proc->ftn, NULL, proc);

	if(init_process_vm(proc, proc->vm) != 0){
		goto err_free_sigshared;
	}

	cpu_set(ihk_mc_get_processor_id(), &proc->vm->cpu_set, 
			&proc->vm->cpu_set_lock);

	ihk_mc_spinlock_init(&proc->spin_sleep_lock);
	proc->spin_sleep = 0;

	return proc;

err_free_sigshared:
	kfree(proc->sigshared);

err_free_sighandler:
	kfree(proc->sighandler);

err_free_process:
	ihk_mc_free_pages(proc, KERNEL_STACK_NR_PAGES);
	
	return NULL;
}

struct process *clone_process(struct process *org, unsigned long pc,
                              unsigned long sp, int clone_flags)
{
	struct process *proc;
	int termsig = clone_flags & 0xff;

	if (termsig < 0 || _NSIG < termsig) {
		return (void *)-EINVAL;
	}

	if ((proc = ihk_mc_alloc_pages(KERNEL_STACK_NR_PAGES, 
					IHK_MC_AP_NOWAIT)) == NULL) {
		return NULL;
	}

	memset(proc, 0, sizeof(struct process));
	ihk_atomic_set(&proc->refcount, 2);	
	memcpy(&proc->cpu_set, &org->cpu_set, sizeof(proc->cpu_set));

	/* NOTE: sp is the user mode stack! */
	ihk_mc_init_user_process(&proc->ctx, &proc->uctx,
	                         ((char *)proc) + 
							 KERNEL_STACK_NR_PAGES * PAGE_SIZE, pc, sp);

	memcpy(proc->uctx, org->uctx, sizeof(*org->uctx));
	ihk_mc_modify_user_context(proc->uctx, IHK_UCR_STACK_POINTER, sp);
	ihk_mc_modify_user_context(proc->uctx, IHK_UCR_PROGRAM_COUNTER, pc);

	memcpy(proc->rlimit, org->rlimit, sizeof(struct rlimit) * MCK_RLIM_MAX);
	proc->sigmask = org->sigmask;
	
	proc->ftn = kmalloc(sizeof(struct fork_tree_node), IHK_MC_AP_NOWAIT);
	if (!proc->ftn) {
		goto err_free_sigshared;
	}

	proc->ftn->termsig = termsig;

	init_fork_tree_node(proc->ftn, org->ftn, proc);

	proc->sched_policy = org->sched_policy;
	proc->sched_param.sched_priority = org->sched_param.sched_priority;

	/* clone signal handlers */
	if (clone_flags & CLONE_SIGHAND) {
		proc->sigstack.ss_sp = NULL;
		proc->sigstack.ss_flags = SS_DISABLE;
		proc->sigstack.ss_size = 0;

		proc->sighandler = org->sighandler;
		ihk_atomic_inc(&org->sighandler->use);

		proc->sigshared = org->sigshared;
		ihk_atomic_inc(&org->sigshared->use);

		ihk_mc_spinlock_init(&proc->sigpendinglock);
		INIT_LIST_HEAD(&proc->sigpending);
	}
	/* copy signal handlers (i.e., fork()) */
	else {
		dkprintf("fork(): sighandler\n");
		proc->sighandler = kmalloc(sizeof(struct sig_handler), 
				IHK_MC_AP_NOWAIT);
		
		if (!proc->sighandler) {
			goto err_free_proc;
		}

		dkprintf("fork(): sigshared\n");
		proc->sigshared = kmalloc(sizeof(struct sig_shared), IHK_MC_AP_NOWAIT);
		
		if (!proc->sigshared) {
			goto err_free_sighandler;
		}

		memcpy(proc->sighandler, org->sighandler, sizeof(struct sig_handler));
		ihk_atomic_set(&proc->sighandler->use, 1);
		ihk_mc_spinlock_init(&proc->sighandler->lock);
		ihk_atomic_set(&proc->sigshared->use, 1);
		ihk_mc_spinlock_init(&proc->sigshared->lock);
		INIT_LIST_HEAD(&proc->sigshared->sigpending);
		ihk_mc_spinlock_init(&proc->sigpendinglock);
		INIT_LIST_HEAD(&proc->sigpending);
	}

	/* clone VM */
	if (clone_flags & CLONE_VM) {
		ihk_atomic_inc(&org->vm->refcount);
		proc->vm = org->vm;
	}
	/* fork() */
	else {
		proc->vm = (struct process_vm *)(proc + 1);
		
		dkprintf("fork(): init_process_vm()\n");
		if (init_process_vm(proc, proc->vm) != 0) {
			goto err_free_sigshared;
		}

		memcpy(&proc->vm->region, &org->vm->region, sizeof(struct vm_regions));
		
		dkprintf("fork(): copy_user_ranges()\n");
		/* Copy user-space mappings.
		 * TODO: do this with COW later? */	
		if (copy_user_ranges(proc, org) != 0) {
			goto err_free_sigshared;
		}
		
		dkprintf("fork(): copy_user_ranges() OK\n");
	}
	
	/* Add thread/proc's fork_tree_node to parent's children list */
	ihk_mc_spinlock_lock_noirq(&org->ftn->lock);
	list_add_tail(&proc->ftn->siblings_list, &org->ftn->children);
	ihk_mc_spinlock_unlock_noirq(&org->ftn->lock);	

	/* We hold a reference to parent */
	hold_fork_tree_node(proc->ftn->parent);

	/* Parent holds a reference to us */
	hold_fork_tree_node(proc->ftn);

	ihk_mc_spinlock_init(&proc->spin_sleep_lock);
	proc->spin_sleep = 0;

	return proc;

err_free_sigshared:
	kfree(proc->sigshared);

err_free_sighandler:
	ihk_mc_free_pages(proc->sighandler, KERNEL_STACK_NR_PAGES);

err_free_proc:
	ihk_mc_free_pages(proc, KERNEL_STACK_NR_PAGES);
	release_process(org);
	return NULL;
}

int ptrace_traceme(void){
	int error = 0;
	struct process *proc = cpu_local_var(current);
	struct fork_tree_node *child, *next;
	dkprintf("ptrace_traceme,pid=%d,proc->ftn->parent=%p\n", proc->ftn->pid, proc->ftn->parent);

	if (proc->ftn->parent == NULL || proc->ftn->ptrace) {
		error = -EPERM;
		goto out;
	}

	dkprintf("ptrace_traceme,parent->pid=%d\n", proc->ftn->parent->pid);

	ihk_mc_spinlock_lock_noirq(&proc->ftn->lock);

	ihk_mc_spinlock_lock_noirq(&proc->ftn->parent->lock);
	list_for_each_entry_safe(child, next, &proc->ftn->parent->children, siblings_list) {
		if(child == proc->ftn) {
			list_del(&child->siblings_list);
			goto found;
		}
	}
	kprintf("ptrace_traceme,not found\n");
	error = -EPERM;
	goto out_notfound;
 found:
	proc->ftn->ptrace = PT_TRACED | PT_TRACE_EXEC;
	proc->ftn->ppid_parent = proc->ftn->parent;

	list_add_tail(&proc->ftn->ptrace_siblings_list, &proc->ftn->parent->ptrace_children);

	ihk_mc_spinlock_unlock_noirq(&proc->ftn->parent->lock);
	ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);

	if (proc->ptrace_debugreg == NULL) {
		error = alloc_debugreg(proc);
	}

	clear_single_step(proc);

 out:
	dkprintf("ptrace_traceme,returning,error=%d\n", error);
	return error;
 out_notfound:
	ihk_mc_spinlock_unlock_noirq(&proc->ftn->parent->lock);
	ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);
	goto out;
}

static int copy_user_ranges(struct process *proc, struct process *org) 
{
	struct vm_range *src_range;
	struct vm_range *range;	
	
	ihk_mc_spinlock_lock_noirq(&org->vm->memory_range_lock);

	/* Iterate original process' vm_range list and take a copy one-by-one */
	list_for_each_entry(src_range, &org->vm->vm_range_list, list) {
		void *ptepgaddr;
		size_t ptepgsize;
		int ptep2align;
		void *pg_vaddr;
		size_t pgsize;
		void *vaddr;
		int p2align;
		enum ihk_mc_pt_attribute attr;
		pte_t *ptep;

		range = kmalloc(sizeof(struct vm_range), IHK_MC_AP_NOWAIT);
		if (!range) {
			goto err_rollback;
		}

		INIT_LIST_HEAD(&range->list);
		range->start = src_range->start;
		range->end = src_range->end;
		range->flag = src_range->flag;
		range->memobj = src_range->memobj;
		range->objoff = src_range->objoff;
		if (range->memobj) {
			memobj_ref(range->memobj);
		}

		/* Copy actual mappings */
		vaddr = (void *)range->start; 
		while ((unsigned long)vaddr < range->end) {
			/* Get source PTE */
			ptep = ihk_mc_pt_lookup_pte(org->vm->page_table, vaddr,
					&ptepgaddr, &ptepgsize, &ptep2align);

			if (!ptep || pte_is_null(ptep) || !pte_is_present(ptep)) {
				vaddr += PAGE_SIZE;
				continue;
			}
			if (1) {
				struct page *page;

				page = phys_to_page(pte_get_phys(ptep));
				if (page && page_is_in_memobj(page)) {
					vaddr += PAGE_SIZE;
					continue;
				}
			}

			dkprintf("copy_user_ranges(): 0x%lx PTE found\n", vaddr);
			
			/* Page size */
			if (arch_get_smaller_page_size(NULL, -1, &ptepgsize, 
						&ptep2align)) {

				kprintf("ERROR: copy_user_ranges() "
						"(%p,%lx-%lx %lx,%lx):"
						"get pgsize failed\n", org->vm,
						range->start, range->end,
						range->flag, vaddr);

				goto err_free_range_rollback;
			}
			
			pgsize = ptepgsize;
			p2align = ptep2align;
			dkprintf("copy_user_ranges(): page size: %d\n", pgsize);
			
			/* Get physical page */
			pg_vaddr = ihk_mc_alloc_aligned_pages(1, p2align, IHK_MC_AP_NOWAIT);

			if (!pg_vaddr) {
				kprintf("ERROR: copy_user_ranges() allocating new page\n");
				goto err_free_range_rollback;
			}
			dkprintf("copy_user_ranges(): phys page allocated\n", pgsize);

			/* Copy content */
			memcpy(pg_vaddr, vaddr, pgsize);
			dkprintf("copy_user_ranges(): memcpy OK\n", pgsize);

			/* Set up new PTE */
			attr = arch_vrflag_to_ptattr(range->flag, PF_POPULATE, NULL);
			if (ihk_mc_pt_set_range(proc->vm->page_table, proc->vm, vaddr,
						vaddr + pgsize, virt_to_phys(pg_vaddr), attr)) {
				kprintf("ERROR: copy_user_ranges() "
						"(%p,%lx-%lx %lx,%lx):"
						"set range failed.\n",
						org->vm, range->start, range->end,
						range->flag, vaddr);

				goto err_free_range_rollback;
			}
			dkprintf("copy_user_ranges(): new PTE set\n", pgsize);
			
			vaddr += pgsize;
		}

		insert_vm_range_list(proc->vm, range);
	}

	ihk_mc_spinlock_unlock_noirq(&org->vm->memory_range_lock);
	
	return 0;

err_free_range_rollback:
	kfree(range);

err_rollback:

	/* TODO: implement rollback */


	ihk_mc_spinlock_unlock_noirq(&org->vm->memory_range_lock);

	return -1;
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
	attr |= (range->flag & VR_PROT_EXEC)? 0: PTATTR_NO_EXECUTE;

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
				kprintf("ERROR: setting large page for 0x%lX -> 0x%lX\n", 
						p, pa);
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
				kprintf("ERROR: setting page for 0x%lX -> 0x%lX\n", p, pa);
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

	dkprintf("free_process_memory_range(%p, 0x%lx - 0x%lx)\n",
			vm, range->start, range->end);

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
		error = ihk_mc_pt_free_range(vm->page_table, vm,
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
		error = ihk_mc_pt_clear_range(vm->page_table, vm,
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

enum ihk_mc_pt_attribute common_vrflag_to_ptattr(unsigned long flag, uint64_t fault, pte_t *ptep)
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

	if (!(flag & VR_PROT_EXEC)) {
		attr |= PTATTR_NO_EXECUTE;
	}

	if (flag & VR_WRITE_COMBINED) {
		attr |= PTATTR_WRITE_COMBINED;
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
		kprintf("ERROR: allocating pages for range\n");
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
		dkprintf("range: 0x%lX - 0x%lX (%ld) [%lx]\n",
				range->start, range->end, range->end - range->start,
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
		kprintf("ERROR: preparing page tables\n");
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

int extend_up_process_memory_range(struct process_vm *vm,
		struct vm_range *range, uintptr_t newend)
{
	int error;
	struct vm_range *next;

	dkprintf("exntend_up_process_memory_range(%p,%p %#lx-%#lx,%#lx)\n",
			vm, range, range->start, range->end, newend);
	if (newend <= range->end) {
		error = -EINVAL;
		goto out;
	}

	if (vm->region.user_end < newend) {
		error = -EPERM;
		goto out;
	}

	next = next_process_memory_range(vm ,range);
	if (next && (next->start < newend)) {
		error = -ENOMEM;
		goto out;
	}

	error = 0;
	range->end = newend;

out:
	dkprintf("exntend_up_process_memory_range(%p,%p %#lx-%#lx,%#lx):%d\n",
			vm, range, range->start, range->end, newend, error);
	return error;
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

	oldattr = arch_vrflag_to_ptattr(range->flag, PF_POPULATE, NULL);
	newattr = arch_vrflag_to_ptattr(newflag, PF_POPULATE, NULL);

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

struct rfp_args {
	off_t off;
	uintptr_t start;
	struct memobj *memobj;
};

static int remap_one_page(void *arg0, page_table_t pt, pte_t *ptep,
		void *pgaddr, size_t pgsize)
{
	struct rfp_args * const args = arg0;
	int error;
	off_t off;
	pte_t apte;
	uintptr_t phys;
	struct page *page;

	dkprintf("remap_one_page(%p,%p,%p %#lx,%p,%#lx)\n",
			arg0, pt, ptep, *ptep, pgaddr, pgsize);

	/* XXX: NYI: large pages */
	if (pgsize != PAGE_SIZE) {
		error = -E2BIG;
		ekprintf("remap_one_page(%p,%p,%p %#lx,%p,%#lx):%d\n",
				arg0, pt, ptep, *ptep, pgaddr, pgsize, error);
		goto out;
	}

	off = args->off + ((uintptr_t)pgaddr - args->start);
	pte_make_fileoff(off, 0, pgsize, &apte);

	pte_xchg(ptep, &apte);
	flush_tlb_single((uintptr_t)pgaddr);	/* XXX: TLB flush */

	if (pte_is_null(&apte) || pte_is_fileoff(&apte, pgsize)) {
		error = 0;
		goto out;
	}
	phys = pte_get_phys(&apte);

	if (pte_is_dirty(&apte, pgsize)) {
		memobj_flush_page(args->memobj, phys, pgsize);	/* XXX: in lock period */
	}

	page = phys_to_page(phys);
	if (page && page_unmap(page)) {
		ihk_mc_free_pages(phys_to_virt(phys), pgsize/PAGE_SIZE);
	}

	error = 0;
out:
	dkprintf("remap_one_page(%p,%p,%p %#lx,%p,%#lx): %d\n",
			arg0, pt, ptep, *ptep, pgaddr, pgsize, error);
	return error;
}

int remap_process_memory_range(struct process_vm *vm, struct vm_range *range,
		uintptr_t start, uintptr_t end, off_t off)
{
	struct rfp_args args;
	int error;

	dkprintf("remap_process_memory_range(%p,%p,%#lx,%#lx,%#lx)\n",
			vm, range, start, end, off);
	ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
	memobj_lock(range->memobj);

	args.start = start;
	args.off = off;
	args.memobj = range->memobj;

	error = visit_pte_range(vm->page_table, (void *)start,
			(void *)end, VPTEF_DEFAULT, &remap_one_page, &args);
	if (error) {
		ekprintf("remap_process_memory_range(%p,%p,%#lx,%#lx,%#lx):"
				"visit pte failed %d\n",
				vm, range, start, end, off, error);
		goto out;
	}

	error = 0;
out:
	memobj_unlock(range->memobj);
	ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
	dkprintf("remap_process_memory_range(%p,%p,%#lx,%#lx,%#lx):%d\n",
			vm, range, start, end, off, error);
	return error;
}

struct sync_args {
	struct memobj *memobj;
};

static int sync_one_page(void *arg0, page_table_t pt, pte_t *ptep,
		void *pgaddr, size_t pgsize)
{
	struct sync_args *args = arg0;
	int error;
	uintptr_t phys;

	dkprintf("sync_one_page(%p,%p,%p %#lx,%p,%#lx)\n",
			arg0, pt, ptep, *ptep, pgaddr, pgsize);
	if (pte_is_null(ptep) || pte_is_fileoff(ptep, pgsize)
			|| !pte_is_dirty(ptep, pgsize)) {
		error = 0;
		goto out;
	}

	pte_clear_dirty(ptep, pgsize);
	flush_tlb_single((uintptr_t)pgaddr);	/* XXX: TLB flush */

	phys = pte_get_phys(ptep);
	error = memobj_flush_page(args->memobj, phys, pgsize);
	if (error) {
		ekprintf("sync_one_page(%p,%p,%p %#lx,%p,%#lx):"
				"flush failed. %d\n",
				arg0, pt, ptep, *ptep, pgaddr, pgsize, error);
		pte_set_dirty(ptep, pgsize);
		goto out;
	}

	error = 0;
out:
	dkprintf("sync_one_page(%p,%p,%p %#lx,%p,%#lx):%d\n",
			arg0, pt, ptep, *ptep, pgaddr, pgsize, error);
	return error;
}

int sync_process_memory_range(struct process_vm *vm, struct vm_range *range,
		uintptr_t start, uintptr_t end)
{
	int error;
	struct sync_args args;

	dkprintf("sync_process_memory_range(%p,%p,%#lx,%#lx)\n",
			vm, range, start, end);
	args.memobj = range->memobj;

	ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
	memobj_lock(range->memobj);
	error = visit_pte_range(vm->page_table, (void *)start, (void *)end,
			VPTEF_SKIP_NULL, &sync_one_page, &args);
	memobj_unlock(range->memobj);
	ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
	if (error) {
		ekprintf("sync_process_memory_range(%p,%p,%#lx,%#lx):"
				"visit failed%d\n",
				vm, range, start, end, error);
		goto out;
	}
out:
	dkprintf("sync_process_memory_range(%p,%p,%#lx,%#lx):%d\n",
			vm, range, start, end, error);
	return error;
}

struct invalidate_args {
	struct vm_range *range;
};

static int invalidate_one_page(void *arg0, page_table_t pt, pte_t *ptep,
		void *pgaddr, size_t pgsize)
{
	struct invalidate_args *args = arg0;
	struct vm_range *range = args->range;
	int error;
	uintptr_t phys;
	struct page *page;
	off_t linear_off;
	pte_t apte;

	dkprintf("invalidate_one_page(%p,%p,%p %#lx,%p,%#lx)\n",
			arg0, pt, ptep, *ptep, pgaddr, pgsize);
	if (pte_is_null(ptep) || pte_is_fileoff(ptep, pgsize)) {
		error = 0;
		goto out;
	}

	phys = pte_get_phys(ptep);
	page = phys_to_page(phys);
	linear_off = range->objoff + ((uintptr_t)pgaddr - range->start);
	if (page && (page->offset == linear_off)) {
		pte_make_null(&apte, pgsize);
	}
	else {
		pte_make_fileoff(page->offset, 0, pgsize, &apte);
	}
	pte_xchg(ptep, &apte);
	flush_tlb_single((uintptr_t)pgaddr);	/* XXX: TLB flush */

	if (page && page_unmap(page)) {
		panic("invalidate_one_page");
	}

	error = memobj_invalidate_page(range->memobj, phys, pgsize);
	if (error) {
		ekprintf("invalidate_one_page(%p,%p,%p %#lx,%p,%#lx):"
				"invalidate failed. %d\n",
				arg0, pt, ptep, *ptep, pgaddr, pgsize, error);
		goto out;
	}

	error = 0;
out:
	dkprintf("invalidate_one_page(%p,%p,%p %#lx,%p,%#lx):%d\n",
			arg0, pt, ptep, *ptep, pgaddr, pgsize, error);
	return error;
}

int invalidate_process_memory_range(struct process_vm *vm,
		struct vm_range *range, uintptr_t start, uintptr_t end)
{
	int error;
	struct invalidate_args args;

	dkprintf("invalidate_process_memory_range(%p,%p,%#lx,%#lx)\n",
			vm, range, start, end);
	args.range = range;

	ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
	memobj_lock(range->memobj);
	error = visit_pte_range(vm->page_table, (void *)start, (void *)end,
			VPTEF_SKIP_NULL, &invalidate_one_page, &args);
	memobj_unlock(range->memobj);
	ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
	if (error) {
		ekprintf("invalidate_process_memory_range(%p,%p,%#lx,%#lx):"
				"visit failed%d\n",
				vm, range, start, end, error);
		goto out;
	}
out:
	dkprintf("invalidate_process_memory_range(%p,%p,%#lx,%#lx):%d\n",
			vm, range, start, end, error);
	return error;
}

static int page_fault_process_memory_range(struct process_vm *vm, struct vm_range *range, uintptr_t fault_addr, uint64_t reason)
{
	int error;
	pte_t *ptep;
	void *pgaddr;
	size_t pgsize;
	int p2align;
	enum ihk_mc_pt_attribute attr;
	uintptr_t phys;
	struct page *page = NULL;
	unsigned long memobj_flag = 0;

	dkprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx)\n", vm, range->start, range->end, range->flag, fault_addr, reason);
	ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
	/*****/
	ptep = ihk_mc_pt_lookup_pte(vm->page_table, (void *)fault_addr, &pgaddr, &pgsize, &p2align);
	if (!(reason & (PF_PROT | PF_PATCH)) && ptep && !pte_is_null(ptep)
			&& !pte_is_fileoff(ptep, pgsize)) {
		if (!pte_is_present(ptep)) {
			error = -EFAULT;
			kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):PROT_NONE. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
			goto out;
		}
		error = 0;
		goto out;
	}
	if ((reason & PF_PROT) && (!ptep || !pte_is_present(ptep))) {
		flush_tlb_single(fault_addr);
		error = 0;
		goto out;
	}
	/*****/
	if (!ptep || (pgsize != PAGE_SIZE)) {
		ptep = NULL;
		pgsize = PAGE_SIZE;
		p2align = PAGE_P2ALIGN;
	}
	pgaddr = (void *)(fault_addr & ~(pgsize - 1));
	if (!ptep || pte_is_null(ptep) || pte_is_fileoff(ptep, pgsize)) {
		if (range->memobj) {
			off_t off;

			if (!ptep || !pte_is_fileoff(ptep, pgsize)) {
				off = range->objoff + ((uintptr_t)pgaddr - range->start);
			}
			else {
				off = pte_get_off(ptep, pgsize);
			}
			error = memobj_get_page(range->memobj, off, p2align, 
					&phys, &memobj_flag);
			if (error) {
				if (error != -ERESTART) {
				}
				goto out;
			}
		}
		else {
			void *virt;
			size_t npages;

			npages = pgsize / PAGE_SIZE;
			virt = ihk_mc_alloc_aligned_pages(npages, p2align, IHK_MC_AP_NOWAIT);
			if (!virt) {
				error = -ENOMEM;
				kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):cannot allocate new page. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
				goto out;
			}
			memset(virt, 0, pgsize);
			phys = virt_to_phys(virt);
			page_map(phys_to_page(phys));
		}
	}
	else {
		phys = pte_get_phys(ptep);
	}
	
	page = phys_to_page(phys);
	
	attr = arch_vrflag_to_ptattr(range->flag | memobj_flag, reason, ptep);
	
	/*****/
	if (((range->flag & VR_PRIVATE)
				|| ((reason & PF_PATCH)
					&& !(range->flag & VR_PROT_WRITE)))
			&& (!page || page_is_in_memobj(page) || page_is_multi_mapped(page))) {
		if (!(attr & PTATTR_DIRTY)) {
			attr &= ~PTATTR_WRITABLE;
		}
		else {
			void *virt;
			size_t npages;

			npages = pgsize / PAGE_SIZE;
			virt = ihk_mc_alloc_aligned_pages(npages, p2align, IHK_MC_AP_NOWAIT);
			if (!virt) {
				error = -ENOMEM;
				kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):cannot allocate copy page. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
				goto out;
			}
			memcpy(virt, phys_to_virt(phys), pgsize);

			phys = virt_to_phys(virt);
			if (page) {
				page_unmap(page);
			}
			page = phys_to_page(phys);
		}
	}
	/*****/
	if (ptep) {
		error = ihk_mc_pt_set_pte(vm->page_table, ptep, pgsize, phys, attr);
		if (error) {
			kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):set_pte failed. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
			goto out;
		}
	}
	else {
		error = ihk_mc_pt_set_range(vm->page_table, vm, pgaddr, pgaddr + pgsize, 
				phys, attr);
		if (error) {
			kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):set_range failed. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
			goto out;
		}
	}
	flush_tlb_single(fault_addr);
	error = 0;
	page = NULL;
out:
	ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
	if (page) {
		page_unmap(page);
	}
	dkprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx): %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
	return error;
}

static int do_page_fault_process_vm(struct process_vm *vm, void *fault_addr0, uint64_t reason)
{
	int error;
	const uintptr_t fault_addr = (uintptr_t)fault_addr0;
	struct vm_range *range;

	dkprintf("[%d]do_page_fault_process_vm(%p,%lx,%lx)\n",
			ihk_mc_get_processor_id(), vm, fault_addr0, reason);

	ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);

	if (vm->exiting) {
		error = -ECANCELED;
		goto out;
	}

	range = lookup_process_memory_range(vm, fault_addr, fault_addr+1);
	if (range == NULL) {
		error = -EFAULT;
		kprintf("[%d]do_page_fault_process_vm(%p,%lx,%lx):"
				"out of range. %d\n",
				ihk_mc_get_processor_id(), vm,
				fault_addr0, reason, error);
		goto out;
	}

	if (((range->flag & VR_PROT_MASK) == VR_PROT_NONE)
			|| (((reason & PF_WRITE) && !(reason & PF_PATCH))
				&& !(range->flag & VR_PROT_WRITE))
			|| ((reason & PF_INSTR)
				&& !(range->flag & VR_PROT_EXEC))) {
		error = -EFAULT;
		kprintf("[%d]do_page_fault_process_vm(%p,%lx,%lx):"
				"access denied. %d\n",
				ihk_mc_get_processor_id(), vm,
				fault_addr0, reason, error);
		if (((range->flag & VR_PROT_MASK) == VR_PROT_NONE)) 
			kprintf("if (((range->flag & VR_PROT_MASK) == VR_PROT_NONE))\n");
		if (((reason & PF_WRITE) && !(reason & PF_PATCH)))
			kprintf("if (((reason & PF_WRITE) && !(reason & PF_PATCH)))\n");
		if (!(range->flag & VR_PROT_WRITE))
			kprintf("if (!(range->flag & VR_PROT_WRITE))\n");
		if ((reason & PF_INSTR) && !(range->flag & VR_PROT_EXEC))
			kprintf("if ((reason & PF_INSTR) && !(range->flag & VR_PROT_EXEC))\n");
		goto out;
	}

	/*
	 * XXX: quick fix
	 * Corrupt data was read by the following sequence.
	 * 1) a process did mmap(MAP_PRIVATE|MAP_ANONYMOUS)
	 * 2) the process fetched the contents of a page of (1)'s mapping.
	 * 3) the process wrote the contents of the page of (1)'s mapping.
	 * 4) the process changed the contents of the page of (1)'s mapping.
	 * 5) the process read something in the page of (1)'s mapping.
	 *
	 * In the case of the above sequence,
	 * copy-on-write pages was mapped at (2). And their physical pages
	 * were informed to mcctrl/mcexec at (3). However, page remapping
	 * at (4) was not informed to mcctrl/mcexec, and the data read at (5)
	 * was transferred to old pages which had been mapped at (2).
	 */
	if ((range->flag & VR_PRIVATE) && range->memobj) {
		struct memobj *obj;

		if (zeroobj_create(&obj)) {
			panic("DPFP: zeroobj_crate");
		}

		if (range->memobj == obj) {
			reason |= PF_POPULATE;
		}
	}

	error = page_fault_process_memory_range(vm, range, fault_addr, reason);
	if (error == -ERESTART) {
		goto out;
	}
	if (error) {
		kprintf("[%d]do_page_fault_process_vm(%p,%lx,%lx):"
				"fault range failed. %d\n",
				ihk_mc_get_processor_id(), vm,
				fault_addr0, reason, error);
		goto out;
	}

	error = 0;
out:
	ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);
	dkprintf("[%d]do_page_fault_process_vm(%p,%lx,%lx): %d\n",
			ihk_mc_get_processor_id(), vm, fault_addr0,
			reason, error);
	return error;
}

int page_fault_process_vm(struct process_vm *fault_vm, void *fault_addr, uint64_t reason)
{
	int error;
	struct process *proc = cpu_local_var(current);

	for (;;) {
		error = do_page_fault_process_vm(fault_vm, fault_addr, reason);
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
	unsigned long at_rand;

	/* create stack range */
	minsz = PAGE_SIZE;
	size = process->rlimit[MCK_RLIMIT_STACK].rlim_cur & PAGE_MASK;
	if (size > (USER_END / 2)) {
		size = USER_END / 2;
	}
	else if (size < minsz) {
		size = minsz;
	}
	start = end - size;

	vrflag = VR_STACK | VR_DEMAND_PAGING;
	vrflag |= PROT_TO_VR_FLAG(pn->stack_prot);
	vrflag |= VR_MAXPROT_READ | VR_MAXPROT_WRITE | VR_MAXPROT_EXEC;
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
	error = ihk_mc_pt_set_range(process->vm->page_table, process->vm,
			(void *)(end-minsz), (void *)end,
			virt_to_phys(stack),
			arch_vrflag_to_ptattr(vrflag, PF_POPULATE, NULL));
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
	
	/* "random" 16 bytes on the very top */
	p[s_ind--] = 0x010101011;
	p[s_ind--] = 0x010101011;
	at_rand = end + sizeof(unsigned long) * s_ind;
	
	/* auxiliary vector */
	/* If you add/delete entires, please increase/decrease
	   AUXV_LEN in include/process.h. */
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
	p[s_ind--] = 4096; /* AT_PAGESZ */
	p[s_ind--] = AT_PAGESZ;
	p[s_ind--] = pn->at_clktck; /* AT_CLKTCK */
	p[s_ind--] = AT_CLKTCK;
	p[s_ind--] = at_rand; /* AT_RANDOM */
	p[s_ind--] = AT_RANDOM;
	
	/* Save auxiliary vector for later use. */
	memcpy(process->saved_auxv, &p[s_ind + 1], 
	       sizeof(process->saved_auxv));
		   
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
	ihk_mc_pt_clear_range(proc->vm->page_table, proc->vm, 
			(void *)start, (void *)end);
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
	/* Let concurrent page faults know the VM will be gone */
	vm->exiting = 1;
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

void free_process_memory_ranges(struct process *proc)
{
	int error;
	struct vm_range *range, *next;
	struct process_vm *vm = proc->vm;

	if (vm == NULL) {
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
	release_process(vm->owner_process);
}

int populate_process_memory(struct process *proc, void *start, size_t len)
{
	int error;
	const int reason = PF_USER | PF_POPULATE;
	uintptr_t end;
	uintptr_t addr;

	end = (uintptr_t)start + len;
	for (addr = (uintptr_t)start; addr < end; addr += PAGE_SIZE) {
		error = page_fault_process_vm(proc->vm, (void *)addr, reason);
		if (error) {
			ekprintf("populate_process_range:page_fault_process_vm"
					"(%p,%lx,%lx) failed %d\n",
					proc, addr, reason, error);
			goto out;
		}
	}

	error = 0;
out:
	return error;
}

void hold_process(struct process *proc)
{
	if (proc->ftn->status & (PS_ZOMBIE | PS_EXITED)) {
		panic("hold_process: already exited process");
	}

	ihk_atomic_inc(&proc->refcount);
	return;
}

void destroy_process(struct process *proc)
{
	struct sig_pending *pending;
	struct sig_pending *next;

	delete_proc_procfs_files(proc->ftn->pid);

	if (proc->vm) {
		cpu_clear(proc->cpu_id, &proc->vm->cpu_set, &proc->vm->cpu_set_lock);
	}

	free_process_memory(proc);	

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
	if (proc->ptrace_debugreg) {
		kfree(proc->ptrace_debugreg);
	}
	if (proc->ptrace_recvsig) {
		kfree(proc->ptrace_recvsig);
	}
	if (proc->ptrace_sendsig) {
		kfree(proc->ptrace_sendsig);
	}
	if (proc->fp_regs) {
		release_fp_regs(proc);
	}
	if (proc->saved_cmdline) {
		kfree(proc->saved_cmdline);
	}
	ihk_mc_free_pages(proc, KERNEL_STACK_NR_PAGES);
}

void release_process(struct process *proc)
{
	if (!ihk_atomic_dec_and_test(&proc->refcount)) {
		return;
	}

	destroy_process(proc);
}

void cpu_set(int cpu, cpu_set_t *cpu_set, ihk_spinlock_t *lock)
{
	unsigned int flags;
	flags = ihk_mc_spinlock_lock(lock);
	CPU_SET(cpu, cpu_set);
	ihk_mc_spinlock_unlock(lock, flags);
}

void cpu_clear(int cpu, cpu_set_t *cpu_set, ihk_spinlock_t *lock)
{
	unsigned int flags;
	flags = ihk_mc_spinlock_lock(lock);
	CPU_CLR(cpu, cpu_set);
	ihk_mc_spinlock_unlock(lock, flags);
}

void cpu_clear_and_set(int c_cpu, int s_cpu, 
	cpu_set_t *cpu_set, ihk_spinlock_t *lock)
{
	unsigned int flags;
	flags = ihk_mc_spinlock_lock(lock);
	CPU_CLR(c_cpu, cpu_set);
	CPU_SET(s_cpu, cpu_set);
	ihk_mc_spinlock_unlock(lock, flags);
}


static void do_migrate(void);

static void idle(void)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	
	/* Release runq_lock before starting the idle loop.
	 * See comments at release_runq_lock().
	 */
	ihk_mc_spinlock_unlock(&(cpu_local_var(runq_lock)), 
			cpu_local_var(runq_irqstate));

	if(v->status == CPU_STATUS_RUNNING)
		v->status = CPU_STATUS_IDLE;
	cpu_enable_interrupt();

	while (1) {
		schedule();
		cpu_disable_interrupt();
		
		/* See if we need to migrate a process somewhere */
		if (v->flags & CPU_FLAG_NEED_MIGRATE) {
			v->flags &= ~CPU_FLAG_NEED_MIGRATE;
			do_migrate();
		}

		/*
		 * XXX: KLUDGE: It is desirable to be resolved in schedule().
		 *
		 * There is a problem which causes wait4(2) hang when
		 * wait4(2) called by a process races with its child process
		 * termination. This is a quick fix for this problem.
		 *
		 * The problem occurrd in the following sequence.
		 * 1) The parent process called schedule() from sys_wait4() to
		 *    wait for an event generated by the child process.
		 * 2) schedule() resumed the idle process because there was no
		 *    runnable process in run queue.
		 * 3) At the moment, the child process began to end. It set
		 *    the parent process runnable, and sent an interrupt to
		 *    the parent process's cpu. But this interrupt had no
		 *    effect because the parent process's cpu had not halted.
		 * 4) The idle process was resumed, and halted for waiting for
		 *    the interrupt that had already been handled.
		 */
		if (v->status == CPU_STATUS_IDLE ||
		    v->status == CPU_STATUS_RESERVED) {
			long s;
			struct process *p;

			s = ihk_mc_spinlock_lock(&v->runq_lock);
			list_for_each_entry(p, &v->runq, sched_list) {
				if (p->ftn->status == PS_RUNNING) {
					v->status = CPU_STATUS_RUNNING;
					break;
				}
			}
			ihk_mc_spinlock_unlock(&v->runq_lock, s);
		}
		if (v->status == CPU_STATUS_IDLE ||
		    v->status == CPU_STATUS_RESERVED) {
			cpu_safe_halt();
		}
		else {
			cpu_enable_interrupt();
		}
	}
}

void sched_init(void)
{
	struct process *idle_process = &cpu_local_var(idle);

	memset(idle_process, 0, sizeof(struct process));
	memset(&cpu_local_var(idle_vm), 0, sizeof(struct process_vm));
	memset(&cpu_local_var(idle_ftn), 0, sizeof(struct fork_tree_node));

	idle_process->vm = &cpu_local_var(idle_vm);
	idle_process->ftn = &cpu_local_var(idle_ftn);

	ihk_mc_init_context(&idle_process->ctx, NULL, idle);
	idle_process->ftn->pid = 0;
	idle_process->ftn->tid = ihk_mc_get_processor_id();

	INIT_LIST_HEAD(&cpu_local_var(runq));
	cpu_local_var(runq_len) = 0;
	ihk_mc_spinlock_init(&cpu_local_var(runq_lock));

	INIT_LIST_HEAD(&cpu_local_var(migq));
	ihk_mc_spinlock_init(&cpu_local_var(migq_lock));

#ifdef TIMER_CPU_ID
	if (ihk_mc_get_processor_id() == TIMER_CPU_ID) {
		init_timers();
		wake_timers_loop();
	}
#endif
}

static void double_rq_lock(struct cpu_local_var *v1, struct cpu_local_var *v2, unsigned long *irqstate)
{
	if (v1 < v2) {
		*irqstate = ihk_mc_spinlock_lock(&v1->runq_lock);
		ihk_mc_spinlock_lock_noirq(&v2->runq_lock);
	} else {
		*irqstate = ihk_mc_spinlock_lock(&v2->runq_lock);
		ihk_mc_spinlock_lock_noirq(&v1->runq_lock);
	}
}

static void double_rq_unlock(struct cpu_local_var *v1, struct cpu_local_var *v2, unsigned long irqstate)
{
	ihk_mc_spinlock_unlock_noirq(&v1->runq_lock);
	ihk_mc_spinlock_unlock(&v2->runq_lock, irqstate);
}

struct migrate_request {
	struct list_head list;
	struct process *proc;
	struct waitq wq;
};

static void do_migrate(void)
{
	int cur_cpu_id = ihk_mc_get_processor_id();
	struct cpu_local_var *cur_v = get_cpu_local_var(cur_cpu_id);
	struct migrate_request *req, *tmp;
	unsigned long irqstate = 0;

	irqstate = ihk_mc_spinlock_lock(&cur_v->migq_lock);
	list_for_each_entry_safe(req, tmp, &cur_v->migq, list) {
		int cpu_id;
		int old_cpu_id;
		struct cpu_local_var *v;

		/* 0. check if migration is necessary */
		list_del(&req->list);
		if (req->proc->cpu_id != cur_cpu_id) /* already not here */
			goto ack;
		if (CPU_ISSET(cur_cpu_id, &req->proc->cpu_set)) /* good affinity */
			goto ack;

		/* 1. select CPU */
		for (cpu_id = 0; cpu_id < CPU_SETSIZE; cpu_id++)
			if (CPU_ISSET(cpu_id, &req->proc->cpu_set))
				break;
		if (CPU_SETSIZE == cpu_id) /* empty affinity (bug?) */
			goto ack;

		/* 2. migrate thread */
		v = get_cpu_local_var(cpu_id);
		double_rq_lock(cur_v, v, &irqstate);
		list_del(&req->proc->sched_list);
		cur_v->runq_len -= 1;
		old_cpu_id = req->proc->cpu_id;
		req->proc->cpu_id = cpu_id;
		settid(req->proc, 2, cpu_id, old_cpu_id);
		list_add_tail(&req->proc->sched_list, &v->runq);
		v->runq_len += 1;
		
		/* update cpu_set of the VM for remote TLB invalidation */
		cpu_clear_and_set(old_cpu_id, cpu_id, &req->proc->vm->cpu_set, 
				&req->proc->vm->cpu_set_lock);

		dkprintf("do_migrate(): migrated TID %d from CPU %d to CPU %d\n",
			req->proc->ftn->tid, old_cpu_id, cpu_id);
		
		if (v->runq_len == 1)
			ihk_mc_interrupt_cpu(get_x86_cpu_local_variable(cpu_id)->apic_id, 0xd1);
		double_rq_unlock(cur_v, v, irqstate);

ack:
		waitq_wakeup(&req->wq);
	}
	ihk_mc_spinlock_unlock(&cur_v->migq_lock, irqstate);
}

extern int num_processors;
extern ihk_spinlock_t cpuid_head_lock;

void schedule(void)
{
	struct cpu_local_var *v;
	struct process *next, *prev, *proc, *tmp = NULL;
	int switch_ctx = 0;
	struct process *last;

	if (cpu_local_var(no_preempt)) {
		dkprintf("no schedule() while no preemption! \n");
		return;
	}
	
	if (cpu_local_var(current)->in_syscall_offload) {
		dkprintf("no schedule() while syscall offload!\n");
		return;
	}
	
redo:
	cpu_local_var(runq_irqstate) = 
		ihk_mc_spinlock_lock(&(get_this_cpu_local_var()->runq_lock));
	v = get_this_cpu_local_var();

	next = NULL;
	prev = v->current;

	/* All runnable processes are on the runqueue */
	if (prev && prev != &cpu_local_var(idle)) {
		list_del(&prev->sched_list);
		--v->runq_len;	
		
		/* Round-robin if not exited yet */
		if (!(prev->ftn->status & (PS_ZOMBIE | PS_EXITED))) {
			list_add_tail(&prev->sched_list, &(v->runq));
			++v->runq_len;
		}

		/* Toggle timesharing if CPU core is oversubscribed */
		if (v->runq_len > 1) {
			if (!cpu_local_var(timer_enabled)) {
				lapic_timer_enable(10000000);
				cpu_local_var(timer_enabled) = 1;
			}
		}
		else {
			if (cpu_local_var(timer_enabled)) {
				lapic_timer_disable();
				cpu_local_var(timer_enabled) = 0;
			}
		}
	}

	if (v->flags & CPU_FLAG_NEED_MIGRATE) {
		next = &cpu_local_var(idle);
	} else {
		/* Pick a new running process */
		list_for_each_entry_safe(proc, tmp, &(v->runq), sched_list) {
			if (proc->ftn->status == PS_RUNNING) {
				next = proc;
				break;
			}
		}

		/* No process? Run idle.. */
		if (!next) {
			next = &cpu_local_var(idle);
			v->status = v->runq_len? CPU_STATUS_RESERVED: CPU_STATUS_IDLE;
		}
	}

	if (prev != next) {
		switch_ctx = 1;
		v->current = next;
	}
	
	if (switch_ctx) {
		dkprintf("schedule: %d => %d \n",
		        prev ? prev->ftn->tid : 0, next ? next->ftn->tid : 0);

		if (prev && prev->ptrace_debugreg) {
			save_debugreg(prev->ptrace_debugreg);
			if (next->ptrace_debugreg == NULL) {
				clear_debugreg();
			}
		}
		if (next->ptrace_debugreg) {
			restore_debugreg(next->ptrace_debugreg);
		}

		/* Take care of floating point registers except for idle process */
		if (prev && prev != &cpu_local_var(idle)) {
			save_fp_regs(prev);
		}

		if (next != &cpu_local_var(idle)) {
			restore_fp_regs(next);
		}

		ihk_mc_load_page_table(next->vm->page_table);
		
		dkprintf("[%d] schedule: tlsblock_base: 0x%lX\n", 
		         ihk_mc_get_processor_id(), next->thread.tlsblock_base); 

		/* Set up new TLS.. */
		do_arch_prctl(ARCH_SET_FS, next->thread.tlsblock_base);
		
		if (prev) {
			last = ihk_mc_switch_context(&prev->ctx, &next->ctx, prev);
		} 
		else {
			last = ihk_mc_switch_context(NULL, &next->ctx, prev);
		}
		
		/* 
		 * We must hold the lock throughout the context switch, otherwise
		 * an IRQ could deschedule this process between page table loading and 
		 * context switching and leave the execution in an inconsistent state.
		 * Since we may be migrated to another core meanwhile, we refer 
		 * directly to cpu_local_var. 
		 */
		ihk_mc_spinlock_unlock(&(cpu_local_var(runq_lock)), 
			cpu_local_var(runq_irqstate));

		/* Have we migrated to another core meanwhile? */
		if (v != get_this_cpu_local_var()) {
			dkprintf("migrated, skipping freeing last\n");
			goto redo;
		}

		if ((last != NULL) && (last->ftn) && (last->ftn->status & (PS_ZOMBIE | PS_EXITED))) {
			free_process_memory(last);
			release_process(last);
		}
	}
	else {
		ihk_mc_spinlock_unlock(&(cpu_local_var(runq_lock)), 
			cpu_local_var(runq_irqstate));
	}
}

void
release_cpuid(int cpuid)
{
	if (!get_cpu_local_var(cpuid)->runq_len)
		get_cpu_local_var(cpuid)->status = CPU_STATUS_IDLE;
}

void check_need_resched(void)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	if (v->flags & CPU_FLAG_NEED_RESCHED) {
		if (v->in_interrupt && (v->flags & CPU_FLAG_NEED_MIGRATE)) {
			dkprintf("no migration in IRQ context\n");
			return;
		}
		v->flags &= ~CPU_FLAG_NEED_RESCHED;
		schedule();
	}
}


int sched_wakeup_process(struct process *proc, int valid_states)
{
	int status;
	int spin_slept = 0;
	unsigned long irqstate;
	struct cpu_local_var *v = get_cpu_local_var(proc->cpu_id);

	dkprintf("sched_wakeup_process,proc->pid=%d,valid_states=%08x,proc->status=%08x,proc->cpu_id=%d,my cpu_id=%d\n",
			 proc->ftn->pid, valid_states, proc->ftn->status, proc->cpu_id, ihk_mc_get_processor_id());
	
	irqstate = ihk_mc_spinlock_lock(&(proc->spin_sleep_lock));
	if (proc->spin_sleep > 0) {
		dkprintf("sched_wakeup_process() spin wakeup: cpu_id: %d\n", 
				 proc->cpu_id);

		spin_slept = 1;
		status = 0;	
	}
	--proc->spin_sleep;
	ihk_mc_spinlock_unlock(&(proc->spin_sleep_lock), irqstate);
	
	if (spin_slept) {
		return status;
	}

	irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
	
	if (proc->ftn->status & valid_states) {
		xchg4((int *)(&proc->ftn->status), PS_RUNNING);
		status = 0;
	} 
	else {
		status = -EINVAL;
	}

	ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);

	if (!status && (proc->cpu_id != ihk_mc_get_processor_id())) {
		dkprintf("sched_wakeup_process,issuing IPI,proc->cpu_id=%d\n", 
				 proc->cpu_id);
		ihk_mc_interrupt_cpu(get_x86_cpu_local_variable(proc->cpu_id)->apic_id,
		                     0xd1);
	}

	return status;
}

/*
 * 1. Add current process to waitq
 * 2. Queue migration request into the target CPU's queue
 * 3. Kick migration on the CPU
 * 4. Wait for completion of the migration
 *
 * struct migrate_request {
 *     list //migq,
 *     wq,
 *     proc
 * }
 *
 * [expected processing of the target CPU]
 * 1. Interrupted by IPI
 * 2. call schedule() via check_resched()
 * 3. Do migration
 * 4. Wake up this thread
 */
void sched_request_migrate(int cpu_id, struct process *proc)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	struct migrate_request req = { .proc = proc };
	unsigned long irqstate;
	DECLARE_WAITQ_ENTRY(entry, cpu_local_var(current));

	waitq_init(&req.wq);
	waitq_prepare_to_wait(&req.wq, &entry, PS_UNINTERRUPTIBLE);

	irqstate = ihk_mc_spinlock_lock(&v->migq_lock);
	list_add_tail(&req.list, &v->migq);
	ihk_mc_spinlock_unlock(&v->migq_lock, irqstate);

	irqstate = ihk_mc_spinlock_lock(&v->runq_lock);
	v->flags |= CPU_FLAG_NEED_RESCHED | CPU_FLAG_NEED_MIGRATE;
	v->status = CPU_STATUS_RUNNING;
	ihk_mc_spinlock_unlock(&v->runq_lock, irqstate);

	if (cpu_id != ihk_mc_get_processor_id())
		ihk_mc_interrupt_cpu(/* Kick scheduler */
				get_x86_cpu_local_variable(cpu_id)->apic_id, 0xd1);

	schedule();
	waitq_finish_wait(&req.wq, &entry);
}

/* Runq lock must be held here */
void __runq_add_proc(struct process *proc, int cpu_id)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	list_add_tail(&proc->sched_list, &v->runq);
	++v->runq_len;
	proc->cpu_id = cpu_id;
	//proc->ftn->status = PS_RUNNING;	/* not set here */
	get_cpu_local_var(cpu_id)->status = CPU_STATUS_RUNNING;

	dkprintf("runq_add_proc(): tid %d added to CPU[%d]'s runq\n", 
             proc->ftn->tid, cpu_id);
}

void runq_add_proc(struct process *proc, int cpu_id)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	unsigned long irqstate;
	
	irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
	__runq_add_proc(proc, cpu_id);
	ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);

	create_proc_procfs_files(proc->ftn->pid, cpu_id);

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

struct process *
findthread_and_lock(int pid, int tid, ihk_spinlock_t **savelock, unsigned long *irqstate)
{
	struct cpu_local_var *v;
	struct process *p;
	int i;
	extern int num_processors;

	for(i = 0; i < num_processors; i++){
		v = get_cpu_local_var(i);
		*savelock = &(v->runq_lock);
		*irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
		list_for_each_entry(p, &(v->runq), sched_list){
			if(p->ftn->pid == pid &&
			   (tid == -1 || p->ftn->tid == tid)){
				return p;
			}
		}
		ihk_mc_spinlock_unlock(&(v->runq_lock), *irqstate);
	}
	return NULL;
}

void
process_unlock(void *savelock, unsigned long irqstate)
{
	ihk_mc_spinlock_unlock((ihk_spinlock_t *)savelock, irqstate);
}

void
debug_log(unsigned long arg)
{
	struct cpu_local_var *v;
	struct process *p;
	int i;
	extern int num_processors;
	unsigned long irqstate;

	switch(arg){
	    case 1:
		for(i = 0; i < num_processors; i++){
			v = get_cpu_local_var(i);
			irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
			list_for_each_entry(p, &(v->runq), sched_list){
				if(p->ftn->pid <= 0)
					continue;
				kprintf("cpu=%d pid=%d tid=%d status=%d\n",
				        i, p->ftn->pid, p->ftn->tid, p->ftn->status);
			}
			ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
		}
		break;
	}
}
