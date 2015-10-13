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
extern long alloc_debugreg(struct thread *proc);
extern void save_debugreg(unsigned long *debugreg);
extern void restore_debugreg(unsigned long *debugreg);
extern void clear_debugreg(void);
extern void clear_single_step(struct thread *proc);
static void insert_vm_range_list(struct process_vm *vm,
		struct vm_range *newrange);
static int copy_user_ranges(struct process_vm *vm, struct process_vm *orgvm);
extern void release_fp_regs(struct thread *proc);
extern void save_fp_regs(struct thread *proc);
extern void restore_fp_regs(struct thread *proc);
void settid(struct thread *proc, int mode, int newcpuid, int oldcpuid);
extern void __runq_add_proc(struct thread *proc, int cpu_id);
extern void terminate_host(int pid);
extern void lapic_timer_enable(unsigned int clocks);
extern void lapic_timer_disable();
extern int num_processors;
extern ihk_spinlock_t cpuid_head_lock;
int ptrace_detach(int pid, int data);
extern unsigned long do_kill(struct thread *, int pid, int tid, int sig, struct siginfo *info, int ptracecont);

struct list_head resource_set_list;
mcs_rwlock_lock_t    resource_set_lock;

void
init_process(struct process *proc, struct process *parent)
{
	/* These will be filled out when changing status */
	proc->pid = -1;
	proc->exit_status = -1;
	proc->pstatus = PS_RUNNING;

	if(parent){
		proc->parent = parent;
		proc->ppid_parent = parent;
		proc->pgid = parent->pgid;
		proc->ruid = parent->ruid;
		proc->euid = parent->euid;
		proc->suid = parent->suid;
		proc->fsuid = parent->fsuid;
		proc->rgid = parent->rgid;
		proc->egid = parent->egid;
		proc->sgid = parent->sgid;
		proc->fsgid = parent->fsgid;
		memcpy(proc->rlimit, parent->rlimit,
		       sizeof(struct rlimit) * MCK_RLIM_MAX);
	}

	INIT_LIST_HEAD(&proc->threads_list);
	INIT_LIST_HEAD(&proc->children_list);
	INIT_LIST_HEAD(&proc->ptraced_children_list);
	mcs_rwlock_init(&proc->threads_lock);
	mcs_rwlock_init(&proc->children_lock);
	waitq_init(&proc->waitpid_q);
	ihk_atomic_set(&proc->refcount, 2);
}

void
chain_process(struct process *proc)
{
	struct mcs_rwlock_node_irqsave lock;
	struct process *parent = proc->parent;
	int hash;
	struct process_hash *phash;

	mcs_rwlock_writer_lock(&parent->children_lock, &lock);
	list_add_tail(&proc->siblings_list, &parent->children_list);
	mcs_rwlock_writer_unlock(&parent->children_lock, &lock);

	hash = process_hash(proc->pid);
	phash = cpu_local_var(resource_set)->process_hash;
	mcs_rwlock_writer_lock(&phash->lock[hash], &lock);
	list_add_tail(&proc->hash_list, &phash->list[hash]);
	mcs_rwlock_writer_unlock(&phash->lock[hash], &lock);
}

void
chain_thread(struct thread *thread)
{
	struct mcs_rwlock_node_irqsave lock;
	struct process *proc = thread->proc;
	int hash;
	struct thread_hash *thash;

	mcs_rwlock_writer_lock(&proc->threads_lock, &lock);
	list_add_tail(&thread->siblings_list, &proc->threads_list);
	mcs_rwlock_writer_unlock(&proc->threads_lock, &lock);

	hash = thread_hash(thread->tid);
	thash = cpu_local_var(resource_set)->thread_hash;
	mcs_rwlock_writer_lock(&thash->lock[hash], &lock);
	list_add_tail(&thread->hash_list, &thash->list[hash]);
	mcs_rwlock_writer_unlock(&thash->lock[hash], &lock);

	ihk_atomic_inc(&proc->refcount);
}

struct address_space *
create_address_space(struct resource_set *res, int type, int n)
{
	struct address_space *asp;
	void *pt;

	asp = kmalloc(sizeof(struct address_space) + sizeof(int) * n, IHK_MC_AP_NOWAIT);
	if(!asp)
		return NULL;
	pt = ihk_mc_pt_create(IHK_MC_AP_NOWAIT);
	if(!pt){
		kfree(asp);
		return NULL;
	}

	memset(asp, '\0', sizeof(struct address_space) + sizeof(int) * n);
	asp->res = res;
	asp->type = type;
	asp->nslots = n;
	asp->page_table = pt;
	return asp;
}

void
remove_address_space(struct address_space *asp)
{
	ihk_mc_pt_destroy(asp->page_table);
	kfree(asp);
}

void
detach_address_space(struct address_space *asp, int pid)
{
	if(asp->type == ADDRESS_SPACE_NORMAL){
		remove_address_space(asp);
	}
	else if(asp->type == ADDRESS_SPACE_PVAS){
		int i;

		for(i = 0; i < asp->nslots; i++){
			if(asp->pids[i] == pid){
				asp->pids[i] = 0;
				break;
			}
		}
	}
}

static int
init_process_vm(struct process *owner, struct address_space *asp, struct process_vm *vm)
{
	ihk_mc_spinlock_init(&vm->memory_range_lock);
	ihk_mc_spinlock_init(&vm->page_table_lock);

	ihk_atomic_set(&vm->refcount, 1);
	INIT_LIST_HEAD(&vm->vm_range_list);
	vm->address_space = asp;
	vm->proc = owner;
	memset(&vm->cpu_set, 0, sizeof(cpu_set_t));
	ihk_mc_spinlock_init(&vm->cpu_set_lock);
	vm->exiting = 0;

	return 0;
}

struct thread *
create_thread(unsigned long user_pc)
{
	struct thread *thread;
	struct process *proc;
	struct process_vm *vm = NULL;
	struct address_space *asp = NULL;

	thread = ihk_mc_alloc_pages(KERNEL_STACK_NR_PAGES, IHK_MC_AP_NOWAIT);
	if (!thread)
		return NULL;
	memset(thread, 0, sizeof(struct thread));
	ihk_atomic_set(&thread->refcount, 2);
	proc = kmalloc(sizeof(struct process), IHK_MC_AP_NOWAIT);
	vm = kmalloc(sizeof(struct process_vm), IHK_MC_AP_NOWAIT);
	asp = create_address_space(cpu_local_var(resource_set),
				   ADDRESS_SPACE_NORMAL, 1);
	if (!proc || !vm || !asp)
		goto err;
	memset(proc, 0, sizeof(struct process));
	memset(vm, 0, sizeof(struct process_vm));
	init_process(proc, cpu_local_var(resource_set)->pid1);

	if (1) {
		struct ihk_mc_cpu_info *infop;
		int i;

		infop = ihk_mc_get_cpu_info();
		for (i = 0; i < infop->ncpus; ++i) {
			CPU_SET(i, &thread->cpu_set);
		}
	}

	thread->sched_policy = SCHED_NORMAL;

	thread->sigcommon = kmalloc(sizeof(struct sig_common),
	                            IHK_MC_AP_NOWAIT);
	if (!thread->sigcommon) {
		goto err;
	}
	memset(thread->sigcommon, '\0', sizeof(struct sig_common));

	dkprintf("fork(): sigshared\n");

	ihk_atomic_set(&thread->sigcommon->use, 1);
	ihk_mc_spinlock_init(&thread->sigcommon->lock);
	INIT_LIST_HEAD(&thread->sigcommon->sigpending);

	ihk_mc_spinlock_init(&thread->sigpendinglock);
	INIT_LIST_HEAD(&thread->sigpending);

	thread->sigstack.ss_sp = NULL;
	thread->sigstack.ss_flags = SS_DISABLE;
	thread->sigstack.ss_size = 0;

	ihk_mc_init_user_process(&thread->ctx, &thread->uctx, ((char *)thread) +
	                       KERNEL_STACK_NR_PAGES * PAGE_SIZE, user_pc, 0);

	thread->vm = vm;
	thread->proc = proc;
	proc->vm = vm;

	if(init_process_vm(proc, asp, vm) != 0){
		goto err;
	}

	cpu_set(ihk_mc_get_processor_id(), &thread->vm->cpu_set,
			&thread->vm->cpu_set_lock);

	ihk_mc_spinlock_init(&thread->spin_sleep_lock);
	thread->spin_sleep = 0;

	return thread;

err:
	if(proc)
		kfree(proc);
	if(vm)
		kfree(vm);
	if(asp)
		remove_address_space(asp);
	if(thread->sigcommon)
		kfree(thread->sigcommon);
	ihk_mc_free_pages(thread, KERNEL_STACK_NR_PAGES);

	return NULL;
}

struct thread *
clone_thread(struct thread *org, unsigned long pc, unsigned long sp,
              int clone_flags)
{
	struct thread *thread;
	int termsig = clone_flags & 0xff;
	struct process *proc = NULL;
	struct address_space *asp = NULL;


	if (termsig < 0 || _NSIG < termsig) {
		return (void *)-EINVAL;
	}

	if((clone_flags & CLONE_SIGHAND) &&
	   !(clone_flags & CLONE_VM))
		return (void *)-EINVAL;
	if((clone_flags & CLONE_THREAD) &&
	   !(clone_flags & CLONE_SIGHAND))
		return (void *)-EINVAL;
	if((clone_flags & CLONE_FS) &&
	   (clone_flags & CLONE_NEWNS))
		return (void *)-EINVAL;
	if((clone_flags & CLONE_NEWIPC) &&
	   (clone_flags & CLONE_SYSVSEM))
		return (void *)-EINVAL;
	if((clone_flags & CLONE_NEWPID) &&
	   (clone_flags & CLONE_THREAD))
		return (void *)-EINVAL;


	if ((thread = ihk_mc_alloc_pages(KERNEL_STACK_NR_PAGES,
					IHK_MC_AP_NOWAIT)) == NULL) {
		return NULL;
	}

	memset(thread, 0, sizeof(struct thread));
	ihk_atomic_set(&thread->refcount, 2);
	memcpy(&thread->cpu_set, &org->cpu_set, sizeof(thread->cpu_set));

	/* NOTE: sp is the user mode stack! */
	ihk_mc_init_user_process(&thread->ctx, &thread->uctx, ((char *)thread) +
				 KERNEL_STACK_NR_PAGES * PAGE_SIZE, pc, sp);

	memcpy(thread->uctx, org->uctx, sizeof(*org->uctx));
	ihk_mc_modify_user_context(thread->uctx, IHK_UCR_STACK_POINTER, sp);
	ihk_mc_modify_user_context(thread->uctx, IHK_UCR_PROGRAM_COUNTER, pc);

	thread->sched_policy = org->sched_policy;
	thread->sched_param.sched_priority = org->sched_param.sched_priority;

	/* clone VM */
	if (clone_flags & CLONE_VM) {
		proc = org->proc;
		thread->vm = org->vm;
		thread->proc = proc;
	}
	/* fork() */
	else {
		proc = kmalloc(sizeof(struct process), IHK_MC_AP_NOWAIT);
		if(!proc)
			goto err_free_proc;
		memset(proc, '\0', sizeof(struct process));
		init_process(proc, org->proc);

		proc->termsig = termsig;
		asp = create_address_space(cpu_local_var(resource_set),
		                           ADDRESS_SPACE_NORMAL, 1);
		if(!asp){
			kfree(proc);
			goto err_free_proc;
		}
		proc->vm = kmalloc(sizeof(struct process_vm), IHK_MC_AP_NOWAIT);
		if(!proc->vm){
			remove_address_space(asp);
			kfree(proc);
			goto err_free_proc;
		}
		memset(proc->vm, '\0', sizeof(struct process_vm));

		dkprintf("fork(): init_process_vm()\n");
		if (init_process_vm(proc, asp, proc->vm) != 0) {
			remove_address_space(asp);
			kfree(proc->vm);
			kfree(proc);
			goto err_free_proc;
		}
		thread->proc = proc;
		thread->vm = proc->vm;

		memcpy(&proc->vm->region, &org->vm->region, sizeof(struct vm_regions));

		dkprintf("fork(): copy_user_ranges()\n");
		/* Copy user-space mappings.
		 * TODO: do this with COW later? */
		if (copy_user_ranges(proc->vm, org->vm) != 0) {
			remove_address_space(asp);
			kfree(proc->vm);
			kfree(proc);
			goto err_free_proc;
		}

		dkprintf("fork(): copy_user_ranges() OK\n");
	}

	/* clone signal handlers */
	if (clone_flags & CLONE_SIGHAND) {
		thread->sigcommon = org->sigcommon;
		ihk_atomic_inc(&org->sigcommon->use);
	}
	/* copy signal handlers (i.e., fork()) */
	else {
		dkprintf("fork(): sigcommon\n");
		thread->sigcommon = kmalloc(sizeof(struct sig_common),
		                             IHK_MC_AP_NOWAIT);
		if (!thread->sigcommon) {
			goto err_free_proc;
		}
		memset(thread->sigcommon, '\0', sizeof(struct sig_common));

		dkprintf("fork(): sigshared\n");

		memcpy(thread->sigcommon->action, org->sigcommon->action,
		       sizeof(struct k_sigaction) * _NSIG);
		ihk_atomic_set(&thread->sigcommon->use, 1);
		ihk_mc_spinlock_init(&thread->sigcommon->lock);
		INIT_LIST_HEAD(&thread->sigcommon->sigpending);
		// TODO: copy signalfd
	}
	thread->sigstack.ss_sp = NULL;
	thread->sigstack.ss_flags = SS_DISABLE;
	thread->sigstack.ss_size = 0;
	ihk_mc_spinlock_init(&thread->sigpendinglock);
	INIT_LIST_HEAD(&thread->sigpending);
	thread->sigmask = org->sigmask;

	ihk_mc_spinlock_init(&thread->spin_sleep_lock);
	thread->spin_sleep = 0;

	return thread;

err_free_proc:
	ihk_mc_free_pages(thread, KERNEL_STACK_NR_PAGES);
	return NULL;
}

int
ptrace_traceme(void)
{
	int error = 0;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct process *parent = proc->parent;
	struct mcs_rwlock_node_irqsave lock;
	struct mcs_rwlock_node child_lock;

	dkprintf("ptrace_traceme,pid=%d,proc->parent=%p\n", proc->pid, proc->parent);

	if (proc->ptrace & PT_TRACED) {
		return -EPERM;
	}

	dkprintf("ptrace_traceme,parent->pid=%d\n", proc->parent->pid);

	mcs_rwlock_writer_lock(&proc->update_lock, &lock);
	mcs_rwlock_writer_lock_noirq(&parent->children_lock, &child_lock);
	list_add_tail(&proc->ptraced_siblings_list, &parent->ptraced_children_list);
	mcs_rwlock_writer_unlock_noirq(&parent->children_lock, &child_lock);
	proc->ptrace = PT_TRACED | PT_TRACE_EXEC;
	mcs_rwlock_writer_unlock(&proc->update_lock, &lock);

	if (thread->ptrace_debugreg == NULL) {
		error = alloc_debugreg(thread);
	}

	clear_single_step(thread);

	dkprintf("ptrace_traceme,returning,error=%d\n", error);
	return error;
}

static int copy_user_ranges(struct process_vm *vm, struct process_vm *orgvm)
{
	struct vm_range *src_range;
	struct vm_range *range;

	ihk_mc_spinlock_lock_noirq(&orgvm->memory_range_lock);

	/* Iterate original process' vm_range list and take a copy one-by-one */
	list_for_each_entry(src_range, &orgvm->vm_range_list, list) {
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
			ptep = ihk_mc_pt_lookup_pte(orgvm->address_space->
			                                 page_table, vaddr,
			                            &ptepgaddr, &ptepgsize,
			                            &ptep2align);

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
						"get pgsize failed\n", orgvm,
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

			if (ihk_mc_pt_set_range(vm->address_space->page_table,
			                        vm, vaddr, vaddr + pgsize,
			                        virt_to_phys(pg_vaddr), attr)) {
				kprintf("ERROR: copy_user_ranges() "
						"(%p,%lx-%lx %lx,%lx):"
						"set range failed.\n",
						orgvm, range->start, range->end,
						range->flag, vaddr);

				goto err_free_range_rollback;
			}
			dkprintf("copy_user_ranges(): new PTE set\n", pgsize);

			vaddr += pgsize;
		}

		insert_vm_range_list(vm, range);
	}

	ihk_mc_spinlock_unlock_noirq(&orgvm->memory_range_lock);

	return 0;

err_free_range_rollback:
	kfree(range);

err_rollback:

	/* TODO: implement rollback */


	ihk_mc_spinlock_unlock_noirq(&orgvm->memory_range_lock);

	return -1;
}

int update_process_page_table(struct process_vm *vm,
                          struct vm_range *range, uint64_t phys,
			  enum ihk_mc_pt_attribute flag)
{
	unsigned long p, pa = phys;
	unsigned long pp;
	unsigned long flags;
	enum ihk_mc_pt_attribute attr;

	flags = ihk_mc_spinlock_lock(&vm->page_table_lock);
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

			if (ihk_mc_pt_set_large_page(vm->address_space->
			                             page_table, (void *)p,
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
			if(ihk_mc_pt_set_page(vm->address_space->page_table,
			                      (void *)p, pa, attr) != 0){
				kprintf("ERROR: setting page for 0x%lX -> 0x%lX\n", p, pa);
				goto err;
			}

			pa += PAGE_SIZE;
			p += PAGE_SIZE;
#ifdef USE_LARGE_PAGES
		}
#endif
	}
	ihk_mc_spinlock_unlock(&vm->page_table_lock, flags);
	return 0;

err:
	pp = range->start;
	pa = phys;
	while(pp < p){
#ifdef USE_LARGE_PAGES
		if ((p & (LARGE_PAGE_SIZE - 1)) == 0 &&
				(pa & (LARGE_PAGE_SIZE - 1)) == 0 &&
				(range->end - p) >= LARGE_PAGE_SIZE) {
			ihk_mc_pt_clear_large_page(vm->address_space->
			                           page_table, (void *)pp);
			pa += LARGE_PAGE_SIZE;
			pp += LARGE_PAGE_SIZE;
		}
		else{
#endif
			ihk_mc_pt_clear_page(vm->address_space->page_table,
			                     (void *)pp);
			pa += PAGE_SIZE;
			pp += PAGE_SIZE;
#ifdef USE_LARGE_PAGES
		}
#endif
	}

	ihk_mc_spinlock_unlock(&vm->page_table_lock, flags);
	return -ENOMEM;
}

int split_process_memory_range(struct process_vm *vm, struct vm_range *range,
		uintptr_t addr, struct vm_range **splitp)
{
	int error;
	struct vm_range *newrange = NULL;

	dkprintf("split_process_memory_range(%p,%lx-%lx,%lx,%p)\n",
			vm, range->start, range->end, addr, splitp);

	newrange = kmalloc(sizeof(struct vm_range), IHK_MC_AP_NOWAIT);
	if (!newrange) {
		ekprintf("split_process_memory_range(%p,%lx-%lx,%lx,%p):"
				"kmalloc failed\n",
				vm, range->start, range->end, addr, splitp);
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
			vm, range->start, range->end, addr, splitp,
			error, newrange,
			newrange? newrange->start: 0, newrange? newrange->end: 0);
	return error;
}

int join_process_memory_range(struct process_vm *vm,
		struct vm_range *surviving, struct vm_range *merging)
{
	int error;

	dkprintf("join_process_memory_range(%p,%lx-%lx,%lx-%lx)\n",
			vm, surviving->start, surviving->end,
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
			vm, surviving->start, surviving->end, merging, error);
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
		error = ihk_mc_pt_free_range(vm->address_space->page_table, vm,
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
		error = ihk_mc_pt_clear_range(vm->address_space->page_table, vm,
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

int remove_process_memory_range(struct process_vm *vm,
		unsigned long start, unsigned long end, int *ro_freedp)
{
	struct vm_range *range;
	struct vm_range *next;
	int error;
	struct vm_range *freerange;
	int ro_freed = 0;

	dkprintf("remove_process_memory_range(%p,%lx,%lx)\n",
			vm, start, end);

	list_for_each_entry_safe(range, next, &vm->vm_range_list, list) {
		if ((range->end <= start) || (end <= range->start)) {
			/* no overlap */
			continue;
		}
		freerange = range;

		if (freerange->start < start) {
			error = split_process_memory_range(vm,
					freerange, start, &freerange);
			if (error) {
				ekprintf("remove_process_memory_range(%p,%lx,%lx):"
						"split failed %d\n",
						vm, start, end, error);
				return error;
			}
		}

		if (end < freerange->end) {
			error = split_process_memory_range(vm,
					freerange, end, NULL);
			if (error) {
				ekprintf("remove_process_memory_range(%p,%lx,%lx):"
						"split failed %d\n",
						vm, start, end, error);
				return error;
			}
		}

		if (!(freerange->flag & VR_PROT_WRITE)) {
			ro_freed = 1;
		}

		error = free_process_memory_range(vm, freerange);
		if (error) {
			ekprintf("remove_process_memory_range(%p,%lx,%lx):"
					"free failed %d\n",
					vm, start, end, error);
			return error;
		}

	}

	if (ro_freedp) {
		*ro_freedp = ro_freed;
	}
	dkprintf("remove_process_memory_range(%p,%lx,%lx): 0 %d\n",
			vm, start, end, ro_freed);
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

int add_process_memory_range(struct process_vm *vm,
                             unsigned long start, unsigned long end,
                             unsigned long phys, unsigned long flag,
			     struct memobj *memobj, off_t offset)
{
	struct vm_range *range;
	int rc;
#if 0
	extern void __host_update_process_range(struct thread *process,
						struct vm_range *range);
#endif

	if ((start < vm->region.user_start)
			|| (vm->region.user_end < end)) {
		kprintf("range(%#lx - %#lx) is not in user avail(%#lx - %#lx)\n",
				start, end, vm->region.user_start,
				vm->region.user_end);
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
		rc = update_process_page_table(vm, range, phys, IHK_PTA_REMOTE);
	} else if (flag & VR_IO_NOCACHE) {
		rc = update_process_page_table(vm, range, phys, PTATTR_UNCACHABLE);
	} else if(flag & VR_DEMAND_PAGING){
	  //demand paging no need to update process table now
	  dkprintf("demand paging do not update process page table\n");
      rc = 0;
	} else if ((range->flag & VR_PROT_MASK) == VR_PROT_NONE) {
		rc = 0;
	} else {
		rc = update_process_page_table(vm, range, phys, 0);
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

	insert_vm_range_list(vm, range);

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

int change_prot_process_memory_range(struct process_vm *vm,
		struct vm_range *range, unsigned long protflag)
{
	unsigned long newflag;
	int error;
	enum ihk_mc_pt_attribute oldattr;
	enum ihk_mc_pt_attribute newattr;
	enum ihk_mc_pt_attribute clrattr;
	enum ihk_mc_pt_attribute setattr;

	dkprintf("change_prot_process_memory_range(%p,%lx-%lx,%lx)\n",
			vm, range->start, range->end, protflag);

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

	ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
	error = ihk_mc_pt_change_attr_range(vm->address_space->page_table,
			(void *)range->start, (void *)range->end,
			clrattr, setattr);
	ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
	if (error && (error != -ENOENT)) {
		ekprintf("change_prot_process_memory_range(%p,%lx-%lx,%lx):"
				"ihk_mc_pt_change_attr_range failed: %d\n",
				vm, range->start, range->end, protflag, error);
		goto out;
	}

	if (((range->flag & VR_PROT_MASK) == PROT_NONE)
			&& !(range->flag & VR_DEMAND_PAGING)) {
		ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
		error = ihk_mc_pt_alloc_range(vm->address_space->page_table,
				(void *)range->start, (void *)range->end,
				newattr);
		ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
		if (error) {
			ekprintf("change_prot_process_memory_range(%p,%lx-%lx,%lx):"
					"ihk_mc_pt_alloc_range failed: %d\n",
					vm, range->start, range->end, protflag, error);
			goto out;
		}
	}

	range->flag = newflag;
	error = 0;
out:
	dkprintf("change_prot_process_memory_range(%p,%lx-%lx,%lx): %d\n",
			vm, range->start, range->end, protflag, error);
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

	error = visit_pte_range(vm->address_space->page_table, (void *)start,
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
	error = visit_pte_range(vm->address_space->page_table, (void *)start,
	                        (void *)end, VPTEF_SKIP_NULL, &sync_one_page,
	                        &args);
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
	error = visit_pte_range(vm->address_space->page_table, (void *)start,
	                        (void *)end, VPTEF_SKIP_NULL,
	                        &invalidate_one_page, &args);
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
	ptep = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
	                            (void *)fault_addr, &pgaddr, &pgsize,
	                            &p2align);
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
		error = ihk_mc_pt_set_pte(vm->address_space->page_table, ptep,
		                          pgsize, phys, attr);
		if (error) {
			kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):set_pte failed. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
			goto out;
		}
	}
	else {
		error = ihk_mc_pt_set_range(vm->address_space->page_table, vm,
		                            pgaddr, pgaddr + pgsize, phys,
		                            attr);
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
		dkprintf("[%d]do_page_fault_process_vm(%p,%lx,%lx):"
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
		dkprintf("[%d]do_page_fault_process_vm(%p,%lx,%lx):"
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
		dkprintf("[%d]do_page_fault_process_vm(%p,%lx,%lx):"
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
	struct thread *thread = cpu_local_var(current);

	for (;;) {
		error = do_page_fault_process_vm(fault_vm, fault_addr, reason);
		if (error != -ERESTART) {
			break;
		}

		if (thread->pgio_fp) {
			(*thread->pgio_fp)(thread->pgio_arg);
			thread->pgio_fp = NULL;
		}
	}

	return error;
}

int init_process_stack(struct thread *thread, struct program_load_desc *pn,
                        int argc, char **argv,
                        int envc, char **env)
{
	int s_ind = 0;
	int arg_ind;
	unsigned long size;
	unsigned long end = thread->vm->region.user_end;
	unsigned long start;
	int rc;
	unsigned long vrflag;
	char *stack;
	int error;
	unsigned long *p;
	unsigned long minsz;
	unsigned long at_rand;
	struct process *proc = thread->proc;

	/* create stack range */
	minsz = PAGE_SIZE;
	size = proc->rlimit[MCK_RLIMIT_STACK].rlim_cur & PAGE_MASK;
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
	if ((rc = add_process_memory_range(thread->vm, start, end, NOPHYS,
					vrflag, NULL, 0)) != 0) {
		return rc;
	}

	/* map physical pages for initial stack frame */
	stack = ihk_mc_alloc_pages(minsz >> PAGE_SHIFT, IHK_MC_AP_NOWAIT);
	if (!stack) {
		return -ENOMEM;
	}
	memset(stack, 0, minsz);
	error = ihk_mc_pt_set_range(thread->vm->address_space->page_table,
	                            thread->vm, (void *)(end-minsz),
	                            (void *)end, virt_to_phys(stack),
	                            arch_vrflag_to_ptattr(vrflag, PF_POPULATE,
	                                                  NULL));
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
	memcpy(proc->saved_auxv, &p[s_ind + 1], sizeof(proc->saved_auxv));

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

	ihk_mc_modify_user_context(thread->uctx, IHK_UCR_STACK_POINTER,
	                           end + sizeof(unsigned long) * s_ind);
	thread->vm->region.stack_end = end;
	thread->vm->region.stack_start = start;
	return 0;
}


unsigned long extend_process_region(struct process_vm *vm,
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
			if((rc = add_process_memory_range(vm, old_aligned_end,
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

		if((rc = add_process_memory_range(vm, aligned_end,
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
	if((rc = add_process_memory_range(vm, aligned_end, aligned_new_end,
                                      (p==0?0:virt_to_phys(p)), flag, NULL, 0)) != 0){
		free_pages(p, (aligned_new_end - aligned_end) >> PAGE_SHIFT);
		return end;
	}

	return address;
}

// Original version retained because dcfa (src/mccmd/client/ibmic/main.c) calls this
int remove_process_region(struct process_vm *vm,
                          unsigned long start, unsigned long end)
{
	if ((start & (PAGE_SIZE - 1)) || (end & (PAGE_SIZE - 1))) {
		return -EINVAL;
	}

	ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
	/* We defer freeing to the time of exit */
	// XXX: check error
	ihk_mc_pt_clear_range(vm->address_space->page_table, vm,
			(void *)start, (void *)end);
	ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);

	return 0;
}

void flush_process_memory(struct process_vm *vm)
{
	struct vm_range *range;
	struct vm_range *next;
	int error;

	dkprintf("flush_process_memory(%p)\n", vm);
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
						vm, range->start, range->end, error);
				/* through */
			}
		}
	}
	ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);
	dkprintf("flush_process_memory(%p):\n", vm);
	return;
}

void free_process_memory_ranges(struct process_vm *vm)
{
	int error;
	struct vm_range *range, *next;

	if (vm == NULL) {
		return;
	}

	ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);
	list_for_each_entry_safe(range, next, &vm->vm_range_list, list) {
		error = free_process_memory_range(vm, range);
		if (error) {
			ekprintf("free_process_memory(%p):"
					"free range failed. %lx-%lx %d\n",
					vm, range->start, range->end, error);
			/* through */
		}
	}
	ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);
}

void
hold_process(struct process *proc)
{
	ihk_atomic_inc(&proc->refcount);
}

void
release_process(struct process *proc)
{
	struct process *parent;
	struct mcs_rwlock_node_irqsave lock;
	struct process_hash *phash;
	struct resource_set *rset;
	int hash;

	if (!ihk_atomic_dec_and_test(&proc->refcount)) {
		return;
	}

	rset = cpu_local_var(resource_set);
	phash = rset->process_hash;
	hash = process_hash(proc->pid);

	mcs_rwlock_writer_lock(&phash->lock[hash], &lock);
	list_del(&proc->hash_list);
	mcs_rwlock_writer_unlock(&phash->lock[hash], &lock);

	parent = proc->parent;
	mcs_rwlock_writer_lock(&parent->children_lock, &lock);
	list_del(&proc->siblings_list);
	mcs_rwlock_writer_unlock(&parent->children_lock, &lock);

	if(proc->ptrace & PT_TRACED){
		parent = proc->ppid_parent;
		mcs_rwlock_writer_lock(&parent->children_lock, &lock);
		list_del(&proc->ptraced_siblings_list);
		mcs_rwlock_writer_unlock(&parent->children_lock, &lock);
	}

	kfree(proc);
}

void
hold_process_vm(struct process_vm *vm)
{
	ihk_atomic_inc(&vm->refcount);
}

void
release_process_vm(struct process_vm *vm)
{
	struct vm_range *range, *next;
	int error;

	if (!ihk_atomic_dec_and_test(&vm->refcount)) {
		return;
	}

	ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);
	list_for_each_entry_safe(range, next, &vm->vm_range_list, list) {
		error = free_process_memory_range(vm, range);
		if (error) {
			ekprintf("free_process_memory(%p):"
					"free range failed. %lx-%lx %d\n",
					vm, range->start, range->end, error);
			/* through */
		}
	}
	ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);
}

static void
free_process_vm(struct process_vm *vm)
{
	detach_address_space(vm->address_space, vm->proc->pid);
	kfree(vm);
	release_process(vm->proc);
}

int populate_process_memory(struct process_vm *vm, void *start, size_t len)
{
	int error;
	const int reason = PF_USER | PF_POPULATE;
	uintptr_t end;
	uintptr_t addr;

	end = (uintptr_t)start + len;
	for (addr = (uintptr_t)start; addr < end; addr += PAGE_SIZE) {
		error = page_fault_process_vm(vm, (void *)addr, reason);
		if (error) {
			ekprintf("populate_process_range:page_fault_process_vm"
					"(%p,%lx,%lx) failed %d\n",
					vm, addr, reason, error);
			goto out;
		}
	}

	error = 0;
out:
	return error;
}

void hold_thread(struct thread *thread)
{
	if (thread->proc->pstatus & (PS_ZOMBIE | PS_EXITED)) {
		panic("hold_thread: already exited process");
	}

	ihk_atomic_inc(&thread->refcount);
	return;
}

void
hold_sigcommon(struct sig_common *sigcommon)
{
	ihk_atomic_inc(&sigcommon->use);
}

void
release_sigcommon(struct sig_common *sigcommon)
{
	struct sig_pending *pending;
	struct sig_pending *next;

	if (!ihk_atomic_dec_and_test(&sigcommon->use)) {
		return;
	}

	list_for_each_entry_safe(pending, next, &sigcommon->sigpending, list){
		list_del(&pending->list);
		kfree(pending);
	}
	kfree(sigcommon);
}

void destroy_thread(struct thread *thread)
{
	struct sig_pending *pending;
	struct sig_pending *signext;
	struct mcs_rwlock_node_irqsave lock;
	struct process *proc = thread->proc;
	struct resource_set *resource_set = cpu_local_var(resource_set);
	int hash;

	mcs_rwlock_writer_lock(&proc->threads_lock, &lock);
	list_del(&thread->siblings_list);
	mcs_rwlock_writer_unlock(&proc->threads_lock, &lock);

	hash = thread_hash(thread->tid);
	mcs_rwlock_writer_lock(&resource_set->thread_hash->lock[hash], &lock);
	list_del(&thread->hash_list);
	mcs_rwlock_writer_unlock(&resource_set->thread_hash->lock[hash], &lock);

	cpu_clear(thread->cpu_id, &thread->vm->cpu_set, &thread->vm->cpu_set_lock);
	list_for_each_entry_safe(pending, signext, &thread->sigpending, list){
		list_del(&pending->list);
		kfree(pending);
	}

	if (thread->ptrace_debugreg) {
		kfree(thread->ptrace_debugreg);
	}
	if (thread->ptrace_recvsig) {
		kfree(thread->ptrace_recvsig);
	}
	if (thread->ptrace_sendsig) {
		kfree(thread->ptrace_sendsig);
	}
	if (thread->fp_regs) {
		release_fp_regs(thread);
	}

	release_sigcommon(thread->sigcommon);

	ihk_mc_free_pages(thread, KERNEL_STACK_NR_PAGES);
}

void release_thread(struct thread *thread)
{
	struct process_vm *vm;
	struct process *proc;

	if (!ihk_atomic_dec_and_test(&thread->refcount)) {
		return;
	}

	vm = thread->vm;
	proc = thread->proc;

	destroy_thread(thread);

	if(ihk_atomic_read(&vm->refcount) == 0)
		free_process_vm(vm);
	release_process(proc);
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
			do_migrate();
			v->flags &= ~CPU_FLAG_NEED_MIGRATE;
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
			struct thread *t;

			s = ihk_mc_spinlock_lock(&v->runq_lock);
			list_for_each_entry(t, &v->runq, sched_list) {
				if (t->tstatus == PS_RUNNING) {
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

struct resource_set *
new_resource_set()
{
	struct resource_set *res;
	struct process_hash *phash;
	struct thread_hash *thash;
	struct process *pid1;
	int i;
	int hash;

	res = kmalloc(sizeof(struct resource_set), IHK_MC_AP_NOWAIT);
	phash = kmalloc(sizeof(struct process_hash), IHK_MC_AP_NOWAIT);
	thash = kmalloc(sizeof(struct thread_hash), IHK_MC_AP_NOWAIT);
	pid1 = kmalloc(sizeof(struct process), IHK_MC_AP_NOWAIT);

	if(!res || !phash || !thash || !pid1){
		if(res)
			kfree(res);
		if(phash)
			kfree(phash);
		if(thash)
			kfree(thash);
		if(pid1)
			kfree(pid1);
		return NULL;
	}

	memset(res, '\0', sizeof(struct resource_set));
	memset(phash, '\0', sizeof(struct process_hash));
	memset(thash, '\0', sizeof(struct thread_hash));
	memset(pid1, '\0', sizeof(struct process));

	INIT_LIST_HEAD(&res->phys_mem_list);
	mcs_rwlock_init(&res->phys_mem_lock);
	mcs_rwlock_init(&res->cpu_set_lock);

	for(i = 0; i < HASH_SIZE; i++){
		INIT_LIST_HEAD(&phash->list[i]);
		mcs_rwlock_init(&phash->lock[i]);
	}
	res->process_hash = phash;

	for(i = 0; i < HASH_SIZE; i++){
		INIT_LIST_HEAD(&thash->list[i]);
		mcs_rwlock_init(&thash->lock[i]);
	}
	res->thread_hash = thash;

	init_process(pid1, pid1);
	pid1->pid = 1;
	hash = process_hash(1);
	list_add_tail(&pid1->hash_list, &phash->list[hash]);
	res->pid1 = pid1;

	return res;
}

void
proc_init()
{
	struct resource_set *res = new_resource_set();
	int i;

	if(!res){
		panic("no mem for resource_set");
	}
	INIT_LIST_HEAD(&resource_set_list);
	mcs_rwlock_init(&resource_set_lock);
	for(i = 0; i < num_processors; i++){
		CPU_SET(i, &res->cpu_set);
	}
	// TODO: setup for phys mem
	res->path = kmalloc(2, IHK_MC_AP_NOWAIT);
	if(!res->path){
		panic("no mem for resource_set");
	}
	res->path[0] = '/';
	res->path[0] = '\0';
	list_add_tail(&res->list, &resource_set_list);
}

void sched_init(void)
{
	struct thread *idle_thread = &cpu_local_var(idle);
	struct resource_set *res;

	res = list_first_entry(&resource_set_list, struct resource_set, list);
	cpu_local_var(resource_set) = res;

	memset(idle_thread, 0, sizeof(struct thread));
	memset(&cpu_local_var(idle_vm), 0, sizeof(struct process_vm));
	memset(&cpu_local_var(idle_proc), 0, sizeof(struct process));

	idle_thread->vm = &cpu_local_var(idle_vm);
	idle_thread->vm->address_space = &cpu_local_var(idle_asp);
	idle_thread->proc = &cpu_local_var(idle_proc);
	init_process(idle_thread->proc, NULL);
	idle_thread->proc->vm = &cpu_local_var(idle_vm);
	list_add_tail(&idle_thread->siblings_list,
	               &idle_thread->proc->children_list);

	ihk_mc_init_context(&idle_thread->ctx, NULL, idle);
	ihk_mc_spinlock_init(&idle_thread->vm->memory_range_lock);
	INIT_LIST_HEAD(&idle_thread->vm->vm_range_list);
	idle_thread->proc->pid = 0;
	idle_thread->tid = ihk_mc_get_processor_id();

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
	struct thread *thread;
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
		if (req->thread->cpu_id != cur_cpu_id) /* already not here */
			goto ack;
		if (CPU_ISSET(cur_cpu_id, &req->thread->cpu_set)) /* good affinity */
			goto ack;

		/* 1. select CPU */
		for (cpu_id = 0; cpu_id < CPU_SETSIZE; cpu_id++)
			if (CPU_ISSET(cpu_id, &req->thread->cpu_set))
				break;
		if (CPU_SETSIZE == cpu_id) /* empty affinity (bug?) */
			goto ack;

		/* 2. migrate thread */
		v = get_cpu_local_var(cpu_id);
		double_rq_lock(cur_v, v, &irqstate);
		list_del(&req->thread->sched_list);
		cur_v->runq_len -= 1;
		old_cpu_id = req->thread->cpu_id;
		req->thread->cpu_id = cpu_id;
		settid(req->thread, 2, cpu_id, old_cpu_id);
		list_add_tail(&req->thread->sched_list, &v->runq);
		v->runq_len += 1;
		
		/* update cpu_set of the VM for remote TLB invalidation */
		cpu_clear_and_set(old_cpu_id, cpu_id, &req->thread->vm->cpu_set,
				&req->thread->vm->cpu_set_lock);

		dkprintf("do_migrate(): migrated TID %d from CPU %d to CPU %d\n",
			req->thread->tid, old_cpu_id, cpu_id);
		
		v->flags |= CPU_FLAG_NEED_RESCHED;
		ihk_mc_interrupt_cpu(get_x86_cpu_local_variable(cpu_id)->apic_id, 0xd1);
		double_rq_unlock(cur_v, v, irqstate);

ack:
		waitq_wakeup(&req->wq);
	}
	ihk_mc_spinlock_unlock(&cur_v->migq_lock, irqstate);
}

void schedule(void)
{
	struct cpu_local_var *v;
	struct thread *next, *prev, *thread, *tmp = NULL;
	int switch_ctx = 0;
	struct thread *last;

	if (cpu_local_var(no_preempt)) {
		kprintf("no schedule() while no preemption! \n");
panic("panic schedule\n");
		return;
	}

	if (cpu_local_var(current)
			&& cpu_local_var(current)->in_syscall_offload) {
		dkprintf("no schedule() while syscall offload!\n");
		return;
	}

redo:
	cpu_local_var(runq_irqstate) = 
		ihk_mc_spinlock_lock(&(get_this_cpu_local_var()->runq_lock));
	v = get_this_cpu_local_var();

	next = NULL;
	prev = v->current;
	
	v->flags &= ~CPU_FLAG_NEED_RESCHED;

	/* All runnable processes are on the runqueue */
	if (prev && prev != &cpu_local_var(idle)) {
		list_del(&prev->sched_list);
		--v->runq_len;

		/* Round-robin if not exited yet */
		if (prev->tstatus != PS_EXITED) {
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
		list_for_each_entry_safe(thread, tmp, &(v->runq), sched_list) {
			if (thread->tstatus == PS_RUNNING) {
				next = thread;
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
		        prev ? prev->tid : 0, next ? next->tid : 0);

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

		ihk_mc_load_page_table(next->vm->address_space->page_table);

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

		if ((last != NULL) && (last->tstatus == PS_EXITED)) {
			release_thread(last);
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
	unsigned long irqstate;
	struct cpu_local_var *v = get_this_cpu_local_var();
	irqstate = ihk_mc_spinlock_lock(&v->runq_lock);
	if (v->flags & CPU_FLAG_NEED_RESCHED) {
		if (v->in_interrupt && (v->flags & CPU_FLAG_NEED_MIGRATE)) {
			kprintf("no migration in IRQ context\n");
			ihk_mc_spinlock_unlock(&v->runq_lock, irqstate);
			return;
		}
		ihk_mc_spinlock_unlock(&v->runq_lock, irqstate);
		schedule();
	}
	else {
		ihk_mc_spinlock_unlock(&v->runq_lock, irqstate);
	}
}

int
sched_wakeup_thread(struct thread *thread, int valid_states)
{
	int status;
	int spin_slept = 0;
	unsigned long irqstate;
	struct cpu_local_var *v = get_cpu_local_var(thread->cpu_id);

	dkprintf("sched_wakeup_process,proc->pid=%d,valid_states=%08x,proc->status=%08x,proc->cpu_id=%d,my cpu_id=%d\n",
			 thread->proc->pid, valid_states, thread->tstatus, thread->cpu_id, ihk_mc_get_processor_id());

	irqstate = ihk_mc_spinlock_lock(&(thread->spin_sleep_lock));
	if (thread->spin_sleep > 0) {
		dkprintf("sched_wakeup_process() spin wakeup: cpu_id: %d\n",
				 thread->cpu_id);

		spin_slept = 1;
		status = 0;
	}
	--thread->spin_sleep;
	ihk_mc_spinlock_unlock(&(thread->spin_sleep_lock), irqstate);

	if (spin_slept) {
		return status;
	}

	irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));

	if (thread->tstatus & valid_states) {
		xchg4((int *)(&thread->tstatus), PS_RUNNING);
		status = 0;
	}
	else {
		status = -EINVAL;
	}

	ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);

	if (!status && (thread->cpu_id != ihk_mc_get_processor_id())) {
		dkprintf("sched_wakeup_process,issuing IPI,thread->cpu_id=%d\n",
				 thread->cpu_id);
		ihk_mc_interrupt_cpu(get_x86_cpu_local_variable(thread->cpu_id)->apic_id,
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
void sched_request_migrate(int cpu_id, struct thread *thread)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	struct migrate_request req = { .thread = thread };
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
void __runq_add_thread(struct thread *thread, int cpu_id)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	list_add_tail(&thread->sched_list, &v->runq);
	++v->runq_len;
	v->flags |= CPU_FLAG_NEED_RESCHED;
	thread->cpu_id = cpu_id;
	//thread->proc->status = PS_RUNNING;	/* not set here */
	get_cpu_local_var(cpu_id)->status = CPU_STATUS_RUNNING;

	dkprintf("runq_add_proc(): tid %d added to CPU[%d]'s runq\n", 
             thread->tid, cpu_id);
}

void runq_add_thread(struct thread *thread, int cpu_id)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	unsigned long irqstate;
	
	irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
	__runq_add_thread(thread, cpu_id);
	ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);

	create_proc_procfs_files(thread->proc->pid, cpu_id);

	/* Kick scheduler */
	if (cpu_id != ihk_mc_get_processor_id())
		ihk_mc_interrupt_cpu(
		         get_x86_cpu_local_variable(cpu_id)->apic_id, 0xd1);
}

/* NOTE: shouldn't remove a running process! */
void runq_del_thread(struct thread *thread, int cpu_id)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	unsigned long irqstate;

	irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
	list_del(&thread->sched_list);
	--v->runq_len;

	if (!v->runq_len)
		get_cpu_local_var(cpu_id)->status = CPU_STATUS_IDLE;

	ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
}

struct thread *
find_thread(int pid, int tid, struct mcs_rwlock_node_irqsave *lock)
{
	struct thread *thread;
	struct thread_hash *thash = cpu_local_var(resource_set)->thread_hash;
	int hash = thread_hash(tid);

	if(tid <= 0)
		return NULL;
	mcs_rwlock_reader_lock(&thash->lock[hash], lock);
	list_for_each_entry(thread, &thash->list[hash], hash_list){
		if(thread->tid == tid){
			if(pid <= 0)
				return thread;
			if(pid == thread->proc->pid)
				return thread;
		}
	}
	mcs_rwlock_reader_unlock(&thash->lock[hash], lock);
	return NULL;
}

void
thread_unlock(struct thread *thread, struct mcs_rwlock_node_irqsave *lock)
{
	struct thread_hash *thash = cpu_local_var(resource_set)->thread_hash;
	int hash;

	if(!thread)
		return;
	hash = thread_hash(thread->tid);
	mcs_rwlock_reader_unlock(&thash->lock[hash], lock);
}

struct process *
find_process(int pid, struct mcs_rwlock_node_irqsave *lock)
{
	struct process *proc;
	struct process_hash *phash = cpu_local_var(resource_set)->process_hash;
	int hash = process_hash(pid);

	if(pid <= 0)
		return NULL;
	mcs_rwlock_reader_lock(&phash->lock[hash], lock);
	list_for_each_entry(proc, &phash->list[hash], hash_list){
		if(proc->pid == pid){
			if(pid == proc->pid)
				return proc;
		}
	}
	mcs_rwlock_reader_unlock(&phash->lock[hash], lock);
	return NULL;
}

void
process_unlock(struct process *proc, struct mcs_rwlock_node_irqsave *lock)
{
	struct process_hash *phash = cpu_local_var(resource_set)->process_hash;
	int hash;

	if(!proc)
		return;
	hash = process_hash(proc->pid);
	mcs_rwlock_reader_unlock(&phash->lock[hash], lock);
}

void
debug_log(unsigned long arg)
{
	struct process *p;
	struct thread *t;
	int i;
	struct mcs_rwlock_node_irqsave lock;
	struct resource_set *rset = cpu_local_var(resource_set);
	struct process_hash *phash = rset->process_hash;
	struct thread_hash *thash = rset->thread_hash;

	switch(arg){
	    case 1:
		for(i = 0; i < HASH_SIZE; i++){
			__mcs_rwlock_reader_lock(&phash->lock[i], &lock);
			list_for_each_entry(p, &phash->list[i], hash_list){
				kprintf("pid=%d ppid=%d status=%d\n",
				        p->pid, p->ppid_parent->pid, p->pstatus);
			}
			__mcs_rwlock_reader_unlock(&phash->lock[i], &lock);
		}
		break;
	    case 2:
		for(i = 0; i < HASH_SIZE; i++){
			__mcs_rwlock_reader_lock(&thash->lock[i], &lock);
			list_for_each_entry(t, &thash->list[i], hash_list){
				kprintf("cpu=%d pid=%d tid=%d status=%d offload=%d\n",
				        t->cpu_id, t->proc->pid, t->tid,
				        t->tstatus, t->in_syscall_offload);
			}
			__mcs_rwlock_reader_unlock(&thash->lock[i], &lock);
		}
		break;
	    case 3:
		for(i = 0; i < HASH_SIZE; i++){
			if(phash->lock[i].node)
				kprintf("phash[i] is locked\n");
			list_for_each_entry(p, &phash->list[i], hash_list){
				kprintf("pid=%d ppid=%d status=%d\n",
				        p->pid, p->ppid_parent->pid, p->pstatus);
			}
		}
		break;
	    case 4:
		for(i = 0; i < HASH_SIZE; i++){
			if(thash->lock[i].node)
				kprintf("thash[i] is locked\n");
			list_for_each_entry(t, &thash->list[i], hash_list){
				kprintf("cpu=%d pid=%d tid=%d status=%d\n",
				        t->cpu_id, t->proc->pid, t->tid,
				        t->tstatus);
			}
		}
		break;
	}
}
