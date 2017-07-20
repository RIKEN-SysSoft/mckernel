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
#include <xpmem.h>
#include <rusage.h>
#include <xpmem.h>

//#define DEBUG_PRINT_PROCESS

#ifdef DEBUG_PRINT_PROCESS
#define dkprintf(...) kprintf(__VA_ARGS__)
#define ekprintf(...) kprintf(__VA_ARGS__)
#else
#define dkprintf(...) do { if (0) kprintf(__VA_ARGS__); } while (0)
#define ekprintf(...) kprintf(__VA_ARGS__)
#endif

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
extern void __runq_add_proc(struct thread *proc, int cpu_id);
extern void terminate_host(int pid);
extern void lapic_timer_enable(unsigned int clocks);
extern void lapic_timer_disable();
extern int num_processors;
extern ihk_spinlock_t cpuid_head_lock;
int ptrace_detach(int pid, int data);
extern unsigned long do_kill(struct thread *, int pid, int tid, int sig, struct siginfo *info, int ptracecont);
extern void procfs_create_thread(struct thread *);
extern void procfs_delete_thread(struct thread *);
extern void perf_start(struct mc_perf_event *event);
extern void perf_reset(struct mc_perf_event *event);

struct list_head resource_set_list;
mcs_rwlock_lock_t    resource_set_lock;

void
init_process(struct process *proc, struct process *parent)
{
	/* These will be filled out when changing status */
	proc->pid = -1;
	proc->status = PS_RUNNING;

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
		proc->mpol_flags = parent->mpol_flags;
		proc->mpol_threshold = parent->mpol_threshold;
		memcpy(proc->rlimit, parent->rlimit,
		       sizeof(struct rlimit) * MCK_RLIM_MAX);
	}

	INIT_LIST_HEAD(&proc->threads_list);
	INIT_LIST_HEAD(&proc->children_list);
	INIT_LIST_HEAD(&proc->ptraced_children_list);
	mcs_rwlock_init(&proc->threads_lock);
	mcs_rwlock_init(&proc->children_lock);
	ihk_mc_spinlock_init(&proc->mckfd_lock);
	waitq_init(&proc->waitpid_q);
	ihk_atomic_set(&proc->refcount, 2);
	proc->monitoring_event = NULL;
#ifdef PROFILE_ENABLE
	mcs_lock_init(&proc->profile_lock);
	proc->profile_events = NULL;
#endif
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
	struct process_vm *vm = thread->vm;
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

	ihk_atomic_inc(&vm->refcount);
}

struct address_space *
create_address_space(struct resource_set *res, int n)
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
	asp->nslots = n;
	asp->page_table = pt;
	ihk_atomic_set(&asp->refcount, 1);
	memset(&asp->cpu_set, 0, sizeof(cpu_set_t));
	ihk_mc_spinlock_init(&asp->cpu_set_lock);
	return asp;
}

void
hold_address_space(struct address_space *asp)
{
	ihk_atomic_inc(&asp->refcount);
}

void
release_address_space(struct address_space *asp)
{
	if (!ihk_atomic_dec_and_test(&asp->refcount)) {
		return;
	}
	if(asp->free_cb)
		asp->free_cb(asp, asp->opt);
	ihk_mc_pt_destroy(asp->page_table);
	kfree(asp);
}

void
detach_address_space(struct address_space *asp, int pid)
{
	int i;

	for(i = 0; i < asp->nslots; i++){
		if(asp->pids[i] == pid){
			asp->pids[i] = 0;
			break;
		}
	}
	release_address_space(asp);
}

static int
init_process_vm(struct process *owner, struct address_space *asp, struct process_vm *vm)
{
	int i;
	ihk_mc_spinlock_init(&vm->memory_range_lock);
	ihk_mc_spinlock_init(&vm->page_table_lock);

	ihk_atomic_set(&vm->refcount, 1);
	INIT_LIST_HEAD(&vm->vm_range_list);
	INIT_LIST_HEAD(&vm->vm_range_numa_policy_list);
	vm->address_space = asp;
	vm->proc = owner;
	vm->exiting = 0;

	memset(&vm->numa_mask, 0, sizeof(vm->numa_mask));
	for (i = 0; i < ihk_mc_get_nr_numa_nodes(); ++i) {
		if (i >= PROCESS_NUMA_MASK_BITS) {
			kprintf("%s: error: NUMA id is larger than mask size!\n",
				__FUNCTION__);
			break;
		}
		set_bit(i, &vm->numa_mask[0]);
	}
	vm->numa_mem_policy = MPOL_DEFAULT;

	for (i = 0; i < VM_RANGE_CACHE_SIZE; ++i) {
		vm->range_cache[i] = NULL;
	}
	vm->range_cache_ind = 0;

	return 0;
}

struct thread *create_thread(unsigned long user_pc,
		unsigned long *__cpu_set, size_t cpu_set_size)
{
	struct thread *thread;
	struct process *proc;
	struct process_vm *vm = NULL;
	struct address_space *asp = NULL;
	int cpu;
	int cpu_set_empty = 1;

	thread = ihk_mc_alloc_pages(KERNEL_STACK_NR_PAGES, IHK_MC_AP_NOWAIT);
	if (!thread)
		return NULL;
	memset(thread, 0, sizeof(struct thread));
	ihk_atomic_set(&thread->refcount, 2);
	proc = kmalloc(sizeof(struct process), IHK_MC_AP_NOWAIT);
	vm = kmalloc(sizeof(struct process_vm), IHK_MC_AP_NOWAIT);
	asp = create_address_space(cpu_local_var(resource_set), 1);
	if (!proc || !vm || !asp)
		goto err;
	memset(proc, 0, sizeof(struct process));
	memset(vm, 0, sizeof(struct process_vm));
	init_process(proc, cpu_local_var(resource_set)->pid1);

	/* Use requested CPU cores */
	for_each_set_bit(cpu, __cpu_set, cpu_set_size * BITS_PER_BYTE) {
		if (cpu >= num_processors) {
			kprintf("%s: invalid CPU requested in initial cpu_set\n",
				__FUNCTION__);
			goto err;
		}

		dkprintf("%s: pid: %d, CPU: %d\n",
			__FUNCTION__, proc->pid, cpu); 
		CPU_SET(cpu, &thread->cpu_set);
		CPU_SET(cpu, &proc->cpu_set);
		cpu_set_empty = 0;
	}

	/* Default allows all cores */
	if (cpu_set_empty) {
		struct ihk_mc_cpu_info *infop;
		int i;

		infop = ihk_mc_get_cpu_info();
		for (i = 0; i < infop->ncpus; ++i) {
			CPU_SET(i, &thread->cpu_set);
			CPU_SET(i, &proc->cpu_set);
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
	mcs_rwlock_init(&thread->sigcommon->lock);
	INIT_LIST_HEAD(&thread->sigcommon->sigpending);

	mcs_rwlock_init(&thread->sigpendinglock);
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
	thread->exit_status = -1;

	cpu_set(ihk_mc_get_processor_id(), &thread->vm->address_space->cpu_set,
			&thread->vm->address_space->cpu_set_lock);

	ihk_mc_spinlock_init(&thread->spin_sleep_lock);
	thread->spin_sleep = 0;

	return thread;

err:
	if(proc)
		kfree(proc);
	if(vm)
		kfree(vm);
	if(asp)
		release_address_space(asp);
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

		thread->sigstack.ss_sp = NULL;
		thread->sigstack.ss_flags = SS_DISABLE;
		thread->sigstack.ss_size = 0;
	}
	/* fork() */
	else {
		proc = kmalloc(sizeof(struct process), IHK_MC_AP_NOWAIT);
		if(!proc)
			goto err_free_proc;
		memset(proc, '\0', sizeof(struct process));
		init_process(proc, org->proc);
#ifdef PROFILE_ENABLE
		proc->profile = org->proc->profile;
#endif

		proc->termsig = termsig;
		asp = create_address_space(cpu_local_var(resource_set), 1);
		if(!asp){
			kfree(proc);
			goto err_free_proc;
		}
		proc->vm = kmalloc(sizeof(struct process_vm), IHK_MC_AP_NOWAIT);
		if(!proc->vm){
			release_address_space(asp);
			kfree(proc);
			goto err_free_proc;
		}
		memset(proc->vm, '\0', sizeof(struct process_vm));

		dkprintf("fork(): init_process_vm()\n");
		if (init_process_vm(proc, asp, proc->vm) != 0) {
			release_address_space(asp);
			kfree(proc->vm);
			kfree(proc);
			goto err_free_proc;
		}
		memcpy(&proc->vm->numa_mask, &org->vm->numa_mask,
				sizeof(proc->vm->numa_mask));
		proc->vm->numa_mem_policy =
			org->vm->numa_mem_policy;

		thread->proc = proc;
		thread->vm = proc->vm;

		memcpy(&proc->vm->region, &org->vm->region, sizeof(struct vm_regions));

		dkprintf("fork(): copy_user_ranges()\n");
		/* Copy user-space mappings.
		 * TODO: do this with COW later? */
		if (copy_user_ranges(proc->vm, org->vm) != 0) {
			release_address_space(asp);
			kfree(proc->vm);
			kfree(proc);
			goto err_free_proc;
		}

		thread->vm->vdso_addr = org->vm->vdso_addr;
		thread->vm->vvar_addr = org->vm->vvar_addr;
		thread->proc->maxrss = org->proc->maxrss;
		thread->vm->currss = org->vm->currss;

		thread->sigstack.ss_sp = org->sigstack.ss_sp;
		thread->sigstack.ss_flags = org->sigstack.ss_flags;
		thread->sigstack.ss_size = org->sigstack.ss_size;

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
		mcs_rwlock_init(&thread->sigcommon->lock);
		INIT_LIST_HEAD(&thread->sigcommon->sigpending);
		// TODO: copy signalfd
	}
	mcs_rwlock_init(&thread->sigpendinglock);
	INIT_LIST_HEAD(&thread->sigpending);
	thread->sigmask = org->sigmask;

	ihk_mc_spinlock_init(&thread->spin_sleep_lock);
	thread->spin_sleep = 0;

#ifdef PROFILE_ENABLE
	thread->profile = org->profile | proc->profile;
#endif

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

struct copy_args {
	struct process_vm *new_vm;
	unsigned long new_vrflag;

	/* out */
	intptr_t fault_addr;
};

static int copy_user_pte(void *arg0, page_table_t src_pt, pte_t *src_ptep, void *pgaddr, int pgshift)
{
	struct copy_args * const args = arg0;
	int error;
	intptr_t src_phys;
	struct page *src_page;
	void *src_kvirt;
	const size_t pgsize = (size_t)1 << pgshift;
	int npages;
	void *virt = NULL;
	intptr_t phys;
	const int pgalign = pgshift - PAGE_SHIFT;
	enum ihk_mc_pt_attribute attr;

	if (!pte_is_present(src_ptep)) {
		error = 0;
		goto out;
	}

	src_phys = pte_get_phys(src_ptep);
	src_page = phys_to_page(src_phys);
	src_kvirt = phys_to_virt(src_phys);

	if (src_page && page_is_in_memobj(src_page)) {
		error = 0;
		goto out;
	}

	if (args->new_vrflag & VR_REMOTE) {
		phys = src_phys;
		attr = pte_get_attr(src_ptep, pgsize);
	}
	else {
		dkprintf("copy_user_pte(): 0x%lx PTE found\n", pgaddr);
		dkprintf("copy_user_pte(): page size: %d\n", pgsize);

		npages = pgsize / PAGE_SIZE;
		virt = ihk_mc_alloc_aligned_pages_user(npages, pgalign,
		                                       IHK_MC_AP_NOWAIT);
		if (!virt) {
			kprintf("ERROR: copy_user_pte() allocating new page\n");
			error = -ENOMEM;
			goto out;
		}
		phys = virt_to_phys(virt);
		dkprintf("copy_user_pte(): phys page allocated\n");

		memcpy(virt, src_kvirt, pgsize);
		dkprintf("copy_user_pte(): memcpy OK\n");

		attr = arch_vrflag_to_ptattr(args->new_vrflag, PF_POPULATE, NULL);
	}

	error = ihk_mc_pt_set_range(args->new_vm->address_space->page_table,
			args->new_vm, pgaddr, pgaddr+pgsize, phys, attr,
			pgshift);
	if (error) {
		args->fault_addr = (intptr_t)pgaddr;
		goto out;
	}

	dkprintf("copy_user_pte(): new PTE set\n");
	error = 0;
	virt = NULL;

out:
	if (virt) {
		ihk_mc_free_pages(virt, npages);
	}
	return error;
}

static int copy_user_ranges(struct process_vm *vm, struct process_vm *orgvm)
{
	int error;
	struct vm_range *src_range;
	struct vm_range *range;
	struct copy_args args;

	ihk_mc_spinlock_lock_noirq(&orgvm->memory_range_lock);

	/* Iterate original process' vm_range list and take a copy one-by-one */
	src_range = NULL;
	for (;;) {
		if (!src_range) {
			src_range = lookup_process_memory_range(orgvm, 0, -1);
		}
		else {
			src_range = next_process_memory_range(orgvm, src_range);
		}
		if (!src_range) {
			break;
		}

		if(src_range->flag & VR_DONTFORK)
			continue;

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
		range->pgshift = src_range->pgshift;
		range->private_data = src_range->private_data;
		if (range->memobj) {
			memobj_ref(range->memobj);
		}

		/* Copy actual mappings */
		args.new_vrflag = range->flag;
		args.new_vm = vm;
		args.fault_addr = -1;

		error = visit_pte_range(orgvm->address_space->page_table,
				(void *)range->start, (void *)range->end,
				range->pgshift, VPTEF_SKIP_NULL,
				&copy_user_pte, &args);
		if (error) {
			if (args.fault_addr != -1) {
				kprintf("ERROR: copy_user_ranges() "
						"(%p,%lx-%lx %lx,%lx):"
						"get pgsize failed\n", orgvm,
						range->start, range->end,
						range->flag, args.fault_addr);
			}
			goto err_free_range_rollback;
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
	int error;
	unsigned long flags;
	enum ihk_mc_pt_attribute attr;

	attr = arch_vrflag_to_ptattr(range->flag, PF_POPULATE, NULL);
	flags = ihk_mc_spinlock_lock(&vm->page_table_lock);
	error = ihk_mc_pt_set_range(vm->address_space->page_table, vm,
			(void *)range->start, (void *)range->end, phys, attr,
			range->pgshift);
	if (error) {
		kprintf("update_process_page_table:ihk_mc_pt_set_range failed. %d\n", error);
		goto out;
	}

	error = 0;
out:
	ihk_mc_spinlock_unlock(&vm->page_table_lock, flags);
	return error;
}

int split_process_memory_range(struct process_vm *vm, struct vm_range *range,
		uintptr_t addr, struct vm_range **splitp)
{
	int error;
	struct vm_range *newrange = NULL;

	dkprintf("split_process_memory_range(%p,%lx-%lx,%lx,%p)\n",
			vm, range->start, range->end, addr, splitp);

	error = ihk_mc_pt_split(vm->address_space->page_table, vm, (void *)addr);
	if (error) {
		ekprintf("split_process_memory_range:"
				"ihk_mc_pt_split failed. %d\n", error);
		goto out;
	}

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
	newrange->pgshift = range->pgshift;
	newrange->private_data = range->private_data;

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
	int i;

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
	for (i = 0; i < VM_RANGE_CACHE_SIZE; ++i) {
		if (vm->range_cache[i] == merging)
			vm->range_cache[i] = surviving;
	}
	kfree(merging);

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
	int error, i;
	intptr_t start;
	intptr_t end;
	struct vm_range *neighbor;
	intptr_t lpstart;
	intptr_t lpend;
	size_t pgsize;

	dkprintf("free_process_memory_range(%p, 0x%lx - 0x%lx)\n",
			vm, range->start, range->end);

	start = range->start;
	end = range->end;
	if (!(range->flag & (VR_REMOTE | VR_IO_NOCACHE | VR_RESERVED))) {
		neighbor = previous_process_memory_range(vm, range);
		pgsize = -1;
		for (;;) {
			error = arch_get_smaller_page_size(
					NULL, pgsize, &pgsize, NULL);
			if (error) {
				kprintf("free_process_memory_range:"
						"arch_get_smaller_page_size failed."
						" %d\n", error);
				break;
			}
			lpstart = start & ~(pgsize - 1);
			if (!neighbor || (neighbor->end <= lpstart)) {
				start = lpstart;
				break;
			}
		}
		neighbor = next_process_memory_range(vm, range);
		pgsize = -1;
		for (;;) {
			error = arch_get_smaller_page_size(
					NULL, pgsize, &pgsize, NULL);
			if (error) {
				kprintf("free_process_memory_range:"
						"arch_get_smaller_page_size failed."
						" %d\n", error);
				break;
			}
			lpend = (end + pgsize - 1) & ~(pgsize - 1);
			if (!neighbor || (lpend <= neighbor->start)) {
				end = lpend;
				break;
			}
		}

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
	for (i = 0; i < VM_RANGE_CACHE_SIZE; ++i) {
		if (vm->range_cache[i] == range)
			vm->range_cache[i] = NULL;
	}
	kfree(range);

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

		if (freerange->private_data) {
			xpmem_remove_process_memory_range(vm, freerange);
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


/* Parallel memset implementation on top of general
 * SMP funcution call facility */
struct memset_smp_req {
	unsigned long phys;
	size_t len;
	int val;
};

int memset_smp_handler(int cpu_index, int nr_cpus, void *arg)
{
	struct memset_smp_req *req =
		(struct memset_smp_req *)arg;
	size_t len = req->len / nr_cpus;

	if (!len) {
		/* First core clears all */
		if (!cpu_index) {
			memset((void *)phys_to_virt(req->phys), req->val, req->len);
		}
	}
	else {
		/* Divide and clear */
		unsigned long p_s = req->phys + (cpu_index * len);
		unsigned long p_e = p_s + len;
		if (cpu_index == nr_cpus - 1) {
			p_e = req->phys + req->len;
		}

		memset((void *)phys_to_virt(p_s), req->val, p_e - p_s);
		dkprintf("%s: cpu_index: %d, nr_cpus: %d, phys: 0x%lx, "
				"len: %lu, p_s: 0x%lx, p_e: 0x%lx\n",
				__FUNCTION__, cpu_index, nr_cpus,
				req->phys, req->len,
				p_s, p_e);
	}

	return 0;
}

void *memset_smp(cpu_set_t *cpu_set, void *s, int c, size_t n)
{
	struct memset_smp_req req = {
		.phys = virt_to_phys(s),
		.len = n,
		.val = c,
	};

	smp_call_func(cpu_set, memset_smp_handler, &req);
	return NULL;
}

int add_process_memory_range(struct process_vm *vm,
		unsigned long start, unsigned long end,
		unsigned long phys, unsigned long flag,
		struct memobj *memobj, off_t offset,
		int pgshift, struct vm_range **rp)
{
	struct vm_range *range;
	int rc;

	if ((start < vm->region.user_start)
			|| (vm->region.user_end < end)) {
		kprintf("%s: error: range %lx - %lx is not in user available area\n",
				__FUNCTION__,
				start, end, vm->region.user_start,
				vm->region.user_end);
		return -EINVAL;
	}

	range = kmalloc(sizeof(struct vm_range), IHK_MC_AP_NOWAIT);
	if (!range) {
		kprintf("%s: ERROR: allocating pages for range\n", __FUNCTION__);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&range->list);
	range->start = start;
	range->end = end;
	range->flag = flag;
	range->memobj = memobj;
	range->objoff = offset;
	range->pgshift = pgshift;
	range->private_data = NULL;

	rc = 0;
	if (phys == NOPHYS) {
		/* Nothing to map */
	}
	else if (flag & VR_REMOTE) {
		rc = update_process_page_table(vm, range, phys, IHK_PTA_REMOTE);
	}
	else if (flag & VR_IO_NOCACHE) {
		rc = update_process_page_table(vm, range, phys, PTATTR_UNCACHABLE);
	}
	else if (flag & VR_DEMAND_PAGING) {
		dkprintf("%s: range: 0x%lx - 0x%lx is demand paging\n",
				__FUNCTION__, range->start, range->end);
		rc = 0;
	}
	else if ((range->flag & VR_PROT_MASK) == VR_PROT_NONE) {
		rc = 0;
	}
	else {
		rc = update_process_page_table(vm, range, phys, 0);
	}

	if (rc != 0) {
		kprintf("%s: ERROR: preparing page tables\n", __FUNCTION__);
		kfree(range);
		return rc;
	}

	insert_vm_range_list(vm, range);

	/* Clear content! */
	if (phys != NOPHYS && !(flag & (VR_REMOTE | VR_DEMAND_PAGING))
			&& ((flag & VR_PROT_MASK) != VR_PROT_NONE)) {
#if 1
			memset((void*)phys_to_virt(phys), 0, end - start);
#else
		if (end - start < (1024*1024)) {
			memset((void*)phys_to_virt(phys), 0, end - start);
		}
		else {
			memset_smp(&cpu_local_var(current)->cpu_set,
					(void *)phys_to_virt(phys), 0, end - start);
		}
#endif
	}

	/* Return range object if requested */
	if (rp) {
		*rp = range;
	}

	return 0;
}

struct vm_range *lookup_process_memory_range(
		struct process_vm *vm, uintptr_t start, uintptr_t end)
{
	int i;
	struct vm_range *range = NULL;

	dkprintf("lookup_process_memory_range(%p,%lx,%lx)\n", vm, start, end);

	if (end <= start) {
		goto out;
	}

	for (i = 0; i < VM_RANGE_CACHE_SIZE; ++i) {
		int c_i = (i + vm->range_cache_ind) % VM_RANGE_CACHE_SIZE;
		if (!vm->range_cache[c_i])
			continue;

		if (vm->range_cache[c_i]->start <= start &&
			vm->range_cache[c_i]->end >= end)
			return vm->range_cache[c_i];
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
	if (range) {
		vm->range_cache_ind = (vm->range_cache_ind - 1 + VM_RANGE_CACHE_SIZE)
			% VM_RANGE_CACHE_SIZE;
		vm->range_cache[vm->range_cache_ind] = range;
	}

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
		void *pgaddr, int pgshift)
{
	struct rfp_args * const args = arg0;
	const size_t pgsize = (size_t)1 << pgshift;
	int error;
	off_t off;
	pte_t apte;
	uintptr_t phys;
	struct page *page;

	dkprintf("remap_one_page(%p,%p,%p %#lx,%p,%d)\n",
			arg0, pt, ptep, *ptep, pgaddr, pgshift);

	/* XXX: NYI: large pages */
	if (pgsize != PAGE_SIZE) {
		error = -E2BIG;
		ekprintf("remap_one_page(%p,%p,%p %#lx,%p,%d):%d\n",
				arg0, pt, ptep, *ptep, pgaddr, pgshift, error);
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
		ihk_mc_free_pages_user(phys_to_virt(phys), pgsize/PAGE_SIZE);
	}

	error = 0;
out:
	dkprintf("remap_one_page(%p,%p,%p %#lx,%p,%d): %d\n",
			arg0, pt, ptep, *ptep, pgaddr, pgshift, error);
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
			(void *)end, range->pgshift, VPTEF_DEFAULT,
			&remap_one_page, &args);
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
		void *pgaddr, int pgshift)
{
	struct sync_args *args = arg0;
	const size_t pgsize = (size_t)1 << pgshift;
	int error;
	uintptr_t phys;

	dkprintf("sync_one_page(%p,%p,%p %#lx,%p,%d)\n",
			arg0, pt, ptep, *ptep, pgaddr, pgshift);
	if (pte_is_null(ptep) || pte_is_fileoff(ptep, pgsize)
			|| !pte_is_dirty(ptep, pgsize)) {
		error = 0;
		goto out;
	}

	pte_clear_dirty(ptep, pgsize);
	flush_tlb_single((uintptr_t)pgaddr);	/* XXX: TLB flush */

	phys = pte_get_phys(ptep);
	if (args->memobj->flags & MF_ZEROFILL) {
		error = 0;
		goto out;
	}

	error = memobj_flush_page(args->memobj, phys, pgsize);
	if (error) {
		ekprintf("sync_one_page(%p,%p,%p %#lx,%p,%d):"
				"flush failed. %d\n",
				arg0, pt, ptep, *ptep, pgaddr, pgshift, error);
		pte_set_dirty(ptep, pgsize);
		goto out;
	}

	error = 0;
out:
	dkprintf("sync_one_page(%p,%p,%p %#lx,%p,%d):%d\n",
			arg0, pt, ptep, *ptep, pgaddr, pgshift, error);
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

	if (!(range->memobj->flags & MF_ZEROFILL)) {
		memobj_lock(range->memobj);
	}

	error = visit_pte_range(vm->address_space->page_table, (void *)start,
			(void *)end, range->pgshift, VPTEF_SKIP_NULL,
			&sync_one_page, &args);

	if (!(range->memobj->flags & MF_ZEROFILL)) {
		memobj_unlock(range->memobj);
	}

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
		void *pgaddr, int pgshift)
{
	struct invalidate_args *args = arg0;
	struct vm_range *range = args->range;
	const size_t pgsize = (size_t)1 << pgshift;
	int error;
	uintptr_t phys;
	struct page *page;
	off_t linear_off;
	pte_t apte;

	dkprintf("invalidate_one_page(%p,%p,%p %#lx,%p,%d)\n",
			arg0, pt, ptep, *ptep, pgaddr, pgshift);
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
		ekprintf("invalidate_one_page(%p,%p,%p %#lx,%p,%d):"
				"invalidate failed. %d\n",
				arg0, pt, ptep, *ptep, pgaddr, pgshift, error);
		goto out;
	}

	error = 0;
out:
	dkprintf("invalidate_one_page(%p,%p,%p %#lx,%p,%d):%d\n",
			arg0, pt, ptep, *ptep, pgaddr, pgshift, error);
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
	                        (void *)end, range->pgshift, VPTEF_SKIP_NULL,
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
			(void *)fault_addr, range->pgshift, &pgaddr, &pgsize,
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
	while (((uintptr_t)pgaddr < range->start)
			|| (range->end < ((uintptr_t)pgaddr + pgsize))) {
		ptep = NULL;
		error = arch_get_smaller_page_size(NULL, pgsize, &pgsize, &p2align);
		if (error) {
			kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):arch_get_smaller_page_size(pte) failed. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
			goto out;
		}
		pgaddr = (void *)(fault_addr & ~(pgsize - 1));
	}
	/*****/
	if (!ptep || pte_is_null(ptep) || pte_is_fileoff(ptep, pgsize)) {
		phys = NOPHYS;
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
				struct memobj *obj;

				if (zeroobj_create(&obj)) {
					panic("PFPMR: zeroobj_crate");
				}

				if (range->memobj != obj) {
					goto out;
				}
			}
		}
		if (phys == NOPHYS) {
			void *virt = NULL;
			size_t npages;

retry:
			npages = pgsize / PAGE_SIZE;
			virt = ihk_mc_alloc_aligned_pages_user(npages, p2align,
					IHK_MC_AP_NOWAIT |
					(range->flag & VR_AP_USER) ? IHK_MC_AP_USER : 0);
			if (!virt && !range->pgshift && (pgsize != PAGE_SIZE)) {
				error = arch_get_smaller_page_size(NULL, pgsize, &pgsize, &p2align);
				if (error) {
					kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):arch_get_smaller_page_size(anon) failed. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
					goto out;
				}
				ptep = NULL;
				pgaddr = (void *)(fault_addr & ~(pgsize - 1));
				goto retry;
			}
			if (!virt) {
				error = -ENOMEM;
				kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):cannot allocate new page. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
				goto out;
			}
			dkprintf("%s: clearing 0x%lx:%lu\n",
					__FUNCTION__, pgaddr, pgsize);
#ifdef PROFILE_ENABLE
			profile_event_add(PROFILE_page_fault_anon_clr, pgsize);
#endif // PROFILE_ENABLE
			memset(virt, 0, pgsize);
			phys = virt_to_phys(virt);
			if (phys_to_page(phys)) {
				page_map(phys_to_page(phys));
			}
		}
	}
	else {
		phys = pte_get_phys(ptep);
	}

	page = phys_to_page(phys);

	attr = arch_vrflag_to_ptattr(range->flag | memobj_flag, reason, ptep);

	/* Copy on write */
	if (((range->flag & VR_PRIVATE) ||
				((reason & PF_PATCH) && !(range->flag & VR_PROT_WRITE)))
			&& ((!page && phys == NOPHYS) || (page &&
					(page_is_in_memobj(page) ||
					 page_is_multi_mapped(page))))) {

		if (!(attr & PTATTR_DIRTY)) {
			attr &= ~PTATTR_WRITABLE;
		}
		else {
			void *virt;
			size_t npages;

			npages = pgsize / PAGE_SIZE;
			virt = ihk_mc_alloc_aligned_pages_user(npages, p2align,
			                                      IHK_MC_AP_NOWAIT);
			if (!virt) {
				error = -ENOMEM;
				kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):cannot allocate copy page. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
				goto out;
			}
			dkprintf("%s: copying 0x%lx:%lu\n",
				__FUNCTION__, pgaddr, pgsize);
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
		                            attr, range->pgshift);
		if (error) {
			kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):set_range failed. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
			goto out;
		}
	}
	flush_tlb_single(fault_addr);
	vm->currss += pgsize;
	if(vm->currss > vm->proc->maxrss)
		vm->proc->maxrss = vm->currss;

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
		dkprintf("do_page_fault_process_vm(): vm: %p, addr: %p, reason: %lx):"
				"out of range: %d\n",
				vm, fault_addr0, reason, error);
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
		kprintf("%s: reason: %s%s%s%s%s%s%s\n", __FUNCTION__,
			(reason & PF_PROT) ? "PF_PROT " : "",
			(reason & PF_WRITE) ? "PF_WRITE " : "",
			(reason & PF_USER) ? "PF_USER " : "",
			(reason & PF_RSVD) ? "PF_RSVD " : "",
			(reason & PF_INSTR) ? "PF_INSTR " : "",
			(reason & PF_PATCH) ? "PF_PATCH " : "",
			(reason & PF_POPULATE) ? "PF_POPULATE " : "");
		kprintf("%s: range->flag & (%s%s%s)\n", __FUNCTION__,
			(range->flag & VR_PROT_READ) ? "VR_PROT_READ " : "",
			(range->flag & VR_PROT_WRITE) ? "VR_PROT_WRITE " : "",
			(range->flag & VR_PROT_EXEC) ? "VR_PROT_EXEC " : "");
		if (((range->flag & VR_PROT_MASK) == VR_PROT_NONE))
			kprintf("if (((range->flag & VR_PROT_MASK) == VR_PROT_NONE))\n");
		if (((reason & PF_WRITE) && !(reason & PF_PATCH)))
			kprintf("if (((reason & PF_WRITE) && !(reason & PF_PATCH)))\n");
		if (!(range->flag & VR_PROT_WRITE)) {
			kprintf("if (!(range->flag & VR_PROT_WRITE))\n");
			//kprintf("setting VR_PROT_WRITE\n");
			//range->flag |= VR_PROT_WRITE;
			//goto cont;
		}
		if ((reason & PF_INSTR) && !(range->flag & VR_PROT_EXEC)) {
			kprintf("if ((reason & PF_INSTR) && !(range->flag & VR_PROT_EXEC))\n");
			//kprintf("setting VR_PROT_EXEC\n");
			//range->flag |= VR_PROT_EXEC;
			//goto cont;
		}
		goto out;
	}

	/*
	 * Fix for #284
	 * Symptom: read() writes data onto the zero page by the following sequence.
	 * (1) A process performs mmap(MAP_PRIVATE|MAP_ANONYMOUS)
	 * (2) The process loads data from the VM range to cause a PF
	 *     to make the PTE point to the zero page.
	 * (3) The process performs write() using the VM range as the source
         *     to cause a PF on the Linux side to make the PTE point to the zero page.
         *     Note that we can't make the PTE read-only because [mckernel] pseudo
	 *     file covering the range is created with O_RDWR.
	 * (4) The process stores data to the VM range to cause another PF to perform
         *     copy-on-write.
	 * (5) The process performs read() using the VM range as the destination.
         *     However, no PF and hence copy-on-write occurs because of (3).
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

	if (!range->private_data) {
		error = page_fault_process_memory_range(vm, range, fault_addr, reason);
	}
	else {
		error = xpmem_fault_process_memory_range(vm, range, fault_addr, reason);
	}
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
	unsigned long end;
	unsigned long start;
	int rc;
	unsigned long vrflag;
	char *stack;
	int error;
	unsigned long *p;
	unsigned long minsz;
	unsigned long at_rand;
	struct process *proc = thread->proc;
	unsigned long ap_flag;

	/* Create stack range */
	end = STACK_TOP(&thread->vm->region) & LARGE_PAGE_MASK;
	minsz = (proc->rlimit[MCK_RLIMIT_STACK].rlim_cur
			+ LARGE_PAGE_SIZE - 1) & LARGE_PAGE_MASK;
	size = (proc->rlimit[MCK_RLIMIT_STACK].rlim_max
			+ LARGE_PAGE_SIZE - 1) & LARGE_PAGE_MASK;
	dkprintf("%s: rlim_max: %lu, rlim_cur: %lu\n",
			__FUNCTION__,
			proc->rlimit[MCK_RLIMIT_STACK].rlim_max,
			proc->rlimit[MCK_RLIMIT_STACK].rlim_cur);
	if (size > (USER_END / 2)) {
		size = USER_END / 2;
	}
	else if (size < minsz) {
		size = minsz;
	}
	start = (end - size) & LARGE_PAGE_MASK;

	/* Apply user allocation policy to stacks */
	/* TODO: make threshold kernel or mcexec argument */
	ap_flag = (size >= proc->mpol_threshold &&
		!(proc->mpol_flags & MPOL_NO_STACK)) ? IHK_MC_AP_USER : 0;
	dkprintf("%s: max size: %lu, mapped size: %lu %s\n",
			__FUNCTION__, size, minsz,
			ap_flag ? "(IHK_MC_AP_USER)" : "");

	stack = ihk_mc_alloc_aligned_pages_user(minsz >> PAGE_SHIFT,
				LARGE_PAGE_P2ALIGN, IHK_MC_AP_NOWAIT | ap_flag);

	if (!stack) {
		kprintf("%s: error: couldn't allocate initial stack\n",
				__FUNCTION__);
		return -ENOMEM;
	}

	memset(stack, 0, minsz);

	vrflag = VR_STACK | VR_DEMAND_PAGING;
	vrflag |= ((ap_flag & IHK_MC_AP_USER) ? VR_AP_USER : 0);
	vrflag |= PROT_TO_VR_FLAG(pn->stack_prot);
	vrflag |= VR_MAXPROT_READ | VR_MAXPROT_WRITE | VR_MAXPROT_EXEC;
#define	NOPHYS	((uintptr_t)-1)
	if ((rc = add_process_memory_range(thread->vm, start, end, NOPHYS,
					vrflag, NULL, 0, LARGE_PAGE_SHIFT, NULL)) != 0) {
		ihk_mc_free_pages_user(stack, minsz >> PAGE_SHIFT);
		return rc;
	}

	/* Map physical pages for initial stack frame */
	error = ihk_mc_pt_set_range(thread->vm->address_space->page_table,
			thread->vm, (void *)(end - minsz),
			(void *)end, virt_to_phys(stack),
			arch_vrflag_to_ptattr(vrflag, PF_POPULATE, NULL),
			LARGE_PAGE_SHIFT);

	if (error) {
		kprintf("init_process_stack:"
				"set range %lx-%lx %lx failed. %d\n",
				(end-minsz), end, stack, error);
		ihk_mc_free_pages_user(stack, minsz >> PAGE_SHIFT);
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
#ifndef AT_SYSINFO_EHDR
#define AT_SYSINFO_EHDR AT_IGNORE
#endif
	p[s_ind--] = (long)(thread->vm->vdso_addr);
	p[s_ind--] = (thread->vm->vdso_addr)? AT_SYSINFO_EHDR: AT_IGNORE;

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
		unsigned long end_allocated,
		unsigned long address, unsigned long flag)
{
	unsigned long new_end_allocated;
	void *p;
	int rc;

	size_t align_size = vm->proc->heap_extension > PAGE_SIZE ?
		LARGE_PAGE_SIZE : PAGE_SIZE;
	unsigned long align_mask = vm->proc->heap_extension > PAGE_SIZE ?
		LARGE_PAGE_MASK : PAGE_MASK;
	unsigned long align_p2align = vm->proc->heap_extension > PAGE_SHIFT ?
		LARGE_PAGE_P2ALIGN : PAGE_P2ALIGN;

	new_end_allocated = (address + (PAGE_SIZE - 1)) & PAGE_MASK;
	if ((new_end_allocated - end_allocated) < vm->proc->heap_extension) {
		new_end_allocated = (end_allocated + vm->proc->heap_extension +
				(align_size - 1)) & align_mask;
	}

	if (flag & VR_DEMAND_PAGING) {
		p = 0;
	}
	else {
		p = ihk_mc_alloc_aligned_pages_user(
				(new_end_allocated - end_allocated) >> PAGE_SHIFT,
				align_p2align, IHK_MC_AP_NOWAIT |
				(!(vm->proc->mpol_flags & MPOL_NO_HEAP) ? IHK_MC_AP_USER : 0));

		if (!p) {
			return end_allocated;
		}
	}

	if ((rc = add_process_memory_range(vm, end_allocated, new_end_allocated,
					(p == 0 ? 0 : virt_to_phys(p)), flag, NULL, 0,
					align_p2align, NULL)) != 0) {
		ihk_mc_free_pages_user(p, (new_end_allocated - end_allocated) >> PAGE_SHIFT);
		return end_allocated;
	}

	dkprintf("%s: new_end_allocated: 0x%lu, align_size: %lu, align_mask: %lx\n",
		__FUNCTION__, new_end_allocated, align_size, align_mask);

	return new_end_allocated;
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

	if (proc->tids) kfree(proc->tids);
#ifdef PROFILE_ENABLE
	if (proc->profile) {
		if (proc->nr_processes) {
			profile_accumulate_and_print_job_events(proc);
		}
		else {
			profile_print_proc_stats(proc);
		}
	}
	profile_dealloc_proc_events(proc);
#endif // PROFILE_ENABLE
	kfree(proc);
}

void
hold_process_vm(struct process_vm *vm)
{
	ihk_atomic_inc(&vm->refcount);
}

void
free_all_process_memory_range(struct process_vm *vm)
{
	struct vm_range *range, *next;
	int error;

	ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);
	list_for_each_entry_safe(range, next, &vm->vm_range_list, list) {
		if (range->memobj) {
			range->memobj->flags |= MF_HOST_RELEASED;
		}
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
release_process_vm(struct process_vm *vm)
{
	struct process *proc = vm->proc;

	if (!ihk_atomic_dec_and_test(&vm->refcount)) {
		return;
	}

	{
		long irqstate;
		struct mckfd *fdp;

		irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);
		for (fdp = proc->mckfd; fdp; fdp = fdp->next) {
			if (fdp->close_cb) {
				fdp->close_cb(fdp, NULL);
			}
		}
		ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);
	}

	if(vm->free_cb)
		vm->free_cb(vm, vm->opt);

	flush_nfo_tlb_mm(vm);
	free_all_process_memory_range(vm);

	detach_address_space(vm->address_space, vm->proc->pid);
	proc->vm = NULL;
	release_process(proc);
	kfree(vm);
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
			ekprintf("%s: WARNING: page_fault_process_vm(): vm: %p, "
					"addr: %lx, reason: %lx, off: %lu, len: %lu returns %d\n",
					__FUNCTION__, vm, addr, reason,
					((void *)addr - start), len, error);
			goto out;
		}
	}

	error = 0;
out:
	return error;
}

void hold_thread(struct thread *thread)
{
	if (thread->status == PS_EXITED) {
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

/*
 * Release the TID from the process' TID set corresponding to this thread.
 * NOTE: threads_lock must be held.
 */
void __release_tid(struct process *proc, struct thread *thread) {
	int i;

	for (i = 0; i < proc->nr_tids; ++i) {
		if (proc->tids[i].thread != thread) continue;

		proc->tids[i].thread = NULL;
		dkprintf("%s: tid %d has been released by %p\n",
			__FUNCTION__, thread->tid, thread);
		break;
	}
}

void destroy_thread(struct thread *thread)
{
	struct sig_pending *pending;
	struct sig_pending *signext;
	struct mcs_rwlock_node_irqsave lock;
	struct process *proc = thread->proc;
	struct resource_set *resource_set = cpu_local_var(resource_set);
	int hash;

	hash = thread_hash(thread->tid);
	mcs_rwlock_writer_lock(&resource_set->thread_hash->lock[hash], &lock);
	list_del(&thread->hash_list);
	mcs_rwlock_writer_unlock(&resource_set->thread_hash->lock[hash], &lock);

	mcs_rwlock_writer_lock(&proc->threads_lock, &lock);
	list_del(&thread->siblings_list);
	__release_tid(proc, thread);
	mcs_rwlock_writer_unlock(&proc->threads_lock, &lock);

	cpu_clear(thread->cpu_id, &thread->vm->address_space->cpu_set,
	          &thread->vm->address_space->cpu_set_lock);
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
	struct mcs_rwlock_node_irqsave lock;
	struct timespec ats;

	if (!ihk_atomic_dec_and_test(&thread->refcount)) {
		return;
	}

	mcs_rwlock_writer_lock(&thread->proc->update_lock, &lock);
	tsc_to_ts(thread->system_tsc, &ats);
	ts_add(&thread->proc->stime, &ats);
	tsc_to_ts(thread->user_tsc, &ats);
	ts_add(&thread->proc->utime, &ats);
	mcs_rwlock_writer_unlock(&thread->proc->update_lock, &lock);

	vm = thread->vm;

#ifdef PROFILE_ENABLE
	profile_accumulate_events(thread, thread->proc);
	//profile_print_thread_stats(thread);
	profile_dealloc_thread_events(thread);
#endif // PROFILE_ENABLE
	procfs_delete_thread(thread);
	destroy_thread(thread);

	release_process_vm(vm);
	rusage_num_threads_dec();
}

void cpu_set(int cpu, cpu_set_t *cpu_set, ihk_spinlock_t *lock)
{
	unsigned long flags;
	flags = ihk_mc_spinlock_lock(lock);
	CPU_SET(cpu, cpu_set);
	ihk_mc_spinlock_unlock(lock, flags);
}

void cpu_clear(int cpu, cpu_set_t *cpu_set, ihk_spinlock_t *lock)
{
	unsigned long flags;
	flags = ihk_mc_spinlock_lock(lock);
	CPU_CLR(cpu, cpu_set);
	ihk_mc_spinlock_unlock(lock, flags);
}

void cpu_clear_and_set(int c_cpu, int s_cpu,
	cpu_set_t *cpu_set, ihk_spinlock_t *lock)
{
	unsigned long flags;
	flags = ihk_mc_spinlock_lock(lock);
	CPU_CLR(c_cpu, cpu_set);
	CPU_SET(s_cpu, cpu_set);
	ihk_mc_spinlock_unlock(lock, flags);
}


static void do_migrate(void);

static void idle(void)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	struct ihk_os_cpu_monitor *monitor = v->monitor;

	/* Release runq_lock before starting the idle loop.
	 * See comments at release_runq_lock().
	 */
	ihk_mc_spinlock_unlock(&(cpu_local_var(runq_lock)),
			cpu_local_var(runq_irqstate));

	if(v->status == CPU_STATUS_RUNNING)
		v->status = CPU_STATUS_IDLE;
	cpu_enable_interrupt();

	while (1) {
		cpu_local_var(current)->status = PS_STOPPED;
		schedule();
		cpu_local_var(current)->status = PS_RUNNING;
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
				if (t->status == PS_RUNNING) {
					v->status = CPU_STATUS_RUNNING;
					break;
				}
			}
			ihk_mc_spinlock_unlock(&v->runq_lock, s);
		}
		if (v->status == CPU_STATUS_IDLE ||
		    v->status == CPU_STATUS_RESERVED) {
			/* No work to do? Consolidate the kmalloc free list */
			kmalloc_consolidate_free_list();
			monitor->status = IHK_OS_MONITOR_IDLE;
			cpu_local_var(current)->status = PS_INTERRUPTIBLE;
			cpu_safe_halt();
			monitor->status = IHK_OS_MONITOR_KERNEL;
			monitor->counter++;
			cpu_local_var(current)->status = PS_RUNNING;
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
	cpu_local_var(idle_proc).nohost = 1;
	idle_thread->proc->vm = &cpu_local_var(idle_vm);
	list_add_tail(&idle_thread->siblings_list,
	               &idle_thread->proc->children_list);

	ihk_mc_init_context(&idle_thread->ctx, NULL, idle);
	ihk_mc_spinlock_init(&idle_thread->vm->memory_range_lock);
	INIT_LIST_HEAD(&idle_thread->vm->vm_range_list);
	INIT_LIST_HEAD(&idle_thread->vm->vm_range_numa_policy_list);
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
		struct thread *thread;
		int clear_old_cpu = 1;

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
		list_add_tail(&req->thread->sched_list, &v->runq);
		v->runq_len += 1;

		/* Find out whether there is another thread of the same process
		 * on the source CPU */
		list_for_each_entry(thread, &(cur_v->runq), sched_list) {
			if (thread->vm && thread->vm == req->thread->vm) {
				clear_old_cpu = 0;
				break;
			}
		}

		/* Update cpu_set of the VM for remote TLB invalidation */
		if (clear_old_cpu) {
			cpu_clear_and_set(old_cpu_id, cpu_id,
					&req->thread->vm->address_space->cpu_set,
					&req->thread->vm->address_space->cpu_set_lock);
		}
		else {
			cpu_set(cpu_id,
					&req->thread->vm->address_space->cpu_set,
					&req->thread->vm->address_space->cpu_set_lock);

		}

		dkprintf("%s: migrated TID %d from CPU %d to CPU %d\n",
			__FUNCTION__, req->thread->tid, old_cpu_id, cpu_id);
		
		v->flags |= CPU_FLAG_NEED_RESCHED;
		waitq_wakeup(&req->wq);
		double_rq_unlock(cur_v, v, irqstate);
		continue;
ack:
		waitq_wakeup(&req->wq);
	}
	ihk_mc_spinlock_unlock(&cur_v->migq_lock, irqstate);
}

void
set_timer()
{
	struct cpu_local_var *v = get_this_cpu_local_var();

	/* Toggle timesharing if CPU core is oversubscribed */
	if (v->runq_len > 1 || v->current->itimer_enabled) {
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

/*
 * NOTE: it is assumed that a wait-queue (or futex queue) is
 * set before calling this function.
 * NOTE: one must set thread->spin_sleep to 1 before evaluating
 * the wait condition to avoid lost wake-ups.
 */
void spin_sleep_or_schedule(void)
{
	struct thread *thread = cpu_local_var(current);
	struct cpu_local_var *v;
	int do_schedule = 0;
	int woken = 0;
	long irqstate;

	/* Try to spin sleep */
	irqstate = ihk_mc_spinlock_lock(&thread->spin_sleep_lock);
	if (thread->spin_sleep == 0) {
		dkprintf("%s: caught a lost wake-up!\n", __FUNCTION__);
	}
	ihk_mc_spinlock_unlock(&thread->spin_sleep_lock, irqstate);

	for (;;) {
		/* Check if we need to reschedule */
		irqstate =
			ihk_mc_spinlock_lock(&(get_this_cpu_local_var()->runq_lock));
		v = get_this_cpu_local_var();

		if (v->flags & CPU_FLAG_NEED_RESCHED || v->runq_len > 1) {
			do_schedule = 1;
		}

		ihk_mc_spinlock_unlock(&v->runq_lock, irqstate);

		/* Check if we were woken up */
		irqstate = ihk_mc_spinlock_lock(&thread->spin_sleep_lock);
		if (thread->spin_sleep == 0) {
			woken = 1;
		}

		/* Indicate that we are not spinning any more */
		if (do_schedule) {
			thread->spin_sleep = 0;
		}
		ihk_mc_spinlock_unlock(&thread->spin_sleep_lock, irqstate);

		if (woken) {
			return;
		}

		if (do_schedule) {
			break;
		}

		cpu_pause();
	}

	schedule();
}

void schedule(void)
{
	struct cpu_local_var *v;
	struct thread *next, *prev, *thread, *tmp = NULL;
	int switch_ctx = 0;
	struct thread *last;

	if (cpu_local_var(no_preempt)) {
		kprintf("%s: WARNING can't schedule() while no preemption, cnt: %d\n",
			__FUNCTION__, cpu_local_var(no_preempt));
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
		if (prev->status != PS_EXITED) {
			list_add_tail(&prev->sched_list, &(v->runq));
			++v->runq_len;
		}
	}

	if (v->flags & CPU_FLAG_NEED_MIGRATE) {
		next = &cpu_local_var(idle);
	} else {
		/* Pick a new running process or one that has a pending signal */
		list_for_each_entry_safe(thread, tmp, &(v->runq), sched_list) {
			if (thread->status == PS_RUNNING &&
			    thread->mod_clone == SPAWNING_TO_REMOTE){
				next = thread;
				break;
			}
			if (thread->status == PS_RUNNING ||
				(thread->status == PS_INTERRUPTIBLE && hassigpending(thread))) {
				if(!next)
					next = thread;
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
		reset_cputime();
	}

	set_timer();

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

		if (prev && prev->vm->address_space->page_table !=
				next->vm->address_space->page_table)
			ihk_mc_load_page_table(next->vm->address_space->page_table);

		dkprintf("[%d] schedule: tlsblock_base: 0x%lX\n",
		         ihk_mc_get_processor_id(), next->tlsblock_base);

		/* Set up new TLS.. */
		ihk_mc_init_user_tlsbase(next->uctx, next->tlsblock_base);

		/* Performance monitoring inherit */
		if(next->proc->monitoring_event) {
			if(next->proc->perf_status == PP_RESET)
				perf_reset(next->proc->monitoring_event);
			if(next->proc->perf_status != PP_COUNT) {
				perf_reset(next->proc->monitoring_event);
				perf_start(next->proc->monitoring_event);
			}
		}

#ifdef PROFILE_ENABLE
		if (prev->profile && prev->profile_start_ts != 0) {
			prev->profile_elapsed_ts +=
				(rdtsc() - prev->profile_start_ts);
			prev->profile_start_ts = 0;
		}

		if (next->profile && next->profile_start_ts == 0) {
			next->profile_start_ts = rdtsc();
		}
#endif

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

		if ((last != NULL) && (last->status == PS_EXITED)) {
			release_thread(last);
		}

		/* Have we migrated to another core meanwhile? */
		if (v != get_this_cpu_local_var()) {
			goto redo;
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

int __sched_wakeup_thread(struct thread *thread,
		int valid_states, int runq_locked)
{
	int status;
	unsigned long irqstate;
	struct cpu_local_var *v = get_cpu_local_var(thread->cpu_id);
	struct process *proc = thread->proc;
	struct mcs_rwlock_node updatelock;

	dkprintf("%s: proc->pid=%d, valid_states=%08x, "
			"proc->status=%08x, proc->cpu_id=%d,my cpu_id=%d\n",
			__FUNCTION__,
			proc->pid, valid_states, thread->status,
			thread->cpu_id, ihk_mc_get_processor_id());

	irqstate = ihk_mc_spinlock_lock(&(thread->spin_sleep_lock));
	if (thread->spin_sleep == 1) {
		dkprintf("%s: spin wakeup: cpu_id: %d\n",
				__FUNCTION__, thread->cpu_id);

		status = 0;
	}
	thread->spin_sleep = 0;
	ihk_mc_spinlock_unlock(&(thread->spin_sleep_lock), irqstate);

	if (!runq_locked) {
		irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
	}

	if (thread->status & valid_states) {
		mcs_rwlock_writer_lock_noirq(&proc->update_lock, &updatelock);
		if (proc->status != PS_EXITED)
			proc->status = PS_RUNNING;
		mcs_rwlock_writer_unlock_noirq(&proc->update_lock, &updatelock);
		xchg4((int *)(&thread->status), PS_RUNNING);
		status = 0;
	}
	else {
		status = -EINVAL;
	}

	if (!runq_locked) {
		ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
	}

	if (!status && (thread->cpu_id != ihk_mc_get_processor_id())) {
		dkprintf("%s: issuing IPI, thread->cpu_id=%d\n",
				__FUNCTION__, thread->cpu_id);
		ihk_mc_interrupt_cpu(
				get_x86_cpu_local_variable(thread->cpu_id)->apic_id,
				0xd1);
	}

	return status;
}

int sched_wakeup_thread_locked(struct thread *thread, int valid_states)
{
	return __sched_wakeup_thread(thread, valid_states, 1);
}

int sched_wakeup_thread(struct thread *thread, int valid_states)
{
	return __sched_wakeup_thread(thread, valid_states, 0);
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
	DECLARE_WAITQ_ENTRY_LOCKED(entry, cpu_local_var(current));

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
	dkprintf("%s: tid: %d -> cpu: %d\n",
			__FUNCTION__, thread->tid, cpu_id);

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

	procfs_create_thread(thread);

	rusage_num_threads_inc();

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
retry:
	list_for_each_entry(thread, &thash->list[hash], hash_list){
		if(thread->tid == tid){
			if(pid <= 0)
				return thread;
			if(thread->proc->pid == pid)
				return thread;
		}
	}
	/* If no thread with pid == tid was found, then we may be looking for a
	 * specific thread (not the main thread of the process), try to find it
	 * based on tid only */
	if (pid > 0 && pid == tid) {
		pid = 0;
		goto retry;
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
	struct process *pid1 = rset->pid1;
	int found = 0;

	switch(arg){
	    case 1:
		for(i = 0; i < HASH_SIZE; i++){
			__mcs_rwlock_reader_lock(&phash->lock[i], &lock);
			list_for_each_entry(p, &phash->list[i], hash_list){
				if (p == pid1)
					continue;
				found++;
				kprintf("pid=%d ppid=%d status=%d\n",
				        p->pid, p->ppid_parent->pid, p->status);
			}
			__mcs_rwlock_reader_unlock(&phash->lock[i], &lock);
		}
		kprintf("%d processes are found.\n", found);
		break;
	    case 2:
		for(i = 0; i < HASH_SIZE; i++){
			__mcs_rwlock_reader_lock(&thash->lock[i], &lock);
			list_for_each_entry(t, &thash->list[i], hash_list){
				found++;
				kprintf("cpu=%d pid=%d tid=%d status=%d offload=%d\n",
				        t->cpu_id, t->proc->pid, t->tid,
				        t->status, t->in_syscall_offload);
			}
			__mcs_rwlock_reader_unlock(&thash->lock[i], &lock);
		}
		kprintf("%d threads are found.\n", found);
		break;
	    case 3:
		for(i = 0; i < HASH_SIZE; i++){
			list_for_each_entry(p, &phash->list[i], hash_list){
				if (p == pid1)
					continue;
				found++;
				kprintf("pid=%d ppid=%d status=%d\n",
				        p->pid, p->ppid_parent->pid, p->status);
			}
		}
		kprintf("%d processes are found.\n", found);
		break;
	    case 4:
		for(i = 0; i < HASH_SIZE; i++){
			list_for_each_entry(t, &thash->list[i], hash_list){
				found++;
				kprintf("cpu=%d pid=%d tid=%d status=%d\n",
				        t->cpu_id, t->proc->pid, t->tid,
				        t->status);
			}
		}
		kprintf("%d threads are found.\n", found);
		break;
	}
}
