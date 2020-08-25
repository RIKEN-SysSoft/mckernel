/* process.c COPYRIGHT FUJITSU LIMITED 2015-2019 */
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
#include <page.h>
#include <cpulocal.h>
#include <auxvec.h>
#include <hwcap.h>
#include <timer.h>
#include <mman.h>
#include <xpmem.h>
#include <rusage_private.h>
#include <ihk/monitor.h>
#include <ihk/debug.h>

//#define DEBUG_PRINT_PROCESS

#ifdef DEBUG_PRINT_PROCESS
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
static void dtree(struct rb_node *node, int l) {
	struct vm_range *range;
	if (!node)
		return;

	range = rb_entry(node, struct vm_range, vm_rb_node);

	dtree(node->rb_left, l+1);
	kprintf("dtree: %0*d, %p: %lx-%lx\n", l, 0, range, range->start, range->end);
	dtree(node->rb_right, l+1);
}
static void dump_tree(struct process_vm *vm) {
	kprintf("dump_tree %p\n", vm);
	dtree(vm->vm_range_tree.rb_node, 1);
}
#else
static void dump_tree(struct process_vm *vm) {}
#endif

extern struct thread *arch_switch_context(struct thread *prev, struct thread *next);
extern long alloc_debugreg(struct thread *proc);
extern void save_debugreg(unsigned long *debugreg);
extern void restore_debugreg(unsigned long *debugreg);
extern void clear_debugreg(void);
extern void clear_single_step(struct thread *proc);
static int vm_range_insert(struct process_vm *vm,
		struct vm_range *newrange);
static struct vm_range *vm_range_find(struct process_vm *vm,
		unsigned long addr);
static int copy_user_ranges(struct process_vm *vm, struct process_vm *orgvm);
extern void __runq_add_proc(struct thread *proc, int cpu_id);
extern void lapic_timer_enable(unsigned int clocks);
extern void lapic_timer_disable();
extern int num_processors;
extern ihk_spinlock_t cpuid_head_lock;
int ptrace_detach(int pid, int data);
extern void procfs_create_thread(struct thread *);
extern void procfs_delete_thread(struct thread *);

static int free_process_memory_range(struct process_vm *vm,
					struct vm_range *range);
static void free_thread_pages(struct thread *thread);

struct list_head resource_set_list;
mcs_rwlock_lock_t    resource_set_lock;
ihk_spinlock_t runq_reservation_lock;

int idle_halt = 0;
int allow_oversubscribe = 0;
int time_sharing = 1;

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
		proc->thp_disable = parent->thp_disable;
		memcpy(proc->rlimit, parent->rlimit,
		       sizeof(struct rlimit) * MCK_RLIM_MAX);
		memcpy(&proc->cpu_set, &parent->cpu_set,
		       sizeof(proc->cpu_set));
	}

	INIT_LIST_HEAD(&proc->hash_list);
	INIT_LIST_HEAD(&proc->siblings_list);
	INIT_LIST_HEAD(&proc->ptraced_siblings_list);
	mcs_rwlock_init(&proc->update_lock);
	INIT_LIST_HEAD(&proc->report_threads_list);
	INIT_LIST_HEAD(&proc->threads_list);
	INIT_LIST_HEAD(&proc->children_list);
	INIT_LIST_HEAD(&proc->ptraced_children_list);
	mcs_rwlock_init(&proc->threads_lock);
	mcs_rwlock_init(&proc->children_lock);
	mcs_rwlock_init(&proc->coredump_lock);
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
	ihk_rwspinlock_init(&vm->memory_range_lock);
	ihk_mc_spinlock_init(&vm->page_table_lock);

	ihk_atomic_set(&vm->refcount, 1);
	vm->vm_range_tree = RB_ROOT;
	vm->vm_range_numa_policy_tree = RB_ROOT;
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
	INIT_LIST_HEAD(&thread->hash_list);
	INIT_LIST_HEAD(&thread->siblings_list);
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
	proc->main_thread = thread;

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
	struct cpu_local_var *v = get_this_cpu_local_var();

	if ((thread = ihk_mc_alloc_pages(KERNEL_STACK_NR_PAGES,
					IHK_MC_AP_NOWAIT)) == NULL) {
		return NULL;
	}

	memset(thread, 0, sizeof(struct thread));
	INIT_LIST_HEAD(&thread->hash_list);
	INIT_LIST_HEAD(&thread->siblings_list);
	ihk_atomic_set(&thread->refcount, 2);
	memcpy(&thread->cpu_set, &org->cpu_set, sizeof(thread->cpu_set));

	/* New thread is in kernel until jumping to enter_user_mode */
	thread->in_kernel = org->in_kernel;

	/* NOTE: sp is the user mode stack! */
	ihk_mc_init_user_process(&thread->ctx, &thread->uctx, ((char *)thread) +
				 KERNEL_STACK_NR_PAGES * PAGE_SIZE, pc, sp);

	/* copy fp_regs from parent */
	if (save_fp_regs(org)) {
		goto free_thread;
	}
	if (copy_fp_regs(org, thread)) {
		goto free_fp_regs;
	}
	arch_clone_thread(org, pc, sp, thread);

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
			goto free_fp_regs;
		memset(proc, '\0', sizeof(struct process));
		init_process(proc, org->proc);
#ifdef PROFILE_ENABLE
		proc->profile = org->proc->profile;
#endif
		proc->termsig = termsig;
		asp = create_address_space(cpu_local_var(resource_set), 1);
		if (!asp) {
			goto free_fork_process_proc;
		}
		proc->vm = kmalloc(sizeof(struct process_vm), IHK_MC_AP_NOWAIT);
		if (!proc->vm) {
			goto free_fork_process_asp;
		}
		memset(proc->vm, '\0', sizeof(struct process_vm));

		proc->saved_cmdline_len = org->proc->saved_cmdline_len;
		proc->saved_cmdline = kmalloc(proc->saved_cmdline_len,
					      IHK_MC_AP_NOWAIT);
		if (!proc->saved_cmdline) {
			goto free_fork_process_vm;
		}
		memcpy(proc->saved_cmdline, org->proc->saved_cmdline,
		       proc->saved_cmdline_len);

		dkprintf("fork(): init_process_vm()\n");
		if (init_process_vm(proc, asp, proc->vm) != 0) {
			goto free_fork_process_cmdline;
		}
		memcpy(&proc->vm->numa_mask, &org->vm->numa_mask,
				sizeof(proc->vm->numa_mask));
		proc->vm->numa_mem_policy =
			org->vm->numa_mem_policy;

		thread->proc = proc;
		thread->vm = proc->vm;
		proc->main_thread = thread;

		memcpy(&proc->vm->region, &org->vm->region, sizeof(struct vm_regions));

		dkprintf("fork(): copy_user_ranges()\n");
		/* Copy user-space mappings.
		 * TODO: do this with COW later? */
		v->on_fork_vm = proc->vm;
		if (copy_user_ranges(proc->vm, org->vm) != 0) {
			v->on_fork_vm = NULL;
			goto free_fork_process_cmdline;
		}
		v->on_fork_vm = NULL;

		/* Copy mckfd list
		   FIXME: Replace list manipulation with list_add() etc. */
		long irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);
		struct mckfd *cur;
		for (cur = org->proc->mckfd; cur; cur = cur->next) {
			struct mckfd *mckfd = kmalloc(sizeof(struct mckfd), IHK_MC_AP_NOWAIT);
			if(!mckfd) {
				ihk_mc_spinlock_unlock(&proc->mckfd_lock,
							irqstate);
				goto free_fork_process_mckfd;
			}
			memcpy(mckfd, cur, sizeof(struct mckfd));
			
			if (proc->mckfd == NULL) {
				proc->mckfd = mckfd;
				mckfd->next = NULL;
			}
			else {
				mckfd->next = proc->mckfd;
				proc->mckfd = mckfd;
			}

			if (mckfd->dup_cb) {
				mckfd->dup_cb(mckfd, NULL);
			}
		}
		ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);

		thread->vm->vdso_addr = org->vm->vdso_addr;
		thread->vm->vvar_addr = org->vm->vvar_addr;

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
			if (clone_flags & CLONE_VM) {
				goto free_clone_process;
			}
			goto free_fork_process_mckfd;
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

	/*
	 * free process(clone)
	 * case of (clone_flags & CLONE_VM)
	 */
free_clone_process:
	goto  free_fp_regs;

	/*
	 * free process(fork)
	 * case of !(clone_flags & CLONE_VM)
	 */
free_fork_process_mckfd:
	{
		long irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);
		struct mckfd *cur = proc->mckfd;

		while (cur) {
			struct mckfd *next = cur->next;

			kfree(cur);
			cur = next;
		}
		ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);
	}
	free_all_process_memory_range(proc->vm);
free_fork_process_cmdline:
	kfree(proc->saved_cmdline);
free_fork_process_vm:
	kfree(proc->vm);
free_fork_process_asp:
	ihk_mc_pt_destroy(asp->page_table);
	kfree(asp);
free_fork_process_proc:
	kfree(proc);

	/*
	 * free fp_regs
	 */
free_fp_regs:
	release_fp_regs(thread);

	/*
	 * free thread
	 */
free_thread:
	free_thread_pages(thread);
	return NULL;
}

int
ptrace_traceme(void)
{
	int error = 0;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct process *parent = proc->parent;
	struct mcs_rwlock_node child_lock;
	struct resource_set *resource_set = cpu_local_var(resource_set);
	struct process *pid1 = resource_set->pid1;

	dkprintf("ptrace_traceme,pid=%d,proc->parent=%p\n", proc->pid, proc->parent);

	if (thread->ptrace & PT_TRACED) {
		return -EPERM;
	}
	if (parent == pid1) {
		return -EPERM;
	}

	dkprintf("ptrace_traceme,parent->pid=%d\n", proc->parent->pid);

	if (thread == proc->main_thread) {
		mcs_rwlock_writer_lock_noirq(&parent->children_lock,
					     &child_lock);
		list_add_tail(&proc->ptraced_siblings_list,
			      &parent->ptraced_children_list);
		mcs_rwlock_writer_unlock_noirq(&parent->children_lock,
					       &child_lock);
	}
	if (!thread->report_proc) {
		mcs_rwlock_writer_lock_noirq(&parent->threads_lock,
					     &child_lock);
		list_add_tail(&thread->report_siblings_list,
			      &parent->report_threads_list);
		mcs_rwlock_writer_unlock_noirq(&parent->threads_lock,
					       &child_lock);
		thread->report_proc = parent;
	}

	thread->ptrace = PT_TRACED | PT_TRACE_EXEC;

	if (thread->ptrace_debugreg == NULL) {
		error = alloc_debugreg(thread);
	}

	clear_single_step(thread);
	hold_thread(thread);

	dkprintf("ptrace_traceme,returning,error=%d\n", error);
	return error;
}

struct copy_args {
	struct process_vm *new_vm;
	unsigned long new_vrflag;
	struct vm_range *range;

	/* out */
	intptr_t fault_addr;
};

static int copy_user_pte(void *arg0, page_table_t src_pt, pte_t *src_ptep, void *pgaddr, int pgshift)
{
	struct copy_args * const args = arg0;
	int error;
	intptr_t src_phys;
	unsigned long src_lphys;
	void *src_kvirt;
	size_t pgsize = (size_t)1 << pgshift;
	int npages;
	void *virt = NULL;
	intptr_t phys;
	int pgalign = pgshift - PAGE_SHIFT;
	enum ihk_mc_pt_attribute attr;
	int is_mckernel;

	if (!pte_is_present(src_ptep)) {
		error = 0;
		goto out;
	}

	src_phys = pte_get_phys(src_ptep);

	if (args->range->memobj && !(args->new_vrflag & VR_PRIVATE)) {
		error = 0;
		goto out;
	}

	if (args->new_vrflag & VR_REMOTE) {
		phys = src_phys;
		attr = pte_get_attr(src_ptep, pgsize);
	}
	else {
		if (pte_is_contiguous(src_ptep)) {
			if (page_is_contiguous_head(src_ptep, pgsize)) {
				int level = pgsize_to_tbllv(pgsize);

				pgsize = tbllv_to_contpgsize(level);
				pgalign = tbllv_to_contpgshift(level);
				pgalign -= PAGE_SHIFT;
			} else {
				error = 0;
				goto out;
			}
		}

		dkprintf("copy_user_pte(): 0x%lx PTE found\n", pgaddr);
		dkprintf("copy_user_pte(): page size: %d\n", pgsize);

		npages = pgsize / PAGE_SIZE;
		virt = ihk_mc_alloc_aligned_pages_user(npages, pgalign,
		                                       IHK_MC_AP_NOWAIT, (uintptr_t)pgaddr);
		if (!virt) {
			kprintf("ERROR: copy_user_pte() allocating new page\n");
			error = -ENOMEM;
			goto out;
		}
		phys = virt_to_phys(virt);
		dkprintf("copy_user_pte(): phys page allocated\n");

		attr = arch_vrflag_to_ptattr(args->new_vrflag, PF_POPULATE,
					     NULL);

		is_mckernel = is_mckernel_memory(src_phys, src_phys + pgsize);
		if (is_mckernel) {
			src_kvirt = phys_to_virt(src_phys);
		} else {
			src_lphys = ihk_mc_map_memory(NULL, src_phys, pgsize);
			src_kvirt = ihk_mc_map_virtual(src_lphys, 1, attr);
		}

		if (args->new_vrflag & VR_WIPEONFORK) {
			memset(virt, 0, pgsize);
			dkprintf("%s(): memset OK\n", __func__);
		} else {
			memcpy(virt, src_kvirt, pgsize);
			dkprintf("%s(): memcpy OK\n", __func__);
		}

		if (!is_mckernel) {
			ihk_mc_unmap_virtual(src_kvirt, 1);
			ihk_mc_unmap_memory(NULL, src_lphys, pgsize);
		}
	}

	error = ihk_mc_pt_set_range(args->new_vm->address_space->page_table,
								args->new_vm, pgaddr, pgaddr + pgsize, phys, attr,
								pgshift, args->range, 0);
	if (error) {
		args->fault_addr = (intptr_t)pgaddr;
		goto out;
	}
	// fork/clone case: memory_stat_rss_add() is called in ihk_mc_pt_set_range()

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
	struct vm_range *last_insert;
	struct copy_args args;

	ihk_rwspinlock_read_lock_noirq(&orgvm->memory_range_lock);

	/* Iterate original process' vm_range list and take a copy one-by-one */
	last_insert = NULL;
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

		RB_CLEAR_NODE(&range->vm_rb_node);
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

		vm_range_insert(vm, range);
		last_insert = src_range;

		/* Copy actual mappings */
		args.new_vrflag = range->flag;
		args.new_vm = vm;
		args.fault_addr = -1;
		args.range = range;
		
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
			goto err_rollback;
		}
		// memory_stat_rss_add() is called in child-node, i.e. copy_user_pte()
	}

	ihk_rwspinlock_read_unlock_noirq(&orgvm->memory_range_lock);

	return 0;

err_rollback:
	if (last_insert) {
		src_range = lookup_process_memory_range(orgvm, 0, -1);
		while (src_range) {
			struct vm_range *dest_range;

			if (src_range->flag & VR_DONTFORK)
				continue;


			dest_range = lookup_process_memory_range(vm,
							src_range->start,
							src_range->end);
			if (dest_range) {
				free_process_memory_range(vm, dest_range);
			}
			if (src_range == last_insert) {
				break;
			}
			src_range = next_process_memory_range(orgvm, src_range);
		}
	}

	ihk_rwspinlock_read_unlock_noirq(&orgvm->memory_range_lock);
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
								range->pgshift, range, 0);
	if (error) {
		kprintf("update_process_page_table:ihk_mc_pt_set_range failed. %d\n", error);
		goto out;
	}
	// memory_stat_rss_add() is called in ihk_mc_pt_set_range()
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
	unsigned long page_mask;

	dkprintf("split_process_memory_range(%p,%lx-%lx,%lx,%p)\n",
			vm, range->start, range->end, addr, splitp);

	if (range->pgshift != 0) {
		page_mask = (1 << range->pgshift) - 1;
		if (addr & page_mask) {
			/* split addr is not aligned */
			range->pgshift = 0;
		}
	}

	error = ihk_mc_pt_split(vm->address_space->page_table, vm, (void *)addr);
	if (error) {
		ekprintf("split_process_memory_range:"
				"ihk_mc_pt_split failed. %d\n", error);
		goto out;
	}
	// memory_stat_rss_add() is called in child-node, i.e. ihk_mc_pt_split() to deal with L3->L2 case

	newrange = kmalloc(sizeof(struct vm_range), IHK_MC_AP_NOWAIT);
	if (!newrange) {
		ekprintf("split_process_memory_range(%p,%lx-%lx,%lx,%p):"
				"kmalloc failed\n",
				vm, range->start, range->end, addr, splitp);
		error = -ENOMEM;
		goto out;
	}

	newrange->start = addr;
	newrange->straight_start = 0;
	if (range->straight_start) {
		newrange->straight_start =
			range->straight_start + (addr - range->start);
	}
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

	error = vm_range_insert(vm, newrange);
	if (error) {
		kprintf("%s: ERROR: could not insert range: %d\n",
			__FUNCTION__, error);
		return error;
	}

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
		memobj_unref(merging->memobj);
	}
	rb_erase(&merging->vm_rb_node, &vm->vm_range_tree);
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

static int free_process_memory_range(struct process_vm *vm,
					struct vm_range *range)
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

	/* No regular page table manipulation for straight mappings */
	if (range->straight_start || ((void *)start == vm->proc->straight_va))
		goto straight_out;

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

		dkprintf("%s: vm=%p,range=%p,%lx-%lx\n", __FUNCTION__, vm, range, range->start, range->end);
		
		ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
		if (range->memobj) {
			memobj_ref(range->memobj);
		}

		if (range->memobj && range->memobj->flags & MF_HUGETLBFS) {
			error = ihk_mc_pt_clear_range(vm->address_space->page_table,
					vm, (void *)start, (void *)end);
		} else {
			error = ihk_mc_pt_free_range(vm->address_space->page_table,
					vm, (void *)start, (void *)end, range->memobj);
		}
		if (range->memobj) {
			memobj_unref(range->memobj);
		}
		ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
		if (error && (error != -ENOENT)) {
			ekprintf("free_process_memory_range(%p,%lx-%lx):"
					"ihk_mc_pt_free_range(%lx-%lx,%p) failed. %d\n",
					vm, start0, end0, start, end, range->memobj, error);
			/* through */
		}
		// memory_stat_rss_sub() is called downstream, i.e. ihk_mc_pt_free_range() to deal with empty PTE
	}
	else {
		// memory_stat_rss_sub() isn't called because free_physical is set to zero in clear_range()
		dkprintf("%s,memory_stat_rss_sub() isn't called, VR_REMOTE | VR_IO_NOCACHE | VR_RESERVED case, %lx-%lx\n", __FUNCTION__, start, end);
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
		memobj_unref(range->memobj);
	}

straight_out:
	rb_erase(&range->vm_rb_node, &vm->vm_range_tree);
	for (i = 0; i < VM_RANGE_CACHE_SIZE; ++i) {
		if (vm->range_cache[i] == range)
			vm->range_cache[i] = NULL;
	}

	/* For straight ranges just free physical memory */
	if (range->straight_start) {
		ihk_mc_free_pages(phys_to_virt(vm->proc->straight_pa +
					(range->straight_start - (unsigned long)vm->proc->straight_va)),
				(range->end - range->start) >> PAGE_SHIFT);

		dkprintf("%s: straight range 0x%lx @ straight 0x%lx (phys: 0x%lx)"
				" physical memory freed\n",
				__FUNCTION__, range->start, range->straight_start,
				vm->proc->straight_pa +
				(range->straight_start - (unsigned long)vm->proc->straight_va));
	}
	/* For the main straight mapping, free page tables */
	else if (range->start == (unsigned long)vm->proc->straight_va &&
			range->end == ((unsigned long)vm->proc->straight_va +
				vm->proc->straight_len)) {
		ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
		error = ihk_mc_pt_clear_range(vm->address_space->page_table, vm,
				(void *)start, (void *)end);
		ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);

		dkprintf("%s: main straight mapping 0x%lx unmapped\n",
				__FUNCTION__, vm->proc->straight_va);
		vm->proc->straight_len = 0;
	}

	kfree(range);

	dkprintf("free_process_memory_range(%p,%lx-%lx): 0\n",
			vm, start0, end0);
	return 0;
}

int remove_process_memory_range(struct process_vm *vm,
		unsigned long start, unsigned long end, int *ro_freedp)
{
	struct vm_range *range, *next;
	int error;
	int ro_freed = 0;

	dkprintf("remove_process_memory_range(%p,%lx,%lx)\n",
			vm, start, end);

	/*
	 * Convert to real virtual address for straight ranges,
	 * but not for the main straight mapping
	 */
	if (vm->proc->straight_va &&
			start >= (unsigned long)vm->proc->straight_va &&
			end <= ((unsigned long)vm->proc->straight_va +
				vm->proc->straight_len) &&
			!(start == (unsigned long)vm->proc->straight_va &&
				end == ((unsigned long)vm->proc->straight_va +
					vm->proc->straight_len))) {
		struct vm_range *range_iter;
		struct vm_range *range = NULL;
		unsigned long len = end - start;

		range_iter = lookup_process_memory_range(vm, 0, -1);

		while (range_iter) {
			if (range_iter->straight_start &&
					start >= range_iter->straight_start &&
					start < (range_iter->straight_start +
						(range_iter->end - range_iter->start))) {
				range = range_iter;
				break;
			}

			range_iter = next_process_memory_range(vm, range_iter);
		}

		if (!range) {
			kprintf("%s: WARNING: no straight mapping range found for 0x%lx\n",
					__FUNCTION__, start);
			return 0;
		}

		dkprintf("%s: straight range converted from 0x%lx:%lu -> 0x%lx:%lu\n",
				__FUNCTION__,
				start, len,
				range->start + (start - range->straight_start), len);

		start = range->start + (start - range->straight_start);
		end = start + len;
	}

	next = lookup_process_memory_range(vm, start, end);
	while ((range = next) && range->start < end) {
		next = next_process_memory_range(vm, range);

		if (range->start < start) {
			error = split_process_memory_range(vm,
					range, start, &range);
			if (error) {
				ekprintf("remove_process_memory_range(%p,%lx,%lx):"
						"split failed %d\n",
						vm, start, end, error);
				return error;
			}
		}

		if (end < range->end) {
			error = split_process_memory_range(vm,
					range, end, NULL);
			if (error) {
				ekprintf("remove_process_memory_range(%p,%lx,%lx):"
						"split failed %d\n",
						vm, start, end, error);
				return error;
			}
		}

		if (!(range->flag & VR_PROT_WRITE)) {
			ro_freed = 1;
		}

		if (range->private_data) {
			xpmem_remove_process_memory_range(vm, range);
		}

		error = free_process_memory_range(vm, range);
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

static int vm_range_insert(struct process_vm *vm, struct vm_range *newrange)
{
	struct rb_root *root = &vm->vm_range_tree;
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct vm_range *range;

	while (*new) {
		range = rb_entry(*new, struct vm_range, vm_rb_node);
		parent = *new;
		if (newrange->end <= range->start) {
			new = &((*new)->rb_left);
		} else if (newrange->start >= range->end) {
			new = &((*new)->rb_right);
		} else {
			ekprintf("vm_range_insert(%p,%lx-%lx %x): overlap %lx-%lx %lx\n",
					vm, newrange->start, newrange->end, newrange->flag,
					range->start, range->end, range->flag);
			return -EFAULT;
		}
	}

	dkprintf("vm_range_insert: %p,%p: %lx-%lx %x\n", vm, newrange, newrange->start, newrange->end, newrange->flag);
	dump_tree(vm);
	rb_link_node(&newrange->vm_rb_node, parent, new);
	rb_insert_color(&newrange->vm_rb_node, root);

	return 0;
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
	dkprintf("%s: start=%lx,end=%lx,phys=%lx,flag=%lx\n", __FUNCTION__, start, end, phys, flag);
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

	RB_CLEAR_NODE(&range->vm_rb_node);
	range->start = start;
	range->end = end;
	range->flag = flag;
	range->memobj = memobj;
	range->objoff = offset;
	range->pgshift = pgshift;
	range->private_data = NULL;
	range->straight_start = 0;

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
		// memory_stat_rss_add() is called in ihk_mc_pt_set_range()
	}

	if (rc != 0) {
		kprintf("%s: ERROR: preparing page tables\n", __FUNCTION__);
		kfree(range);
		return rc;
	}

	rc = vm_range_insert(vm, range);
	if (rc) {
		kprintf("%s: ERROR: could not insert range: %d\n",
			__FUNCTION__, rc);
		return rc;
	}

	/* Clear content! */
	if (phys != NOPHYS && !(flag & (VR_REMOTE | VR_DEMAND_PAGING))
			&& ((flag & VR_PROT_MASK) != VR_PROT_NONE)) {

		if (!zero_at_free) {
#ifdef ARCH_MEMCLEAR
			memclear((void *)phys_to_virt(phys), end - start);
#else
			memset((void *)phys_to_virt(phys), 0, end - start);
#endif
		}
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
	struct vm_range *range = NULL, *match = NULL;
	struct rb_root *root = &vm->vm_range_tree;
	struct rb_node *node = root->rb_node;

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

	while (node) {
		range = rb_entry(node, struct vm_range, vm_rb_node);
		if (end <= range->start) {
			node = node->rb_left;
		} else if (start >= range->end) {
			node = node->rb_right;
		} else if (start < range->start) {
			/* We have a match, but we need to try left to
			 * return the first possible match */
			match = range;
			node = node->rb_left;
		} else {
			match = range;
			break;
		}
	}

	if (match && end > match->start) {
		vm->range_cache_ind = (vm->range_cache_ind - 1 + VM_RANGE_CACHE_SIZE)
			% VM_RANGE_CACHE_SIZE;
		vm->range_cache[vm->range_cache_ind] = match;
	}

out:
	dkprintf("lookup_process_memory_range(%p,%lx,%lx): %p %lx-%lx\n",
			vm, start, end, match,
			match? match->start: 0, match? match->end: 0);
	return match;
}

struct vm_range *next_process_memory_range(
		struct process_vm *vm, struct vm_range *range)
{
	struct vm_range *next;
	struct rb_node *node;

	dkprintf("next_process_memory_range(%p,%lx-%lx)\n",
			vm, range->start, range->end);

	node = rb_next(&range->vm_rb_node);
	if (node)
		next = rb_entry(node, struct vm_range, vm_rb_node);
	else
		next = NULL;

	dkprintf("next_process_memory_range(%p,%lx-%lx): %p %lx-%lx\n",
			vm, range->start, range->end, next,
			next? next->start: 0, next? next->end: 0);
	return next;
}

struct vm_range *previous_process_memory_range(
		struct process_vm *vm, struct vm_range *range)
{
	struct vm_range *prev;
	struct rb_node *node;

	dkprintf("previous_process_memory_range(%p,%lx-%lx)\n",
			vm, range->start, range->end);

	node = rb_prev(&range->vm_rb_node);
	if (node)
		prev = rb_entry(node, struct vm_range, vm_rb_node);
	else
		prev = NULL;

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

	/*
	 * If this is a file mapping don't set any new prot write.
	 * We need to keep the page table read-only to trigger a page
	 * fault for copy-on-write later on
	 */
	if (range->memobj && (range->flag & VR_PRIVATE) &&
	    !(range->memobj->flags & MF_HUGETLBFS)) {
		setattr &= ~PTATTR_WRITABLE;
		if (!clrattr && !setattr) {
			range->flag = newflag;
			error = 0;
			goto out;
		}
	}

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
	pte_t apte = PTE_NULL;
	uintptr_t phys;
	struct page *page;

	dkprintf("remap_one_page(%p,%p,%p %#lx,%p,%d)\n",
			arg0, pt, ptep, *ptep, pgaddr, pgshift);

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
		dkprintf("%lx-,%s: calling memory_stat_rss_sub(),size=%ld,pgsize=%ld\n", phys, __FUNCTION__, pgsize, pgsize);
		rusage_memory_stat_sub(args->memobj, pgsize, pgsize); 
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
	unsigned int retval;

	dkprintf("remap_process_memory_range(%p,%p,%#lx,%#lx,%#lx)\n",
			vm, range, start, end, off);
	ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
	memobj_ref(range->memobj);

	args.start = start;
	args.off = off;
	args.memobj = range->memobj;

	retval = __sync_val_compare_and_swap(&range->pgshift, 0, PAGE_SHIFT);
	if (retval != 0 && retval != PAGE_SHIFT) {
		error = -E2BIG;
		ekprintf("%s: pgshift is too big (%d)  failed:%d\n", __func__, retval, error);
		goto out;
	}
		
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
	memobj_unref(range->memobj);
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
		memobj_ref(range->memobj);
	}

	error = visit_pte_range(vm->address_space->page_table, (void *)start,
			(void *)end, range->pgshift, VPTEF_SKIP_NULL,
			&sync_one_page, &args);

	if (!(range->memobj->flags & MF_ZEROFILL)) {
		memobj_unref(range->memobj);
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
	pte_t apte = PTE_NULL;
	size_t memobj_pgsize;

	dkprintf("invalidate_one_page(%p,%p,%p %#lx,%p,%d)\n",
			arg0, pt, ptep, *ptep, pgaddr, pgshift);
	if (pte_is_null(ptep) || pte_is_fileoff(ptep, pgsize)) {
		error = 0;
		goto out;
	}

	phys = pte_get_phys(ptep);
	page = phys_to_page(phys);
	linear_off = range->objoff + ((uintptr_t)pgaddr - range->start);

	if (page) {
		if (page->offset != linear_off) {
			pte_make_fileoff(page->offset, 0, pgsize,
					 &apte);
		}
	}

	pte_xchg(ptep, &apte);
	flush_tlb_single((uintptr_t)pgaddr);	/* XXX: TLB flush */

	/* Contiguous PTE head invalidates memobj->pgshift-sized
	 * memory for other members
	 */
	if (pte_is_contiguous(&apte)) {
		if (page_is_contiguous_head(ptep, pgsize)) {
			int level = pgsize_to_tbllv(pgsize);

			memobj_pgsize = tbllv_to_contpgsize(level);
		} else {
			error = 0;
			goto out;
		}
	} else {
		memobj_pgsize = pgsize;
	}

	if (page && page_unmap(page)) {
		panic("invalidate_one_page");
	}

	error = memobj_invalidate_page(range->memobj, phys, memobj_pgsize);
	if (error) {
		ekprintf("invalidate_one_page(%p,%p,%p %#lx,%p,%d):"
				"invalidate failed. %d\n",
				arg0, pt, ptep, *ptep, pgaddr, pgshift, error);
		goto out;
	}
	// memory_stat_rss_sub() is called in downstream, i.e. shmobj_invalidate_page()

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
	pte_t *ptep;
	size_t pgsize;

	dkprintf("invalidate_process_memory_range(%p,%p,%#lx,%#lx)\n",
			vm, range, start, end);
	args.range = range;

	ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
	memobj_ref(range->memobj);

	ptep = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
				    (void *)start, 0, NULL,
				    &pgsize, NULL);
	if (ptep && pte_is_contiguous(ptep)) {
		if (!page_is_contiguous_head(ptep, pgsize)) {
			// start pte is not contiguous head
			error = split_contiguous_pages(ptep, pgsize);
			if (error) {
				ihk_spinlock_t *page_table_lock;

				memobj_unref(range->memobj);
				page_table_lock = &vm->page_table_lock;
				ihk_mc_spinlock_unlock_noirq(page_table_lock);
				goto out;
			}
		}
	}

	ptep = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
				    (void *)end - 1, 0, NULL,
				    &pgsize, NULL);
	if (ptep && pte_is_contiguous(ptep)) {
		if (!page_is_contiguous_tail(ptep, pgsize)) {
			// end pte is not contiguous tail
			error = split_contiguous_pages(ptep, pgsize);
			if (error) {
				ihk_spinlock_t *page_table_lock;

				memobj_unref(range->memobj);
				page_table_lock = &vm->page_table_lock;
				ihk_mc_spinlock_unlock_noirq(page_table_lock);
				goto out;
			}
		}
	}

	if (range->memobj->flags & MF_SHM) {
		error = ihk_mc_pt_free_range(vm->address_space->page_table,
					     vm, (void *)start, (void *)end,
					     range->memobj);
	} else {
		error = visit_pte_range(vm->address_space->page_table,
					(void *)start, (void *)end,
					range->pgshift, VPTEF_SKIP_NULL,
					&invalidate_one_page, &args);
	}
	memobj_unref(range->memobj);
	ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
	if (error) {
		ekprintf("invalidate_process_memory_range(%p,%p,%#lx,%#lx):"
				"visit failed%d\n",
				vm, range, start, end, error);
		goto out;
	}
	// memory_stat_rss_sub() is called downstream, i.e. invalidate_one_page() to deal with empty PTEs
	
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
	int private_range, patching_to_rdonly;
	int devfile_or_hugetlbfs_or_premap, regfile_or_shm;

	if (cpu_local_var(current)->profile) {
		dkprintf("%s: 0x%lx @ %s\n",
				__func__, fault_addr,
				range->memobj && range->memobj->path ?
				range->memobj->path :
				range->private_data ? "XPMEM" : "<unknown>");
	}

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
	dkprintf("%s: pgaddr=%lx,range->start=%lx,range->end=%lx,pgaddr+pgsize=%lx\n", __FUNCTION__, pgaddr, range->start, range->end, pgaddr + pgsize);
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

	arch_adjust_allocate_page_size(vm->address_space->page_table,
				       fault_addr, ptep, &pgaddr, &pgsize);

	/*****/
	dkprintf("%s: ptep=%lx,pte_is_null=%d,pte_is_fileoff=%d\n", __FUNCTION__, ptep, ptep ? pte_is_null(ptep) : -1, ptep ? pte_is_fileoff(ptep, pgsize) : -1);
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
                                       &phys, &memobj_flag, fault_addr);
			if (error) {
				struct memobj *obj;

				if (zeroobj_create(&obj)) {
					panic("PFPMR: zeroobj_crate");
				}

				if (range->memobj != obj) {
					goto out;
				}
			}
			// memory_stat_rss_add() is called downstream, i.e. memobj_get_page() to check page->count
		}
		if (phys == NOPHYS) {
			void *virt = NULL;
			size_t npages;

retry:
			npages = pgsize / PAGE_SIZE;
			virt = ihk_mc_alloc_aligned_pages_user(npages, p2align,
					IHK_MC_AP_NOWAIT |
					((range->flag & VR_AP_USER) ? IHK_MC_AP_USER : 0), fault_addr);
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
				dkprintf("%s: NOPHYS,phys=%lx,vmr(%lx-%lx),flag=%x,fa=%lx,reason=%x\n",
						 __FUNCTION__, page_to_phys(page),
						 range->start, range->end, range->flag, fault_addr, reason);
				
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

	private_range = (range->flag & VR_PRIVATE);
	patching_to_rdonly =
		((reason & PF_PATCH) && !(range->flag & VR_PROT_WRITE));

	/* device file map, hugetlbfs file map, pre-mapped file map */
	devfile_or_hugetlbfs_or_premap =
		(!page &&
		 (range->memobj && !(range->memobj->flags | MF_ZEROOBJ)));

	/* regular file map, Sys V shared memory map */
	regfile_or_shm =
		(page &&
		 (page_is_in_memobj(page) || page_is_multi_mapped(page)));

	if ((private_range || patching_to_rdonly) &&
	    (devfile_or_hugetlbfs_or_premap || regfile_or_shm)) {

		if (!(attr & PTATTR_DIRTY)) {
			attr &= ~PTATTR_WRITABLE;
		}
		else {
			void *virt;
			size_t npages;

			if (!page) {
				kprintf("%s: WARNING: cow on non-struct-page-managed page\n", __FUNCTION__);
			}

			npages = pgsize / PAGE_SIZE;
			virt = ihk_mc_alloc_aligned_pages_user(npages, p2align,
			                                      IHK_MC_AP_NOWAIT, fault_addr);
			if (!virt) {
				error = -ENOMEM;
				kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):cannot allocate copy page. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
				goto out;
			}
			dkprintf("%s: cow,copying virt:%lx<-%lx,phys:%lx<-%lx,pgsize=%lu\n",
					 __FUNCTION__, virt, phys_to_virt(phys), virt_to_phys(virt), phys, pgsize);
			memcpy(virt, phys_to_virt(phys), pgsize);

			/* Count COW-source pointed-to by only fileobj
			 *  The steps in test/rusage/005:
			 *  (1) Private-map regular file
			 *  (2) Don't touch the page
			 *  (3) Fork and then the child touches the page
			 *  (4) Page-in the COW-source
			 *  (5) Reach here
			 */
			if (rusage_memory_stat_add(range, phys, pgsize, pgsize)) {
				dkprintf("%lx+,%s: COW-source pointed-to by only fileobj, calling memory_stat_rss_add(),pgsize=%ld\n",
						phys, __FUNCTION__, pgsize);
			}
			if (page) {
				if (page_unmap(page)) {
					dkprintf("%lx-,%s: cow,calling memory_stat_rss_sub(),size=%ld,pgsize=%ld\n", phys, __FUNCTION__, pgsize, pgsize);
					rusage_memory_stat_sub(range->memobj, pgsize, pgsize); 
				}
			}
			phys = virt_to_phys(virt);
			page = phys_to_page(phys);
		}
	}
	else if (!(range->flag & VR_PRIVATE)) { /*VR_SHARED*/
		if (!(attr & PTATTR_DIRTY)) {
			if (!(range->flag & VR_STACK)) {
				attr &= ~PTATTR_WRITABLE;
			}
		}
	}

	/*****/
	if (ptep && !pgsize_is_contiguous(pgsize)) {
		if (!(reason & PF_PATCH) &&
		    rusage_memory_stat_add(range, phys, pgsize, pgsize)) {
			/* on-demand paging, phys pages are obtained by ihk_mc_alloc_aligned_pages_user() or get_page() */
			dkprintf("%lx+,%s: (on-demand paging && first map) || cow,calling memory_stat_rss_add(),phys=%lx,pgsize=%ld\n",
					 phys, __FUNCTION__, phys, pgsize);
		} else {
			dkprintf("%s: !calling memory_stat_rss_add(),phys=%lx,pgsize=%ld\n",
					 __FUNCTION__, phys, pgsize);
		}

		dkprintf("%s: attr=%x\n", __FUNCTION__, attr);
		error = ihk_mc_pt_set_pte(vm->address_space->page_table, ptep,
		                          pgsize, phys, attr);
		if (error) {
			kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):set_pte failed. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
			goto out;
		}
		dkprintf("%s: non-NULL pte,page=%lx,page_is_in_memobj=%d,page->count=%d\n", __FUNCTION__, page, page ? page_is_in_memobj(page) : 0, page ? ihk_atomic_read(&page->count) : 0);
	}
	else {
		error = ihk_mc_pt_set_range(vm->address_space->page_table, vm,
		                            pgaddr, pgaddr + pgsize, phys,
					    attr, range->pgshift, range, 1);
		if (error) {
			kprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx):set_range failed. %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
			goto out;
		}
		// memory_stat_rss_add() is called in downstream with !memobj check
	}
	flush_tlb_single(fault_addr);

	error = 0;
	page = NULL;

out:
	ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
	if (page) {
		/* Unmap stray struct page */
		dkprintf("%s: out,phys=%lx,vmr(%lx-%lx),flag=%x,fa=%lx,reason=%x\n",
				 __FUNCTION__, page_to_phys(page),
				 range->start, range->end, range->flag, fault_addr, reason);
		if (page_unmap(page)) {
			dkprintf("%lx-,%s: out,calling memory_stat_rss_sub(),size=%ld,pgsize=%ld\n", page_to_phys(page), __FUNCTION__, pgsize, pgsize);
			rusage_memory_stat_sub(range->memobj, pgsize, pgsize); 
		}
	}
	dkprintf("page_fault_process_memory_range(%p,%lx-%lx %lx,%lx,%lx): %d\n", vm, range->start, range->end, range->flag, fault_addr, reason, error);
	return error;
}

static int do_page_fault_process_vm(struct process_vm *vm, void *fault_addr0, uint64_t reason)
{
	int error;
	const uintptr_t fault_addr = (uintptr_t)fault_addr0;
	struct vm_range *range = NULL;
	struct thread *thread = cpu_local_var(current);
	int locked = 0;

	dkprintf("[%d]do_page_fault_process_vm(%p,%lx,%lx)\n",
			ihk_mc_get_processor_id(), vm, fault_addr0, reason);
	
	/* grow stack */
	if (fault_addr >= thread->vm->region.stack_start &&
	    fault_addr < thread->vm->region.stack_end) {
		range = lookup_process_memory_range(vm,
						    thread->vm->region.stack_end - 1,
						    thread->vm->region.stack_end);
		if (range == NULL) {
			error = -EFAULT;
			ekprintf("%s: vm: %p, addr: %p, reason: %lx):"
				 "stack not found: %d\n",
				 __func__, vm, fault_addr0, reason, error);
			goto out;
		}

		/* don't grow if replaced with hugetlbfs */
		if (range->memobj) {
			goto skip;
		}

		if (fault_addr >= range->start) {
			goto skip;
		}

		if (thread->vm->is_memory_range_lock_taken == -1 ||
		    thread->vm->is_memory_range_lock_taken !=
		    ihk_mc_get_processor_id()) {
			ihk_rwspinlock_write_lock_noirq(&vm->memory_range_lock);
			locked = 1;
		}

		if (range->pgshift) {
			range->start = fault_addr &
				~((1UL << range->pgshift) - 1);
		} else {
			range->start = fault_addr & PAGE_MASK;
		}

		if (locked) {
			ihk_rwspinlock_write_unlock_noirq(&vm->memory_range_lock);
			locked = 0;
		}

		dkprintf("%s: addr: %lx, reason: %lx, range: %lx-%lx:"
			 "stack found\n",
			 __func__, (unsigned long)fault_addr, reason,
			 range->start, range->end);
	}
skip:

	if (thread->vm->is_memory_range_lock_taken == -1 ||
			thread->vm->is_memory_range_lock_taken != ihk_mc_get_processor_id()) {
		ihk_rwspinlock_read_lock_noirq(&vm->memory_range_lock);
		locked = 1;
	} else {
		dkprintf("%s: INFO: skip locking of memory_range_lock,pid=%d,tid=%d\n",
			 __func__, thread->proc->pid, thread->tid);
	}	

	if (vm->exiting) {
		error = -ECANCELED;
		goto out;
	}

	if (!range) {
		range = lookup_process_memory_range(vm, fault_addr,
						    fault_addr+1);
		if (range == NULL) {
			error = -EFAULT;
			dkprintf("%s: vm: %p, addr: %p, reason: %lx):"
				 "out of range: %d\n",
				 __func__, vm, fault_addr0, reason, error);
			goto out;
		}
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
	if (locked) {
		ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);
	}
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

		preempt_enable();
		if (thread->pgio_fp) {
			(*thread->pgio_fp)(thread->pgio_arg);
			thread->pgio_fp = NULL;
		}
		preempt_disable();
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
	unsigned long maxsz;
	unsigned long minsz;
	unsigned long at_rand;
	struct process *proc = thread->proc;
	unsigned long ap_flag;
	unsigned long ap_hwcap;
	struct vm_range *range;
	int stack_populated_size = 0;
	int stack_align_padding = 0;

	/* Create stack range */
	end = STACK_TOP(&thread->vm->region) & USER_STACK_PAGE_MASK;
	minsz = (pn->stack_premap + USER_STACK_PREPAGE_SIZE - 1) &
		USER_STACK_PAGE_MASK;
	maxsz = (end - thread->vm->region.map_start) / 2;
	size = proc->rlimit[MCK_RLIMIT_STACK].rlim_cur;
	if (size > maxsz) {
		size = maxsz;
	}
	else if (size < minsz) {
		size = minsz;
	}
	size = (size + USER_STACK_PREPAGE_SIZE - 1) & USER_STACK_PAGE_MASK;
	dkprintf("%s: stack_premap: %lu, rlim_cur: %lu, minsz: %lu, size: %lu, maxsz: %lx\n",
		 __func__, pn->stack_premap,
		 proc->rlimit[MCK_RLIMIT_STACK].rlim_cur,
		 minsz, size, maxsz);
	start = (end - minsz) & USER_STACK_PAGE_MASK;

	/* Apply user allocation policy to stacks */
	/* TODO: make threshold kernel or mcexec argument */
	ap_flag = (minsz >= proc->mpol_threshold &&
		!(proc->mpol_flags & MPOL_NO_STACK)) ? IHK_MC_AP_USER : 0;
	dkprintf("%s: max size: %lu, mapped size: %lu %s\n",
			__FUNCTION__, size, minsz,
			ap_flag ? "(IHK_MC_AP_USER)" : "");

	stack = ihk_mc_alloc_aligned_pages_user(minsz >> PAGE_SHIFT,
						USER_STACK_PAGE_P2ALIGN,
						IHK_MC_AP_NOWAIT | ap_flag,
						start);

	if (!stack) {
		kprintf("%s: error: couldn't allocate initial stack\n",
				__FUNCTION__);
		return -ENOMEM;
	}

	memset(stack, 0, minsz);

	vrflag = VR_STACK | VR_DEMAND_PAGING | VR_PRIVATE;
	vrflag |= ((ap_flag & IHK_MC_AP_USER) ? VR_AP_USER : 0);
	vrflag |= PROT_TO_VR_FLAG(pn->stack_prot);
	vrflag |= VR_MAXPROT_READ | VR_MAXPROT_WRITE | VR_MAXPROT_EXEC;
#define	NOPHYS	((uintptr_t)-1)
	if ((rc = add_process_memory_range(thread->vm, start, end, NOPHYS,
			vrflag, NULL, 0, USER_STACK_PAGE_SHIFT, &range)) != 0) {
		ihk_mc_free_pages_user(stack, minsz >> PAGE_SHIFT);
		kprintf("%s: error addding process memory range: %d\n", rc);
		return rc;
	}

	/* Map physical pages for initial stack frame */
	error = ihk_mc_pt_set_range(thread->vm->address_space->page_table,
				    thread->vm, (void *)(end - minsz),
				    (void *)end, virt_to_phys(stack),
				    arch_vrflag_to_ptattr(vrflag, PF_POPULATE,
							  NULL),
				    USER_STACK_PAGE_SHIFT, range, 0);
	if (error) {
		kprintf("init_process_stack:"
				"set range %lx-%lx %lx failed. %d\n",
				(end-minsz), end, stack, error);
		ihk_mc_free_pages_user(stack, minsz >> PAGE_SHIFT);
		return error;
	}

	/* Pre-compute populated size so that we can align stack
	 * and verify the size at the end */
	stack_align_padding = 0;
	stack_populated_size = 16 /* Random */ +
		AUXV_LEN * sizeof(unsigned long) /* AUXV */ +
		(argc + 2) * sizeof(unsigned long) /* args + term NULL + argc */ +
		(envc + 1) * sizeof(unsigned long); /* envs + term NULL */

	/* set up initial stack frame */
	p = (unsigned long *)(stack + minsz);
	s_ind = -1;

	/* Align stack to 64 bytes */
	while ((unsigned long)(stack + minsz -
				stack_populated_size - stack_align_padding) & (0x40L - 1)) {
		s_ind--;
		stack_align_padding += sizeof(unsigned long);
	}

	/* "random" 16 bytes on the very top */
	p[s_ind--] = 0x010101011;
	p[s_ind--] = 0x010101011;
	at_rand = end + (s_ind + 1) * sizeof(unsigned long);

	/* auxiliary vector */
	/* If you add/delete entires, please increase/decrease
	   AUXV_LEN in include/process.h. */
	p[s_ind--] = 0;     /* AT_NULL */
	p[s_ind--] = 0;
	ap_hwcap = arch_get_hwcap();
	p[s_ind--] = ap_hwcap; /* AT_HWCAP */
	p[s_ind--] = ap_hwcap ? AT_HWCAP : AT_IGNORE;
	p[s_ind--] = pn->at_entry; /* AT_ENTRY */
	p[s_ind--] = AT_ENTRY;
	p[s_ind--] = pn->at_phnum; /* AT_PHNUM */
	p[s_ind--] = AT_PHNUM;
	p[s_ind--] = pn->at_phent;  /* AT_PHENT */
	p[s_ind--] = AT_PHENT;
	p[s_ind--] = pn->at_phdr;  /* AT_PHDR */
	p[s_ind--] = AT_PHDR;
	p[s_ind--] = PAGE_SIZE; /* AT_PAGESZ */
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

	if (((void *)&p[s_ind] != (void *)stack + minsz -
				stack_populated_size - stack_align_padding)) {
		kprintf("%s: WARNING: stack_populated_size mismatch (is AUXV_LEN up-to-date?): "
				"&p[s_ind]: %lu, computed: %lu\n",
				__FUNCTION__,
				(unsigned long)&p[s_ind],
				(unsigned long)stack + minsz -
					stack_populated_size - stack_align_padding);
	}

	if ((unsigned long)&p[s_ind] & (0x40L - 1)) {
		kprintf("%s: WARNING: stack alignment mismatch\n", __FUNCTION__);
	}

	ihk_mc_modify_user_context(thread->uctx, IHK_UCR_STACK_POINTER,
	                           end + sizeof(unsigned long) * s_ind);
	thread->vm->region.stack_end = end;
	thread->vm->region.stack_start = (end - size) & USER_STACK_PAGE_MASK;

	return 0;
}


unsigned long extend_process_region(struct process_vm *vm,
		unsigned long end_allocated,
		unsigned long address, unsigned long flag)
{
	unsigned long new_end_allocated;
	void *p;
	int rc;
	size_t len;
	int npages;

	size_t align_size = vm->proc->heap_extension > PAGE_SIZE ?
		LARGE_PAGE_SIZE : PAGE_SIZE;
	unsigned long align_mask = vm->proc->heap_extension > PAGE_SIZE ?
		LARGE_PAGE_MASK : PAGE_MASK;
	unsigned long align_p2align = vm->proc->heap_extension > PAGE_SIZE ?
		LARGE_PAGE_P2ALIGN : PAGE_P2ALIGN;
	int align_shift = vm->proc->heap_extension > PAGE_SIZE ?
		LARGE_PAGE_SHIFT : PAGE_SHIFT;

	new_end_allocated = (address + (PAGE_SIZE - 1)) & PAGE_MASK;
	if ((new_end_allocated - end_allocated) < vm->proc->heap_extension) {
		new_end_allocated = (end_allocated + vm->proc->heap_extension +
				(align_size - 1)) & align_mask;
	}

	len = new_end_allocated - end_allocated;
	npages = len >> PAGE_SHIFT;

	if (flag & VR_DEMAND_PAGING) {
		p = 0;
	}
	else {
		p = ihk_mc_alloc_aligned_pages_user(
				npages, align_p2align,
				IHK_MC_AP_NOWAIT |
				(!(vm->proc->mpol_flags & MPOL_NO_HEAP) ?
				 IHK_MC_AP_USER : 0),
				end_allocated);

		if (!p) {
			dkprintf("%s: warning: failed to allocate %d contiguous pages "
					" (bytes: %lu, pgshift: %d), enabling demand paging\n",
					 __func__, npages, len, align_p2align);

			/* Give demand paging a chance */
			flag |= VR_DEMAND_PAGING;
		}
	}

	if ((rc = add_process_memory_range(vm, end_allocated, new_end_allocated,
					(p == 0 ? 0 : virt_to_phys(p)), flag, NULL, 0,
					align_shift, NULL)) != 0) {
		ihk_mc_free_pages_user(p, (new_end_allocated - end_allocated) >> PAGE_SHIFT);
		return end_allocated;
	}
	// memory_stat_rss_add() is called in add_process_memory_range()

	dkprintf("%s: new_end_allocated: 0x%lx, align_size: %lu, align_mask: %lx\n",
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

	// memory_stat_rss_sub() isn't called because this execution path is no loger reached
	dkprintf("%s: memory_stat_rss_sub() isn't called,start=%lx,end=%lx\n", __FUNCTION__, start, end);

	return 0;
}

void flush_process_memory(struct process_vm *vm)
{
	struct vm_range *range;
	struct rb_node *node, *next = rb_first(&vm->vm_range_tree);
	int error;

	dkprintf("flush_process_memory(%p)\n", vm);
	ihk_rwspinlock_write_lock_noirq(&vm->memory_range_lock);
	/* Let concurrent page faults know the VM will be gone */
	vm->exiting = 1;
	while ((node = next)) {
		range = rb_entry(node, struct vm_range, vm_rb_node);
		next = rb_next(node);

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
	ihk_rwspinlock_write_unlock_noirq(&vm->memory_range_lock);
	dkprintf("flush_process_memory(%p):\n", vm);
	return;
}

void free_process_memory_ranges(struct process_vm *vm)
{
	int error;
	struct vm_range *range;
	struct rb_node *node, *next = rb_first(&vm->vm_range_tree);

	if (vm == NULL) {
		return;
	}

	ihk_rwspinlock_write_lock_noirq(&vm->memory_range_lock);
	while ((node = next)) {
		range = rb_entry(node, struct vm_range, vm_rb_node);
		next = rb_next(node);

		error = free_process_memory_range(vm, range);
		if (error) {
			ekprintf("free_process_memory(%p):"
					"free range failed. %lx-%lx %d\n",
					vm, range->start, range->end, error);
			/* through */
		}
	}
	ihk_rwspinlock_write_unlock_noirq(&vm->memory_range_lock);
}

static void free_thread_pages(struct thread *thread)
{
	ihk_mc_free_pages(thread, KERNEL_STACK_NR_PAGES);
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
	struct resource_set *rset;

	if (!ihk_atomic_dec_and_test(&proc->refcount)) {
		return;
	}

	rset = cpu_local_var(resource_set);
	if (!list_empty(&proc->hash_list)) {
		struct process_hash *phash = rset->process_hash;
		int hash = process_hash(proc->pid);

		mcs_rwlock_writer_lock(&phash->lock[hash], &lock);
		list_del(&proc->hash_list);
		mcs_rwlock_writer_unlock(&phash->lock[hash], &lock);
	}

	parent = proc->parent;
	mcs_rwlock_writer_lock(&parent->children_lock, &lock);
	list_del(&proc->siblings_list);
	mcs_rwlock_writer_unlock(&parent->children_lock, &lock);

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
	free_thread_pages(proc->main_thread);

	{
		long irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);
		struct mckfd *cur = proc->mckfd;

		while (cur) {
			struct mckfd *next = cur->next;

			kfree(cur);
			cur = next;
		}
		ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);
	}

	kfree(proc);

	/* no process left */
	mcs_rwlock_reader_lock(&rset->pid1->children_lock, &lock);
	if (list_empty(&rset->pid1->children_list)) {
#ifdef ENABLE_TOFU
		extern void tof_utofu_finalize(void);

		tof_utofu_finalize();
#endif
		hugefileobj_cleanup();
	}
	mcs_rwlock_reader_unlock(&rset->pid1->children_lock, &lock);
}

void
hold_process_vm(struct process_vm *vm)
{
	ihk_atomic_inc(&vm->refcount);
}

void
free_all_process_memory_range(struct process_vm *vm)
{
	struct vm_range *range;
	struct rb_node *node, *next = rb_first(&vm->vm_range_tree);
	int error;

	ihk_rwspinlock_write_lock_noirq(&vm->memory_range_lock);
	while ((node = next)) {
		range = rb_entry(node, struct vm_range, vm_rb_node);
		next = rb_next(node);

		error = free_process_memory_range(vm, range);
		if (error) {
			ekprintf("free_process_memory(%p):"
					"free range failed. %lx-%lx %d\n",
					vm, range->start, range->end, error);
			/* through */
		}
	}
	ihk_rwspinlock_write_unlock_noirq(&vm->memory_range_lock);
}

void
release_process_vm(struct process_vm *vm)
{
	struct process *proc = vm->proc;
	struct vm_range_numa_policy *policy;
	struct rb_node *node;

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

	while ((node = rb_first(&vm->vm_range_numa_policy_tree))) {
		policy = rb_entry(node, struct vm_range_numa_policy,
				  policy_rb_node);
		rb_erase(&policy->policy_rb_node,
			 &vm->vm_range_numa_policy_tree);
		kfree(policy);
	}

	kfree(vm);
}

int populate_process_memory(struct process_vm *vm, void *start, size_t len)
{
	int error;
	const int reason = PF_USER | PF_POPULATE;
	uintptr_t end;
	uintptr_t addr;

	end = (uintptr_t)start + len;
	preempt_disable();
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
	preempt_enable();
	return error;
}

int hold_thread(struct thread *thread)
{
	if (thread->status == PS_EXITED) {
		kprintf("hold_thread: WARNING: already exited process,tid=%d\n",
			thread->tid);
	}

	ihk_atomic_inc(&thread->refcount);
	return 0;
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

/* Replace tid specified by thread with tid specified by new_tid */
void __find_and_replace_tid(struct process *proc, struct thread *thread, int new_tid) {
	int i;

	for (i = 0; i < proc->nr_tids; ++i) {
		if (proc->tids[i].thread != thread) continue;

		proc->tids[i].thread = NULL;
		proc->tids[i].tid = new_tid;
		dkprintf("%s: tid %d (thread %p) has been relaced with tid %d\n",
				__FUNCTION__, thread->tid, thread, new_tid);
		break;
	}
}

void destroy_thread(struct thread *thread)
{
	struct sig_pending *pending;
	struct sig_pending *signext;
	struct mcs_rwlock_node_irqsave lock, updatelock;
	struct process *proc = thread->proc;
	struct timespec ats;

	if (!list_empty(&thread->hash_list)) {
		struct resource_set *resource_set = cpu_local_var(resource_set);
		int hash = thread_hash(thread->tid);

		mcs_rwlock_writer_lock(&resource_set->thread_hash->lock[hash],
					&lock);
		list_del(&thread->hash_list);
		mcs_rwlock_writer_unlock(&resource_set->thread_hash->lock[hash],
					&lock);
	}

	mcs_rwlock_writer_lock(&proc->update_lock, &updatelock);
	tsc_to_ts(thread->system_tsc, &ats);
	ts_add(&thread->proc->stime, &ats);
	tsc_to_ts(thread->user_tsc, &ats);
	ts_add(&thread->proc->utime, &ats);
	mcs_rwlock_writer_unlock(&proc->update_lock, &updatelock);

	mcs_rwlock_writer_lock(&proc->threads_lock, &lock);
	list_del(&thread->siblings_list);
	if (thread->uti_state == UTI_STATE_EPILOGUE) {
		__find_and_replace_tid(proc, thread, thread->uti_refill_tid);
	}
	else if (thread != proc->main_thread) {
		__release_tid(proc, thread);
	}

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
	kfree(thread->coredump_regs);

	release_sigcommon(thread->sigcommon);

	if (thread != proc->main_thread)
		free_thread_pages(thread);
	mcs_rwlock_writer_unlock(&proc->threads_lock, &lock);
}

void release_thread(struct thread *thread)
{
	struct process_vm *vm;

	if (!ihk_atomic_dec_and_test(&thread->refcount)) {
		return;
	}

	vm = thread->vm;

#ifdef PROFILE_ENABLE
	profile_accumulate_events(thread, thread->proc);
	//profile_print_thread_stats(thread);
	profile_dealloc_thread_events(thread);
#endif // PROFILE_ENABLE
	procfs_delete_thread(thread);
	destroy_thread(thread);

	release_process_vm(vm);
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
			ihk_numa_zero_free_pages(ihk_mc_get_numa_node_by_distance(0));
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
	ihk_rwspinlock_init(&idle_thread->vm->memory_range_lock);
	idle_thread->vm->vm_range_tree = RB_ROOT;
	idle_thread->vm->vm_range_numa_policy_tree = RB_ROOT;
	idle_thread->proc->pid = 0;
	idle_thread->tid = ihk_mc_get_processor_id();

	INIT_LIST_HEAD(&cpu_local_var(runq));
	cpu_local_var(runq_len) = 0;
	ihk_mc_spinlock_init(&cpu_local_var(runq_lock));

	INIT_LIST_HEAD(&cpu_local_var(migq));
	ihk_mc_spinlock_init(&cpu_local_var(migq_lock));

	// to save default fpregs
	save_fp_regs(idle_thread);

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
		/* Kick scheduler on target CPU */
		ihk_mc_interrupt_cpu(cpu_id, ihk_mc_get_vector(IHK_GV_IKC));

		waitq_wakeup(&req->wq);
		double_rq_unlock(cur_v, v, irqstate);
		continue;
ack:
		waitq_wakeup(&req->wq);
	}
	ihk_mc_spinlock_unlock(&cur_v->migq_lock, irqstate);
}

void set_timer(int runq_locked)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	struct thread *thread;
	int num_running = 0;
	unsigned long irqstate;

	if (!time_sharing) {
		return;
	}

	if (!runq_locked) {
		irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
	}

	list_for_each_entry(thread, &v->runq, sched_list) {
		if (thread->status != PS_RUNNING && !thread->spin_sleep) {
			continue;
		}
		num_running++;
	}

	/* Toggle timesharing if CPU core is oversubscribed */
	if (num_running > 1 || v->current->itimer_enabled ||
	    !list_empty(&v->backlog_list)) {
		if (!cpu_local_var(timer_enabled)) {
			lapic_timer_enable(1000000);
			cpu_local_var(timer_enabled) = 1;
		}
	}
	else {
		if (cpu_local_var(timer_enabled)) {
			lapic_timer_disable();
			cpu_local_var(timer_enabled) = 0;
		}
	}

	if (!runq_locked) {
		ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
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

	/* Spinning disabled explicitly */
	if (idle_halt) {
		dkprintf("%s: idle_halt -> schedule()\n", __FUNCTION__);
		goto out_schedule;
	}

	/* Try to spin sleep */
	irqstate = ihk_mc_spinlock_lock(&thread->spin_sleep_lock);
	if (thread->spin_sleep == 0) {
		dkprintf("%s: caught a lost wake-up!\n", __FUNCTION__);
	}
	ihk_mc_spinlock_unlock(&thread->spin_sleep_lock, irqstate);

	for (;;) {
		/* Check if we need to reschedule */
		irqstate = cpu_disable_interrupt_save();
		ihk_mc_spinlock_lock_noirq(
			&(get_this_cpu_local_var()->runq_lock));
		v = get_this_cpu_local_var();

		if (v->flags & CPU_FLAG_NEED_RESCHED || v->runq_len > 1) {
			v->flags &= ~CPU_FLAG_NEED_RESCHED;
			do_schedule = 1;
		}

		ihk_mc_spinlock_unlock_noirq(&v->runq_lock);
		cpu_restore_interrupt(irqstate);

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

		if ((!list_empty(&thread->sigpending) ||
		     !list_empty(&thread->sigcommon->sigpending)) &&
		    hassigpending(thread)) {
			woken = 1;
		}

		if (woken) {
			if (do_schedule) {
				irqstate = ihk_mc_spinlock_lock(&v->runq_lock);
				v->flags |= CPU_FLAG_NEED_RESCHED;
				ihk_mc_spinlock_unlock(&v->runq_lock, irqstate);
			}
			return;
		}

		if (do_schedule) {
			break;
		}

		ihk_numa_zero_free_pages(ihk_mc_get_numa_node_by_distance(0));
		cpu_pause();
	}

out_schedule:
	schedule();
}

void schedule(void)
{
	struct cpu_local_var *v;
	struct thread *next, *prev, *thread, *tmp = NULL;
	int switch_ctx = 0;
	struct thread *last;
	int prevpid;
	unsigned long irqstate = 0;

	if (cpu_local_var(no_preempt)) {
		kprintf("%s: WARNING can't schedule() while no preemption, cnt: %d\n",
			__FUNCTION__, cpu_local_var(no_preempt));

		irqstate = cpu_disable_interrupt_save();
		ihk_mc_spinlock_lock_noirq(
			&(get_this_cpu_local_var()->runq_lock));
		v = get_this_cpu_local_var();

		v->flags |= CPU_FLAG_NEED_RESCHED;

		ihk_mc_spinlock_unlock_noirq(&v->runq_lock);
		cpu_restore_interrupt(irqstate);
		return;
	}

	irqstate = cpu_disable_interrupt_save();
	ihk_mc_spinlock_lock_noirq(&(get_this_cpu_local_var()->runq_lock));
	cpu_local_var(runq_irqstate) = irqstate;
	v = get_this_cpu_local_var();

	next = NULL;
	prev = v->current;
	prevpid = v->prevpid;
	
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

	/* Switch to idle() when prev is PS_EXITED since it always reaches release_thread() 
	   because it always resumes from just after ihk_mc_switch_context() call. See #1029 */
	if (v->flags & CPU_FLAG_NEED_MIGRATE ||
	    (prev && prev->status == PS_EXITED)) {
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
		v->prevpid = v->current && v->current->proc ?
			v->current->proc->pid : 0;
		v->current = next;
		reset_cputime();
	}

	set_timer(1);

	if (switch_ctx) {
		++cpu_local_var(nr_ctx_switches);
		dkprintf("%s: %d => %d [ctx sws: %lu]\n",
				__func__,
				prev ? prev->tid : 0, next ? next->tid : 0,
				cpu_local_var(nr_ctx_switches));

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
		/* Not to save fp_regs when the process ends */
		if (prev && (prev != &cpu_local_var(idle)
				&& prev->status != PS_EXITED)) {
			save_fp_regs(prev);
		}

		if (next != &cpu_local_var(idle)) {
			restore_fp_regs(next);
		}

		if (prev && prev->vm->address_space->page_table !=
				next->vm->address_space->page_table)
			ihk_mc_load_page_table(next->vm->address_space->page_table);

		/*
		 * Unless switching to a thread in the same process,
		 * to the idle thread, or to the same process that ran
		 * before the idle, clear the instruction cache.
		 */
		if ((prev && prev->proc != next->proc) &&
				next != &cpu_local_var(idle) &&
				(prevpid != next->proc->pid ||
					prev != &cpu_local_var(idle))) {
			arch_flush_icache_all();
		}

		last = arch_switch_context(prev, next);

		/*
		 * We must hold the lock throughout the context switch, otherwise
		 * an IRQ could deschedule this process between page table loading and
		 * context switching and leave the execution in an inconsistent state.
		 * Since we may be migrated to another core meanwhile, we refer
		 * directly to cpu_local_var.
		 */
		ihk_mc_spinlock_unlock_noirq(&(cpu_local_var(runq_lock)));
		cpu_restore_interrupt(cpu_local_var(runq_irqstate));

		if ((last != NULL) && (last->status == PS_EXITED)) {
			v->prevpid = 0;
			arch_flush_icache_all();
			release_thread(last);
			rusage_num_threads_dec();
#ifdef RUSAGE_DEBUG
			if (rusage.num_threads == 0) {
				int i;

				kprintf("total_memory_usage=%ld\n",
					rusage.total_memory_usage);
				for (i = 0; i < IHK_MAX_NUM_PGSIZES; i++) {
					kprintf("memory_stat_rss[%d]=%ld\n", i,
						rusage.memory_stat_rss[i]);
				}
				for (i = 0; i < IHK_MAX_NUM_PGSIZES; i++) {
					kprintf(
					   "memory_stat_mapped_file[%d]=%ld\n",
					    i,
					    rusage.memory_stat_mapped_file[i]);
				}
			}
#endif
		}

		/* Have we migrated to another core meanwhile? */
		if (v != get_this_cpu_local_var()) {
			v = get_this_cpu_local_var();
		}
	}
	else {
		ihk_mc_spinlock_unlock_noirq(&(cpu_local_var(runq_lock)));
		cpu_restore_interrupt(cpu_local_var(runq_irqstate));
	}
}

void
release_cpuid(int cpuid)
{
	unsigned long irqstate;
    struct cpu_local_var *v = get_cpu_local_var(cpuid);
    irqstate = ihk_mc_spinlock_lock(&runq_reservation_lock);
    ihk_mc_spinlock_lock_noirq(&(v->runq_lock));
	if (!v->runq_len)
		v->status = CPU_STATUS_IDLE;
	__sync_fetch_and_sub(&v->runq_reserved, 1);
    ihk_mc_spinlock_unlock_noirq(&(v->runq_lock));
    ihk_mc_spinlock_unlock(&runq_reservation_lock, irqstate);
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
		v->flags &= ~CPU_FLAG_NEED_RESCHED;
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

		/* Make interrupt_exit() call schedule() */
		v->flags |= CPU_FLAG_NEED_RESCHED;

		/* Make sure to check if timer needs to be re-enabled */
		if (thread->cpu_id == ihk_mc_get_processor_id()) {
			set_timer(1);
		}
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
		ihk_mc_interrupt_cpu(thread->cpu_id,
		                     ihk_mc_get_vector(IHK_GV_IKC));
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

	/*
	 * NOTES:
	 * - migration queue lock must be held before runqueue lock.
	 * - the lock must be held until migration request is added
	 *   and the target core is notified, otherwise an interrupt
	 *   may deschedule this thread and leave it hanging in
	 *   uninterruptible state forever.
	 */
	irqstate = ihk_mc_spinlock_lock(&v->migq_lock);
	waitq_init(&req.wq);
	waitq_prepare_to_wait(&req.wq, &entry, PS_UNINTERRUPTIBLE);

	list_add_tail(&req.list, &v->migq);

	ihk_mc_spinlock_lock_noirq(&v->runq_lock);
	v->flags |= CPU_FLAG_NEED_RESCHED | CPU_FLAG_NEED_MIGRATE;
	v->status = CPU_STATUS_RUNNING;
	ihk_mc_spinlock_unlock_noirq(&v->runq_lock);

	if (cpu_id != ihk_mc_get_processor_id()) {
		/* Kick scheduler */
		ihk_mc_interrupt_cpu(thread->cpu_id,
				ihk_mc_get_vector(IHK_GV_IKC));
	}
	dkprintf("%s: tid: %d -> cpu: %d\n",
			__FUNCTION__, thread->tid, cpu_id);
	ihk_mc_spinlock_unlock(&v->migq_lock, irqstate);

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
	irqstate = ihk_mc_spinlock_lock(&runq_reservation_lock);
	ihk_mc_spinlock_lock_noirq(&(v->runq_lock));
	__runq_add_thread(thread, cpu_id);
	__sync_fetch_and_sub(&v->runq_reserved, 1);
	ihk_mc_spinlock_unlock_noirq(&(v->runq_lock));
	ihk_mc_spinlock_unlock(&runq_reservation_lock, irqstate);

	procfs_create_thread(thread);

	__sync_add_and_fetch(&thread->proc->clone_count, 1);
	dkprintf("%s: clone_count is %d\n", __FUNCTION__, thread->proc->clone_count);
	rusage_num_threads_inc();
#ifdef RUSAGE_DEBUG
	if (rusage.num_threads == 1) {
		int i;
		kprintf("total_memory_usage=%ld\n", rusage.total_memory_usage);
		for(i = 0; i < IHK_MAX_NUM_PGSIZES; i++) {
			kprintf("memory_stat_rss[%d]=%ld\n", i, rusage.memory_stat_rss[i]);
		}
		for(i = 0; i < IHK_MAX_NUM_PGSIZES; i++) {
			kprintf("memory_stat_mapped_file[%d]=%ld\n", i, rusage.memory_stat_mapped_file[i]);
		}
	}
#endif

	/* Kick scheduler */
	if (cpu_id != ihk_mc_get_processor_id()) {
		ihk_mc_interrupt_cpu(thread->cpu_id,
				ihk_mc_get_vector(IHK_GV_IKC));
	}
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
find_thread(int pid, int tid)
{
	struct thread *thread;
	struct thread_hash *thash = cpu_local_var(resource_set)->thread_hash;
	int hash = thread_hash(tid);
	struct mcs_rwlock_node_irqsave lock;

	if(tid <= 0)
		return NULL;
	mcs_rwlock_reader_lock(&thash->lock[hash], &lock);
retry:
	list_for_each_entry(thread, &thash->list[hash], hash_list){
		if(thread->tid == tid){
			if (pid <= 0 ||
			    thread->proc->pid == pid) {
				hold_thread(thread);
				mcs_rwlock_reader_unlock(&thash->lock[hash],
							 &lock);
				return thread;
			}
		}
	}
	/* If no thread with pid == tid was found, then we may be looking for a
	 * specific thread (not the main thread of the process), try to find it
	 * based on tid only */
	if (pid > 0 && pid == tid) {
		pid = 0;
		goto retry;
	}
	mcs_rwlock_reader_unlock(&thash->lock[hash], &lock);
	return NULL;
}

void
thread_unlock(struct thread *thread)
{
	if(!thread)
		return;
	release_thread(thread);
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
				kprintf("pid=%d ppid=%d status=%d ref=%d\n",
					p->pid, p->ppid_parent->pid, p->status,
					p->refcount.counter);
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
				kprintf("cpu=%d pid=%d tid=%d status=%d "
					"offload=%d ref=%d ptrace=%08x\n",
					t->cpu_id, t->proc->pid, t->tid,
					t->status, t->in_syscall_offload,
					t->refcount.counter, t->ptrace);
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

int access_ok(struct process_vm *vm, int type, uintptr_t addr, size_t len) {
	struct vm_range *range, *next;
	int first = true;

	range = lookup_process_memory_range(vm, addr, addr + len);

	if (!range || range->start > addr) {
		kprintf("%s: No VM range at 0x%llx, refusing access\n",
			__FUNCTION__, addr);
		return -EFAULT;
	}
	do {
		if (first) {
			first = false;
		} else {
			next = next_process_memory_range(vm, range);
			if (!next) {
				kprintf("%s: No VM range after 0x%llx, but checking until 0x%llx. Refusing access\n",
					__FUNCTION__, range->end, addr + len);
				return -EFAULT;
			}
			if (range->end != next->start) {
				kprintf("%s: 0x%llx - 0x%llx and 0x%llx - 0x%llx are not adjacent (request was %0x%llx-0x%llx %zu)\n",
					__FUNCTION__, range->start, range->end,
					next->start, next->end,
					addr, addr+len, len);
				return -EFAULT;
			}
			range = next;
		}

		if ((type == VERIFY_WRITE && !(range->flag & VR_PROT_WRITE)) ||
		    (type == VERIFY_READ && !(range->flag & VR_PROT_READ))) {
			kprintf("%s: 0x%llx - 0x%llx does not have prot %s (request was %0x%llx-0x%llx %zu)\n",
				__FUNCTION__, range->start, range->end,
				type == VERIFY_WRITE ? "write" : "ready",
				addr, addr+len, len);
			return -EACCES;
		}
	} while (addr + len > range->end);

	return 0;
}
