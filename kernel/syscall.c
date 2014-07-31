/**
 * \file syscall.c
 *  License details are found in the file LICENSE.
 * \brief
 *  system call handlers
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * 	Copyright (C) 2011 - 2012  Taku Shimosawa
 * \author Balazs Gerofi  <bgerofi@riken.jp> \par
 * 	Copyright (C) 2012  RIKEN AICS
 * \author Masamichi Takagi  <m-takagi@ab.jp.nec.com> \par
 * 	Copyright (C) 2012 - 2013  NEC Corporation
 * \author Min Si <msi@is.s.u-tokyo.ac.jp> \par
 * 	Copyright (C) 2012  Min Si
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

#include <types.h>
#include <kmsg.h>
#include <ihk/cpu.h>
#include <cpulocal.h>
#include <ihk/mm.h>
#include <ihk/debug.h>
#include <ihk/ikc.h>
#include <errno.h>
#include <cls.h>
#include <syscall.h>
#include <page.h>
#include <amemcpy.h>
#include <uio.h>
#include <ihk/lock.h>
#include <ctype.h>
#include <waitq.h>
#include <rlimit.h>
#include <affinity.h>
#include <time.h>
#include <ihk/perfctr.h>
#include <mman.h>
#include <kmalloc.h>
#include <memobj.h>
#include <shm.h>

/* Headers taken from kitten LWK */
#include <lwk/stddef.h>
#include <futex.h>

#define SYSCALL_BY_IKC

//#define DEBUG_PRINT_SC

#ifdef DEBUG_PRINT_SC
#define	dkprintf(...) kprintf(__VA_ARGS__)
#define	ekprintf(...) kprintf(__VA_ARGS__)
#else
#define dkprintf(...)
#define	ekprintf(...) kprintf(__VA_ARGS__)
#endif

//static ihk_atomic_t pid_cnt = IHK_ATOMIC_INIT(1024);

/* generate system call handler's prototypes */
#define	SYSCALL_HANDLED(number,name)	extern long sys_##name(int n, ihk_mc_user_context_t *ctx);
#define	SYSCALL_DELEGATED(number,name)
#include <syscall_list.h>
#undef	SYSCALL_HANDLED
#undef	SYSCALL_DELEGATED

/* generate syscall_table[] */
static long (*syscall_table[])(int, ihk_mc_user_context_t *) = {
#define	SYSCALL_HANDLED(number,name)	[number] = &sys_##name,
#define	SYSCALL_DELEGATED(number,name)
#include <syscall_list.h>
#undef	SYSCALL_HANDLED
#undef	SYSCALL_DELEGATED
};

/* generate syscall_name[] */
#define	MCKERNEL_UNUSED	__attribute__ ((unused))
static char *syscall_name[] MCKERNEL_UNUSED = {
#define	DECLARATOR(number,name)		[number] = #name,
#define	SYSCALL_HANDLED(number,name)	DECLARATOR(number,sys_##name)
#define	SYSCALL_DELEGATED(number,name)	DECLARATOR(number,sys_##name)
#include <syscall_list.h>
#undef	DECLARATOR
#undef	SYSCALL_HANDLED
#undef	SYSCALL_DELEGATED
};

void check_signal(unsigned long rc, void *regs);
void do_signal(long rc, void *regs, struct process *proc, struct sig_pending *pending);
extern unsigned long do_kill(int pid, int tid, int sig);
int copy_from_user(struct process *, void *, const void *, size_t);
int copy_to_user(struct process *, void *, const void *, size_t);

int prepare_process_ranges_args_envs(struct process *proc, 
		struct program_load_desc *pn,
		struct program_load_desc *p,
		enum ihk_mc_pt_attribute attr,
		char *args, int args_len,
		char *envs, int envs_len);

#ifdef DCFA_KMOD
static void do_mod_exit(int status);
#endif

static void send_syscall(struct syscall_request *req, int cpu, int pid)
{
	struct ikc_scd_packet packet;
	struct syscall_response *res;
	struct syscall_params *scp;
	struct ihk_ikc_channel_desc *syscall_channel;
	int ret;

	if(req->number == __NR_exit_group ||
	   req->number == __NR_kill){ // interrupt syscall
		extern int num_processors;

		scp = &get_cpu_local_var(0)->scp2;
		syscall_channel = get_cpu_local_var(0)->syscall_channel2;
		
		/* XXX: is this really going to work if multiple processes 
		 * exit/receive signals at the same time?? */
		cpu = num_processors;
		if(req->number == __NR_kill)
			pid = req->args[2];
	}
	else{
		scp = &get_cpu_local_var(cpu)->scp;
		syscall_channel = get_cpu_local_var(cpu)->syscall_channel;
	}
	res = scp->response_va;

	res->status = 0;
	req->valid = 0;

#ifdef USE_DMA
	memcpy_async(scp->request_pa,
	             virt_to_phys(req), sizeof(*req), 0, &fin);

	memcpy_async_wait(&scp->post_fin);
	scp->post_va->v[0] = scp->post_idx;
	memcpy_async_wait(&fin);
#else
	memcpy(scp->request_va, req, sizeof(*req));
#endif

	barrier();
	scp->request_va->valid = 1;
	*(unsigned int *)scp->doorbell_va = cpu + 1;

#ifdef SYSCALL_BY_IKC
	packet.msg = SCD_MSG_SYSCALL_ONESIDE;
	packet.ref = cpu;
	packet.pid = pid ? pid : cpu_local_var(current)->pid;
	packet.arg = scp->request_rpa;	
	dkprintf("send syscall, nr: %d, pid: %d\n", req->number, packet.pid);
	
	ret = ihk_ikc_send(syscall_channel, &packet, 0);
	if (ret < 0) {
		kprintf("ERROR: sending IKC msg, ret: %d\n", ret);
	}
#endif
}

ihk_spinlock_t syscall_lock;

long do_syscall(struct syscall_request *req, ihk_mc_user_context_t *ctx, 
		int cpu, int pid)
{
	struct syscall_response *res;
	struct syscall_request req2 IHK_DMA_ALIGN;
	struct syscall_params *scp;
	int error;
	long rc;
	int islock = 0;
	unsigned long irqstate;

	dkprintf("SC(%d)[%3d] sending syscall\n",
	        ihk_mc_get_processor_id(),
	        req->number);

	if(req->number == __NR_exit_group ||
	   req->number == __NR_kill){ // interrupt syscall
		scp = &get_cpu_local_var(0)->scp2;
		islock = 1;
		irqstate = ihk_mc_spinlock_lock(&syscall_lock);
	}
	else{
		scp = &get_cpu_local_var(cpu)->scp;
	}
	res = scp->response_va;

	send_syscall(req, cpu, pid);

	dkprintf("SC(%d)[%3d] waiting for host.. \n", 
	        ihk_mc_get_processor_id(),
	        req->number);
	
#define	STATUS_IN_PROGRESS	0
#define	STATUS_COMPLETED	1
#define	STATUS_PAGE_FAULT	3
	while (res->status != STATUS_COMPLETED) {
		while (res->status == STATUS_IN_PROGRESS) {
			cpu_pause();
		}
	
		if (res->status == STATUS_PAGE_FAULT) {
			dkprintf("STATUS_PAGE_FAULT in syscall, pid: %d\n", 
					cpu_local_var(current)->pid);		
			error = page_fault_process(get_cpu_local_var(cpu)->current,
					(void *)res->fault_address,
					res->fault_reason|PF_POPULATE);

			/* send result */
			req2.number = __NR_mmap;
#define PAGER_RESUME_PAGE_FAULT	0x0101
			req2.args[0] = PAGER_RESUME_PAGE_FAULT;
			req2.args[1] = error;

			send_syscall(&req2, cpu, pid);
		}
	}

	dkprintf("SC(%d)[%3d] got host reply: %d \n", 
	        ihk_mc_get_processor_id(),
	        req->number, res->ret);

	rc = res->ret;
	if(islock){
		ihk_mc_spinlock_unlock(&syscall_lock, irqstate);
	}

	return rc;
}

long syscall_generic_forwarding(int n, ihk_mc_user_context_t *ctx)
{
	SYSCALL_HEADER;
	dkprintf("syscall_generic_forwarding(%d)\n", n);
	SYSCALL_ARGS_6(D,D,D,D,D,D);
	SYSCALL_FOOTER;
}

#if 0
void sigchld_parent(struct process *parent, int status)
{
	struct process *proc = cpu_local_var(current);
	int irqstate;
	struct sig_pending *pending;
	struct list_head *head;
	__sigset_t mask;

	mask = __sigmask(SIGCHLD);

	head = &parent->sigpending;
	irqstate = ihk_mc_spinlock_lock(&parent->sigpendinglock);

	list_for_each_entry(pending, head, list) {
		if (pending->sigmask.__val[0] == mask)
			break;
	}

	if (&pending->list == head) {
		pending = kmalloc(sizeof(struct sig_pending), IHK_MC_AP_NOWAIT);
		
		if (!pending) {
			/* TODO: what to do here?? */
			panic("ERROR: not enough memory for signaling parent process!");
		}

		pending->sigmask.__val[0] = mask;
		pending->info.si_signo = SIGCHLD;
		pending->info._sifields._sigchld.si_pid = proc->pid;
		pending->info._sifields._sigchld.si_status = status;

		list_add_tail(&pending->list, head);
		proc->sigevent = 1;
	}
	/* TODO: There was a SIGCHLD pending */
	else {

	}

	ihk_mc_spinlock_unlock(&parent->sigpendinglock, irqstate);
}
#endif

/* 
 * From glibc: INLINE_SYSCALL (wait4, 4, pid, stat_loc, options, NULL);
 */
SYSCALL_DECLARE(wait4)
{
	struct process *proc = cpu_local_var(current);
	struct fork_tree_node *child, *child_iter;
	int pid = (int)ihk_mc_syscall_arg0(ctx);
	int *status = (int *)ihk_mc_syscall_arg1(ctx);
	int options = (int)ihk_mc_syscall_arg2(ctx);
	int ret;
	struct waitq_entry waitpid_wqe;
	int empty = 1;

rescan:
	child = NULL;
	pid = (int)ihk_mc_syscall_arg0(ctx);	
	
	ihk_mc_spinlock_lock_noirq(&proc->ftn->lock);
	
	list_for_each_entry(child_iter, &proc->ftn->children, siblings_list) {	
		
		empty = 0;

		ihk_mc_spinlock_lock_noirq(&child_iter->lock);
		
		if (child_iter->status == PS_ZOMBIE
			&& (pid == -1 || pid == child_iter->pid)) {
			child = child_iter;
			ihk_mc_spinlock_unlock_noirq(&child_iter->lock);
			break;
		}
		
		ihk_mc_spinlock_unlock_noirq(&child_iter->lock);
	}

	if (empty) {
		ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);	
		return -ECHILD;
	}

	if (child) {
		struct syscall_request request IHK_DMA_ALIGN;

		dkprintf("wait: found PS_ZOMBIE process: %d\n", child->pid);
		
		list_del(&child->siblings_list);	
		ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);	
		
		if (status) {
			*status = child->exit_status;
		}
		pid = child->pid;
		
		release_fork_tree_node(child);

		/* Ask host to clean up exited child */
		request.number = __NR_wait4;
		request.args[0] = pid;
		request.args[1] = 0;
		ret = do_syscall(&request, ctx, ihk_mc_get_processor_id(), 0);
		
		if (ret != pid)
			kprintf("WARNING: host waitpid failed?\n");
		
		goto exit;
	}
	
	/* Don't sleep if WNOHANG requested */
	if (options & WNOHANG) {
		ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);	

		*status = 0;
		pid = 0;
		goto exit;
	}

	/* Sleep */
	waitq_init_entry(&waitpid_wqe, proc);
	waitq_prepare_to_wait(&proc->ftn->waitpid_q, &waitpid_wqe, PS_INTERRUPTIBLE);

	ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);	

	schedule();
	dkprintf("wait4(): woken up\n");

	waitq_finish_wait(&proc->ftn->waitpid_q, &waitpid_wqe);

	goto rescan;

exit:
	return pid;
}

void
terminate(int rc, int sig, ihk_mc_user_context_t *ctx)
{
	struct syscall_request request IHK_DMA_ALIGN;
	struct process *proc = cpu_local_var(current);
	struct fork_tree_node *ftn = proc->ftn;
	struct fork_tree_node *child, *next;

	request.number = __NR_exit_group;
	request.args[0] = ((rc & 0x00ff) << 8) | (sig & 0x7f);

#ifdef DCFA_KMOD
	do_mod_exit(rc);
#endif

	/* XXX: send SIGKILL to all threads in this process */

	flush_process_memory(proc);	/* temporary hack */
	do_syscall(&request, ctx, ihk_mc_get_processor_id(), 0);

#define	IS_DETACHED_PROCESS(proc)	(1)	/* should be implemented in the future */

	/* Do a "wait" on all children and detach owner process */
	ihk_mc_spinlock_lock_noirq(&ftn->lock);
	list_for_each_entry_safe(child, next, &ftn->children, siblings_list) {
			
		list_del(&child->siblings_list);
		release_fork_tree_node(child);
	}

	ftn->owner = NULL;

	ihk_mc_spinlock_unlock_noirq(&ftn->lock);	

	/* Send SIGCHILD to parent */
	if (ftn->parent) {
		
		ihk_mc_spinlock_lock_noirq(&ftn->lock);
		ftn->pid = proc->pid;
		ftn->exit_status = ((rc & 0x00ff) << 8) | (sig & 0x7f);
		ftn->status = PS_ZOMBIE;
		ihk_mc_spinlock_unlock_noirq(&ftn->lock);	

		/* Signal parent if still attached */
		ihk_mc_spinlock_lock_noirq(&ftn->parent->lock);
		if (ftn->parent->owner) {
			do_kill(ftn->parent->owner->pid, -1, SIGCHLD);
/*
			sigchld_parent(ftn->parent->owner, 0);
*/
		}
		ihk_mc_spinlock_unlock_noirq(&ftn->parent->lock);	
		
		/* Wake parent (if sleeping in wait4()) */
		waitq_wakeup(&ftn->parent->waitpid_q);
		
		release_fork_tree_node(ftn->parent);
	}

	release_fork_tree_node(ftn);
	
	proc->status = PS_EXITED;
	release_process(proc);
	
	schedule();
}

void
interrupt_syscall(int all, int pid)
{
	ihk_mc_user_context_t ctx;
	long lerror;

	ihk_mc_syscall_arg0(&ctx) = all? -1: ihk_mc_get_processor_id();
	ihk_mc_syscall_arg1(&ctx) = 0;
	ihk_mc_syscall_arg2(&ctx) = pid;

	lerror = syscall_generic_forwarding(__NR_kill, &ctx);
	if (lerror) {
		kprintf("clear_host_pte failed. %ld\n", lerror);
	}
	return;
}

SYSCALL_DECLARE(exit_group)
{
#if 0
	SYSCALL_HEADER;
#endif

	terminate((int)ihk_mc_syscall_arg0(ctx), 0, ctx);
#if 0
	struct process *proc = cpu_local_var(current);

#ifdef DCFA_KMOD
	do_mod_exit((int)ihk_mc_syscall_arg0(ctx));
#endif

	/* XXX: send SIGKILL to all threads in this process */

	do_syscall(&request, ctx, ihk_mc_get_processor_id(), 0);

#define	IS_DETACHED_PROCESS(proc)	(1)	/* should be implemented in the future */
	proc->status = PS_ZOMBIE;
	if (IS_DETACHED_PROCESS(proc)) {
		/* release a reference for wait(2) */
		proc->status = PS_EXITED;
		free_process(proc);
	}

	schedule();

#endif

	return 0;
}

static void clear_host_pte(uintptr_t addr, size_t len)
{
	ihk_mc_user_context_t ctx;
	long lerror;

	ihk_mc_syscall_arg0(&ctx) = addr;
	ihk_mc_syscall_arg1(&ctx) = len;
	/* NOTE: 3rd parameter denotes new rpgtable of host process (if not zero) */
	ihk_mc_syscall_arg2(&ctx) = 0;

	lerror = syscall_generic_forwarding(__NR_munmap, &ctx);
	if (lerror) {
		kprintf("clear_host_pte failed. %ld\n", lerror);
	}
	return;
}

static int set_host_vma(uintptr_t addr, size_t len, int prot)
{
	ihk_mc_user_context_t ctx;
	long lerror;

	ihk_mc_syscall_arg0(&ctx) = addr;
	ihk_mc_syscall_arg1(&ctx) = len;
	ihk_mc_syscall_arg2(&ctx) = prot;

	lerror = syscall_generic_forwarding(__NR_mprotect, &ctx);
	if (lerror) {
		kprintf("set_host_vma(%lx,%lx,%x) failed. %ld\n",
				addr, len, prot, lerror);
		goto out;
	}

	lerror = 0;
out:
	return (int)lerror;
}

static int do_munmap(void *addr, size_t len)
{
	int error;
	int ro_freed;

	begin_free_pages_pending();
	error = remove_process_memory_range(cpu_local_var(current),
			(intptr_t)addr, (intptr_t)addr+len, &ro_freed);
	// XXX: TLB flush
	flush_tlb();
	if (error || !ro_freed) {
		clear_host_pte((uintptr_t)addr, len);
	}
	else {
		error = set_host_vma((uintptr_t)addr, len, PROT_READ|PROT_WRITE);
		if (error) {
			kprintf("sys_munmap:set_host_vma failed. %d\n", error);
			/* through */
		}
	}
	finish_free_pages_pending();
	return error;
}

static int search_free_space(size_t len, intptr_t hint, intptr_t *addrp)
{
	struct process *proc = cpu_local_var(current);
	struct vm_regions *region = &proc->vm->region;
	intptr_t addr;
	int error;
	struct vm_range *range;

	dkprintf("search_free_space(%lx,%lx,%p)\n", len, hint, addrp);

	addr = hint;
	for (;;) {
#ifdef USE_LARGE_PAGES
		if (len >= LARGE_PAGE_SIZE) {
			addr = (addr + LARGE_PAGE_SIZE - 1) & LARGE_PAGE_MASK;
		}
#endif /* USE_LARGE_PAGES */

		if ((region->user_end <= addr)
				|| ((region->user_end - len) < addr)) {
			ekprintf("search_free_space(%lx,%lx,%p):"
					"no space. %lx %lx\n",
					len, hint, addrp, addr,
					region->user_end);
			error = -ENOMEM;
			goto out;
		}

		range = lookup_process_memory_range(proc->vm, addr, addr+len);
		if (range == NULL) {
			break;
		}
		addr = range->end;
	}

	error = 0;
	*addrp = addr;

out:
	dkprintf("search_free_space(%lx,%lx,%p): %d %lx\n",
			len, hint, addrp, error, addr);
	return error;
}

SYSCALL_DECLARE(mmap)
{
	const int supported_flags = 0
		| MAP_SHARED		// 01
		| MAP_PRIVATE		// 02
		| MAP_FIXED		// 10
		| MAP_ANONYMOUS		// 20
		| MAP_LOCKED		// 2000
		| MAP_POPULATE		// 8000
		;
	const int ignored_flags = 0
#ifdef	USE_NOCACHE_MMAP
		| MAP_32BIT		// 40
#endif /* USE_NOCACHE_MMAP */
		| MAP_DENYWRITE		// 0800
		| MAP_NORESERVE		// 4000
		| MAP_STACK		// 00020000
		;
	const int error_flags = 0
#ifndef	USE_NOCACHE_MMAP
		| MAP_32BIT		// 40
#endif /* ndef USE_NOCACHE_MMAP */
		| MAP_GROWSDOWN		// 0100
		| MAP_EXECUTABLE	// 1000
		| MAP_NONBLOCK		// 00010000
		| MAP_HUGETLB		// 00040000
		;

	const intptr_t addr0 = ihk_mc_syscall_arg0(ctx);
	const size_t len0 = ihk_mc_syscall_arg1(ctx);
	const int prot = ihk_mc_syscall_arg2(ctx);
	const int flags = ihk_mc_syscall_arg3(ctx);
	const int fd = ihk_mc_syscall_arg4(ctx);
	const off_t off0 = ihk_mc_syscall_arg5(ctx);

	struct process *proc = cpu_local_var(current);
	struct vm_regions *region = &proc->vm->region;
	intptr_t addr;
	size_t len;
	off_t off;
	int error;
	intptr_t npages;
	int p2align;
	void *p = NULL;
	int vrflags;
	intptr_t phys;
	struct memobj *memobj = NULL;
	int maxprot;
	int denied;
	int ro_vma_mapped = 0;
	struct shmid_ds ads;

	dkprintf("[%d]sys_mmap(%lx,%lx,%x,%x,%d,%lx)\n",
			ihk_mc_get_processor_id(),
			addr0, len0, prot, flags, fd, off0);

	/* check constants for flags */
	if (1) {
		int dup_flags;

		dup_flags = (supported_flags & ignored_flags);
		dup_flags |= (ignored_flags & error_flags);
		dup_flags |= (error_flags & supported_flags);

		if (dup_flags) {
			ekprintf("sys_mmap:duplicate flags: %lx\n", dup_flags);
			ekprintf("s-flags: %08x\n", supported_flags);
			ekprintf("i-flags: %08x\n", ignored_flags);
			ekprintf("e-flags: %08x\n", error_flags);
			panic("sys_mmap:duplicate flags\n");
			/* no return */
		}
	}

	/* check arguments */
#define	VALID_DUMMY_ADDR	(region->user_start)
	addr = (flags & MAP_FIXED)? addr0: VALID_DUMMY_ADDR;
	len = (len0 + PAGE_SIZE - 1) & PAGE_MASK;
	if ((addr & (PAGE_SIZE - 1))
			|| (addr < region->user_start)
			|| (region->user_end <= addr)
			|| (len == 0)
			|| (len > (region->user_end - region->user_start))
			|| ((region->user_end - len) < addr)
			|| !(flags & (MAP_SHARED | MAP_PRIVATE))
			|| ((flags & MAP_SHARED) && (flags & MAP_PRIVATE))
			|| (off0 & (PAGE_SIZE - 1))) {
		ekprintf("sys_mmap(%lx,%lx,%x,%x,%x,%lx):EINVAL\n",
				addr0, len0, prot, flags, fd, off0);
		error = -EINVAL;
		goto out2;
	}

	/* check not supported requests */
	if ((flags & error_flags)
			|| (flags & ~(supported_flags | ignored_flags))) {
		ekprintf("sys_mmap(%lx,%lx,%x,%x,%x,%lx):unknown flags %x\n",
				addr0, len0, prot, flags, fd, off0,
				(flags & ~(supported_flags | ignored_flags)));
		error = -EINVAL;
		goto out2;
	}

	ihk_mc_spinlock_lock_noirq(&proc->vm->memory_range_lock);

	if (flags & MAP_FIXED) {
		/* clear specified address range */
		error = do_munmap((void *)addr, len);
		if (error) {
			ekprintf("sys_mmap:do_munmap(%lx,%lx) failed. %d\n",
					addr, len, error);
			goto out;
		}
	}
	else {
		/* choose mapping address */
		error = search_free_space(len, region->map_end, &addr);
		if (error) {
			ekprintf("sys_mmap:search_free_space(%lx,%lx) failed. %d\n",
					len, region->map_end, error);
			goto out;
		}
		region->map_end = addr + len;
	}

	/* do the map */
	vrflags = VR_NONE;
	vrflags |= PROT_TO_VR_FLAG(prot);
	vrflags |= (flags & MAP_PRIVATE)? VR_PRIVATE: 0;
	vrflags |= (flags & MAP_LOCKED)? VR_LOCKED: 0;
	if (flags & MAP_ANONYMOUS) {
		if (0) {
			/* dummy */
		}
#ifdef	USE_NOCACHE_MMAP
#define	X_MAP_NOCACHE	MAP_32BIT
		else if (flags & X_MAP_NOCACHE) {
			vrflags |= VR_IO_NOCACHE;
		}
#endif
		else {
			vrflags |= VR_DEMAND_PAGING;
		}
	}
	else {
		vrflags |= VR_DEMAND_PAGING;
	}

	if (!(prot & PROT_WRITE)) {
		error = set_host_vma(addr, len, PROT_READ);
		if (error) {
			kprintf("sys_mmap:set_host_vma failed. %d\n", error);
			goto out;
		}

		ro_vma_mapped = 1;
	}

	phys = 0;
	off = 0;
	maxprot = PROT_READ | PROT_WRITE | PROT_EXEC;
	if (!(flags & MAP_ANONYMOUS)) {
		off = off0;
		error = fileobj_create(fd, &memobj, &maxprot);
		if (error) {
			ekprintf("sys_mmap:fileobj_create failed. %d\n", error);
			goto out;
		}
	}
	else if (!(vrflags & VR_DEMAND_PAGING)
			&& ((vrflags & VR_PROT_MASK) != VR_PROT_NONE)) {
		npages = len >> PAGE_SHIFT;
		p2align = PAGE_P2ALIGN;
#ifdef USE_LARGE_PAGES
		if ((len >= LARGE_PAGE_SIZE)
				&& ((addr & (LARGE_PAGE_SIZE - 1)) == 0)) {
			p2align = LARGE_PAGE_P2ALIGN;
		}
#endif /* USE_LARGE_PAGES */
		p = ihk_mc_alloc_aligned_pages(npages, p2align, IHK_MC_AP_NOWAIT);
		if (p == NULL) {
			ekprintf("sys_mmap:allocate_pages(%d,%d) failed.\n",
					npages, p2align);
			error = -ENOMEM;
			goto out;
		}
		phys = virt_to_phys(p);
	}
	else if (flags & MAP_SHARED) {
		memset(&ads, 0, sizeof(ads));
		ads.shm_segsz = len;
		error = shmobj_create(&ads, &memobj);
		if (error) {
			ekprintf("sys_mmap:shmobj_create failed. %d\n", error);
			goto out;
		}
	}
	else {
		error = zeroobj_create(&memobj);
		if (error) {
			ekprintf("sys_mmap:zeroobj_create failed. %d\n", error);
			goto out;
		}
	}

	if ((flags & MAP_PRIVATE) && (maxprot & PROT_READ)) {
		maxprot |= PROT_WRITE;
	}
	denied = prot & ~maxprot;
	if (denied) {
		ekprintf("sys_mmap:denied %x. %x %x\n", denied, prot, maxprot);
		error = (denied == PROT_EXEC)? -EPERM: -EACCES;
		goto out;
	}
	vrflags |= VRFLAG_PROT_TO_MAXPROT(PROT_TO_VR_FLAG(maxprot));

	error = add_process_memory_range(proc, addr, addr+len, phys, vrflags, memobj, off);
	if (error) {
		ekprintf("sys_mmap:add_process_memory_range"
				"(%p,%lx,%lx,%lx,%lx) failed %d\n",
				proc, addr, addr+len,
				virt_to_phys(p), vrflags, error);
		goto out;
	}

	error = 0;
	p = NULL;
	memobj = NULL;
	ro_vma_mapped = 0;

out:
	if (ro_vma_mapped) {
		(void)set_host_vma(addr, len, PROT_READ|PROT_WRITE);
	}
	ihk_mc_spinlock_unlock_noirq(&proc->vm->memory_range_lock);

	if (!error && (flags & (MAP_POPULATE | MAP_LOCKED))) {
		error = populate_process_memory(proc, (void *)addr, len);
		if (error) {
			ekprintf("sys_mmap:populate_process_memory"
					"(%p,%p,%lx) failed %d\n",
					proc, (void *)addr, len, error);
			/*
			 * In this case,
			 * the mapping established by this call should be unmapped
			 * before mmap() returns with error.
			 *
			 * However, the mapping cannot be unmaped simply,
			 * because the mapping can be modified by other thread
			 * because memory_range_lock has been released.
			 *
			 * For the moment, like a linux-2.6.38-8,
			 * the physical page allocation failure is ignored.
			 */
			error = 0;
		}
	}

out2:
	if (p) {
		ihk_mc_free_pages(p, npages);
	}
	if (memobj) {
		memobj_release(memobj);
	}
	dkprintf("[%d]sys_mmap(%lx,%lx,%x,%x,%d,%lx): %ld %lx\n",
			ihk_mc_get_processor_id(),
			addr0, len0, prot, flags, fd, off0, error, addr);
	return (!error)? addr: error;
}

SYSCALL_DECLARE(munmap)
{
	const uintptr_t addr = ihk_mc_syscall_arg0(ctx);
	const size_t len0 = ihk_mc_syscall_arg1(ctx);
	struct process *proc = cpu_local_var(current);
	struct vm_regions *region = &proc->vm->region;
	size_t len;
	int error;

	dkprintf("[%d]sys_munmap(%lx,%lx)\n",
			ihk_mc_get_processor_id(), addr, len0);

	len = (len0 + PAGE_SIZE - 1) & PAGE_MASK;
	if ((addr & (PAGE_SIZE - 1))
			|| (addr < region->user_start)
			|| (region->user_end <= addr)
			|| (len == 0)
			|| (len > (region->user_end - region->user_start))
			|| ((region->user_end - len) < addr)) {
		error = -EINVAL;
		goto out;
	}

	ihk_mc_spinlock_lock_noirq(&proc->vm->memory_range_lock);
	error = do_munmap((void *)addr, len);
	ihk_mc_spinlock_unlock_noirq(&proc->vm->memory_range_lock);

out:
	dkprintf("[%d]sys_munmap(%lx,%lx): %d\n",
			ihk_mc_get_processor_id(), addr, len0, error);
	return error;
}

SYSCALL_DECLARE(mprotect)
{
	const intptr_t start = ihk_mc_syscall_arg0(ctx);
	const size_t len0 = ihk_mc_syscall_arg1(ctx);
	const int prot = ihk_mc_syscall_arg2(ctx);
	struct process *proc = cpu_local_var(current);
	struct vm_regions *region = &proc->vm->region;
	size_t len;
	intptr_t end;
	struct vm_range *first;
	intptr_t addr;
	struct vm_range *range;
	int error;
	struct vm_range *changed;
	const unsigned long protflags = PROT_TO_VR_FLAG(prot);
	unsigned long denied;
	int ro_changed = 0;

	dkprintf("[%d]sys_mprotect(%lx,%lx,%x)\n",
			ihk_mc_get_processor_id(), start, len0, prot);

	len = (len0 + PAGE_SIZE - 1) & PAGE_MASK;
	end = start + len;

	/* check arguments */
	if ((start & (PAGE_SIZE - 1))
			|| (start < region->user_start)
			|| (region->user_end <= start)
			|| (len > (region->user_end - region->user_start)
			|| ((region->user_end - len) < start))) {
		ekprintf("[%d]sys_mprotect(%lx,%lx,%x): -EINVAL\n",
				ihk_mc_get_processor_id(), start, len0, prot);
		return -EINVAL;
	}

	if (len == 0) {
		/* nothing to do */
		return 0;
	}

	ihk_mc_spinlock_lock_noirq(&proc->vm->memory_range_lock);

#if 0
	/* check contiguous map */
	first = NULL;
	for (addr = start; addr < end; addr = range->end) {
		if (first == NULL) {
			range = lookup_process_memory_range(proc->vm, start, start+PAGE_SIZE);
			first = range;
		}
		else {
			range = next_process_memory_range(proc->vm, range);
		}

		if ((range == NULL) || (addr < range->start)) {
			/* not contiguous */
			ekprintf("sys_mprotect(%lx,%lx,%x):not contiguous\n",
					start, len0, prot);
			error = -ENOMEM;
			goto out;
		}

		if (range->flag & (VR_REMOTE | VR_RESERVED | VR_IO_NOCACHE)) {
			ekprintf("sys_mprotect(%lx,%lx,%x):cannot change\n",
					start, len0, prot);
			error = -EINVAL;
			goto out;
		}
	}
#else
	first = lookup_process_memory_range(proc->vm, start, start+PAGE_SIZE);
#endif

	/* do the mprotect */
	changed = NULL;
	for (addr = start; addr < end; addr = changed->end) {
		if (changed == NULL) {
			range = first;
		}
		else {
			range = next_process_memory_range(proc->vm, changed);
		}

		if ((range == NULL) || (addr < range->start)) {
			/* not contiguous */
			ekprintf("sys_mprotect(%lx,%lx,%x):not contiguous\n",
					start, len0, prot);
			error = -ENOMEM;
			goto out;
		}

		denied = protflags & ~VRFLAG_MAXPROT_TO_PROT(range->flag);
		if (denied) {
			ekprintf("sys_mprotect(%lx,%lx,%x):denied %lx. %lx %lx\n",
					start, len0, prot, denied, protflags, range->flag);
			error = -EACCES;
			goto out;
		}

		if (range->flag & (VR_REMOTE | VR_RESERVED | VR_IO_NOCACHE)) {
			ekprintf("sys_mprotect(%lx,%lx,%x):cannot change\n",
					start, len0, prot);
			error = -ENOMEM;
			goto out;
		}

		if (range->start < addr) {
			error = split_process_memory_range(proc, range, addr, &range);
			if (error) {
				ekprintf("sys_mprotect(%lx,%lx,%x):split failed. %d\n",
						start, len0, prot, error);
				goto out;
			}
		}
		if (end < range->end) {
			error = split_process_memory_range(proc, range, end, NULL);
			if (error) {
				ekprintf("sys_mprotect(%lx,%lx,%x):split failed. %d\n",
						start, len0, prot, error);
				goto out;
			}
		}

		if ((range->flag ^ protflags) & VR_PROT_WRITE) {
			ro_changed = 1;
		}

		error = change_prot_process_memory_range(proc, range, protflags);
		if (error) {
			ekprintf("sys_mprotect(%lx,%lx,%x):change failed. %d\n",
					start, len0, prot, error);
			goto out;
		}

		if (changed == NULL) {
			changed = range;
		}
		else {
			error = join_process_memory_range(proc, changed, range);
			if (error) {
				ekprintf("sys_mprotect(%lx,%lx,%x):join failed. %d\n",
						start, len0, prot, error);
				changed = range;
				/* through */
			}
		}
	}

	error = 0;
out:
	// XXX: TLB flush
	flush_tlb();
	if (ro_changed && !error) {
		error = set_host_vma(start, len, prot & (PROT_READ|PROT_WRITE));
		if (error) {
			kprintf("sys_mprotect:set_host_vma failed. %d\n", error);
			/* through */
		}
	}
	ihk_mc_spinlock_unlock_noirq(&proc->vm->memory_range_lock);
	dkprintf("[%d]sys_mprotect(%lx,%lx,%x): %d\n",
			ihk_mc_get_processor_id(), start, len0, prot, error);
	return error;
}

SYSCALL_DECLARE(brk)
{
	unsigned long address = ihk_mc_syscall_arg0(ctx);
	struct vm_regions *region = &cpu_local_var(current)->vm->region;
	unsigned long r;
	unsigned long vrflag;

	dkprintf("SC(%d)[sys_brk] brk_start=%lx,end=%lx\n",
			ihk_mc_get_processor_id(), region->brk_start, region->brk_end);

	/* brk change fail, including glibc trick brk(0) to obtain current brk */
	if(address < region->brk_start) {
		r = region->brk_end;
		goto out;
	}

	/* brk change fail, because we don't shrink memory region  */
	if(address < region->brk_end) {
		r = region->brk_end;
		goto out;
	}

	/* try to extend memory region */
	vrflag = VR_PROT_READ | VR_PROT_WRITE;
	vrflag |= VRFLAG_PROT_TO_MAXPROT(vrflag);
	ihk_mc_spinlock_lock_noirq(&cpu_local_var(current)->vm->memory_range_lock);
	region->brk_end = extend_process_region(cpu_local_var(current),
			region->brk_start, region->brk_end, address, vrflag);
	ihk_mc_spinlock_unlock_noirq(&cpu_local_var(current)->vm->memory_range_lock);
	dkprintf("SC(%d)[sys_brk] brk_end set to %lx\n",
			ihk_mc_get_processor_id(), region->brk_end);

	r = region->brk_end;

out:
	return r;
}

SYSCALL_DECLARE(getpid)
{
	return cpu_local_var(current)->pid;
}

SYSCALL_DECLARE(gettid)
{
	return cpu_local_var(current)->tid;
}

long do_arch_prctl(unsigned long code, unsigned long address)
{
	int err = 0;
	enum ihk_asr_type type;

	switch (code) {
		case ARCH_SET_FS:
		case ARCH_GET_FS:
			type = IHK_ASR_X86_FS;
			break;
		case ARCH_GET_GS:
			type = IHK_ASR_X86_GS;
			break;
		case ARCH_SET_GS:
			return -ENOTSUPP;
		default:
			return -EINVAL;
	}

	switch (code) {
		case ARCH_SET_FS:
			dkprintf("[%d] arch_prctl: ARCH_SET_FS: 0x%lX\n",
			        ihk_mc_get_processor_id(), address);
			cpu_local_var(current)->thread.tlsblock_base = address;
			err = ihk_mc_arch_set_special_register(type, address);
			break;
		case ARCH_SET_GS:
			err = ihk_mc_arch_set_special_register(type, address);
			break;
		case ARCH_GET_FS:
		case ARCH_GET_GS:
			err = ihk_mc_arch_get_special_register(type,
												   (unsigned long*)address);
			break;
		default:
			break;
	}

	return err;
}


SYSCALL_DECLARE(arch_prctl)
{
	return do_arch_prctl(ihk_mc_syscall_arg0(ctx), 
	                     ihk_mc_syscall_arg1(ctx));
}

SYSCALL_DECLARE(execve)
{
	long ret;
	const char *filename = (const char *)ihk_mc_syscall_arg0(ctx);
	char **argv = (char **)ihk_mc_syscall_arg1(ctx);
	char **envp = (char **)ihk_mc_syscall_arg2(ctx);

	char *argv_flat = NULL;
	int argv_flat_len = 0;
	char *envp_flat = NULL;
	int envp_flat_len = 0;
	
	struct syscall_request request IHK_DMA_ALIGN;
	struct program_load_desc *desc;

	desc = ihk_mc_alloc_pages(1, IHK_MC_AP_NOWAIT);
	if (!desc) {
		kprintf("execve(): ERROR: allocating program descriptor\n");
		return -ENOMEM;
	}

	memset((void*)desc, 0, PAGE_SIZE);

	/* Request host to open executable and load ELF section descriptions */
	request.number = __NR_execve;  
	request.args[0] = 1;  /* 1st phase - get ELF desc */
	request.args[1] = (unsigned long)filename;	
	request.args[2] = virt_to_phys(desc);
	ret = do_syscall(&request, ctx, ihk_mc_get_processor_id(), 0);

	if (ret != 0) {
		kprintf("execve(): ERROR: host failed to load elf header\n");
		return -EINVAL;
	}

	dkprintf("execve(): ELF desc received, num sections: %d\n",
		desc->num_sections);

	/* Flatten argv and envp into kernel-space buffers */
	argv_flat_len = flatten_strings(-1, argv, &argv_flat);
	if (argv_flat_len == 0) {
		kprintf("ERROR: no argv for executable: %s?\n", filename);
		return -EINVAL;
	}

	envp_flat_len = flatten_strings(-1, envp, &envp_flat);
	if (envp_flat_len == 0) {
		kprintf("ERROR: no envp for executable: %s?\n", filename);
		return -EINVAL;
	}

	/* Unmap all memory areas of the process, userspace will be gone */
	free_process_memory_ranges(cpu_local_var(current));

	ihk_mc_init_user_process(&cpu_local_var(current)->ctx, 
			&cpu_local_var(current)->uctx,
			((char *)cpu_local_var(current)) + 
			KERNEL_STACK_NR_PAGES * PAGE_SIZE, desc->entry, 0);

	/* Create virtual memory ranges and update args/envs */
	if (prepare_process_ranges_args_envs(cpu_local_var(current), desc, desc, 
				PTATTR_NO_EXECUTE | PTATTR_WRITABLE | PTATTR_FOR_USER,
				argv_flat, argv_flat_len, envp_flat, envp_flat_len) != 0) {
		kprintf("execve(): PANIC: preparing ranges, args, envs, stack\n");
		panic("");
	}
	
	/* Clear host user space PTEs */
	request.number = __NR_munmap;
	request.args[0] = cpu_local_var(current)->vm->region.user_start;
	request.args[1] = cpu_local_var(current)->vm->region.user_end - 
		cpu_local_var(current)->vm->region.user_start;
	dkprintf("execve(): requesting host PTE clear\n");

	if (do_syscall(&request, ctx, ihk_mc_get_processor_id(), 0)) {
		kprintf("execve(): ERROR: clearing PTEs in host process\n");
		panic("");
	}		

	/* Request host to transfer ELF image */
	request.number = __NR_execve;  
	request.args[0] = 2;  /* 2nd phase - transfer ELF image */
	request.args[1] = virt_to_phys(desc);
	request.args[2] = sizeof(struct program_load_desc) + 
		sizeof(struct program_image_section) * desc->num_sections;

	ret = do_syscall(&request, ctx, ihk_mc_get_processor_id(), 0);

	if (ret != 0) {
		kprintf("execve(): PANIC: host failed to load elf image\n");
		panic("");
	}

	/* Switch to new execution context */
	dkprintf("execve(): switching to new process\n");
	
	ihk_mc_switch_context(NULL, &cpu_local_var(current)->ctx, 
		cpu_local_var(current));

	/* Never reach here */
	return 0;
}

SYSCALL_DECLARE(clone)
{
	int cpuid;
	int clone_flags = ihk_mc_syscall_arg0(ctx);
	struct process *new;
	ihk_mc_user_context_t ctx1;
	struct syscall_request request1 IHK_DMA_ALIGN;

	dkprintf("clone(): stack_pointr passed in: 0x%lX, stack pointer of caller: 0x%lx\n",
			 (unsigned long)ihk_mc_syscall_arg1(ctx),
			 (unsigned long)ihk_mc_syscall_sp(ctx));

	cpuid = obtain_clone_cpuid();

	new = clone_process(cpu_local_var(current), ihk_mc_syscall_pc(ctx),
	                    ihk_mc_syscall_arg1(ctx) ? ihk_mc_syscall_arg1(ctx) :
						ihk_mc_syscall_sp(ctx), 
						clone_flags);
	
	if (!new) {
		return -ENOMEM;
	}

	cpu_set(cpuid, &new->vm->cpu_set, &new->vm->cpu_set_lock);

	if (clone_flags & CLONE_VM) {
		new->pid = cpu_local_var(current)->pid;
		
		request1.number = __NR_gettid;
		new->tid = do_syscall(&request1, &ctx1, cpuid, new->pid);
	}
	/* fork() a new process on the host */
	else {
		request1.number = __NR_fork;
		new->pid = do_syscall(&request1, &ctx1, ihk_mc_get_processor_id(), 0);
		
		if (new->pid == -1) {
			kprintf("ERROR: forking host process\n");
			
			/* TODO: clean-up new */
			return -EFAULT;
		}

		/* In a single threaded process TID equals to PID */
		new->tid = new->pid;

		dkprintf("fork(): new pid: %d\n", new->pid);
		/* clear user space PTEs and set new rpgtable so that consequent 
		 * page faults will look up the right mappings */
		request1.number = __NR_munmap;
		request1.args[0] = new->vm->region.user_start;
		request1.args[1] = new->vm->region.user_end - 
			new->vm->region.user_start;
		/* 3rd parameter denotes new rpgtable of host process */
		request1.args[2] = virt_to_phys(new->vm->page_table);
		request1.args[3] = new->pid;

		dkprintf("fork(): requesting PTE clear and rpgtable (0x%lx) update\n",
				request1.args[2]);

		if (do_syscall(&request1, &ctx1, ihk_mc_get_processor_id(), new->pid)) {
			kprintf("ERROR: clearing PTEs in host process\n");
		}		
	}

	new->ftn->pid = new->pid;
	
	if (clone_flags & CLONE_PARENT_SETTID) {
		dkprintf("clone_flags & CLONE_PARENT_SETTID: 0x%lX\n",
		         (unsigned long)ihk_mc_syscall_arg2(ctx));
		
		*(int*)ihk_mc_syscall_arg2(ctx) = new->pid;
	}
	
	if (clone_flags & CLONE_CHILD_CLEARTID) {
		dkprintf("clone_flags & CLONE_CHILD_CLEARTID: 0x%lX\n", 
			     (unsigned long)ihk_mc_syscall_arg3(ctx));

		new->thread.clear_child_tid = (int*)ihk_mc_syscall_arg3(ctx);
	}
	
	if (clone_flags & CLONE_CHILD_SETTID) {
		unsigned long phys;
		dkprintf("clone_flags & CLONE_CHILD_SETTID: 0x%lX\n",
				(unsigned long)ihk_mc_syscall_arg3(ctx));

		if (ihk_mc_pt_virt_to_phys(new->vm->page_table, 
					(void *)ihk_mc_syscall_arg3(ctx), &phys)) { 
			kprintf("ERROR: looking up physical addr for child process\n");
			return -EFAULT; 
		}
	
		*((int*)phys_to_virt(phys)) = new->tid;
	}
	
	if (clone_flags & CLONE_SETTLS) {
		dkprintf("clone_flags & CLONE_SETTLS: 0x%lX\n", 
			     (unsigned long)ihk_mc_syscall_arg4(ctx));
		
		new->thread.tlsblock_base = 
			(unsigned long)ihk_mc_syscall_arg4(ctx);
	}
	else { 
		new->thread.tlsblock_base = 
			cpu_local_var(current)->thread.tlsblock_base;
	}

	ihk_mc_syscall_ret(new->uctx) = 0;

	dkprintf("clone: kicking scheduler!,cpuid=%d pid=%d tid=%d\n", cpuid, new->pid, new->tid);
	runq_add_proc(new, cpuid);

	return new->tid;
}

SYSCALL_DECLARE(set_tid_address)
{
	cpu_local_var(current)->thread.clear_child_tid = 
	                        (int*)ihk_mc_syscall_arg0(ctx);

	return cpu_local_var(current)->pid;
}

SYSCALL_DECLARE(kill)
{
	int pid = ihk_mc_syscall_arg0(ctx);
	int sig = ihk_mc_syscall_arg1(ctx);

	return do_kill(pid, -1, sig);
}

// see linux-2.6.34.13/kernel/signal.c
SYSCALL_DECLARE(tgkill)
{
	int tgid = ihk_mc_syscall_arg0(ctx);
	int pid = ihk_mc_syscall_arg1(ctx);
	int sig = ihk_mc_syscall_arg2(ctx);

	return do_kill(tgid, pid, sig);
}

SYSCALL_DECLARE(set_robust_list)
{
	return -ENOSYS;
}

int
do_sigaction(int sig, struct k_sigaction *act, struct k_sigaction *oact)
{
	struct process *proc = cpu_local_var(current);
	struct k_sigaction *k;
	int	irqstate;

	irqstate = ihk_mc_spinlock_lock(&proc->sighandler->lock);
	k = proc->sighandler->action + sig - 1;
	if(oact)
		memcpy(oact, k, sizeof(struct k_sigaction));
	if(act)
		memcpy(k, act, sizeof(struct k_sigaction));
	ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);
	return 0;
}

SYSCALL_DECLARE(rt_sigprocmask)
{
	int how = ihk_mc_syscall_arg0(ctx);
	const sigset_t *set = (const sigset_t *)ihk_mc_syscall_arg1(ctx);
	sigset_t *oldset = (sigset_t *)ihk_mc_syscall_arg2(ctx);
	size_t sigsetsize = (size_t)ihk_mc_syscall_arg3(ctx);
	struct process *proc = cpu_local_var(current);
	int flag;
	__sigset_t wsig;

	if(sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if(set &&
	   how != SIG_BLOCK &&
	   how != SIG_UNBLOCK &&
	   how != SIG_SETMASK)
		return -EINVAL;

	flag = ihk_mc_spinlock_lock(&proc->sighandler->lock);
	if(oldset){
		wsig = proc->sigmask.__val[0];
		if(copy_to_user(proc, oldset->__val, &wsig, sizeof wsig))
			goto fault;
	}
	if(set){
		if(copy_from_user(proc, &wsig, set->__val, sizeof wsig))
			goto fault;
		switch(how){
		    case SIG_BLOCK:
			proc->sigmask.__val[0] |= wsig;
			break;
		    case SIG_UNBLOCK:
			proc->sigmask.__val[0] &= ~wsig;
			break;
		    case SIG_SETMASK:
			proc->sigmask.__val[0] = wsig;
			break;
		}
	}
	ihk_mc_spinlock_unlock(&proc->sighandler->lock, flag);
	return 0;
fault:
	ihk_mc_spinlock_unlock(&proc->sighandler->lock, flag);
	return -EFAULT;
}

SYSCALL_DECLARE(rt_sigpending)
{
	int flag;
	struct sig_pending *pending;
	struct list_head *head;
	ihk_spinlock_t *lock;
	__sigset_t w = 0;
	struct process *proc = cpu_local_var(current);
	sigset_t *set = (sigset_t *)ihk_mc_syscall_arg0(ctx);
	size_t sigsetsize = (size_t)ihk_mc_syscall_arg1(ctx);

	if (sigsetsize > sizeof(sigset_t))
		return -EINVAL;

	lock = &proc->sigshared->lock;
	head = &proc->sigshared->sigpending;
	flag = ihk_mc_spinlock_lock(lock);
	list_for_each_entry(pending, head, list){
		w |= pending->sigmask.__val[0];
	}
	ihk_mc_spinlock_unlock(lock, flag);

	lock = &proc->sigpendinglock;
	head = &proc->sigpending;
	flag = ihk_mc_spinlock_lock(lock);
	list_for_each_entry(pending, head, list){
		w |= pending->sigmask.__val[0];
	}
	ihk_mc_spinlock_unlock(lock, flag);

	if(copy_to_user(proc, set->__val, &w, sizeof w))
		return -EFAULT;

	return 0;
}

SYSCALL_DECLARE(rt_sigtimedwait)
{
	struct process *proc = cpu_local_var(current);
	const sigset_t *set = (const sigset_t *)ihk_mc_syscall_arg0(ctx);
	siginfo_t *info = (siginfo_t *)ihk_mc_syscall_arg1(ctx);
	void *timeout = (void *)ihk_mc_syscall_arg2(ctx);
	size_t sigsetsize = (size_t)ihk_mc_syscall_arg3(ctx);
	siginfo_t winfo;
	__sigset_t wset;
	long wtimeout[2];

	if (sigsetsize > sizeof(sigset_t))
		return -EINVAL;

	memset(&winfo, '\0', sizeof winfo);
	if(copy_from_user(proc, &wset, set, sizeof wset))
		return -EFAULT;
	if(copy_from_user(proc, wtimeout, timeout, sizeof wtimeout))
		return -EFAULT;
	if(copy_to_user(proc, info, &winfo, sizeof winfo))
		return -EFAULT;

	return -EOPNOTSUPP;
}

SYSCALL_DECLARE(rt_sigqueueinfo)
{
	struct process *proc = cpu_local_var(current);
	int pid = (int)ihk_mc_syscall_arg0(ctx);
	int sig = (int)ihk_mc_syscall_arg1(ctx);
	siginfo_t *info = (siginfo_t *)ihk_mc_syscall_arg2(ctx);
	siginfo_t winfo;

	if(copy_from_user(proc, &winfo, info, sizeof winfo))
		return -EFAULT;

	return -EOPNOTSUPP;
}

static int
do_sigsuspend(struct process *proc, const sigset_t *set)
{
	__sigset_t wset;
	int flag;
	struct sig_pending *pending;
	struct list_head *head;
	ihk_spinlock_t *lock;

	wset = set->__val[0];
	wset &= ~__sigmask(SIGKILL);
	wset &= ~__sigmask(SIGTERM);
	proc->sigmask.__val[0] = wset;

	for(;;){
		while(proc->sigevent == 0);
		proc->sigevent = 0;

		lock = &proc->sigshared->lock;
		head = &proc->sigshared->sigpending;
		flag = ihk_mc_spinlock_lock(lock);
		list_for_each_entry(pending, head, list){
			if(!(pending->sigmask.__val[0] & wset))
				break;
		}

		if(&pending->list == head){
			ihk_mc_spinlock_unlock(lock, flag);

			lock = &proc->sigpendinglock;
			head = &proc->sigpending;
			flag = ihk_mc_spinlock_lock(lock);
			list_for_each_entry(pending, head, list){
				if(!(pending->sigmask.__val[0] & wset))
					break;
			}
		}
		if(&pending->list == head){
			ihk_mc_spinlock_unlock(lock, flag);
			continue;
		}

		list_del(&pending->list);
		ihk_mc_spinlock_unlock(lock, flag);
		do_signal(-EINTR, NULL, proc, pending);
		break;
	}
	return -EINTR;
}


SYSCALL_DECLARE(pause)
{
	struct process *proc = cpu_local_var(current);

	return do_sigsuspend(proc, &proc->sigmask);
}

SYSCALL_DECLARE(rt_sigsuspend)
{
	struct process *proc = cpu_local_var(current);
	const sigset_t *set = (const sigset_t *)ihk_mc_syscall_arg0(ctx);
	size_t sigsetsize = (size_t)ihk_mc_syscall_arg1(ctx);
	sigset_t wset;

	if (sigsetsize > sizeof(sigset_t))
		return -EINVAL;
	if(copy_from_user(proc, &wset, set, sizeof wset))
		return -EFAULT;

	return do_sigsuspend(proc, &wset);
}

SYSCALL_DECLARE(sigaltstack)
{
	struct process *proc = cpu_local_var(current);
	const stack_t *ss = (const stack_t *)ihk_mc_syscall_arg0(ctx);
	stack_t *oss = (stack_t *)ihk_mc_syscall_arg1(ctx);
	stack_t	wss;

	if(oss)
		if(copy_to_user(proc, oss, &proc->sigstack, sizeof wss))
			return -EFAULT;
	if(ss){
		if(copy_from_user(proc, &wss, ss, sizeof wss))
			return -EFAULT;
		if(wss.ss_flags != 0 && wss.ss_flags != SS_DISABLE)
			return -EINVAL;
		if(wss.ss_flags == SS_DISABLE){
			proc->sigstack.ss_sp = NULL;
			proc->sigstack.ss_flags = SS_DISABLE;
			proc->sigstack.ss_size = 0;
		}
		else{
			if(wss.ss_size < MINSIGSTKSZ)
				return -ENOMEM;

			memcpy(&proc->sigstack, &wss, sizeof wss);
		}
	}

	return 0;
}

SYSCALL_DECLARE(madvise)
{
	const uintptr_t start = (uintptr_t)ihk_mc_syscall_arg0(ctx);
	const size_t len0 = (size_t)ihk_mc_syscall_arg1(ctx);
	const int advice = (int)ihk_mc_syscall_arg2(ctx);
	size_t len;
	uintptr_t end;
	struct process *proc = cpu_local_var(current);
	struct vm_regions *region = &proc->vm->region;
	struct vm_range *first;
	uintptr_t addr;
	struct vm_range *range;
	int error;

	dkprintf("[%d]sys_madvise(%lx,%lx,%x)\n",
			ihk_mc_get_processor_id(), start, len0, advice);

	len = (len0 + PAGE_SIZE - 1) & PAGE_MASK;
	end = start + len;

	if ((start & (PAGE_SIZE - 1))
			|| (len < len0)
			|| (end < start)) {
		error = -EINVAL;
		goto out2;
	}

	if ((start < region->user_start)
			|| (region->user_end <= start)
			|| (len > (region->user_end - region->user_start))
			|| ((region->user_end - len) < start)) {
		error = -ENOMEM;
		goto out2;
	}

	error = 0;
	switch (advice) {
	default:
	case MADV_MERGEABLE:
	case MADV_UNMERGEABLE:
	case MADV_HUGEPAGE:
	case MADV_NOHUGEPAGE:
	case MADV_DONTDUMP:
	case MADV_DODUMP:
		error = -EINVAL;
		break;

	case MADV_NORMAL:
	case MADV_RANDOM:
	case MADV_SEQUENTIAL:
	case MADV_WILLNEED:
	case MADV_DONTNEED:
	case MADV_DONTFORK:
	case MADV_DOFORK:
		break;

	case MADV_REMOVE:
		error = -EACCES;
		break;

	case MADV_HWPOISON:
	case MADV_SOFT_OFFLINE:
		error = -EPERM;
		break;

	}
	if (error) {
		goto out2;
	}

	if (start == end) {
		error = 0;
		goto out2;
	}

	ihk_mc_spinlock_lock_noirq(&proc->vm->memory_range_lock);
	/* check contiguous map */
	first = NULL;
	for (addr = start; addr < end; addr = range->end) {
		if (first == NULL) {
			range = lookup_process_memory_range(proc->vm, start, start+PAGE_SIZE);
			first = range;
		}
		else {
			range = next_process_memory_range(proc->vm, range);
		}

		if ((range == NULL) || (addr < range->start)) {
			/* not contiguous */
			dkprintf("[%d]sys_madvise(%lx,%lx,%x):not contig "
					"%lx [%lx-%lx)\n",
					ihk_mc_get_processor_id(), start,
					len0, advice, addr, range?range->start:0,
					range?range->end:0);
			error = -ENOMEM;
			goto out;
		}

		if (!range->memobj || !memobj_has_pager(range->memobj)) {
			dkprintf("[%d]sys_madvise(%lx,%lx,%x):has not pager"
					"[%lx-%lx) %lx\n",
					ihk_mc_get_processor_id(), start,
					len0, advice, range->start,
					range->end, range->memobj);
			error = -EBADF;
			goto out;
		}

		if ((advice == MADV_DONTNEED)
				&& (range->flag & VR_LOCKED)) {
			dkprintf("[%d]sys_madvise(%lx,%lx,%x):locked"
					"[%lx-%lx) %lx\n",
					ihk_mc_get_processor_id(), start,
					len0, advice, range->start,
					range->end, range->flag);
			error = -EINVAL;
			goto out;
		}
	}

	error = 0;
out:
	ihk_mc_spinlock_unlock_noirq(&proc->vm->memory_range_lock);

out2:
	dkprintf("[%d]sys_madvise(%lx,%lx,%x): %d\n",
			ihk_mc_get_processor_id(), start, len0, advice, error);
	return error;
}

SYSCALL_DECLARE(futex)
{
	uint64_t timeout = 0; // No timeout
	uint32_t val2 = 0;

	uint32_t *uaddr = (uint32_t *)ihk_mc_syscall_arg0(ctx);
	int op = (int)ihk_mc_syscall_arg1(ctx);
	uint32_t val = (uint32_t)ihk_mc_syscall_arg2(ctx);
	struct timespec *utime = (struct timespec*)ihk_mc_syscall_arg3(ctx);
	uint32_t *uaddr2 = (uint32_t *)ihk_mc_syscall_arg4(ctx);
	uint32_t val3 = (uint32_t)ihk_mc_syscall_arg5(ctx);
    
	/* Mask off the FUTEX_PRIVATE_FLAG,
	 * assume all futexes are address space private */
	op = (op & FUTEX_CMD_MASK);
	
	dkprintf("futex op=[%x, %s],uaddr=%lx, val=%x, utime=%lx, uaddr2=%lx, val3=%x, []=%x\n", 
	op,
	(op == FUTEX_WAIT) ? "FUTEX_WAIT" :
	(op == FUTEX_WAIT_BITSET) ? "FUTEX_WAIT_BITSET" :
	(op == FUTEX_WAKE) ? "FUTEX_WAKE" :
	(op == FUTEX_WAKE_OP) ? "FUTEX_WAKE_OP" :
	(op == FUTEX_WAKE_BITSET) ? "FUTEX_WAKE_BITSET" :
	(op == FUTEX_CMP_REQUEUE) ? "FUTEX_CMP_REQUEUE" :
	(op == FUTEX_REQUEUE) ? "FUTEX_REQUEUE (NOT IMPL!)" : "unknown",
	(unsigned long)uaddr, op, val, utime, uaddr2, val3, *uaddr);

	if (utime && (op == FUTEX_WAIT_BITSET || op == FUTEX_WAIT)) {
		struct syscall_request request IHK_DMA_ALIGN; 
		struct timeval tv_now;
		request.number = n;
		unsigned long __phys;                                          

		dkprintf("futex,utime and FUTEX_WAIT_*, uaddr=%lx, []=%x\n", (unsigned long)uaddr, *uaddr);

		if (ihk_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, 
					(void *)&tv_now, &__phys)) { 
			return -EFAULT; 
		}

		request.args[0] = __phys;               

		int r = do_syscall(&request, ctx, ihk_mc_get_processor_id(), 0);

		if (r < 0) {
			return -EFAULT;
		}

		dkprintf("futex, FUTEX_WAIT_*, arg3 != NULL, pc=%lx\n", (unsigned long)ihk_mc_syscall_pc(ctx));
		dkprintf("now->tv_sec=%016ld,tv_nsec=%016ld\n", tv_now.tv_sec, tv_now.tv_usec * 1000);
		dkprintf("utime->tv_sec=%016ld,tv_nsec=%016ld\n", utime->tv_sec, utime->tv_nsec);

		long nsec_now = ((long)tv_now.tv_sec * 1000000000ULL) + 
			tv_now.tv_usec * 1000;
		long nsec_timeout = ((long)utime->tv_sec * 1000000000ULL) + 
			utime->tv_nsec * 1;
		long diff_nsec = nsec_timeout - nsec_now;

		timeout = (diff_nsec / 1000) * 1100; // (usec * 1.1GHz)
		dkprintf("futex timeout: %lu\n", timeout);
	}

	/* Requeue parameter in 'utime' if op == FUTEX_CMP_REQUEUE.
	 * number of waiters to wake in 'utime' if op == FUTEX_WAKE_OP. */
	if (op == FUTEX_CMP_REQUEUE || op == FUTEX_WAKE_OP)
		val2 = (uint32_t) (unsigned long) ihk_mc_syscall_arg3(ctx);

	return futex(uaddr, op, val, timeout, uaddr2, val2, val3);
}

SYSCALL_DECLARE(exit)
{
	struct process *proc = cpu_local_var(current);

#ifdef DCFA_KMOD
	do_mod_exit((int)ihk_mc_syscall_arg0(ctx));
#endif

	/* XXX: for if all threads issued the exit(2) rather than exit_group(2),
	 *      exit(2) also should delegate.
	 */
	/* If there is a clear_child_tid address set, clear it and wake it.
	 * This unblocks any pthread_join() waiters. */
	if (proc->thread.clear_child_tid) {
		
		dkprintf("exit clear_child!\n");

		*proc->thread.clear_child_tid = 0;
		barrier();
		futex((uint32_t *)proc->thread.clear_child_tid,
		      FUTEX_WAKE, 1, 0, NULL, 0, 0);
	}
	
	proc->status = PS_ZOMBIE;
	
	release_fork_tree_node(proc->ftn);
	release_process(proc);

	schedule();
	
	return 0;
}

SYSCALL_DECLARE(getrlimit)
{
	int ret;
	int resource = ihk_mc_syscall_arg0(ctx);
	struct rlimit *rlm = (struct rlimit *)ihk_mc_syscall_arg1(ctx);
	struct process *proc = cpu_local_var(current);

	switch (resource) {

	case RLIMIT_STACK:
		dkprintf("[%d] getrlimit() RLIMIT_STACK\n", ihk_mc_get_processor_id());
		if(copy_to_user(proc, &rlm->rlim_cur, &proc->rlimit_stack.rlim_cur, sizeof rlm->rlim_cur))
			return -EFAULT;
		if(copy_to_user(proc, &rlm->rlim_max, &proc->rlimit_stack.rlim_max, sizeof rlm->rlim_max))
			return -EFAULT;
		ret = 0;
		break;

	case RLIMIT_FSIZE:
	case RLIMIT_LOCKS:
	case RLIMIT_NOFILE:
		/* just forward */
		ret = syscall_generic_forwarding(n, ctx);
		break;

	default:

		return -ENOSYS;
	}

	return ret;
}

SYSCALL_DECLARE(ptrace)
{
	const int request = ihk_mc_syscall_arg0(ctx);
	const long pid = ihk_mc_syscall_arg1(ctx);
	void * const addr = (void *)ihk_mc_syscall_arg2(ctx);
	void * const data = (void *)ihk_mc_syscall_arg3(ctx);

	kprintf("ptrace(%d,%ld,%p,%p): ENOSYS\n", request, pid, addr, data);
	return -ENOSYS;
}

#define MIN2(x,y) (x) < (y) ? (x) : (y)
SYSCALL_DECLARE(sched_setaffinity)
{
	int tid = (int)ihk_mc_syscall_arg0(ctx);
	size_t len = (size_t)ihk_mc_syscall_arg1(ctx);
	cpu_set_t *u_cpu_set = (cpu_set_t *)ihk_mc_syscall_arg2(ctx);

	cpu_set_t k_cpu_set, cpu_set;
	struct process *thread;
	int cpu_id;

	if (sizeof(k_cpu_set) > len) {
		kprintf("%s:%d\n Too small buffer.", __FILE__, __LINE__);
		return -EINVAL;
	}
	len = MIN2(len, sizeof(k_cpu_set));

	if (copy_from_user(cpu_local_var(current), &k_cpu_set, u_cpu_set, len)) {
		kprintf("%s:%d copy_from_user failed.\n", __FILE__, __LINE__);
		return -EFAULT;
	}

	// XXX: We should build something like cpu_available_mask in advance
	CPU_ZERO(&cpu_set);
	extern int num_processors;
	for (cpu_id = 0; cpu_id < num_processors; cpu_id++)
		if (CPU_ISSET(cpu_id, &k_cpu_set))
			CPU_SET(cpu_id, &cpu_set);

	for (cpu_id = 0; cpu_id < num_processors; cpu_id++) {
		ihk_mc_spinlock_lock_noirq(&get_cpu_local_var(cpu_id)->runq_lock);
		list_for_each_entry(thread, &get_cpu_local_var(cpu_id)->runq, sched_list)
			if (thread->pid && thread->tid == tid)
				goto found; /* without unlocking runq_lock */
		ihk_mc_spinlock_unlock_noirq(&get_cpu_local_var(cpu_id)->runq_lock);
	}
	kprintf("%s:%d Thread not found.\n", __FILE__, __LINE__);
	return -ESRCH;

found:
	memcpy(&thread->cpu_set, &cpu_set, sizeof(cpu_set));

	if (!CPU_ISSET(cpu_id, &thread->cpu_set)) {
		hold_process(thread);
		ihk_mc_spinlock_unlock_noirq(&get_cpu_local_var(cpu_id)->runq_lock);
		sched_request_migrate(cpu_id, thread);
		release_process(thread);
		return 0;
	} else {
		ihk_mc_spinlock_unlock_noirq(&get_cpu_local_var(cpu_id)->runq_lock);
		return 0;
	}
}

// see linux-2.6.34.13/kernel/sched.c
SYSCALL_DECLARE(sched_getaffinity)
{
	int tid = (int)ihk_mc_syscall_arg0(ctx);
	size_t len = (size_t)ihk_mc_syscall_arg1(ctx);
	cpu_set_t k_cpu_set, *u_cpu_set = (cpu_set_t *)ihk_mc_syscall_arg2(ctx);

	int ret;
	int found = 0;
	int i;

	if (sizeof(k_cpu_set) > len) {
		kprintf("%s:%d Too small buffer.\n", __FILE__, __LINE__);
		return -EINVAL;
	}
	len = MIN2(len, sizeof(k_cpu_set));

	extern int num_processors;
	for (i = 0; i < num_processors && !found; i++) {
		struct process *thread;
		ihk_mc_spinlock_lock_noirq(&get_cpu_local_var(i)->runq_lock);
		list_for_each_entry(thread, &get_cpu_local_var(i)->runq, sched_list) {
			if (thread->pid && thread->tid == tid) {
				found = 1;
				memcpy(&k_cpu_set, &thread->cpu_set, sizeof(k_cpu_set));
				break;
			}
		}
		ihk_mc_spinlock_unlock_noirq(&get_cpu_local_var(i)->runq_lock);
	}
	if (!found) {
		kprintf("%s:%d Thread not found.\n", __FILE__, __LINE__);
		return -ESRCH;
	}
	ret = copy_to_user(cpu_local_var(current), u_cpu_set, &k_cpu_set, len);
	kprintf("%s %d %d\n", __FILE__, __LINE__, ret);
	if (ret < 0)
		return ret;
	return len;
}

SYSCALL_DECLARE(get_cpu_id)
{
	return ihk_mc_get_processor_id();
}

SYSCALL_DECLARE(sched_yield)
{
	return -ENOSYS;
}

SYSCALL_DECLARE(mlock)
{
	const uintptr_t start0 = ihk_mc_syscall_arg0(ctx);
	const size_t len0 = ihk_mc_syscall_arg1(ctx);
	struct process *proc = cpu_local_var(current);
	struct vm_regions *region = &proc->vm->region;
	uintptr_t start;
	size_t len;
	uintptr_t end;
	struct vm_range *first;
	uintptr_t addr;
	struct vm_range *range;
	int error;
	struct vm_range *changed;

	dkprintf("[%d]sys_mlock(%lx,%lx)\n",
			ihk_mc_get_processor_id(), start0, len0);

	start = start0 & PAGE_MASK;
	len = (start & (PAGE_SIZE - 1)) + len0;
	len = (len + PAGE_SIZE - 1) & PAGE_MASK;
	end = start + len;

	if (end < start) {
		error = -EINVAL;
		goto out2;
	}

	if ((start < region->user_start)
			|| (region->user_end <= start)
			|| (len > (region->user_end - region->user_start))
			|| ((region->user_end - len) < start)) {
		error = -ENOMEM;
		goto out2;
	}

	if (start == end) {
		error = 0;
		goto out2;
	}

	ihk_mc_spinlock_lock_noirq(&proc->vm->memory_range_lock);

	/* check contiguous map */
	first = NULL;
	for (addr = start; addr < end; addr = range->end) {
		if (first == NULL) {
			range = lookup_process_memory_range(proc->vm, start, start+PAGE_SIZE);
			first = range;
		}
		else {
			range = next_process_memory_range(proc->vm, range);
		}

		if (!range || (addr < range->start)) {
			/* not contiguous */
			dkprintf("[%d]sys_mlock(%lx,%lx):not contiguous."
				       " %lx [%lx-%lx)\n",
					ihk_mc_get_processor_id(), start0,
					len0, addr, range->start, range->end);
			error = -ENOMEM;
			goto out;
		}

		if (range->flag & (VR_REMOTE | VR_RESERVED | VR_IO_NOCACHE)) {
			ekprintf("[%d]sys_mlock(%lx,%lx):cannot change."
				       " [%lx-%lx) %lx\n",
					ihk_mc_get_processor_id(), start0,
					len0, range->start, range->end,
					range->flag);
			error = -EINVAL;
			goto out;
		}
	}

	/* do the mlock */
	changed = NULL;
	for (addr = start; addr < end; addr = changed->end) {
		if (!changed) {
			range = first;
		}
		else {
			range = next_process_memory_range(proc->vm, changed);
		}

		if (!range || (addr < range->start)) {
			/* not contiguous */
			dkprintf("[%d]sys_mlock(%lx,%lx):not contiguous."
				       " %lx [%lx-%lx)\n",
					ihk_mc_get_processor_id(), start0,
					len0, addr, range?range->start:0,
					range?range->end:0);
			error = -ENOMEM;
			goto out;
		}

		if (range->start < addr) {
			error = split_process_memory_range(proc, range, addr, &range);
			if (error) {
				ekprintf("[%d]sys_mlock(%lx,%lx):split failed. "
						" [%lx-%lx) %lx %d\n",
						ihk_mc_get_processor_id(),
						start0, len0, range->start,
						range->end, addr, error);
				goto out;
			}
		}
		if (end < range->end) {
			error = split_process_memory_range(proc, range, end, NULL);
			if (error) {
				ekprintf("[%d]sys_mlock(%lx,%lx):split failed. "
						" [%lx-%lx) %lx %d\n",
						ihk_mc_get_processor_id(),
						start0, len0, range->start,
						range->end, addr, error);
				goto out;
			}
		}

		range->flag |= VR_LOCKED;

		if (!changed) {
			changed = range;
		}
		else {
			error = join_process_memory_range(proc, changed, range);
			if (error) {
				dkprintf("[%d]sys_mlock(%lx,%lx):join failed. %d",
						ihk_mc_get_processor_id(),
						start0, len0, error);
				dkprintf("LHS: %p [%lx-%lx) %lx %p\n",
						changed, changed->start,
						changed->end, changed->flag,
						changed->memobj);
				dkprintf("RHS: %p [%lx-%lx) %lx %p\n",
						range, range->start,
						range->end, range->flag,
						range->memobj);
				changed = range;
				/* through */
			}
		}
	}

	error = 0;
out:
	ihk_mc_spinlock_unlock_noirq(&proc->vm->memory_range_lock);

	if (!error) {
		error = populate_process_memory(proc, (void *)start, len);
		if (error) {
			ekprintf("sys_mlock(%lx,%lx):populate failed. %d\n",
					start0, len0, error);
			/*
			 * In this case,
			 * the region locked by this call should be unlocked
			 * before mlock() returns with error.
			 *
			 * However, the region cannot be unlocked simply,
			 * because the region can be modified by other thread
			 * because memory_range_lock has been released.
			 *
			 * For the time being, like a linux-2.6.38-8,
			 * the physical page allocation failure is ignored.
			 */
			error = 0;
		}
	}

out2:
	dkprintf("[%d]sys_mlock(%lx,%lx): %d\n",
			ihk_mc_get_processor_id(), start0, len0, error);
	return error;
}

SYSCALL_DECLARE(munlock)
{
	const uintptr_t start0 = ihk_mc_syscall_arg0(ctx);
	const size_t len0 = ihk_mc_syscall_arg1(ctx);
	struct process *proc = cpu_local_var(current);
	struct vm_regions *region = &proc->vm->region;
	uintptr_t start;
	size_t len;
	uintptr_t end;
	struct vm_range *first;
	uintptr_t addr;
	struct vm_range *range;
	int error;
	struct vm_range *changed;

	dkprintf("[%d]sys_munlock(%lx,%lx)\n",
			ihk_mc_get_processor_id(), start0, len0);

	start = start0 & PAGE_MASK;
	len = (start & (PAGE_SIZE - 1)) + len0;
	len = (len + PAGE_SIZE - 1) & PAGE_MASK;
	end = start + len;

	if (end < start) {
		error = -EINVAL;
		goto out2;
	}

	if ((start < region->user_start)
			|| (region->user_end <= start)
			|| (len > (region->user_end - region->user_start))
			|| ((region->user_end - len) < start)) {
		error = -ENOMEM;
		goto out2;
	}

	if (start == end) {
		error = 0;
		goto out2;
	}

	ihk_mc_spinlock_lock_noirq(&proc->vm->memory_range_lock);

	/* check contiguous map */
	first = NULL;
	for (addr = start; addr < end; addr = range->end) {
		if (first == NULL) {
			range = lookup_process_memory_range(proc->vm, start, start+PAGE_SIZE);
			first = range;
		}
		else {
			range = next_process_memory_range(proc->vm, range);
		}

		if (!range || (addr < range->start)) {
			/* not contiguous */
			dkprintf("[%d]sys_munlock(%lx,%lx):not contiguous."
				       " %lx [%lx-%lx)\n",
					ihk_mc_get_processor_id(), start0,
					len0, addr, range->start, range->end);
			error = -ENOMEM;
			goto out;
		}

		if (range->flag & (VR_REMOTE | VR_RESERVED | VR_IO_NOCACHE)) {
			ekprintf("[%d]sys_munlock(%lx,%lx):cannot change."
				       " [%lx-%lx) %lx\n",
					ihk_mc_get_processor_id(), start0,
					len0, range->start, range->end,
					range->flag);
			error = -EINVAL;
			goto out;
		}
	}

	/* do the munlock */
	changed = NULL;
	for (addr = start; addr < end; addr = changed->end) {
		if (!changed) {
			range = first;
		}
		else {
			range = next_process_memory_range(proc->vm, changed);
		}

		if (!range || (addr < range->start)) {
			/* not contiguous */
			dkprintf("[%d]sys_munlock(%lx,%lx):not contiguous."
				       " %lx [%lx-%lx)\n",
					ihk_mc_get_processor_id(), start0,
					len0, addr, range?range->start:0,
					range?range->end:0);
			error = -ENOMEM;
			goto out;
		}

		if (range->start < addr) {
			error = split_process_memory_range(proc, range, addr, &range);
			if (error) {
				ekprintf("[%d]sys_munlock(%lx,%lx):split failed. "
						" [%lx-%lx) %lx %d\n",
						ihk_mc_get_processor_id(),
						start0, len0, range->start,
						range->end, addr, error);
				goto out;
			}
		}
		if (end < range->end) {
			error = split_process_memory_range(proc, range, end, NULL);
			if (error) {
				ekprintf("[%d]sys_munlock(%lx,%lx):split failed. "
						" [%lx-%lx) %lx %d\n",
						ihk_mc_get_processor_id(),
						start0, len0, range->start,
						range->end, addr, error);
				goto out;
			}
		}

		range->flag &= ~VR_LOCKED;

		if (!changed) {
			changed = range;
		}
		else {
			error = join_process_memory_range(proc, changed, range);
			if (error) {
				dkprintf("[%d]sys_munlock(%lx,%lx):join failed. %d",
						ihk_mc_get_processor_id(),
						start0, len0, error);
				dkprintf("LHS: %p [%lx-%lx) %lx %p\n",
						changed, changed->start,
						changed->end, changed->flag,
						changed->memobj);
				dkprintf("RHS: %p [%lx-%lx) %lx %p\n",
						range, range->start,
						range->end, range->flag,
						range->memobj);
				changed = range;
				/* through */
			}
		}
	}

	error = 0;
out:
	ihk_mc_spinlock_unlock_noirq(&proc->vm->memory_range_lock);
out2:
	dkprintf("[%d]sys_munlock(%lx,%lx): %d\n",
			ihk_mc_get_processor_id(), start0, len0, error);
	return error;
}

SYSCALL_DECLARE(remap_file_pages)
{
	const uintptr_t start0 = ihk_mc_syscall_arg0(ctx);
	const size_t size = ihk_mc_syscall_arg1(ctx);
	const int prot = ihk_mc_syscall_arg2(ctx);
	const size_t pgoff = ihk_mc_syscall_arg3(ctx);
	const int flags = ihk_mc_syscall_arg4(ctx);
	int error;
	const uintptr_t start = start0 & PAGE_MASK;
	const uintptr_t end = start + size;
	const off_t off = (off_t)pgoff << PAGE_SHIFT;
	struct process * const proc = cpu_local_var(current);
	struct vm_range *range;
	int er;
	int need_populate = 0;

	dkprintf("sys_remap_file_pages(%#lx,%#lx,%#x,%#lx,%#x)\n",
			start0, size, prot, pgoff, flags);
	ihk_mc_spinlock_lock_noirq(&proc->vm->memory_range_lock);
#define	PGOFF_LIMIT	((off_t)1 << ((8*sizeof(off_t) - 1) - PAGE_SHIFT))
	if ((size <= 0) || (size & (PAGE_SIZE - 1)) || (prot != 0)
			|| (pgoff < 0) || (PGOFF_LIMIT <= pgoff)
			|| ((PGOFF_LIMIT - pgoff) < (size / PAGE_SIZE))
			|| !((start < end) || (end == 0))) {
		ekprintf("sys_remap_file_pages(%#lx,%#lx,%#x,%#lx,%#x):"
				"invalid args\n",
				start0, size, prot, pgoff, flags);
		error = -EINVAL;
		goto out;
	}

	range = lookup_process_memory_range(proc->vm, start, end);
	if (!range || (start < range->start) || (range->end < end)
			|| (range->flag & VR_PRIVATE)
			|| (range->flag & (VR_REMOTE|VR_IO_NOCACHE|VR_RESERVED))
			|| !range->memobj) {
		ekprintf("sys_remap_file_pages(%#lx,%#lx,%#x,%#lx,%#x):"
				"invalid VMR:[%#lx-%#lx) %#lx %p\n",
				start0, size, prot, pgoff, flags,
				range?range->start:0, range?range->end:0,
				range?range->flag:0, range?range->memobj:NULL);
		error = -EINVAL;
		goto out;
	}

	range->flag |= VR_FILEOFF;
	error = remap_process_memory_range(proc->vm, range, start, end, off);
	if (error) {
		ekprintf("sys_remap_file_pages(%#lx,%#lx,%#x,%#lx,%#x):"
				"remap failed %d\n",
				start0, size, prot, pgoff, flags, error);
		goto out;
	}
	clear_host_pte(start, size);	/* XXX: workaround */

	if (range->flag & VR_LOCKED) {
		need_populate = 1;
	}
	error = 0;
out:
	ihk_mc_spinlock_unlock_noirq(&proc->vm->memory_range_lock);

	if (need_populate
			&& (er = populate_process_memory(
					proc, (void *)start, size))) {
		ekprintf("sys_remap_file_pages(%#lx,%#lx,%#x,%#lx,%#x):"
				"populate failed %d\n",
				start0, size, prot, pgoff, flags, er);
		/* ignore populate error */
	}

	dkprintf("sys_remap_file_pages(%#lx,%#lx,%#x,%#lx,%#x): %d\n",
			start0, size, prot, pgoff, flags, error);
	return error;
}

SYSCALL_DECLARE(mremap)
{
	const uintptr_t oldaddr = ihk_mc_syscall_arg0(ctx);
	const size_t oldsize0 = ihk_mc_syscall_arg1(ctx);
	const size_t newsize0 = ihk_mc_syscall_arg2(ctx);
	const int flags = ihk_mc_syscall_arg3(ctx);
	const uintptr_t newaddr = ihk_mc_syscall_arg4(ctx);
	const ssize_t oldsize = (oldsize0 + PAGE_SIZE - 1) & PAGE_MASK;
	const ssize_t newsize = (newsize0 + PAGE_SIZE - 1) & PAGE_MASK;
	const uintptr_t oldstart = oldaddr;
	const uintptr_t oldend = oldstart + oldsize;
	struct process *proc = cpu_local_var(current);
	struct process_vm *vm = proc->vm;
	int error;
	struct vm_range *range;
	int need_relocate;
	uintptr_t newstart;
	uintptr_t newend;
	size_t size;
	uintptr_t ret;
	uintptr_t lckstart = -1;
	uintptr_t lckend = -1;

	dkprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx)\n",
			oldaddr, oldsize0, newsize0, flags, newaddr);
	ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);

	if ((oldaddr & ~PAGE_MASK)
			|| (oldsize < 0)
			|| (newsize <= 0)
			|| (flags & ~(MREMAP_MAYMOVE | MREMAP_FIXED))
			|| ((flags & MREMAP_FIXED)
				&& !(flags & MREMAP_MAYMOVE))
			|| ((flags & MREMAP_FIXED)
				&& (newaddr & ~PAGE_MASK))) {
		error = -EINVAL;
		ekprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):invalid. %d\n",
				oldaddr, oldsize0, newsize0, flags, newaddr,
				error);
		goto out;
	}

	/* check original mapping */
	range = lookup_process_memory_range(vm, oldstart, oldstart+PAGE_SIZE);
	if (!range || (oldstart < range->start) || (range->end < oldend)
			|| (range->flag & (VR_FILEOFF))
			|| (range->flag & (VR_REMOTE|VR_IO_NOCACHE|VR_RESERVED))) {
		error = -EFAULT;
		ekprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):"
				"lookup failed. %d %p %#lx-%#lx %#lx\n",
				oldaddr, oldsize0, newsize0, flags, newaddr,
				error, range, range?range->start:0,
				range?range->end:0, range?range->flag:0);
		goto out;
	}

	if (oldend < oldstart) {
		error = -EINVAL;
		ekprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):"
				"old range overflow. %d\n",
				oldaddr, oldsize0, newsize0, flags, newaddr,
				error);
		goto out;
	}

	/* determine new mapping range */
	need_relocate = 0;
	if (flags & MREMAP_FIXED) {
		need_relocate = 1;
		newstart = newaddr;
		newend = newstart + newsize;
		if (newstart < vm->region.user_start) {
			error = -EPERM;
			ekprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):"
					"mmap_min_addr %#lx. %d\n",
					oldaddr, oldsize0, newsize0, flags,
					newaddr, vm->region.user_start,
					error);
			goto out;
		}
		if ((newstart < oldend) && (oldstart < newend)) {
			error = -EINVAL;
			ekprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):"
					"fixed:overlapped. %d\n",
					oldaddr, oldsize0, newsize0, flags,
					newaddr, error);
			goto out;
		}
	}
	else if (!(flags & MREMAP_FIXED) && (oldsize < newsize)) {
		if (oldend == range->end) {
			newstart = oldstart;
			newend = newstart + newsize;
			error = extend_up_process_memory_range(vm, range,
					newend);
			if (!error) {
				if (range->flag & VR_LOCKED) {
					lckstart = oldend;
					lckend = newend;
				}
				goto out;
			}
		}
		if (!(flags & MREMAP_MAYMOVE)) {
			error = -ENOMEM;
			ekprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):"
					"cannot relocate. %d\n",
					oldaddr, oldsize0, newsize0, flags,
					newaddr, error);
			goto out;
		}
		need_relocate = 1;
		error = search_free_space(newsize, vm->region.map_end,
				(intptr_t *)&newstart);
		if (error) {
			ekprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):"
					"search failed. %d\n",
					oldaddr, oldsize0, newsize0, flags,
					newaddr, error);
			goto out;
		}
		newend = newstart + newsize;
	}
	else {
		newstart = oldstart;
		newend = newstart + newsize;
	}

	/* do the remap */
	if (need_relocate) {
		if (flags & MREMAP_FIXED) {
			error = do_munmap((void *)newstart, newsize);
			if (error) {
				ekprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):"
						"fixed:munmap failed. %d\n",
						oldaddr, oldsize0, newsize0,
						flags, newaddr, error);
				goto out;
			}
		}
		if (range->memobj) {
			memobj_ref(range->memobj);
		}
		error = add_process_memory_range(proc, newstart, newend, -1,
				range->flag, range->memobj,
				range->objoff + (oldstart - range->start));
		if (error) {
			ekprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):"
					"add failed. %d\n",
					oldaddr, oldsize0, newsize0, flags,
					newaddr, error);
			if (range->memobj) {
				memobj_release(range->memobj);
			}
			goto out;
		}
		if (range->flag & VR_LOCKED) {
			lckstart = newstart;
			lckend = newend;
		}

		if (oldsize > 0) {
			size = (oldsize < newsize)? oldsize: newsize;
			ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
			error = move_pte_range(vm->page_table, vm,
					(void *)oldstart, (void *)newstart,
					size);
			ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
			if (error) {
				ekprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):"
						"move failed. %d\n",
						oldaddr, oldsize0, newsize0,
						flags, newaddr, error);
				goto out;
			}

			error = do_munmap((void *)oldstart, oldsize);
			if (error) {
				ekprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):"
						"relocate:munmap failed. %d\n",
						oldaddr, oldsize0, newsize0,
						flags, newaddr, error);
				goto out;
			}
		}
	}
	else if (newsize < oldsize) {
		error = do_munmap((void *)newend, (oldend - newend));
		if (error) {
			ekprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):"
					"shrink:munmap failed. %d\n",
					oldaddr, oldsize0, newsize0, flags,
					newaddr, error);
			goto out;
		}
	}
	else {
		/* nothing to do */
	}

	error = 0;
out:
	ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);
	if (!error && (lckstart < lckend)) {
		error = populate_process_memory(proc, (void *)lckstart, (lckend - lckstart));
		if (error) {
			ekprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):"
					"populate failed. %d %#lx-%#lx\n",
					oldaddr, oldsize0, newsize0, flags,
					newaddr, error, lckstart, lckend);
			error = 0;	/* ignore error */
		}
	}
	ret = (error)? error: newstart;
	dkprintf("sys_mremap(%#lx,%#lx,%#lx,%#x,%#lx):%d %#lx\n",
			oldaddr, oldsize0, newsize0, flags, newaddr, error,
			ret);
	return ret;
}

#ifdef DCFA_KMOD

#ifdef CMD_DCFA
extern int ibmic_cmd_syscall(char *uargs);
extern void ibmic_cmd_exit(int status);
#endif

#ifdef CMD_DCFAMPI
extern int dcfampi_cmd_syscall(char *uargs);
#endif

static int (*mod_call_table[]) (char *) = {
#ifdef CMD_DCFA
		[1] = ibmic_cmd_syscall,
#endif
#ifdef CMD_DCFAMPI
		[2] = dcfampi_cmd_syscall,
#endif
};

static void (*mod_exit_table[]) (int) = {
#ifdef CMD_DCFA
		[1] = ibmic_cmd_exit,
#endif
#ifdef CMD_DCFAMPI
		[2] = NULL,
#endif
};

SYSCALL_DECLARE(mod_call) {
	int mod_id;
	unsigned long long uargs;

	mod_id = ihk_mc_syscall_arg0(ctx);
	uargs = ihk_mc_syscall_arg1(ctx);

	dkprintf("mod_call id:%d, uargs=0x%llx, type=%s, command=%x\n", mod_id, uargs, mod_id==1?"ibmic":"dcfampi", *((uint32_t*)(((char*)uargs)+0)));

	if(mod_call_table[mod_id])
		return mod_call_table[mod_id]((char*)uargs);

	kprintf("ERROR! undefined mod_call id:%d\n", mod_id);

	return -ENOSYS;
}

static void do_mod_exit(int status){
	int i;
	for(i=1; i<=2; i++){
		if(mod_exit_table[i])
			mod_exit_table[i](status);
	}
}
#endif

/* select counter type */
SYSCALL_DECLARE(pmc_init)
{
    int counter = ihk_mc_syscall_arg0(ctx);

    enum ihk_perfctr_type type = (enum ihk_perfctr_type)ihk_mc_syscall_arg1(ctx);
    /* see ihk/manycore/generic/include/ihk/perfctr.h */

    int mode = PERFCTR_USER_MODE;

    return ihk_mc_perfctr_init(counter, type, mode);
}

SYSCALL_DECLARE(pmc_start)
{
    unsigned long counter = ihk_mc_syscall_arg0(ctx);
    return ihk_mc_perfctr_start(1 << counter);
}

SYSCALL_DECLARE(pmc_stop)
{
    unsigned long counter = ihk_mc_syscall_arg0(ctx);
    return ihk_mc_perfctr_stop(1 << counter);
}

SYSCALL_DECLARE(pmc_reset)
{
    int counter = ihk_mc_syscall_arg0(ctx);
    return ihk_mc_perfctr_reset(counter);
}

long syscall(int num, ihk_mc_user_context_t *ctx)
{
	long l;

	cpu_enable_interrupt();


#if 0
	if(num != 24)  // if not sched_yield
#endif
	dkprintf("SC(%d:%d)[%3d=%s](%lx, %lx,%lx, %lx, %lx, %lx)@%lx,sp:%lx",
             ihk_mc_get_processor_id(),
             ihk_mc_get_hardware_processor_id(),
             num, syscall_name[num],
             ihk_mc_syscall_arg0(ctx), ihk_mc_syscall_arg1(ctx),
             ihk_mc_syscall_arg2(ctx), ihk_mc_syscall_arg3(ctx),
             ihk_mc_syscall_arg4(ctx), ihk_mc_syscall_arg5(ctx),
             ihk_mc_syscall_pc(ctx), ihk_mc_syscall_sp(ctx));
#if 1
#if 0
	if(num != 24)  // if not sched_yield
#endif
    dkprintf(",*sp:%lx,*(sp+8):%lx,*(sp+16):%lx,*(sp+24):%lx",
             *((unsigned long*)ihk_mc_syscall_sp(ctx)),
             *((unsigned long*)(ihk_mc_syscall_sp(ctx)+8)),
             *((unsigned long*)(ihk_mc_syscall_sp(ctx)+16)),
             *((unsigned long*)(ihk_mc_syscall_sp(ctx)+24)));
#endif
#if 0
	if(num != 24)  // if not sched_yield
#endif
    dkprintf("\n");


	if ((0 <= num) && (num < (sizeof(syscall_table) / sizeof(syscall_table[0])))
			&& (syscall_table[num] != NULL)) {
		l = syscall_table[num](num, ctx);
		
		dkprintf("SC(%d)[%3d] ret: %d\n", 
				ihk_mc_get_processor_id(), num, l);
	} else {
		dkprintf("USC[%3d](%lx, %lx, %lx, %lx, %lx) @ %lx | %lx\n", num,
		        ihk_mc_syscall_arg0(ctx), ihk_mc_syscall_arg1(ctx),
		        ihk_mc_syscall_arg2(ctx), ihk_mc_syscall_arg3(ctx),
		        ihk_mc_syscall_arg4(ctx), ihk_mc_syscall_pc(ctx),
		        ihk_mc_syscall_sp(ctx));
		l = syscall_generic_forwarding(num, ctx);
	}

	check_signal(l, NULL);
	check_need_resched();

	return l;
}

#if 0
void __host_update_process_range(struct process *process, 
                                 struct vm_range *range)
{
	struct syscall_post *post;
	int idx;

	memcpy_async_wait(&cpu_local_var(scp).post_fin);

	post = &cpu_local_var(scp).post_buf;

	post->v[0] = 1;
	post->v[1] = range->start;
	post->v[2] = range->end;
	post->v[3] = range->phys;

	cpu_disable_interrupt();
	if (cpu_local_var(scp).post_idx >= 
	    PAGE_SIZE / sizeof(struct syscall_post)) {
		/* XXX: Wait until it is consumed */
	} else {
		idx = ++(cpu_local_var(scp).post_idx);

		cpu_local_var(scp).post_fin = 0;
		memcpy_async(cpu_local_var(scp).post_pa + 
		             idx * sizeof(*post),
		             virt_to_phys(post), sizeof(*post), 0,
		             &cpu_local_var(scp).post_fin);
	}
	cpu_enable_interrupt();
}
#endif
