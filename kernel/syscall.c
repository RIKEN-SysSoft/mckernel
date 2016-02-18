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
#include <prio.h>
#include <arch/cpu.h>
#include <limits.h>

/* Headers taken from kitten LWK */
#include <lwk/stddef.h>
#include <futex.h>

#define SYSCALL_BY_IKC

//#define DEBUG_PRINT_SC

#ifdef DEBUG_PRINT_SC
#define	dkprintf(...) kprintf(__VA_ARGS__)
#define	ekprintf(...) kprintf(__VA_ARGS__)
#else
#define dkprintf(...) do { if (0) kprintf(__VA_ARGS__); } while (0)
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

static ihk_spinlock_t tod_data_lock = SPIN_LOCK_UNLOCKED;
static void calculate_time_from_tsc(struct timespec *ts);

void check_signal(unsigned long, void *, int);
void do_signal(long rc, void *regs, struct thread *thread, struct sig_pending *pending, int num);
extern unsigned long do_kill(struct thread *thread, int pid, int tid, int sig, struct siginfo *info, int ptracecont);
extern struct sigpending *hassigpending(struct thread *thread);
int copy_from_user(void *, const void *, size_t);
int read_process_vm(struct process_vm *, void *, const void *, size_t);
int copy_to_user(void *, const void *, size_t);
int patch_process_vm(struct process_vm *, void *, const void *, size_t);
extern long alloc_debugreg(struct thread *thread);
extern int num_processors;
extern unsigned long ihk_mc_get_ns_per_tsc(void);
extern int ptrace_detach(int pid, int data);
extern void debug_log(unsigned long);
extern void free_all_process_memory_range(struct process_vm *vm);
extern struct cpu_local_var *clv;

int prepare_process_ranges_args_envs(struct thread *thread, 
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
	   req->number == __NR_gettid ||
	   req->number == __NR_kill){ // interrupt syscall
		extern int num_processors;

		scp = &get_cpu_local_var(0)->scp2;
		syscall_channel = get_cpu_local_var(0)->syscall_channel2;
		
		/* XXX: is this really going to work if multiple processes 
		 * exit/receive signals at the same time?? */
		cpu = num_processors;
		if(req->number == __NR_kill)
			pid = req->args[0];
		if(req->number == __NR_gettid)
			pid = req->args[1];
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
	packet.pid = pid ? pid : cpu_local_var(current)->proc->pid;
	packet.arg = scp->request_rpa;	
	dkprintf("send syscall, nr: %d, pid: %d\n", req->number, packet.pid);

	ret = ihk_ikc_send(syscall_channel, &packet, 0);
	if (ret < 0) {
		kprintf("ERROR: sending IKC msg, ret: %d\n", ret);
	}
#endif
}

ihk_spinlock_t syscall_lock;

long do_syscall(struct syscall_request *req, int cpu, int pid)
{
	struct syscall_response *res;
	struct syscall_request req2 IHK_DMA_ALIGN;
	struct syscall_params *scp;
	int error;
	long rc;
	int islock = 0;
	unsigned long irqstate;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;

	dkprintf("SC(%d)[%3d] sending syscall\n",
		ihk_mc_get_processor_id(),
		req->number);

	if(req->number != __NR_exit_group){
		if(proc->nohost && // host is down
		   pid == proc->pid) {
			return -EPIPE;
		}
		++thread->in_syscall_offload;
	}

	irqstate = 0;	/* for avoidance of warning */
	if(req->number == __NR_exit_group ||
	   req->number == __NR_gettid ||
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
					cpu_local_var(current)->proc->pid);
			error = page_fault_process_vm(thread->vm,
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

	if(req->number != __NR_exit_group){
		--thread->in_syscall_offload;
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

static int wait_zombie(struct thread *thread, struct process *child, int *status, int options) {
    int ret;
    struct syscall_request request IHK_DMA_ALIGN;
	int ppid = 0;
    
    dkprintf("wait_zombie,found PS_ZOMBIE process: %d\n", child->pid);
    
    if (status) {
        *status = child->exit_status;
    }
    
	ppid = child->ppid_parent->pid;
	if(ppid == 1 || child->nowait)
		return 0;
	request.number = __NR_wait4;
	request.args[0] = child->pid;
	request.args[1] = 0;
	request.args[2] = options;
	/* Ask host to clean up exited child */
	ret = do_syscall(&request, ihk_mc_get_processor_id(), ppid);

	if (ret != child->pid)
		kprintf("WARNING: host waitpid failed?\n");
	dkprintf("wait_zombie,child->pid=%d,status=%08x\n",
		 child->pid, status ? *status : -1);

    return ret;
}

static int wait_stopped(struct thread *thread, struct process *child, int *status, int options)
{
	dkprintf("wait_stopped,proc->pid=%d,child->pid=%d,options=%08x\n",
			 thread->proc->pid, child->pid, options);
	int ret;

	/* Copy exit_status created in do_signal */
	int *exit_status = child->status == PS_STOPPED ? 
		&child->group_exit_status :
		&child->exit_status;

	/* Skip this process because exit_status has been reaped. */
	if (!*exit_status) {
		ret = 0;
		goto out;
	}

	/* TODO: define 0x7f in kernel/include/process.h */
	if (status) {
		*status =  (*exit_status << 8) | 0x7f;
	}

	/* Reap exit_status. signal_flags is reaped on receiving signal
	   in do_kill(). */
	if(!(options & WNOWAIT)) {
		*exit_status = 0;
	}

	dkprintf("wait_stopped,child->pid=%d,status=%08x\n",
			 child->pid, status ? *status : -1);
	ret = child->pid;
 out:
	return ret;    
}

static int wait_continued(struct thread *thread, struct process *child, int *status, int options) {
	int ret;

	if (status) {
		*status = 0xffff;
	}

	/* Reap signal_flags */
	if(!(options & WNOWAIT)) {
		child->signal_flags &= ~SIGNAL_STOP_CONTINUED;
	}

	dkprintf("wait4,SIGNAL_STOP_CONTINUED,pid=%d,status=%08x\n",
			 child->pid, status ? *status : -1);
	ret = child->pid;
	return ret;
}

/* 
 * From glibc: INLINE_SYSCALL (wait4, 4, pid, stat_loc, options, NULL);
 */
static int
do_wait(int pid, int *status, int options, void *rusage)
{
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct process *child, *next;
	int pgid = proc->pgid;
	int ret;
	struct waitq_entry waitpid_wqe;
	int empty = 1;
	int orgpid = pid;
	struct mcs_rwlock_node lock;

	dkprintf("wait4,thread->pid=%d,pid=%d\n", thread->proc->pid, pid);

 rescan:
	pid = orgpid;

	mcs_rwlock_writer_lock_noirq(&thread->proc->children_lock, &lock);
	list_for_each_entry_safe(child, next, &proc->children_list, siblings_list) {	
		if (!(!!(options & __WCLONE) ^ (child->termsig == SIGCHLD))) {
			continue;
		}

		if ((pid < 0 && -pid == child->pgid) ||
			pid == -1 ||
			(pid == 0 && pgid == child->pgid) ||
			(pid > 0 && pid == child->pid)) {

			empty = 0;

			if((options & WEXITED) &&
			   child->status == PS_ZOMBIE) {
				ret = wait_zombie(thread, child, status, options);
				mcs_rwlock_writer_unlock_noirq(&thread->proc->children_lock, &lock);
				if(!(options & WNOWAIT)){
					mcs_rwlock_writer_lock_noirq(&proc->update_lock, &lock);
					ts_add(&proc->stime_children, &child->stime);
					ts_add(&proc->utime_children, &child->utime);
					ts_add(&proc->stime_children, &child->stime_children);
					ts_add(&proc->utime_children, &child->utime_children);
					mcs_rwlock_writer_unlock_noirq(&proc->update_lock, &lock);
					release_process(child);
				}
				goto out_found;
			}

			if(!(child->ptrace & PT_TRACED) &&
			   (child->signal_flags & SIGNAL_STOP_STOPPED) &&
			   (options & WUNTRACED)) {
				/* Not ptraced and in stopped state and WUNTRACED is specified */
				ret = wait_stopped(thread, child, status, options);
				if(!(options & WNOWAIT)){
					child->signal_flags &= ~SIGNAL_STOP_STOPPED;
				}
				mcs_rwlock_writer_unlock_noirq(&thread->proc->children_lock, &lock);
				goto out_found;
			}

			if((child->ptrace & PT_TRACED) &&
			   (child->status & (PS_STOPPED | PS_TRACED))) {
				ret = wait_stopped(thread, child, status, options);
				if(ret == child->pid){
					if(!(options & WNOWAIT)){
						child->signal_flags &= ~SIGNAL_STOP_STOPPED;
					}
					mcs_rwlock_writer_unlock_noirq(&thread->proc->children_lock, &lock);
					goto out_found;
				}
			}

			if((child->signal_flags & SIGNAL_STOP_CONTINUED) &&
			   (options & WCONTINUED)) {
				ret = wait_continued(thread, child, status, options);
				if(!(options & WNOWAIT)){
					child->signal_flags &= ~SIGNAL_STOP_CONTINUED;
				}
				mcs_rwlock_writer_unlock_noirq(&thread->proc->children_lock, &lock);
				goto out_found;
			}
		}

	}

	if (empty) {
		ret = -ECHILD;
		goto out_notfound;
	}

	/* Don't sleep if WNOHANG requested */
	if (options & WNOHANG) {
		*status = 0;
		ret = 0;
		goto out_notfound;
	}

	/* Sleep */
	dkprintf("wait4,sleeping\n");
	waitq_init_entry(&waitpid_wqe, thread);
	waitq_prepare_to_wait(&thread->proc->waitpid_q, &waitpid_wqe, PS_INTERRUPTIBLE);

	mcs_rwlock_writer_unlock_noirq(&thread->proc->children_lock, &lock);	
	if(hassigpending(thread)){
		waitq_finish_wait(&thread->proc->waitpid_q, &waitpid_wqe);
		return -EINTR;
	}

	schedule();
	dkprintf("wait4(): woken up\n");

	waitq_finish_wait(&thread->proc->waitpid_q, &waitpid_wqe);

	goto rescan;

 exit:
	return ret;
 out_found:
	dkprintf("wait4,out_found\n");
	goto exit;
 out_notfound:
	dkprintf("wait4,out_notfound\n");
	mcs_rwlock_writer_unlock_noirq(&thread->proc->children_lock, &lock);
	goto exit;
}

SYSCALL_DECLARE(wait4)
{
	int pid = (int)ihk_mc_syscall_arg0(ctx);
	int *status = (int *)ihk_mc_syscall_arg1(ctx);
	int options = (int)ihk_mc_syscall_arg2(ctx);
	void *rusage = (void *)ihk_mc_syscall_arg3(ctx);
	int st;
	int rc;

	if(options & ~(WNOHANG | WUNTRACED | WCONTINUED | __WCLONE)){
		dkprintf("wait4: unexpected options(%x).\n", options);
		return -EINVAL;
	}
	rc = do_wait(pid, &st, WEXITED | options, rusage);
	if(rc >= 0 && status)
		copy_to_user(status, &st, sizeof(int));
	return rc;
}

SYSCALL_DECLARE(waitid)
{
	int idtype = (int)ihk_mc_syscall_arg0(ctx);
	int id = (int)ihk_mc_syscall_arg1(ctx);
	siginfo_t *infop = (siginfo_t *)ihk_mc_syscall_arg2(ctx);
	int options = (int)ihk_mc_syscall_arg3(ctx);
	int pid;
	int status;
	int rc;

	if(idtype == P_PID)
		pid = id;
	else if(idtype == P_PGID)
		pid = -id;
	else if(idtype == P_ALL)
		pid = -1;
	else
		return -EINVAL;
	if(options & ~(WEXITED | WSTOPPED | WCONTINUED | WNOHANG | WNOWAIT | __WCLONE)){
		dkprintf("waitid: unexpected options(%x).\n", options);
		return -EINVAL;
	}
	if(!(options & (WEXITED | WSTOPPED | WCONTINUED))){
		dkprintf("waitid: no waiting status(%x).\n", options);
		return -EINVAL;
	}
	rc = do_wait(pid, &status, options, NULL);
	if(rc < 0)
		return rc;
	if(rc && infop){
		siginfo_t info;
		memset(&info, '\0', sizeof(siginfo_t));
		info.si_signo = SIGCHLD;
		info._sifields._sigchld.si_pid = rc;
		info._sifields._sigchld.si_status = status;
		if((status & 0x000000ff) == 0x0000007f)
			info.si_code = CLD_STOPPED;
		else if((status & 0x0000ffff) == 0x0000ffff)
			info.si_code = CLD_CONTINUED;
		else if(status & 0x000000ff)
			info.si_code = CLD_KILLED;
		else
			info.si_code = CLD_EXITED;
		copy_to_user(infop, &info, sizeof info);
	}
	return 0;
}

void
terminate(int rc, int sig)
{
	struct resource_set *resource_set = cpu_local_var(resource_set);
	struct thread *mythread = cpu_local_var(current);
	struct thread *thread;
	struct process *proc = mythread->proc;
	struct process *child;
	struct process *next;
	struct process *pid1 = resource_set->pid1;
	struct process_vm *vm;
	struct mcs_rwlock_node_irqsave lock;
	struct mcs_rwlock_node updatelock;
	struct mcs_rwlock_node childlock;
	struct mcs_rwlock_node childlock1;
	int i;
	int n;
	int *ids = NULL;
	struct syscall_request request IHK_DMA_ALIGN;

	// clean up threads
	mcs_rwlock_reader_lock(&proc->threads_lock, &lock); // conflict clone
	mcs_rwlock_writer_lock_noirq(&proc->update_lock, &updatelock);
	if(proc->status == PS_EXITED){
		mcs_rwlock_writer_unlock_noirq(&proc->update_lock, &updatelock);
		mcs_rwlock_reader_unlock(&proc->threads_lock, &lock);
		mythread->status = PS_EXITED;
		release_thread(mythread);
		schedule();
		// no return
		return;
	}
	proc->exit_status = ((rc & 0x00ff) << 8) | (sig & 0xff);
	proc->status = PS_EXITED;
	mcs_rwlock_writer_unlock_noirq(&proc->update_lock, &updatelock);
	mcs_rwlock_reader_unlock(&proc->threads_lock, &lock);

	mcs_rwlock_writer_lock(&proc->threads_lock, &lock);
	list_del(&mythread->siblings_list);
	mcs_rwlock_writer_unlock(&proc->threads_lock, &lock);

	mcs_rwlock_reader_lock(&proc->threads_lock, &lock);
	n = 0;
	list_for_each_entry(thread, &proc->threads_list, siblings_list) {
		n++;
	}
	if(n){
		ids = kmalloc(sizeof(int) * n, IHK_MC_AP_NOWAIT);
		i = 0;
		if(ids){
			list_for_each_entry(thread, &proc->threads_list, siblings_list) {
				if(thread != mythread){
					ids[i] = thread->tid;
					i++;
				}
			}
		}
	}
	mcs_rwlock_reader_unlock(&proc->threads_lock, &lock);
	if(ids){
		for(i = 0; i < n; i++){
			do_kill(mythread, proc->pid, ids[i], SIGKILL, NULL, 0);
		}
		kfree(ids);
		ids = NULL;
	}

	for(;;){
		__mcs_rwlock_reader_lock(&proc->threads_lock, &lock);
		if(list_empty(&proc->threads_list)){
			mcs_rwlock_reader_unlock(&proc->threads_lock, &lock);
			break;
		}
		__mcs_rwlock_reader_unlock(&proc->threads_lock, &lock);
		cpu_pause();
	}

	mcs_rwlock_writer_lock(&proc->threads_lock, &lock);
	list_add_tail(&mythread->siblings_list, &proc->threads_list);
	mcs_rwlock_writer_unlock(&proc->threads_lock, &lock);

	vm = proc->vm;
	free_all_process_memory_range(vm);

	if (proc->saved_cmdline) {
		kfree(proc->saved_cmdline);
	}

	// check tracee and ptrace_detach
	n = 0;
	mcs_rwlock_reader_lock(&proc->children_lock, &lock);
	list_for_each_entry(child, &proc->children_list, siblings_list) {
		if(child->ptrace & PT_TRACED)
			n++;
	}
	if(n){
		ids = kmalloc(sizeof(int) * n, IHK_MC_AP_NOWAIT);
		i = 0;
		if(ids){
			list_for_each_entry(child, &proc->children_list, siblings_list) {
				if(child->ptrace & PT_TRACED){
					ids[i] = child->pid;
					i++;
				}
			}
		}
	}
	mcs_rwlock_reader_unlock(&proc->children_lock, &lock);
	if(ids){
		for(i = 0; i < n; i++){
			ptrace_detach(ids[i], 0);
		}
		kfree(ids);
	}

	// clean up children
	for(i = 0; i < HASH_SIZE; i++){
		mcs_rwlock_writer_lock(&resource_set->process_hash->lock[i],
		                   &lock);
		list_for_each_entry_safe(child, next,
		                         &resource_set->process_hash->list[i],
		                         hash_list){
			mcs_rwlock_writer_lock_noirq(&child->update_lock,
			                         &updatelock);
			if(child->ppid_parent == proc &&
			   child->status == PS_ZOMBIE){
				list_del(&child->hash_list);
				list_del(&child->siblings_list);
				kfree(child);
			}
			else if(child->ppid_parent == proc){
				mcs_rwlock_writer_lock_noirq(&proc->children_lock,
				                         &childlock);
				mcs_rwlock_writer_lock_noirq(&pid1->children_lock,
				                         &childlock1);
				child->ppid_parent = pid1;
				if(child->parent == proc){
					child->parent = pid1;
					list_del(&child->siblings_list);
					list_add_tail(&child->siblings_list,
					              &pid1->children_list);
				}
				else{
					list_del(&child->ptraced_siblings_list);
					list_add_tail(&child->ptraced_siblings_list,
					              &pid1->ptraced_children_list);
				}
				mcs_rwlock_writer_unlock_noirq(&pid1->children_lock,
				                         &childlock1);
				mcs_rwlock_writer_unlock_noirq(&proc->children_lock,
				                         &childlock);
			}
			mcs_rwlock_writer_unlock_noirq(&child->update_lock,
			                           &updatelock);
		}
		mcs_rwlock_writer_unlock(&resource_set->process_hash->lock[i],
		                   &lock);
	}

	dkprintf("terminate,pid=%d\n", proc->pid);

#ifdef DCFA_KMOD
	do_mod_exit(rc);
#endif

	// clean up memory
	if(!proc->nohost){
		request.number = __NR_exit_group;
		request.args[0] = proc->exit_status;
		do_syscall(&request, ihk_mc_get_processor_id(), proc->pid);
		proc->nohost = 1;
	}

	// Send signal to parent
	if (proc->parent == pid1) {
		proc->status = PS_ZOMBIE;
		release_process(proc);
	}
	else {
		proc->status = PS_ZOMBIE;

		dkprintf("terminate,wakeup\n");

		/* Signal parent if still attached */
		if (proc->termsig != 0) {
			struct siginfo info;
			int error;

			memset(&info, '\0', sizeof info);
			info.si_signo = SIGCHLD;
			info.si_code = (proc->exit_status & 0x7f)?
			               ((proc->exit_status & 0x80)?
			                CLD_DUMPED: CLD_KILLED): CLD_EXITED;
			info._sifields._sigchld.si_pid = proc->pid;
			info._sifields._sigchld.si_status = proc->exit_status;
			error = do_kill(NULL, proc->parent->pid, -1, SIGCHLD, &info, 0);
			dkprintf("terminate,klll %d,error=%d\n",
					proc->termsig, error);
		}
		/* Wake parent (if sleeping in wait4()) */
		waitq_wakeup(&proc->parent->waitpid_q);
	}

	mythread->status = PS_EXITED;
	release_thread(mythread);
	release_process_vm(vm);
	schedule();
	// no return
}

void
terminate_host(int pid)
{
	struct process *proc;
	struct mcs_rwlock_node_irqsave lock;

	proc = find_process(pid, &lock);
	if(!proc)
		return;
	proc->nohost = 1;
	process_unlock(proc, &lock);
	do_kill(cpu_local_var(current), pid, -1, SIGKILL, NULL, 0);
}

void
interrupt_syscall(int pid, int cpuid)
{
	dkprintf("interrupt_syscall,target pid=%d,target cpuid=%d\n", pid, cpuid);
	ihk_mc_user_context_t ctx;
	long lerror;

	ihk_mc_syscall_arg0(&ctx) = pid;
	ihk_mc_syscall_arg1(&ctx) = cpuid;

	lerror = syscall_generic_forwarding(__NR_kill, &ctx);
	if (lerror) {
		kprintf("interrupt_syscall failed. %ld\n", lerror);
	}
	return;
}

SYSCALL_DECLARE(exit_group)
{
	dkprintf("sys_exit_group,pid=%d\n", cpu_local_var(current)->proc->pid);
	terminate((int)ihk_mc_syscall_arg0(ctx), 0);

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
	error = remove_process_memory_range(cpu_local_var(current)->vm,
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
	struct thread *thread = cpu_local_var(current);
	struct vm_regions *region = &thread->vm->region;
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

		range = lookup_process_memory_range(thread->vm, addr, addr+len);
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

	struct thread *thread = cpu_local_var(current);
	struct vm_regions *region = &thread->vm->region;
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
	int populated_mapping = 0;

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

	ihk_mc_spinlock_lock_noirq(&thread->vm->memory_range_lock);

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
			if (!anon_on_demand) {
				populated_mapping = 1;
			}
		}
	}
	else {
		vrflags |= VR_DEMAND_PAGING;
	}

	if (flags & (MAP_POPULATE | MAP_LOCKED)) {
		populated_mapping = 1;
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
#ifdef ATTACHED_MIC
		/*
		 * XXX: refuse device mapping in attached-mic now:
		 *
		 * In attached-mic, ihk_mc_map_memory() cannot convert into a local
		 * physical address a remote physical address which point KNC's memory.
		 * It seems that ihk_mc_map_memory() needs to set up SMPT.
		 */
		if (error == -ESRCH) {
			error = -ENODEV;
		}
#endif
		if (error == -ESRCH) {
			kprintf("sys_mmap:hit non VREG\n");
			/*
			 * XXX: temporary:
			 *
			 * device mappings are uncachable
			 * until memory type setting codes are implemented.
			 */
			if (1) {
				vrflags &= ~VR_MEMTYPE_MASK;
				vrflags |= VR_MEMTYPE_UC;
			}
			error = devobj_create(fd, len, off, &memobj, &maxprot);
		}
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
		ads.shm_perm.mode = SHM_DEST;
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

	error = add_process_memory_range(thread->vm, addr, addr+len, phys, vrflags, memobj, off);
	if (error) {
		ekprintf("sys_mmap:add_process_memory_range"
				"(%p,%lx,%lx,%lx,%lx) failed %d\n",
				thread->vm, addr, addr+len,
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
	ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);

	if (!error && populated_mapping) {
		error = populate_process_memory(thread->vm, (void *)addr, len);
		if (error) {
			ekprintf("sys_mmap:populate_process_memory"
					"(%p,%p,%lx) failed %d\n",
					thread->vm, (void *)addr, len, error);
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
	struct thread *thread = cpu_local_var(current);
	struct vm_regions *region = &thread->vm->region;
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

	ihk_mc_spinlock_lock_noirq(&thread->vm->memory_range_lock);
	error = do_munmap((void *)addr, len);
	ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);

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
	struct thread *thread = cpu_local_var(current);
	struct vm_regions *region = &thread->vm->region;
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

	ihk_mc_spinlock_lock_noirq(&thread->vm->memory_range_lock);

	first = lookup_process_memory_range(thread->vm, start, start+PAGE_SIZE);

	/* do the mprotect */
	changed = NULL;
	for (addr = start; addr < end; addr = changed->end) {
		if (changed == NULL) {
			range = first;
		}
		else {
			range = next_process_memory_range(thread->vm, changed);
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
			error = split_process_memory_range(thread->vm, range, addr, &range);
			if (error) {
				ekprintf("sys_mprotect(%lx,%lx,%x):split failed. %d\n",
						start, len0, prot, error);
				goto out;
			}
		}
		if (end < range->end) {
			error = split_process_memory_range(thread->vm, range, end, NULL);
			if (error) {
				ekprintf("sys_mprotect(%lx,%lx,%x):split failed. %d\n",
						start, len0, prot, error);
				goto out;
			}
		}

		if ((range->flag ^ protflags) & VR_PROT_WRITE) {
			ro_changed = 1;
		}

		error = change_prot_process_memory_range(thread->vm, range, protflags);
		if (error) {
			ekprintf("sys_mprotect(%lx,%lx,%x):change failed. %d\n",
					start, len0, prot, error);
			goto out;
		}

		if (changed == NULL) {
			changed = range;
		}
		else {
			error = join_process_memory_range(thread->vm, changed, range);
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
	ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);
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
	region->brk_end = extend_process_region(cpu_local_var(current)->vm,
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
	return cpu_local_var(current)->proc->pid;
}

SYSCALL_DECLARE(getppid)
{
	struct thread *thread = cpu_local_var(current);

	return thread->proc->ppid_parent->pid;
}

void
settid(struct thread *thread, int mode, int newcpuid, int oldcpuid)
{
	struct syscall_request request IHK_DMA_ALIGN;
	unsigned long rc;

	request.number = __NR_gettid;
	request.args[0] = mode;
	request.args[1] = thread->proc->pid;
	request.args[2] = newcpuid;
	request.args[3] = oldcpuid;
	rc = do_syscall(&request, ihk_mc_get_processor_id(), thread->proc->pid);
	if (mode != 2) {
		thread->tid = rc;
	}
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
			cpu_local_var(current)->tlsblock_base = address;
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

extern void ptrace_report_signal(struct thread *thread, int sig);
static int ptrace_report_exec(struct thread *thread)
{
	int ptrace = thread->proc->ptrace;

	if (ptrace & (PT_TRACE_EXEC|PTRACE_O_TRACEEXEC)) {
		ihk_mc_kernel_context_t ctx;
		int sig = (SIGTRAP | (PTRACE_EVENT_EXEC << 8));

		memcpy(&ctx, &thread->ctx, sizeof ctx);
		ptrace_report_signal(thread, sig);
		memcpy(&thread->ctx, &ctx, sizeof ctx);
	}
	return 0;
}


static void ptrace_syscall_enter(struct thread *thread)
{
	int ptrace = thread->proc->ptrace;
	struct mcs_rwlock_node_irqsave lock;

	if (ptrace & PT_TRACE_SYSCALL_ENTER) {
		int sig = (SIGTRAP | ((ptrace & PTRACE_O_TRACESYSGOOD) ? 0x80 : 0));
		ptrace_report_signal(thread, sig);
		mcs_rwlock_writer_lock(&thread->proc->update_lock, &lock);
		if (thread->proc->ptrace & PT_TRACE_SYSCALL_ENTER) {
			thread->proc->ptrace |= PT_TRACE_SYSCALL_EXIT;
		}
		mcs_rwlock_writer_unlock(&thread->proc->update_lock, &lock);
	}
}

static void ptrace_syscall_exit(struct thread *thread)
{
	int ptrace = thread->proc->ptrace;

	if (ptrace & PT_TRACE_SYSCALL_EXIT) {
		int sig = (SIGTRAP | ((ptrace & PTRACE_O_TRACESYSGOOD) ? 0x80 : 0));
		ptrace_report_signal(thread, sig);
	}
}

static int ptrace_check_clone_event(struct thread *thread, int clone_flags)
{
	int event = 0;

	if (clone_flags & CLONE_VFORK) {
		/* vfork */
		if (thread->proc->ptrace & PTRACE_O_TRACEVFORK) {
			event = PTRACE_EVENT_VFORK;
		}
		if (thread->proc->ptrace & PTRACE_O_TRACEVFORKDONE) {
			event = PTRACE_EVENT_VFORK_DONE;
		}
	} else if ((clone_flags & CSIGNAL) == SIGCHLD) {
		/* fork */
		if (thread->proc->ptrace & PTRACE_O_TRACEFORK) {
			event = PTRACE_EVENT_FORK;
		}
	} else {
		/* clone */
		if (thread->proc->ptrace & PTRACE_O_TRACECLONE) {
			event = PTRACE_EVENT_CLONE;
		}
	}

	return event;
}

static int ptrace_report_clone(struct thread *thread, struct thread *new, int event)
{
	dkprintf("ptrace_report_clone,enter\n");
	int error = 0;
	long rc;
	struct siginfo info;
	struct mcs_rwlock_node lock;
	struct mcs_rwlock_node updatelock;
	int parent_pid;

	/* Save reason why stopped and process state for wait4() to reap */
	mcs_rwlock_writer_lock_noirq(&thread->proc->update_lock, &lock);
	thread->proc->exit_status = (SIGTRAP | (event << 8));
	/* Transition process state */
	thread->proc->status = PS_TRACED;
	thread->status = PS_TRACED;
	thread->proc->ptrace_eventmsg = new->tid;
	thread->proc->ptrace &= ~PT_TRACE_SYSCALL_MASK;
	parent_pid = thread->proc->parent->pid;
	mcs_rwlock_writer_unlock_noirq(&thread->proc->update_lock, &lock);

	if (event != PTRACE_EVENT_VFORK_DONE) {
		/* PTRACE_EVENT_FORK or PTRACE_EVENT_VFORK or PTRACE_EVENT_CLONE */

		mcs_rwlock_writer_lock_noirq(&new->proc->update_lock, &updatelock);
		/* set ptrace features to new process */
		new->proc->ptrace = thread->proc->ptrace;
		new->proc->ppid_parent = new->proc->parent; /* maybe proc */

		if ((new->proc->ptrace & PT_TRACED) && new->ptrace_debugreg == NULL) {
			alloc_debugreg(new);
		}

		mcs_rwlock_writer_lock_noirq(&new->proc->parent->children_lock, &lock);
		list_del(&new->proc->siblings_list);
		list_add_tail(&new->proc->ptraced_siblings_list, &new->proc->parent->ptraced_children_list);
		mcs_rwlock_writer_unlock_noirq(&new->proc->parent->children_lock, &lock);

		new->proc->parent = thread->proc->parent; /* new ptracing parent */
		mcs_rwlock_writer_lock_noirq(&new->proc->parent->children_lock, &lock);
		list_add_tail(&new->proc->siblings_list, &new->proc->parent->children_list);
		mcs_rwlock_writer_unlock_noirq(&new->proc->parent->children_lock, &lock);

		/* trace and SIGSTOP */
		new->proc->exit_status = SIGSTOP;
		new->proc->status = PS_TRACED;
		new->status = PS_TRACED;

		mcs_rwlock_writer_unlock_noirq(&new->proc->update_lock, &updatelock);
	}

	dkprintf("ptrace_report_clone,kill SIGCHLD\n");
	memset(&info, '\0', sizeof info);
	info.si_signo = SIGCHLD;
	info.si_code = CLD_TRAPPED;
	info._sifields._sigchld.si_pid = thread->proc->pid;
	info._sifields._sigchld.si_status = thread->proc->exit_status;
	rc = do_kill(cpu_local_var(current), parent_pid, -1, SIGCHLD, &info, 0);
	if(rc < 0) {
		dkprintf("ptrace_report_clone,do_kill failed\n");
	}

	/* Wake parent (if sleeping in wait4()) */
	waitq_wakeup(&thread->proc->parent->waitpid_q);

	return error;
}

static void munmap_all(void)
{
	struct thread *thread = cpu_local_var(current);
	struct process_vm *vm = thread->vm;
	struct vm_range *range;
	struct vm_range *next;
	void *addr;
	size_t size;
	int error;

	ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);
	list_for_each_entry_safe(range, next, &vm->vm_range_list, list) {
		addr = (void *)range->start;
		size = range->end - range->start;
		error = do_munmap(addr, size);
		if (error) {
			kprintf("munmap_all():do_munmap(%p,%lx) failed. %d\n",
					addr, size, error);
			/* through */
		}
	}
	ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);

	/* free vm_ranges which do_munmap() failed to remove. */
	free_process_memory_ranges(thread->vm);
	return;
} /* munmap_all() */

SYSCALL_DECLARE(execve)
{
	int error;
	long ret;
	char *empty_envp[1] = {NULL};
	const char *filename = (const char *)ihk_mc_syscall_arg0(ctx);
	char **argv = (char **)ihk_mc_syscall_arg1(ctx);
	char **envp = (char **)ihk_mc_syscall_arg2(ctx) ? 
		(char **)ihk_mc_syscall_arg2(ctx) : empty_envp;

	char *argv_flat = NULL;
	int argv_flat_len = 0;
	char *envp_flat = NULL;
	int envp_flat_len = 0;
	
	struct syscall_request request IHK_DMA_ALIGN;
	struct program_load_desc *desc;
	struct thread *thread = cpu_local_var(current);
	struct process_vm *vm = thread->vm;
	struct vm_range *range;
	struct process *proc = thread->proc;
	int i;

	ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);

	range = lookup_process_memory_range(vm, (unsigned long)filename, 
			(unsigned long)filename+1);

	if (range == NULL || !(range->flag & VR_PROT_READ)) {
		ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);
		kprintf("execve(): ERROR: filename is bad address\n");
		return -EFAULT;
	}
	
	ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);

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
	ret = do_syscall(&request, ihk_mc_get_processor_id(), 0);

	if (ret != 0) {
		kprintf("execve(): ERROR: host failed to load elf header, errno: %d\n", 
				ret);
		return -ret;
	}

	dkprintf("execve(): ELF desc received, num sections: %d\n",
		desc->num_sections);
	
	if (desc->shell_path[0]) {
		dkprintf("execve(): shell interpreter: %s\n", desc->shell_path);
	}

	/* Flatten argv and envp into kernel-space buffers */
	argv_flat_len = flatten_strings(-1, (desc->shell_path[0] ? 
				desc->shell_path : NULL), argv, &argv_flat);
	if (argv_flat_len == 0) {
		kprintf("ERROR: no argv for executable: %s?\n", filename);
		return -EINVAL;
	}

	envp_flat_len = flatten_strings(-1, NULL, envp, &envp_flat);
	if (envp_flat_len == 0) {
		kprintf("ERROR: no envp for executable: %s?\n", filename);
		return -EINVAL;
	}

	/* Unmap all memory areas of the process, userspace will be gone */
	munmap_all();

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

	if (do_syscall(&request, ihk_mc_get_processor_id(), 0)) {
		kprintf("execve(): ERROR: clearing PTEs in host process\n");
		panic("");
	}		

	/* Request host to transfer ELF image */
	request.number = __NR_execve;  
	request.args[0] = 2;  /* 2nd phase - transfer ELF image */
	request.args[1] = virt_to_phys(desc);
	request.args[2] = sizeof(struct program_load_desc) + 
		sizeof(struct program_image_section) * desc->num_sections;

	ret = do_syscall(&request, ihk_mc_get_processor_id(), 0);

	if (ret != 0) {
		kprintf("execve(): PANIC: host failed to load elf image\n");
		panic("");
	}

	for(i = 0; i < _NSIG; i++){
		if(thread->sigcommon->action[i].sa.sa_handler != SIG_IGN &&
		   thread->sigcommon->action[i].sa.sa_handler != SIG_DFL)
			thread->sigcommon->action[i].sa.sa_handler = SIG_DFL;
	}

	error = ptrace_report_exec(cpu_local_var(current));
	if(error) {
		kprintf("execve(): ERROR: ptrace_report_exec()\n");
	}

	/* Switch to new execution context */
	dkprintf("execve(): switching to new process\n");
	proc->execed = 1;
	
	/* Lock run queue because enter_user_mode expects to release it */
	cpu_local_var(runq_irqstate) = 
		ihk_mc_spinlock_lock(&(get_this_cpu_local_var()->runq_lock));

	ihk_mc_switch_context(NULL, &cpu_local_var(current)->ctx, 
		cpu_local_var(current));

	/* Never reach here */
	return 0;
}

unsigned long do_fork(int clone_flags, unsigned long newsp,
                      unsigned long parent_tidptr, unsigned long child_tidptr,
                      unsigned long tlsblock_base, unsigned long curpc,
                      unsigned long cursp)
{
	int cpuid;
	struct thread *new;
	struct syscall_request request1 IHK_DMA_ALIGN;
	int ptrace_event = 0;
	int termsig = clone_flags & 0x000000ff;

    dkprintf("do_fork,flags=%08x,newsp=%lx,ptidptr=%lx,ctidptr=%lx,tls=%lx,curpc=%lx,cursp=%lx",
            clone_flags, newsp, parent_tidptr, child_tidptr, tlsblock_base, curpc, cursp);

	dkprintf("do_fork(): stack_pointr passed in: 0x%lX, stack pointer of caller: 0x%lx\n",
			 newsp, cursp);
	
	if (((clone_flags & CLONE_VM) && !(clone_flags & CLONE_THREAD)) ||
		(!(clone_flags & CLONE_VM) && (clone_flags & CLONE_THREAD))) {
		kprintf("clone(): ERROR: CLONE_VM and CLONE_THREAD should be set together\n");
		return -EINVAL;
	}

	if (termsig < 0 || _NSIG < termsig) {
		return -EINVAL;
	}

	if((clone_flags & CLONE_SIGHAND) &&
	   !(clone_flags & CLONE_VM)){
		return -EINVAL;
	}
	if((clone_flags & CLONE_THREAD) &&
	   !(clone_flags & CLONE_SIGHAND)){
		return -EINVAL;
	}
	if((clone_flags & CLONE_FS) &&
	   (clone_flags & CLONE_NEWNS)){
		return -EINVAL;
	}
	if((clone_flags & CLONE_NEWIPC) &&
	   (clone_flags & CLONE_SYSVSEM)){
		return -EINVAL;
	}
	if((clone_flags & CLONE_NEWPID) &&
	   (clone_flags & CLONE_THREAD)){
		return -EINVAL;
	}

	cpuid = obtain_clone_cpuid();
    if (cpuid == -1) {
		kprintf("do_fork,core not available\n");
        return -EAGAIN;
    }

	new = clone_thread(cpu_local_var(current), curpc,
	                    newsp ? newsp : cursp, clone_flags);
	
	if (!new) {
		release_cpuid(cpuid);
		return -ENOMEM;
	}

	cpu_set(cpuid, &new->vm->address_space->cpu_set,
	        &new->vm->address_space->cpu_set_lock);

	if (clone_flags & CLONE_VM) {
		settid(new, 1, cpuid, -1);
	}
	/* fork() a new process on the host */
	else {
		request1.number = __NR_fork;
		request1.args[0] = 0;
		if(clone_flags & CLONE_PARENT){
			if(cpu_local_var(current)->proc->ppid_parent->pid != 1)
				request1.args[0] = clone_flags;
		}
		new->proc->pid = do_syscall(&request1, ihk_mc_get_processor_id(), 0);
		if (new->proc->pid == -1) {
			kprintf("ERROR: forking host process\n");
			
			/* TODO: clean-up new */
			release_cpuid(cpuid);
			return -EFAULT;
		}

		/* In a single threaded process TID equals to PID */
		settid(new, 0, cpuid, -1);
		new->vm->address_space->pids[0] = new->proc->pid;

		dkprintf("fork(): new pid: %d\n", new->proc->pid);
		/* clear user space PTEs and set new rpgtable so that consequent 
		 * page faults will look up the right mappings */
		request1.number = __NR_munmap;
		request1.args[0] = new->vm->region.user_start;
		request1.args[1] = new->vm->region.user_end - 
			new->vm->region.user_start;
		/* 3rd parameter denotes new rpgtable of host process */
		request1.args[2] = virt_to_phys(new->vm->address_space->page_table);
		request1.args[3] = new->proc->pid;

		dkprintf("fork(): requesting PTE clear and rpgtable (0x%lx) update\n",
				request1.args[2]);

		if (do_syscall(&request1, ihk_mc_get_processor_id(), new->proc->pid)) {
			kprintf("ERROR: clearing PTEs in host process\n");
		}		
	}

	if (clone_flags & CLONE_PARENT_SETTID) {
		dkprintf("clone_flags & CLONE_PARENT_SETTID: 0x%lX\n",
		         parent_tidptr);
		
		*(int*)parent_tidptr = new->tid;
	}
	
	if (clone_flags & CLONE_CHILD_CLEARTID) {
		dkprintf("clone_flags & CLONE_CHILD_CLEARTID: 0x%lX\n", 
			     child_tidptr);

		new->clear_child_tid = (int*)child_tidptr;
	}
	
	if (clone_flags & CLONE_CHILD_SETTID) {
		unsigned long phys;
		dkprintf("clone_flags & CLONE_CHILD_SETTID: 0x%lX\n",
				child_tidptr);

		if (ihk_mc_pt_virt_to_phys(new->vm->address_space->page_table, 
					(void *)child_tidptr, &phys)) { 
			kprintf("ERROR: looking up physical addr for child process\n");
			release_cpuid(cpuid);
			return -EFAULT; 
		}
	
		*((int*)phys_to_virt(phys)) = new->tid;
	}
	
	if (clone_flags & CLONE_SETTLS) {
		dkprintf("clone_flags & CLONE_SETTLS: 0x%lX\n", 
			     tlsblock_base);
		
		new->tlsblock_base = tlsblock_base;
	}
	else { 
		new->tlsblock_base = 
			cpu_local_var(current)->tlsblock_base;
	}

	ihk_mc_syscall_ret(new->uctx) = 0;

	new->status = PS_RUNNING;
	chain_thread(new);
	if (!(clone_flags & CLONE_VM)) {
		new->proc->status = PS_RUNNING;
		if(clone_flags & CLONE_PARENT){
			struct mcs_rwlock_node_irqsave lock;
			struct process *proc = cpu_local_var(current)->proc;
			struct process *parent;
			struct mcs_rwlock_node parent_lock;

			mcs_rwlock_reader_lock(&proc->update_lock, &lock);
			parent = proc->ppid_parent;
			mcs_rwlock_reader_lock_noirq(&parent->update_lock, &parent_lock);
			if(parent->status == PS_EXITED || parent->status == PS_ZOMBIE){
				mcs_rwlock_reader_unlock_noirq(&parent->update_lock, &parent_lock);
				parent = cpu_local_var(resource_set)->pid1;
				mcs_rwlock_reader_lock_noirq(&parent->update_lock, &parent_lock);
			}
			new->proc->parent = parent;
			new->proc->ppid_parent = parent;
			new->proc->nowait = 1;
			chain_process(new->proc);
			mcs_rwlock_reader_unlock_noirq(&parent->update_lock, &parent_lock);
			mcs_rwlock_reader_unlock(&proc->update_lock, &lock);
		}
		else
			chain_process(new->proc);
	}

	if (cpu_local_var(current)->proc->ptrace) {
		ptrace_event = ptrace_check_clone_event(cpu_local_var(current), clone_flags);
		if (ptrace_event) {
			ptrace_report_clone(cpu_local_var(current), new, ptrace_event);
		}
	}

	dkprintf("clone: kicking scheduler!,cpuid=%d pid=%d tid %d -> tid=%d\n", 
		cpuid, new->proc->pid, 
		cpu_local_var(current)->tid,
		new->tid);

	runq_add_thread(new, cpuid);

	if (ptrace_event) {
		schedule();
	}

	return new->tid;
}

SYSCALL_DECLARE(vfork)
{
    return do_fork(CLONE_VFORK|SIGCHLD, 0, 0, 0, 0, ihk_mc_syscall_pc(ctx), ihk_mc_syscall_sp(ctx));
}

SYSCALL_DECLARE(clone)
{
    return do_fork((int)ihk_mc_syscall_arg0(ctx), ihk_mc_syscall_arg1(ctx),
                   ihk_mc_syscall_arg2(ctx), ihk_mc_syscall_arg3(ctx),
                   ihk_mc_syscall_arg4(ctx), ihk_mc_syscall_pc(ctx),
                   ihk_mc_syscall_sp(ctx));
}

SYSCALL_DECLARE(set_tid_address)
{
	cpu_local_var(current)->clear_child_tid = 
	                        (int*)ihk_mc_syscall_arg0(ctx);

	return cpu_local_var(current)->proc->pid;
}

static unsigned long
timespec_to_jiffy(const struct timespec *ats)
{
	return ats->tv_sec * 100 + ats->tv_nsec / 10000000;
}

SYSCALL_DECLARE(times)
{
	struct tms {
		unsigned long tms_utime;
		unsigned long tms_stime;
		unsigned long tms_cutime;
		unsigned long tms_cstime;
	};
	struct tms mytms;
	struct tms *buf = (struct tms *)ihk_mc_syscall_arg0(ctx);
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct timespec ats;

	mytms.tms_utime = timespec_to_jiffy(&thread->utime);
	mytms.tms_stime = timespec_to_jiffy(&thread->stime);
	ats.tv_sec = proc->utime.tv_sec;
	ats.tv_nsec = proc->utime.tv_nsec;
	ts_add(&ats, &proc->utime_children);
	mytms.tms_cutime = timespec_to_jiffy(&ats);
	ats.tv_sec = proc->stime.tv_sec;
	ats.tv_nsec = proc->stime.tv_nsec;
	ts_add(&ats, &proc->stime_children);
	mytms.tms_cstime = timespec_to_jiffy(&ats);
	if(copy_to_user(buf, &mytms, sizeof mytms))
		return -EFAULT;
	if(gettime_local_support){
		calculate_time_from_tsc(&ats);
	}
	else{
		ats.tv_sec = 0;
		ats.tv_nsec = 0;
	}

	return timespec_to_jiffy(&ats);
}

SYSCALL_DECLARE(kill)
{
	int pid = ihk_mc_syscall_arg0(ctx);
	int sig = ihk_mc_syscall_arg1(ctx);
	struct thread *thread = cpu_local_var(current);
	struct siginfo info;
	int error;

	memset(&info, '\0', sizeof info);
	info.si_signo = sig;
	info.si_code = SI_USER;
	info._sifields._kill.si_pid = thread->proc->pid;

	dkprintf("sys_kill,enter,pid=%d,sig=%d\n", pid, sig);
	error = do_kill(thread, pid, -1, sig, &info, 0);
	dkprintf("sys_kill,returning,pid=%d,sig=%d,error=%d\n", pid, sig, error);
	return error;
}

// see linux-2.6.34.13/kernel/signal.c
SYSCALL_DECLARE(tgkill)
{
	int tgid = ihk_mc_syscall_arg0(ctx);
	int tid = ihk_mc_syscall_arg1(ctx);
	int sig = ihk_mc_syscall_arg2(ctx);
	struct thread *thread = cpu_local_var(current);
	struct siginfo info;

	memset(&info, '\0', sizeof info);
	info.si_signo = sig;
	info.si_code = SI_TKILL;
	info._sifields._kill.si_pid = thread->proc->pid;

	if(tid <= 0)
		return -EINVAL;
	if(tgid <= 0 && tgid != -1)
		return -EINVAL;

	return do_kill(thread, tgid, tid, sig, &info, 0);
}

SYSCALL_DECLARE(tkill)
{
	int tid = ihk_mc_syscall_arg0(ctx);
	int sig = ihk_mc_syscall_arg1(ctx);
	struct thread *thread = cpu_local_var(current);
	struct siginfo info;

	memset(&info, '\0', sizeof info);
	info.si_signo = sig;
	info.si_code = SI_TKILL;
	info._sifields._kill.si_pid = thread->proc->pid;

	if(tid <= 0)
		return -EINVAL;

	return do_kill(thread, -1, tid, sig, &info, 0);
}

int *
getcred(int *_buf)
{
	int	*buf;
	struct syscall_request request IHK_DMA_ALIGN;
	unsigned long phys;

	if((((unsigned long)_buf) ^ ((unsigned long)(_buf + 8))) & ~4095)
		buf = _buf + 8;
	else
		buf = _buf;
	phys = virt_to_phys(buf);
	request.number = __NR_setfsuid;
	request.args[0] = phys;
	request.args[1] = 1;
	do_syscall(&request, ihk_mc_get_processor_id(), 0);

	return buf;
}

void
do_setresuid()
{
	int	_buf[16];
	int	*buf;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;

	buf = getcred(_buf);

	proc->ruid = buf[0];
	proc->euid = buf[1];
	proc->suid = buf[2];
	proc->fsuid = buf[3];
}

void
do_setresgid()
{
	int	_buf[16];
	int	*buf;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;

	buf = getcred(_buf);

	proc->rgid = buf[4];
	proc->egid = buf[5];
	proc->sgid = buf[6];
	proc->fsgid = buf[7];
}

SYSCALL_DECLARE(setresuid)
{
	int rc;

	rc = syscall_generic_forwarding(__NR_setresuid, ctx);
	if(rc == 0){
		do_setresuid();
	}
	return rc;
}

SYSCALL_DECLARE(setreuid)
{
	int rc;

	rc = syscall_generic_forwarding(__NR_setreuid, ctx);
	if(rc == 0){
		do_setresuid();
	}
	return rc;
}

SYSCALL_DECLARE(setuid)
{
	long rc;

	rc = syscall_generic_forwarding(__NR_setuid, ctx);
	if(rc == 0){
		do_setresuid();
	}
	return rc;
}

SYSCALL_DECLARE(setfsuid)
{
	int fsuid = (int)ihk_mc_syscall_arg0(ctx);;
	unsigned long newfsuid;
	struct syscall_request request IHK_DMA_ALIGN;

	request.number = __NR_setfsuid;
	request.args[0] = fsuid;
	request.args[1] = 0;
	newfsuid = do_syscall(&request, ihk_mc_get_processor_id(), 0);
	do_setresuid();
	return newfsuid;
}

SYSCALL_DECLARE(setresgid)
{
	int rc;

	rc = syscall_generic_forwarding(__NR_setresgid, ctx);
	if(rc == 0){
		do_setresgid();
	}
	return rc;
}

SYSCALL_DECLARE(setregid)
{
	int rc;

	rc = syscall_generic_forwarding(__NR_setregid, ctx);
	if(rc == 0){
		do_setresgid();
	}
	return rc;
}

SYSCALL_DECLARE(setgid)
{
	long rc;

	rc = syscall_generic_forwarding(__NR_setgid, ctx);
	if(rc == 0){
		do_setresgid();
	}
	return rc;
}

SYSCALL_DECLARE(setfsgid)
{
	int fsgid = (int)ihk_mc_syscall_arg0(ctx);;
	unsigned long newfsgid;
	struct syscall_request request IHK_DMA_ALIGN;

	request.number = __NR_setfsuid;
	request.args[0] = fsgid;
	request.args[1] = 0;
	newfsgid = do_syscall(&request, ihk_mc_get_processor_id(), 0);
	do_setresgid();
	return newfsgid;
}

SYSCALL_DECLARE(getuid)
{
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;

	return proc->ruid;
}

SYSCALL_DECLARE(geteuid)
{
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;

	return proc->euid;
}

SYSCALL_DECLARE(getresuid)
{
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	int *ruid = (int *)ihk_mc_syscall_arg0(ctx);
	int *euid = (int *)ihk_mc_syscall_arg1(ctx);
	int *suid = (int *)ihk_mc_syscall_arg2(ctx);

	if(copy_to_user(ruid, &proc->ruid, sizeof(int)))
		return -EFAULT;
	if(copy_to_user(euid, &proc->euid, sizeof(int)))
		return -EFAULT;
	if(copy_to_user(suid, &proc->suid, sizeof(int)))
		return -EFAULT;

	return 0;
}

SYSCALL_DECLARE(getgid)
{
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;

	return proc->rgid;
}

SYSCALL_DECLARE(getegid)
{
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;

	return proc->egid;
}

SYSCALL_DECLARE(getresgid)
{
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	int *rgid = (int *)ihk_mc_syscall_arg0(ctx);
	int *egid = (int *)ihk_mc_syscall_arg1(ctx);
	int *sgid = (int *)ihk_mc_syscall_arg2(ctx);

	if(copy_to_user(rgid, &proc->rgid, sizeof(int)))
		return -EFAULT;
	if(copy_to_user(egid, &proc->egid, sizeof(int)))
		return -EFAULT;
	if(copy_to_user(sgid, &proc->sgid, sizeof(int)))
		return -EFAULT;

	return 0;
}

SYSCALL_DECLARE(setpgid)
{
	int pid = ihk_mc_syscall_arg0(ctx);
	int pgid = ihk_mc_syscall_arg1(ctx);
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct mcs_rwlock_node_irqsave lock;
	long rc;

	if(pid == 0)
		pid = proc->pid;
	if(pgid == 0)
		pgid = pid;

	if(proc->pid != pid){
		proc = find_process(pid, &lock);
		if(proc){
			if(proc->execed){
				process_unlock(proc, &lock);
				return -EACCES;
			}
			process_unlock(proc, &lock);
		}
		else
			return -ESRCH;
	}

	rc = syscall_generic_forwarding(__NR_setpgid, ctx);
	if(rc == 0){
		proc = find_process(pid, &lock);
		if(proc){
			proc->pgid = pgid;
			process_unlock(proc, &lock);
		}
	}
	return rc;
}

SYSCALL_DECLARE(set_robust_list)
{
	return -ENOSYS;
}

int
do_sigaction(int sig, struct k_sigaction *act, struct k_sigaction *oact)
{
	struct thread *thread = cpu_local_var(current);
	struct k_sigaction *k;
	long	irqstate;
	ihk_mc_user_context_t ctx0;

	irqstate = ihk_mc_spinlock_lock(&thread->sigcommon->lock);
	k = thread->sigcommon->action + sig - 1;
	if(oact)
		memcpy(oact, k, sizeof(struct k_sigaction));
	if(act)
		memcpy(k, act, sizeof(struct k_sigaction));
	ihk_mc_spinlock_unlock(&thread->sigcommon->lock, irqstate);

	if(act){
		ihk_mc_syscall_arg0(&ctx0) = sig;
		ihk_mc_syscall_arg1(&ctx0) = (unsigned long)act->sa.sa_handler;
		ihk_mc_syscall_arg2(&ctx0) = act->sa.sa_flags;
		syscall_generic_forwarding(__NR_rt_sigaction, &ctx0);
	}
	return 0;
}

SYSCALL_DECLARE(read)
{
	int fd = ihk_mc_syscall_arg0(ctx);
	long rc;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct mckfd *fdp;
	long irqstate;

	irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);
	for(fdp = proc->mckfd; fdp; fdp = fdp->next)
		if(fdp->fd == fd)
			break;
	ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);

	if(fdp && fdp->read_cb){
kprintf("read: found system fd %d\n", fd);
		rc = fdp->read_cb(fdp, ctx);
	}
	else{
		rc = syscall_generic_forwarding(__NR_read, ctx);
	}
	return rc;
}

SYSCALL_DECLARE(ioctl)
{
	int fd = ihk_mc_syscall_arg0(ctx);
	long rc;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct mckfd *fdp;
	long irqstate;

	irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);
	for(fdp = proc->mckfd; fdp; fdp = fdp->next)
		if(fdp->fd == fd)
			break;
	ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);

	if(fdp && fdp->ioctl_cb){
kprintf("ioctl: found system fd %d\n", fd);
		rc = fdp->ioctl_cb(fdp, ctx);
	}
	else{
		rc = syscall_generic_forwarding(__NR_ioctl, ctx);
	}
	return rc;
}

SYSCALL_DECLARE(close)
{
	int fd = ihk_mc_syscall_arg0(ctx);
	long rc;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct mckfd *fdp;
	struct mckfd *fdq;
	long irqstate;

	irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);
	for(fdp = proc->mckfd, fdq = NULL; fdp; fdq = fdp, fdp = fdp->next)
		if(fdp->fd == fd)
			break;

	if(fdp){
kprintf("close: found system fd %d pid=%d\n", fd, proc->pid);
		if(fdq)
			fdq->next = fdp->next;
		else
			proc->mckfd = fdp->next;
		ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);
		if(fdp->close_cb)
			fdp->close_cb(fdp, ctx);
		kfree(fdp);
		rc = syscall_generic_forwarding(__NR_close, ctx);
	}
	else{
		ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);
		rc = syscall_generic_forwarding(__NR_close, ctx);
	}
	return rc;
}

SYSCALL_DECLARE(rt_sigprocmask)
{
	int how = ihk_mc_syscall_arg0(ctx);
	const sigset_t *set = (const sigset_t *)ihk_mc_syscall_arg1(ctx);
	sigset_t *oldset = (sigset_t *)ihk_mc_syscall_arg2(ctx);
	size_t sigsetsize = (size_t)ihk_mc_syscall_arg3(ctx);
	struct thread *thread = cpu_local_var(current);
	__sigset_t wsig;
	ihk_mc_user_context_t ctx0;

	if(sigsetsize != sizeof(sigset_t))
		return -EINVAL;

	if(set &&
	   how != SIG_BLOCK &&
	   how != SIG_UNBLOCK &&
	   how != SIG_SETMASK)
		return -EINVAL;

	if(oldset){
		wsig = thread->sigmask.__val[0];
		if(copy_to_user(oldset->__val, &wsig, sizeof wsig))
			goto fault;
	}
	if(set){
		if(copy_from_user(&wsig, set->__val, sizeof wsig))
			goto fault;
		switch(how){
		    case SIG_BLOCK:
			thread->sigmask.__val[0] |= wsig;
			break;
		    case SIG_UNBLOCK:
			thread->sigmask.__val[0] &= ~wsig;
			break;
		    case SIG_SETMASK:
			thread->sigmask.__val[0] = wsig;
			break;
		}
	}
	thread->sigmask.__val[0] &= ~__sigmask(SIGKILL);
	thread->sigmask.__val[0] &= ~__sigmask(SIGSTOP);
	wsig = thread->sigmask.__val[0];

	ihk_mc_syscall_arg0(&ctx0) = wsig;
	syscall_generic_forwarding(__NR_rt_sigprocmask, &ctx0);
	return 0;
fault:
	return -EFAULT;
}

SYSCALL_DECLARE(rt_sigpending)
{
	int flag;
	struct sig_pending *pending;
	struct list_head *head;
	ihk_spinlock_t *lock;
	__sigset_t w = 0;
	struct thread *thread = cpu_local_var(current);
	sigset_t *set = (sigset_t *)ihk_mc_syscall_arg0(ctx);
	size_t sigsetsize = (size_t)ihk_mc_syscall_arg1(ctx);

	if (sigsetsize > sizeof(sigset_t))
		return -EINVAL;

	lock = &thread->sigcommon->lock;
	head = &thread->sigcommon->sigpending;
	flag = ihk_mc_spinlock_lock(lock);
	list_for_each_entry(pending, head, list){
		w |= pending->sigmask.__val[0];
	}
	ihk_mc_spinlock_unlock(lock, flag);

	lock = &thread->sigpendinglock;
	head = &thread->sigpending;
	flag = ihk_mc_spinlock_lock(lock);
	list_for_each_entry(pending, head, list){
		w |= pending->sigmask.__val[0];
	}
	ihk_mc_spinlock_unlock(lock, flag);

	if(copy_to_user(set->__val, &w, sizeof w))
		return -EFAULT;

	return 0;
}

SYSCALL_DECLARE(signalfd)
{
	return -EOPNOTSUPP;
}

SYSCALL_DECLARE(signalfd4)
{
	int fd = ihk_mc_syscall_arg0(ctx);
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct mckfd *sfd;
	long    irqstate;
	sigset_t *maskp = (sigset_t *)ihk_mc_syscall_arg1(ctx);;
	__sigset_t mask;
	size_t sigsetsize = (size_t)ihk_mc_syscall_arg2(ctx);
	int flags = ihk_mc_syscall_arg3(ctx);

	if(sigsetsize != sizeof(sigset_t))
		return -EINVAL;
	if(copy_from_user(&mask, maskp, sizeof mask))
		return -EFAULT;
	if(flags & ~(SFD_NONBLOCK | SFD_CLOEXEC))
		return -EINVAL;

	if(fd == -1){
		struct syscall_request request IHK_DMA_ALIGN;

		request.number = __NR_signalfd4;
		request.args[0] = 0;
		request.args[1] = flags;
		fd = do_syscall(&request, ihk_mc_get_processor_id(), 0);
		if(fd < 0){
			return fd;
		}
		sfd = kmalloc(sizeof(struct mckfd), IHK_MC_AP_NOWAIT);
		if(!sfd)
			return -ENOMEM;
		sfd->fd = fd;
		irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);
		sfd->next = proc->mckfd;
		proc->mckfd = sfd;
	}
	else{
		irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);
		for(sfd = proc->mckfd; sfd; sfd = sfd->next)
			if(sfd->fd == fd)
				break;
		if(!sfd){
			ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);
			return -EINVAL;
		}
	}
	memcpy(&sfd->data, &mask, sizeof mask);
	ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);
	return sfd->fd;
}

static long
perf_event_read(struct mckfd *sfd, ihk_mc_user_context_t *ctx)
{
	return 0;
}

static int
perf_event_ioctl(struct mckfd *sfd, ihk_mc_user_context_t *ctx)
{
	return 0;
}

static int
perf_event_close(struct mckfd *sfd, ihk_mc_user_context_t *ctx)
{
	return 0;
}

SYSCALL_DECLARE(perf_event_open)
{
	struct syscall_request request IHK_DMA_ALIGN;
	struct thread *thread = cpu_local_var(current);
	struct process *proc = thread->proc;
	struct mckfd *sfd;
	int fd;
	long irqstate;

	request.number = __NR_perf_event_open;
	request.args[0] = 0;
	fd = do_syscall(&request, ihk_mc_get_processor_id(), 0);
	if(fd < 0){
		return fd;
	}
	sfd = kmalloc(sizeof(struct mckfd), IHK_MC_AP_NOWAIT);
	if(!sfd)
		return -ENOMEM;
	sfd->fd = fd;
	sfd->read_cb = perf_event_read;
	sfd->ioctl_cb = perf_event_ioctl;
	sfd->close_cb = perf_event_close;
	irqstate = ihk_mc_spinlock_lock(&proc->mckfd_lock);
	sfd->next = proc->mckfd;
	proc->mckfd = sfd;
	ihk_mc_spinlock_unlock(&proc->mckfd_lock, irqstate);
	return sfd->fd;
}

SYSCALL_DECLARE(rt_sigtimedwait)
{
	const sigset_t *set = (const sigset_t *)ihk_mc_syscall_arg0(ctx);
	siginfo_t *info = (siginfo_t *)ihk_mc_syscall_arg1(ctx);
	void *timeout = (void *)ihk_mc_syscall_arg2(ctx);
	size_t sigsetsize = (size_t)ihk_mc_syscall_arg3(ctx);
	struct thread *thread = cpu_local_var(current);
	siginfo_t winfo;
	__sigset_t bset;
	__sigset_t wset;
	__sigset_t nset;
	struct timespec wtimeout;
	unsigned long flag;
	struct sig_pending *pending;
	struct list_head *head;
	ihk_spinlock_t *lock;
	int w;
	int sig;
        struct timespec ats;
        struct timespec ets;

	if (sigsetsize > sizeof(sigset_t))
		return -EINVAL;

	if(set == NULL)
		return -EFAULT;
	memset(&winfo, '\0', sizeof winfo);
	if(copy_from_user(&wset, set, sizeof wset))
		return -EFAULT;
	if(timeout){
		if(copy_from_user(&wtimeout, timeout, sizeof wtimeout))
			return -EFAULT;
		if(wtimeout.tv_nsec >= 1000000000L || wtimeout.tv_nsec < 0 ||
		   wtimeout.tv_sec < 0)
			return -EINVAL;
		if (!gettime_local_support &&
		    (wtimeout.tv_sec || wtimeout.tv_nsec)) {
			return -EOPNOTSUPP;
		}
	}

	wset &= ~__sigmask(SIGKILL);
	wset &= ~__sigmask(SIGSTOP);
	bset = thread->sigmask.__val[0];
	thread->sigmask.__val[0] = bset | wset;
	nset = ~(bset | wset);

	if(timeout){
		if (gettime_local_support) {
			calculate_time_from_tsc(&ets);
			ets.tv_sec += wtimeout.tv_sec;
			ets.tv_nsec += wtimeout.tv_nsec;
			if(ets.tv_nsec >= 1000000000L){
				ets.tv_sec++;
				ets.tv_nsec -= 1000000000L;
			}
		}
		else {
			memset(&ats, '\0', sizeof ats);
			memset(&ets, '\0', sizeof ets);
		}
	}

	thread->sigevent = 1;
	for(;;){
		while(thread->sigevent == 0){
			if(timeout){
				if (gettime_local_support)
					calculate_time_from_tsc(&ats);
				if(ats.tv_sec > ets.tv_sec ||
				   (ats.tv_sec == ets.tv_sec &&
				    ats.tv_nsec >= ets.tv_nsec)){
					return -EAGAIN;
				}
			}

			cpu_pause();
		}

		lock = &thread->sigcommon->lock;
		head = &thread->sigcommon->sigpending;
		flag = ihk_mc_spinlock_lock(lock);
		list_for_each_entry(pending, head, list){
			if(pending->sigmask.__val[0] & wset)
				break;
		}

		if(&pending->list == head){
			ihk_mc_spinlock_unlock(lock, flag);

			lock = &thread->sigpendinglock;
			head = &thread->sigpending;
			flag = ihk_mc_spinlock_lock(lock);
			list_for_each_entry(pending, head, list){
				if(pending->sigmask.__val[0] & wset)
					break;
			}
		}

		if(&pending->list != head){
			list_del(&pending->list);
			thread->sigmask.__val[0] = bset;
			ihk_mc_spinlock_unlock(lock, flag);
			break;
		}
		ihk_mc_spinlock_unlock(lock, flag);

		lock = &thread->sigcommon->lock;
		head = &thread->sigcommon->sigpending;
		flag = ihk_mc_spinlock_lock(lock);
		list_for_each_entry(pending, head, list){
			if(pending->sigmask.__val[0] & nset)
				break;
		}

		if(&pending->list == head){
			ihk_mc_spinlock_unlock(lock, flag);

			lock = &thread->sigpendinglock;
			head = &thread->sigpending;
			flag = ihk_mc_spinlock_lock(lock);
			list_for_each_entry(pending, head, list){
				if(pending->sigmask.__val[0] & nset)
					break;
			}
		}

		if(&pending->list != head){
			list_del(&pending->list);
			thread->sigmask.__val[0] = bset;
			ihk_mc_spinlock_unlock(lock, flag);
			do_signal(-EINTR, NULL, thread, pending, 0);
			return -EINTR;
		}
		ihk_mc_spinlock_unlock(lock, flag);
		thread->sigevent = 0;
	}

	if(info){
		if(copy_to_user(info, &pending->info, sizeof(siginfo_t))){
			kfree(pending);
			return -EFAULT;
		}
	}
	for(w = pending->sigmask.__val[0], sig = 0; w; sig++, w >>= 1);
	kfree(pending);

	return sig;
}

SYSCALL_DECLARE(rt_sigqueueinfo)
{
	int pid = (int)ihk_mc_syscall_arg0(ctx);
	int sig = (int)ihk_mc_syscall_arg1(ctx);
	void *winfo = (void *)ihk_mc_syscall_arg2(ctx);
	struct siginfo info;

	if(pid <= 0)
		return -ESRCH;

	if(copy_from_user(&info, winfo, sizeof info))
		return -EFAULT;

	return do_kill(cpu_local_var(current), pid, -1, sig, &info, 0);
}

static int
do_sigsuspend(struct thread *thread, const sigset_t *set)
{
	__sigset_t wset;
	__sigset_t bset;
	unsigned long flag;
	struct sig_pending *pending;
	struct list_head *head;
	ihk_spinlock_t *lock;

	wset = set->__val[0];
	wset &= ~__sigmask(SIGKILL);
	wset &= ~__sigmask(SIGSTOP);
	bset = thread->sigmask.__val[0];
	thread->sigmask.__val[0] = wset;

	thread->sigevent = 1;
	for(;;){
		while(thread->sigevent == 0)
			cpu_pause();

		lock = &thread->sigcommon->lock;
		head = &thread->sigcommon->sigpending;
		flag = ihk_mc_spinlock_lock(lock);
		list_for_each_entry(pending, head, list){
			if(!(pending->sigmask.__val[0] & wset))
				break;
		}

		if(&pending->list == head){
			ihk_mc_spinlock_unlock(lock, flag);

			lock = &thread->sigpendinglock;
			head = &thread->sigpending;
			flag = ihk_mc_spinlock_lock(lock);
			list_for_each_entry(pending, head, list){
				if(!(pending->sigmask.__val[0] & wset))
					break;
			}
		}
		if(&pending->list == head){
			ihk_mc_spinlock_unlock(lock, flag);
			thread->sigevent = 0;
			continue;
		}

		list_del(&pending->list);
		ihk_mc_spinlock_unlock(lock, flag);
		thread->sigmask.__val[0] = bset;
		do_signal(-EINTR, NULL, thread, pending, 0);
		break;
	}
	return -EINTR;
}

SYSCALL_DECLARE(pause)
{
	struct thread *thread = cpu_local_var(current);

	return do_sigsuspend(thread, &thread->sigmask);
}

SYSCALL_DECLARE(rt_sigsuspend)
{
	struct thread *thread = cpu_local_var(current);
	const sigset_t *set = (const sigset_t *)ihk_mc_syscall_arg0(ctx);
	size_t sigsetsize = (size_t)ihk_mc_syscall_arg1(ctx);
	sigset_t wset;

	if (sigsetsize > sizeof(sigset_t))
		return -EINVAL;
	if(copy_from_user(&wset, set, sizeof wset))
		return -EFAULT;

	return do_sigsuspend(thread, &wset);
}

SYSCALL_DECLARE(sigaltstack)
{
	struct thread *thread = cpu_local_var(current);
	const stack_t *ss = (const stack_t *)ihk_mc_syscall_arg0(ctx);
	stack_t *oss = (stack_t *)ihk_mc_syscall_arg1(ctx);
	stack_t	wss;

	if(oss)
		if(copy_to_user(oss, &thread->sigstack, sizeof wss))
			return -EFAULT;
	if(ss){
		if(copy_from_user(&wss, ss, sizeof wss))
			return -EFAULT;
		if(wss.ss_flags != 0 && wss.ss_flags != SS_DISABLE)
			return -EINVAL;
		if(wss.ss_flags == SS_DISABLE){
			thread->sigstack.ss_sp = NULL;
			thread->sigstack.ss_flags = SS_DISABLE;
			thread->sigstack.ss_size = 0;
		}
		else{
			if(wss.ss_size < MINSIGSTKSZ)
				return -ENOMEM;

			memcpy(&thread->sigstack, &wss, sizeof wss);
		}
	}

	return 0;
}

SYSCALL_DECLARE(mincore)
{
	const uintptr_t start = ihk_mc_syscall_arg0(ctx);
	const size_t len = ihk_mc_syscall_arg1(ctx);
	uint8_t * const vec = (void *)ihk_mc_syscall_arg2(ctx);
	const uintptr_t end = start + len;
	struct thread *thread = cpu_local_var(current);
	struct process_vm *vm = thread->vm;
	void *up;
	uintptr_t addr;
	struct vm_range *range;
	uint8_t value;
	int error;
	pte_t *ptep;

	if (start & (PAGE_SIZE - 1)) {
		kprintf("mincore(0x%lx,0x%lx,%p): EINVAL\n", start, len, vec);
		return -EINVAL;
	}

	range = NULL;
	up = vec;
	for (addr = start; addr < end; addr += PAGE_SIZE) {
		ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);
		range = lookup_process_memory_range(vm, addr, addr+1);
		if (!range) {
			ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);
			kprintf("mincore(0x%lx,0x%lx,%p):lookup failed. ENOMEM\n", start, len, vec);
			return -ENOMEM;
		}

		ihk_mc_spinlock_lock_noirq(&vm->page_table_lock);
		ptep = ihk_mc_pt_lookup_pte(vm->address_space->page_table, (void *)addr, NULL, NULL, NULL);
		/*
		 * XXX: It might be necessary to consider whether this page is COW page or not.
		 */
		value = (pte_is_present(ptep))? 1: 0;
		ihk_mc_spinlock_unlock_noirq(&vm->page_table_lock);
		ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);

		error = copy_to_user(up, &value, sizeof(value));
		if (error) {
			kprintf("mincore(0x%lx,0x%lx,%p):copy failed. %d\n", start, len, vec, error);
			return error;
		}
		++up;
	}

	kprintf("mincore(0x%lx,0x%lx,%p): 0\n", start, len, vec);
	return 0;
} /* sys_mincore() */

SYSCALL_DECLARE(madvise)
{
	const uintptr_t start = (uintptr_t)ihk_mc_syscall_arg0(ctx);
	const size_t len0 = (size_t)ihk_mc_syscall_arg1(ctx);
	const int advice = (int)ihk_mc_syscall_arg2(ctx);
	size_t len;
	uintptr_t end;
	struct thread *thread = cpu_local_var(current);
	struct vm_regions *region = &thread->vm->region;
	struct vm_range *first;
	uintptr_t addr;
	struct vm_range *range;
	int error;
	uintptr_t s;
	uintptr_t e;

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
	case MADV_REMOVE:
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

	ihk_mc_spinlock_lock_noirq(&thread->vm->memory_range_lock);
	/* check contiguous map */
	first = NULL;
	range = NULL;	/* for avoidance of warning */
	for (addr = start; addr < end; addr = range->end) {
		if (first == NULL) {
			range = lookup_process_memory_range(thread->vm, start, start+PAGE_SIZE);
			first = range;
		}
		else {
			range = next_process_memory_range(thread->vm, range);
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

		if (advice == MADV_REMOVE) {
			if (!range->memobj || !memobj_is_removable(range->memobj)) {
				dkprintf("sys_madvise(%lx,%lx,%x):"
						"not removable [%lx-%lx)\n",
						start, len0, advice,
						range->start, range->end);
				error = -EACCES;
				goto out;
			}
		}
		else if (!range->memobj || !memobj_has_pager(range->memobj)) {
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

		s = start;
		if (s < range->start) {
			s = range->start;
		}
		e = end;
		if (range->end < e) {
			e = range->end;
		}

		if (advice == MADV_REMOVE) {
			error = invalidate_process_memory_range(
					thread->vm, range, s, e);
			if (error) {
				kprintf("sys_madvise(%lx,%lx,%x):[%lx-%lx):"
						"invalidate failed. %d\n",
						start, len0, advice,
						range->start, range->end,
						error);
				goto out;
			}
		}
	}

	error = 0;
out:
	ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);

out2:
	dkprintf("[%d]sys_madvise(%lx,%lx,%x): %d\n",
			ihk_mc_get_processor_id(), start, len0, advice, error);
	return error;
}

struct kshmid_ds {
	int destroy;
	int padding;
	struct shmobj *obj;
	struct memobj *memobj;
	struct list_head chain;
};

int the_maxi = -1;
LIST_HEAD(kds_list);
LIST_HEAD(kds_free_list);
struct shminfo the_shminfo = {
	.shmmax = 64L * 1024 * 1024 * 1024,
	.shmmin = 1,
	.shmmni = 4 * 1024,
	.shmall = 4L * 1024 * 1024 * 1024,
};
struct shm_info the_shm_info = { 0, };

static uid_t geteuid(void) {
	struct syscall_request sreq IHK_DMA_ALIGN;
	struct thread *thread = cpu_local_var(current);

	sreq.number = __NR_geteuid;
	return (uid_t)do_syscall(&sreq, ihk_mc_get_processor_id(), thread->proc->pid);
}

static gid_t getegid(void) {
	struct syscall_request sreq IHK_DMA_ALIGN;
	struct thread *thread = cpu_local_var(current);

	sreq.number = __NR_getegid;
	return (gid_t)do_syscall(&sreq, ihk_mc_get_processor_id(), thread->proc->pid);
}

time_t time(void) {
	struct syscall_request sreq IHK_DMA_ALIGN;
	struct thread *thread = cpu_local_var(current);

	sreq.number = __NR_time;
	sreq.args[0] = (uintptr_t)NULL;
	return (time_t)do_syscall(&sreq, ihk_mc_get_processor_id(), thread->proc->pid);
}

pid_t getpid(void) {
	struct thread *thread = cpu_local_var(current);

	return thread->proc->pid;
}

static int make_shmid(struct shmobj *obj)
{
	return ((int)obj->index << 16) | obj->ds.shm_perm.seq;
} /* make_shmid() */

static int shmid_to_index(int shmid)
{
	return (shmid >> 16);
} /* shmid_to_index() */

static int shmid_to_seq(int shmid)
{
	return (shmid & ((1 << 16) - 1));
} /* shmid_to_seq() */

int shmobj_list_lookup(int shmid, struct shmobj **objp)
{
	int index;
	int seq;
	struct shmobj *obj;

	index = shmid_to_index(shmid);
	seq = shmid_to_seq(shmid);

	list_for_each_entry(obj, &kds_list, chain) {
		if (obj->index == index) {
			break;
		}
	}
	if (&obj->chain == &kds_list) {
		return -EINVAL;
	}
	if (obj->ds.shm_perm.seq != seq) {
		return -EIDRM;
	}

	*objp = obj;
	return 0;
} /* shmobj_list_lookup() */

int shmobj_list_lookup_by_key(key_t key, struct shmobj **objp)
{
	struct shmobj *obj;

	list_for_each_entry(obj, &kds_list, chain) {
		if (obj->ds.shm_perm.key == key) {
			break;
		}
	}
	if (&obj->chain == &kds_list) {
		return -EINVAL;
	}

	*objp = obj;
	return 0;
} /* shmobj_list_lookup_by_key() */

int shmobj_list_lookup_by_index(int index, struct shmobj **objp)
{
	struct shmobj *obj;

	list_for_each_entry(obj, &kds_list, chain) {
		if (obj->index == index) {
			break;
		}
	}
	if (&obj->chain == &kds_list) {
		return -EINVAL;
	}

	*objp = obj;
	return 0;
} /* shmobj_list_lookup_by_index() */

SYSCALL_DECLARE(shmget)
{
	const key_t key = ihk_mc_syscall_arg0(ctx);
	const size_t size = ihk_mc_syscall_arg1(ctx);
	const int shmflg = ihk_mc_syscall_arg2(ctx);
	uid_t euid = geteuid();
	gid_t egid = getegid();
	time_t now = time();
	struct thread *thread = cpu_local_var(current);
	int shmid;
	int error;
	struct shmid_ds ads;
	struct shmobj *obj;

	dkprintf("shmget(%#lx,%#lx,%#x)\n", key, size, shmflg);

	if (size < the_shminfo.shmmin) {
		dkprintf("shmget(%#lx,%#lx,%#x): -EINVAL\n", key, size, shmflg);
		return -EINVAL;
	}

	shmobj_list_lock();
	obj = NULL;
	if (key != IPC_PRIVATE) {
		error = shmobj_list_lookup_by_key(key, &obj);
		if (error == -EINVAL) {
			obj = NULL;
		}
		else if (error) {
			shmobj_list_unlock();
			dkprintf("shmget(%#lx,%#lx,%#x): lookup: %d\n", key, size, shmflg, error);
			return error;
		}
		if (!obj && !(shmflg & IPC_CREAT)) {
			shmobj_list_unlock();
			dkprintf("shmget(%#lx,%#lx,%#x): -ENOENT\n", key, size, shmflg);
			return -ENOENT;
		}
		if (obj && (shmflg & IPC_CREAT) && (shmflg & IPC_EXCL)) {
			shmobj_list_unlock();
			dkprintf("shmget(%#lx,%#lx,%#x): -EEXIST\n", key, size, shmflg);
			return -EEXIST;
		}
	}

	if (obj) {
		if (euid) {
			int req;

			req = (shmflg | (shmflg << 3) | (shmflg << 6)) & 0700;
			if ((obj->ds.shm_perm.uid == euid)
					|| (obj->ds.shm_perm.cuid == euid)) {
				/*  nothing to do */
			}
			else if ((obj->ds.shm_perm.gid == egid)
					|| (obj->ds.shm_perm.cgid == egid)) {
				/*
				 * XXX: need to check supplementary group IDs
				 */
				req >>= 3;
			}
			else {
				req >>= 6;
			}
			if (req & ~obj->ds.shm_perm.mode) {
				shmobj_list_unlock();
				dkprintf("shmget(%#lx,%#lx,%#x): -EINVAL\n", key, size, shmflg);
				return -EACCES;
			}
		}
		if (obj->ds.shm_segsz < size) {
			shmobj_list_unlock();
			dkprintf("shmget(%#lx,%#lx,%#x): -EINVAL\n", key, size, shmflg);
			return -EINVAL;
		}
		shmid = make_shmid(obj);
		shmobj_list_unlock();
		dkprintf("shmget(%#lx,%#lx,%#x): %d\n", key, size, shmflg, shmid);
		return shmid;
	}

	if (the_shm_info.used_ids >= the_shminfo.shmmni) {
		shmobj_list_unlock();
		dkprintf("shmget(%#lx,%#lx,%#x): -ENOSPC\n", key, size, shmflg);
		return -ENOSPC;
	}

	memset(&ads, 0, sizeof(ads));
	ads.shm_perm.key = key;
	ads.shm_perm.uid = euid;
	ads.shm_perm.cuid = euid;
	ads.shm_perm.gid = egid;
	ads.shm_perm.cgid = egid;
	ads.shm_perm.mode = shmflg & 0777;
	ads.shm_segsz = size;
	ads.shm_ctime = now;
	ads.shm_cpid = thread->proc->pid;

	error = shmobj_create_indexed(&ads, &obj);
	if (error) {
		shmobj_list_unlock();
		dkprintf("shmget(%#lx,%#lx,%#x): shmobj_create: %d\n", key, size, shmflg, error);
		return error;
	}

	obj->index = ++the_maxi;

	list_add(&obj->chain, &kds_list);
	++the_shm_info.used_ids;

	shmid = make_shmid(obj);
	shmobj_list_unlock();
	memobj_release(&obj->memobj);

	dkprintf("shmget(%#lx,%#lx,%#x): %d\n", key, size, shmflg, shmid);
	return shmid;
} /* sys_shmget() */

SYSCALL_DECLARE(shmat)
{
	const int shmid = ihk_mc_syscall_arg0(ctx);
	void * const shmaddr = (void *)ihk_mc_syscall_arg1(ctx);
	const int shmflg = ihk_mc_syscall_arg2(ctx);
	struct thread *thread = cpu_local_var(current);
	size_t len;
	int error;
	struct vm_regions *region = &thread->vm->region;
	intptr_t addr;
	int prot;
	int vrflags;
	int req;
	uid_t euid = geteuid();
	gid_t egid = getegid();
	struct shmobj *obj;

	dkprintf("shmat(%#x,%p,%#x)\n", shmid, shmaddr, shmflg);

	shmobj_list_lock();
	error = shmobj_list_lookup(shmid, &obj);
	if (error) {
		shmobj_list_unlock();
		dkprintf("shmat(%#x,%p,%#x): lookup: %d\n", shmid, shmaddr, shmflg, error);
		return error;
	}

	if (shmaddr && ((uintptr_t)shmaddr & (PAGE_SIZE - 1)) && !(shmflg & SHM_RND)) {
		shmobj_list_unlock();
		dkprintf("shmat(%#x,%p,%#x): -EINVAL\n", shmid, shmaddr, shmflg);
		return -EINVAL;
	}
	addr = (uintptr_t)shmaddr & PAGE_MASK;
	len = (obj->ds.shm_segsz + PAGE_SIZE - 1) & PAGE_MASK;

	prot = PROT_READ;
	req = 4;
	if (!(shmflg & SHM_RDONLY)) {
		prot |= PROT_WRITE;
		req |= 2;
	}

	if (!euid) {
		req = 0;
	}
	else if ((euid == obj->ds.shm_perm.uid) || (euid == obj->ds.shm_perm.cuid)) {
		req <<= 6;
	}
	else if ((egid == obj->ds.shm_perm.gid) || (egid == obj->ds.shm_perm.cgid)) {
		req <<= 3;
	}
	else {
		req <<= 0;
	}
	if (~obj->ds.shm_perm.mode & req) {
		shmobj_list_unlock();
		dkprintf("shmat(%#x,%p,%#x): -EINVAL\n", shmid, shmaddr, shmflg);
		return -EACCES;
	}

	ihk_mc_spinlock_lock_noirq(&thread->vm->memory_range_lock);

	if (addr) {
		if (lookup_process_memory_range(thread->vm, addr, addr+len)) {
			ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);
			shmobj_list_unlock();
			dkprintf("shmat(%#x,%p,%#x):lookup_process_memory_range succeeded. -ENOMEM\n", shmid, shmaddr, shmflg);
			return -ENOMEM;
		}
	}
	else {
		error = search_free_space(len, region->map_end, &addr);
		if (error) {
			ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);
			shmobj_list_unlock();
			dkprintf("shmat(%#x,%p,%#x):search_free_space failed. %d\n", shmid, shmaddr, shmflg, error);
			return error;
		}
		region->map_end = addr + len;
	}

	vrflags = VR_NONE;
	vrflags |= VR_DEMAND_PAGING;
	vrflags |= PROT_TO_VR_FLAG(prot);
	vrflags |= VRFLAG_PROT_TO_MAXPROT(vrflags);

	if (!(prot & PROT_WRITE)) {
		error = set_host_vma(addr, len, PROT_READ);
		if (error) {
			ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);
			shmobj_list_unlock();
			dkprintf("shmat(%#x,%p,%#x):set_host_vma failed. %d\n", shmid, shmaddr, shmflg, error);
			return error;
		}
	}

	memobj_ref(&obj->memobj);

	error = add_process_memory_range(thread->vm, addr, addr+len, -1, vrflags, &obj->memobj, 0);
	if (error) {
		if (!(prot & PROT_WRITE)) {
			(void)set_host_vma(addr, len, PROT_READ|PROT_WRITE);
		}
		memobj_release(&obj->memobj);
		ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);
		shmobj_list_unlock();
		dkprintf("shmat(%#x,%p,%#x):add_process_memory_range failed. %d\n", shmid, shmaddr, shmflg, error);
		return error;
	}

	ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);
	shmobj_list_unlock();

	dkprintf("shmat:bump shm_nattach %p %d\n", obj, obj->ds.shm_nattch);
	dkprintf("shmat(%#x,%p,%#x): 0x%lx. %d\n", shmid, shmaddr, shmflg, addr);
	return addr;
} /* sys_shmat() */

SYSCALL_DECLARE(shmctl)
{
	const int shmid = ihk_mc_syscall_arg0(ctx);
	const int cmd = ihk_mc_syscall_arg1(ctx);
	struct shmid_ds * const buf = (void *)ihk_mc_syscall_arg2(ctx);
	int error;
	struct shmid_ds ads;
	uid_t euid = geteuid();
	gid_t egid = getegid();
	time_t now = time();
	int req;
	int maxi;
	struct shmobj *obj;

	dkprintf("shmctl(%#x,%d,%p)\n", shmid, cmd, buf);
	if (0) ;
	else if (cmd == IPC_RMID) {
		shmobj_list_lock();
		error = shmobj_list_lookup(shmid, &obj);
		if (error) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): lookup: %d\n", shmid, cmd, buf, error);
			return error;
		}
		if ((obj->ds.shm_perm.uid != euid)
				&& (obj->ds.shm_perm.cuid != euid)) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): -EPERM\n", shmid, cmd, buf);
			return -EPERM;
		}
		obj->ds.shm_perm.mode |= SHM_DEST;
		if (obj->ds.shm_nattch <= 0) {
			shmobj_destroy(obj);
		}
		shmobj_list_unlock();

		dkprintf("shmctl(%#x,%d,%p): 0\n", shmid, cmd, buf);
		return 0;
	}
	else if (cmd == IPC_SET) {
		shmobj_list_lock();
		error = shmobj_list_lookup(shmid, &obj);
		if (error) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): lookup: %d\n", shmid, cmd, buf, error);
			return error;
		}
		if ((obj->ds.shm_perm.uid != euid)
				&& (obj->ds.shm_perm.cuid != euid)) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): -EPERM\n", shmid, cmd, buf);
			return -EPERM;
		}
		error = copy_from_user(&ads, buf, sizeof(ads));
		if (error) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): %d\n", shmid, cmd, buf, error);
			return error;
		}
		obj->ds.shm_perm.uid = ads.shm_perm.uid;
		obj->ds.shm_perm.gid = ads.shm_perm.gid;
		obj->ds.shm_perm.mode &= ~0777;
		obj->ds.shm_perm.mode |= ads.shm_perm.mode & 0777;
		obj->ds.shm_ctime = now;

		shmobj_list_unlock();
		dkprintf("shmctl(%#x,%d,%p): 0\n", shmid, cmd, buf);
		return 0;
	}
	else if (cmd == IPC_STAT) {
		shmobj_list_lock();
		error = shmobj_list_lookup(shmid, &obj);
		if (error) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): lookup: %d\n", shmid, cmd, buf, error);
			return error;
		}
		if (!euid) {
			req = 0;
		}
		else if ((euid == obj->ds.shm_perm.uid) || (euid == obj->ds.shm_perm.cuid)) {
			req = 0400;
		}
		else if ((egid == obj->ds.shm_perm.gid) || (egid == obj->ds.shm_perm.cgid)) {
			req = 0040;
		}
		else {
			req = 0004;
		}
		if (req & ~obj->ds.shm_perm.mode) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): -EACCES\n", shmid, cmd, buf);
			return -EACCES;
		}
		error = copy_to_user(buf, &obj->ds, sizeof(*buf));
		if (error) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): %d\n", shmid, cmd, buf, error);
			return error;
		}

		shmobj_list_unlock();
		dkprintf("shmctl(%#x,%d,%p): 0\n", shmid, cmd, buf);
		return 0;
	}
	else if (cmd == IPC_INFO) {
		shmobj_list_lock();
		error = shmobj_list_lookup(shmid, &obj);
		if (error) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): lookup: %d\n", shmid, cmd, buf, error);
			return error;
		}
		error = copy_to_user(buf, &the_shminfo, sizeof(the_shminfo));
		if (error) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): %d\n", shmid, cmd, buf, error);
			return error;
		}

		maxi = the_maxi;
		if (maxi < 0) {
			maxi = 0;
		}
		shmobj_list_unlock();
		dkprintf("shmctl(%#x,%d,%p): %d\n", shmid, cmd, buf, maxi);
		return maxi;
	}
	else if (cmd == SHM_LOCK) {
		shmobj_list_lock();
		error = shmobj_list_lookup(shmid, &obj);
		if (error) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): lookup: %d\n", shmid, cmd, buf, error);
			return error;
		}
		obj->ds.shm_perm.mode |= SHM_LOCKED;
		shmobj_list_unlock();

		dkprintf("shmctl(%#x,%d,%p): 0\n", shmid, cmd, buf);
		return 0;
	}
	else if (cmd == SHM_UNLOCK) {
		shmobj_list_lock();
		error = shmobj_list_lookup(shmid, &obj);
		if (error) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): lookup: %d\n", shmid, cmd, buf, error);
			return error;
		}
		obj->ds.shm_perm.mode &= ~SHM_LOCKED;
		shmobj_list_unlock();
		dkprintf("shmctl(%#x,%d,%p): 0\n", shmid, cmd, buf);
		return 0;
	}
	else if (cmd == SHM_STAT) {
		shmobj_list_lock();
		error = shmobj_list_lookup_by_index(shmid, &obj);
		if (error) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): lookup: %d\n", shmid, cmd, buf, error);
			return error;
		}
		error = copy_to_user(buf, &obj->ds, sizeof(*buf));
		if (error) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): %d\n", shmid, cmd, buf, error);
			return error;
		}
		shmobj_list_unlock();
		dkprintf("shmctl(%#x,%d,%p): 0\n", shmid, cmd, buf);
		return 0;
	}
	else if (cmd == SHM_INFO) {
		shmobj_list_lock();
		error = copy_to_user(buf, &the_shm_info, sizeof(the_shm_info));
		if (error) {
			shmobj_list_unlock();
			dkprintf("shmctl(%#x,%d,%p): %d\n", shmid, cmd, buf, error);
			return error;
		}

		maxi = the_maxi;
		if (maxi < 0) {
			maxi = 0;
		}
		shmobj_list_unlock();
		dkprintf("shmctl(%#x,%d,%p): %d\n", shmid, cmd, buf, maxi);
		return maxi;
	}

	dkprintf("shmctl(%#x,%d,%p): EINVAL\n", shmid, cmd, buf);
	return -EINVAL;
} /* sys_shmctl() */

SYSCALL_DECLARE(shmdt)
{
	void * const shmaddr = (void *)ihk_mc_syscall_arg0(ctx);
	struct thread *thread = cpu_local_var(current);
	struct vm_range *range;
	int error;

	dkprintf("shmdt(%p)\n", shmaddr);
	ihk_mc_spinlock_lock_noirq(&thread->vm->memory_range_lock);
	range = lookup_process_memory_range(thread->vm, (uintptr_t)shmaddr, (uintptr_t)shmaddr+1);
	if (!range || (range->start != (uintptr_t)shmaddr) || !range->memobj
			|| !(range->memobj->flags & MF_SHMDT_OK)) {
		ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);
		dkprintf("shmdt(%p): -EINVAL\n", shmaddr);
		return -EINVAL;
	}

	error = do_munmap((void *)range->start, (range->end - range->start));
	if (error) {
		ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);
		dkprintf("shmdt(%p): %d\n", shmaddr, error);
		return error;
	}

	ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);
	dkprintf("shmdt(%p): 0\n", shmaddr);
	return 0;
} /* sys_shmdt() */

SYSCALL_DECLARE(futex)
{
	uint64_t timeout = 0; // No timeout
	uint32_t val2 = 0;
	// Only one clock is used, ignore FUTEX_CLOCK_REALTIME
	//int futex_clock_realtime = 0; 
	int fshared = 1;
	int ret = 0;

	uint32_t *uaddr = (uint32_t *)ihk_mc_syscall_arg0(ctx);
	int op = (int)ihk_mc_syscall_arg1(ctx);
	uint32_t val = (uint32_t)ihk_mc_syscall_arg2(ctx);
	struct timespec *utime = (struct timespec*)ihk_mc_syscall_arg3(ctx);
	uint32_t *uaddr2 = (uint32_t *)ihk_mc_syscall_arg4(ctx);
	uint32_t val3 = (uint32_t)ihk_mc_syscall_arg5(ctx);
	int flags = op;
    
	/* Cross-address space futex? */
	if (op & FUTEX_PRIVATE_FLAG) {
		fshared = 0;
	}
	op = (op & FUTEX_CMD_MASK);
	
	dkprintf("futex op=[%x, %s],uaddr=%lx, val=%x, utime=%lx, uaddr2=%lx, val3=%x, []=%x, shared: %d\n", 
			flags,
			(op == FUTEX_WAIT) ? "FUTEX_WAIT" :
			(op == FUTEX_WAIT_BITSET) ? "FUTEX_WAIT_BITSET" :
			(op == FUTEX_WAKE) ? "FUTEX_WAKE" :
			(op == FUTEX_WAKE_OP) ? "FUTEX_WAKE_OP" :
			(op == FUTEX_WAKE_BITSET) ? "FUTEX_WAKE_BITSET" :
			(op == FUTEX_CMP_REQUEUE) ? "FUTEX_CMP_REQUEUE" :
			(op == FUTEX_REQUEUE) ? "FUTEX_REQUEUE (NOT IMPL!)" : "unknown",
			(unsigned long)uaddr, val, utime, uaddr2, val3, *uaddr, fshared);

	if (utime && (op == FUTEX_WAIT_BITSET || op == FUTEX_WAIT)) {
		unsigned long nsec_timeout;

		/* As per the Linux implementation FUTEX_WAIT specifies the duration of
		 * the timeout, while FUTEX_WAIT_BITSET specifies the absolute timestamp */
		if (op == FUTEX_WAIT_BITSET) {
			struct timespec ats;

			if (!gettime_local_support ||
			    !(flags & FUTEX_CLOCK_REALTIME)) {
				struct syscall_request request IHK_DMA_ALIGN; 
				struct timespec tv[2];
				struct timespec *tv_now = tv;
				request.number = n;
				unsigned long __phys;                                          

				if((((unsigned long)tv) ^ ((unsigned long)(tv + 1))) & ~4095)
					tv_now = tv + 1;
				if (ihk_mc_pt_virt_to_phys(cpu_local_var(current)->vm->address_space->page_table, 
						(void *)tv_now, &__phys)) { 
					return -EFAULT; 
				}

				request.args[0] = __phys;               
				request.args[1] = (flags & FUTEX_CLOCK_REALTIME)?
						      CLOCK_REALTIME: CLOCK_MONOTONIC;

				int r = do_syscall(&request, ihk_mc_get_processor_id(), 0);

				if (r < 0) {
					return -EFAULT;
				}

				ats.tv_sec = tv_now->tv_sec;
				ats.tv_nsec = tv_now->tv_nsec;
			}
			/* Compute timeout based on TSC/nanosec ratio */
			else {
				calculate_time_from_tsc(&ats);
			}

			nsec_timeout = (utime->tv_sec * NS_PER_SEC + utime->tv_nsec) -
				(ats.tv_sec * NS_PER_SEC + ats.tv_nsec);
		}
		else {
			nsec_timeout = (utime->tv_sec * NS_PER_SEC + utime->tv_nsec);
		}

		timeout = nsec_timeout * 1000 / ihk_mc_get_ns_per_tsc();
		dkprintf("futex timeout: %lu\n", timeout);
	}

	/* Requeue parameter in 'utime' if op == FUTEX_CMP_REQUEUE.
	 * number of waiters to wake in 'utime' if op == FUTEX_WAKE_OP. */
	if (op == FUTEX_CMP_REQUEUE || op == FUTEX_WAKE_OP)
		val2 = (uint32_t) (unsigned long) ihk_mc_syscall_arg3(ctx);

	ret = futex(uaddr, op, val, timeout, uaddr2, val2, val3, fshared);

	dkprintf("futex op=[%x, %s],uaddr=%lx, val=%x, utime=%lx, uaddr2=%lx, val3=%x, []=%x, shared: %d, ret: %d\n", 
			op,
			(op == FUTEX_WAIT) ? "FUTEX_WAIT" :
			(op == FUTEX_WAIT_BITSET) ? "FUTEX_WAIT_BITSET" :
			(op == FUTEX_WAKE) ? "FUTEX_WAKE" :
			(op == FUTEX_WAKE_OP) ? "FUTEX_WAKE_OP" :
			(op == FUTEX_WAKE_BITSET) ? "FUTEX_WAKE_BITSET" :
			(op == FUTEX_CMP_REQUEUE) ? "FUTEX_CMP_REQUEUE" :
			(op == FUTEX_REQUEUE) ? "FUTEX_REQUEUE (NOT IMPL!)" : "unknown",
			(unsigned long)uaddr, val, utime, uaddr2, val3, *uaddr, fshared, ret);

	return ret;
}

SYSCALL_DECLARE(exit)
{
	struct thread *thread = cpu_local_var(current);
	struct thread *child;
	struct process *proc = thread->proc;
	struct mcs_rwlock_node_irqsave lock;
	int nproc;
	int exit_status = (int)ihk_mc_syscall_arg0(ctx);

	dkprintf("sys_exit,pid=%d\n", proc->pid);

	mcs_rwlock_reader_lock(&proc->threads_lock, &lock);
	nproc = 0;
	list_for_each_entry(child, &proc->threads_list, siblings_list){
		nproc++;
	}
	mcs_rwlock_reader_unlock(&proc->threads_lock, &lock);

	if(nproc == 1){ // process has only one thread
		terminate(exit_status, 0);
		return 0;
	}

#ifdef DCFA_KMOD
	do_mod_exit((int)ihk_mc_syscall_arg0(ctx));
#endif

	/* XXX: for if all threads issued the exit(2) rather than exit_group(2),
	 *      exit(2) also should delegate.
	 */
	/* If there is a clear_child_tid address set, clear it and wake it.
	 * This unblocks any pthread_join() waiters. */
	if (thread->clear_child_tid) {
		
		dkprintf("exit clear_child!\n");

		*thread->clear_child_tid = 0;
		barrier();
		futex((uint32_t *)thread->clear_child_tid,
		      FUTEX_WAKE, 1, 0, NULL, 0, 0, 1);
	}

	mcs_rwlock_reader_lock(&proc->threads_lock, &lock);
	if(proc->status == PS_EXITED){
		mcs_rwlock_reader_unlock(&proc->threads_lock, &lock);
		terminate(exit_status, 0);
		return 0;
	}
	thread->status = PS_EXITED;
	mcs_rwlock_reader_unlock(&proc->threads_lock, &lock);
	release_thread(thread);

	schedule();

	return 0;
}

static int rlimits[] = {
#ifdef RLIMIT_AS
	RLIMIT_AS,	MCK_RLIMIT_AS,
#endif
#ifdef RLIMIT_CORE
	RLIMIT_CORE,	MCK_RLIMIT_CORE,
#endif
#ifdef RLIMIT_CPU
	RLIMIT_CPU,	MCK_RLIMIT_CPU,
#endif
#ifdef RLIMIT_DATA
	RLIMIT_DATA,	MCK_RLIMIT_DATA,
#endif
#ifdef RLIMIT_FSIZE
	RLIMIT_FSIZE,	MCK_RLIMIT_FSIZE,
#endif
#ifdef RLIMIT_LOCKS
	RLIMIT_LOCKS,	MCK_RLIMIT_LOCKS,
#endif
#ifdef RLIMIT_MEMLOCK
	RLIMIT_MEMLOCK,	MCK_RLIMIT_MEMLOCK,
#endif
#ifdef RLIMIT_MSGQUEUE
	RLIMIT_MSGQUEUE,MCK_RLIMIT_MSGQUEUE,
#endif
#ifdef RLIMIT_NICE
	RLIMIT_NICE,	MCK_RLIMIT_NICE,
#endif
#ifdef RLIMIT_NOFILE
	RLIMIT_NOFILE,	MCK_RLIMIT_NOFILE,
#endif
#ifdef RLIMIT_NPROC
	RLIMIT_NPROC,	MCK_RLIMIT_NPROC,
#endif
#ifdef RLIMIT_RSS
	RLIMIT_RSS,	MCK_RLIMIT_RSS,
#endif
#ifdef RLIMIT_RTPRIO
	RLIMIT_RTPRIO,	MCK_RLIMIT_RTPRIO,
#endif
#ifdef RLIMIT_RTTIME
	RLIMIT_RTTIME,	MCK_RLIMIT_RTTIME,
#endif
#ifdef RLIMIT_SIGPENDING
	RLIMIT_SIGPENDING,MCK_RLIMIT_SIGPENDING,
#endif
#ifdef RLIMIT_STACK
	RLIMIT_STACK,	MCK_RLIMIT_STACK,
#endif
};

SYSCALL_DECLARE(setrlimit)
{
	int rc;
	int resource = ihk_mc_syscall_arg0(ctx);
	struct rlimit *rlm = (struct rlimit *)ihk_mc_syscall_arg1(ctx);
	struct thread *thread = cpu_local_var(current);
	int	i;
	int	mcresource;

	switch(resource){
	    case RLIMIT_FSIZE:
	    case RLIMIT_NOFILE:
	    case RLIMIT_LOCKS:
	    case RLIMIT_MSGQUEUE:
		rc = syscall_generic_forwarding(__NR_setrlimit, ctx);
		if(rc < 0)
			return rc;
		break;
	}

	for(i = 0; i < sizeof(rlimits) / sizeof(int); i += 2)
		if(rlimits[i] == resource){
			mcresource = rlimits[i + 1];
			break;
		}
	if(i >= sizeof(rlimits) / sizeof(int)){
		return syscall_generic_forwarding(__NR_setrlimit, ctx);
	}

	if(copy_from_user(thread->proc->rlimit + mcresource, rlm, sizeof(struct rlimit)))
		return -EFAULT;

	return 0;
}

SYSCALL_DECLARE(getrlimit)
{
	int resource = ihk_mc_syscall_arg0(ctx);
	struct rlimit *rlm = (struct rlimit *)ihk_mc_syscall_arg1(ctx);
	struct thread *thread = cpu_local_var(current);
	int	i;
	int	mcresource;

	for(i = 0; i < sizeof(rlimits) / sizeof(int); i += 2)
		if(rlimits[i] == resource){
			mcresource = rlimits[i + 1];
			break;
		}
	if(i >= sizeof(rlimits) / sizeof(int)){
		return syscall_generic_forwarding(__NR_getrlimit, ctx);
	}

// TODO: check limit
	if(copy_to_user(rlm, thread->proc->rlimit + mcresource, sizeof(struct rlimit)))
		return -EFAULT;

	return 0;
}

extern int ptrace_traceme(void);
extern void clear_single_step(struct thread *thread);
extern void set_single_step(struct thread *thread);

static int ptrace_wakeup_sig(int pid, long request, long data) {
	dkprintf("ptrace_wakeup_sig,pid=%d,data=%08x\n", pid, data);
	int error = 0;
	struct thread *child;
	struct siginfo info;
	struct mcs_rwlock_node_irqsave lock;
	struct thread *thread = cpu_local_var(current);

	child = find_thread(pid, pid, &lock);
	if (!child) {
		error = -ESRCH;
		goto out;
	}
	hold_thread(child);
	thread_unlock(child, &lock);

	if (data > 64 || data < 0) {
		error = -EINVAL;
		goto out;
	}

	switch (request) {
	case PTRACE_KILL:
		memset(&info, '\0', sizeof info);
		info.si_signo = SIGKILL;
		error = do_kill(thread, pid, -1, SIGKILL, &info, 0);
		if (error < 0) {
			goto out;
		}
		break;
	case PTRACE_CONT:
	case PTRACE_SINGLESTEP:
	case PTRACE_SYSCALL:
		if (request == PTRACE_SINGLESTEP) {
			set_single_step(child);
		}
		mcs_rwlock_writer_lock(&child->proc->update_lock, &lock);
		child->proc->ptrace &= ~PT_TRACE_SYSCALL_MASK;
		if (request == PTRACE_SYSCALL) {
			child->proc->ptrace |= PT_TRACE_SYSCALL_ENTER;
		}
		mcs_rwlock_writer_unlock(&child->proc->update_lock, &lock);
		if(data != 0 && data != SIGSTOP) {

			/* TODO: Tracing process replace the original
			   signal with "data" */
			if (request == PTRACE_CONT && child->ptrace_sendsig) {
				memcpy(&info, &child->ptrace_sendsig->info, sizeof info);
				kfree(child->ptrace_sendsig);
				child->ptrace_sendsig = NULL;
			}
			else if (request == PTRACE_CONT && child->ptrace_recvsig) {
				memcpy(&info, &child->ptrace_recvsig->info, sizeof info);
				kfree(child->ptrace_recvsig);
				child->ptrace_recvsig = NULL;
			}
			else {
				memset(&info, '\0', sizeof info);
				info.si_signo = data;
				info.si_code = SI_USER;
				info._sifields._kill.si_pid = thread->proc->pid;
			}
			error = do_kill(thread, pid, -1, data, &info, 1);
			if (error < 0) {
				goto out;
			}
		}
		break;
	default:
		break;
	}

	sched_wakeup_thread(child, PS_TRACED | PS_STOPPED);
out:
	if(child)
		release_thread(child);
	return error;
}

extern long ptrace_read_user(struct thread *thread, long addr, unsigned long *value);
extern long ptrace_write_user(struct thread *thread, long addr, unsigned long value);

static long ptrace_pokeuser(int pid, long addr, long data)
{
	long rc = -EIO;
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;

	if(addr > sizeof(struct user) - 8 || addr < 0)
		return -EFAULT;
	child = find_thread(pid, pid, &lock);
	if (!child)
		return -ESRCH;
	if(child->proc->status == PS_TRACED){
		rc = ptrace_write_user(child, addr, (unsigned long)data);
	}
	thread_unlock(child, &lock);

	return rc;
}

static long ptrace_peekuser(int pid, long addr, long data)
{
	long rc = -EIO;
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;
	unsigned long *p = (unsigned long *)data;

	if(addr > sizeof(struct user) - 8|| addr < 0)
		return -EFAULT;
	child = find_thread(pid, pid, &lock);
	if (!child)
		return -ESRCH;
	if(child->proc->status == PS_TRACED){
		unsigned long value;
		rc = ptrace_read_user(child, addr, &value);
		if (rc == 0) {
			rc = copy_to_user(p, (char *)&value, sizeof(value));
		}
	}
	thread_unlock(child, &lock);

	return rc;
}

static long ptrace_getregs(int pid, long data)
{
	struct user_regs_struct *regs = (struct user_regs_struct *)data;
	long rc = -EIO;
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;

	child = find_thread(pid, pid, &lock);
	if (!child)
		return -ESRCH;
	if(child->proc->status == PS_TRACED){
		struct user_regs_struct user_regs;
		long addr;
		unsigned long *p;
		memset(&user_regs, '\0', sizeof(struct user_regs_struct));
		for (addr = 0, p = (unsigned long *)&user_regs;
				addr < sizeof(struct user_regs_struct);
				addr += sizeof(*p), p++) {
			rc = ptrace_read_user(child, addr, p);
			if (rc) break;
		}
		if (rc == 0) {
			rc = copy_to_user(regs, &user_regs, sizeof(struct user_regs_struct));
		}
	}
	thread_unlock(child, &lock);

	return rc;
}

static long ptrace_setregs(int pid, long data)
{
	struct user_regs_struct *regs = (struct user_regs_struct *)data;
	long rc = -EIO;
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;

	child = find_thread(pid, pid, &lock);
	if (!child)
		return -ESRCH;
	if(child->proc->status == PS_TRACED){
		struct user_regs_struct user_regs;
		rc = copy_from_user(&user_regs, regs, sizeof(struct user_regs_struct));
		if (rc == 0) {
			long addr;
			unsigned long *p;
			for (addr = 0, p = (unsigned long *)&user_regs;
					addr < sizeof(struct user_regs_struct);
					addr += sizeof(*p), p++) {
				rc = ptrace_write_user(child, addr, *p);
				if (rc) {
					break;
				}
			}
		}
	}
	thread_unlock(child, &lock);

	return rc;
}

static long ptrace_arch_prctl(int pid, long code, long addr)
{
	long rc = -EIO;
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;

	child = find_thread(pid, pid, &lock);
	if (!child)
		return -ESRCH;
	if (child->proc->status == PS_TRACED) {
		switch (code) {
		case ARCH_GET_FS: {
			unsigned long value;
			unsigned long *p = (unsigned long *)addr;
			rc = ptrace_read_user(child,
					offsetof(struct user_regs_struct, fs_base),
					&value);
			if (rc == 0) {
				rc = copy_to_user(p, (char *)&value, sizeof(value));
			}
			break;
		}
		case ARCH_GET_GS: {
			unsigned long value;
			unsigned long *p = (unsigned long *)addr;
			rc = ptrace_read_user(child,
					offsetof(struct user_regs_struct, gs_base),
					&value);
			if (rc == 0) {
				rc = copy_to_user(p, (char *)&value, sizeof(value));
			}
			break;
		}
		case ARCH_SET_FS:
			rc = ptrace_write_user(child,
					offsetof(struct user_regs_struct, fs_base),
					(unsigned long)addr);
			break;
		case ARCH_SET_GS:
			rc = ptrace_write_user(child,
					offsetof(struct user_regs_struct, gs_base),
					(unsigned long)addr);
			break;
		default:
			rc = -EINVAL;
			break;
		}
	}
	thread_unlock(child, &lock);

	return rc;
}

extern long ptrace_read_fpregs(struct thread *thread, void *fpregs);
extern long ptrace_write_fpregs(struct thread *thread, void *fpregs);

static long ptrace_getfpregs(int pid, long data)
{
	long rc = -EIO;
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;

	child = find_thread(pid, pid, &lock);
	if (!child)
		return -ESRCH;
	if (child->proc->status == PS_TRACED) {
		rc = ptrace_read_fpregs(child, (void *)data);
	}
	thread_unlock(child, &lock);

	return rc;
}

static long ptrace_setfpregs(int pid, long data)
{
	long rc = -EIO;
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;

	child = find_thread(pid, pid, &lock);
	if (!child)
		return -ESRCH;
	if (child->proc->status == PS_TRACED) {
		rc = ptrace_write_fpregs(child, (void *)data);
	}
	thread_unlock(child, &lock);

	return rc;
}

extern long ptrace_read_regset(struct thread *thread, long type, struct iovec *iov);
extern long ptrace_write_regset(struct thread *thread, long type, struct iovec *iov);

static long ptrace_getregset(int pid, long type, long data)
{
	long rc = -EIO;
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;

	child = find_thread(pid, pid, &lock);
	if (!child)
		return -ESRCH;
	if (child->proc->status == PS_TRACED) {
		struct iovec iov;

		rc = copy_from_user(&iov, (struct iovec *)data, sizeof(iov));
		if (rc == 0) {
			rc = ptrace_read_regset(child, type, &iov);
		}
		if (rc == 0) {
			rc = copy_to_user(&((struct iovec *)data)->iov_len,
					&iov.iov_len, sizeof(iov.iov_len));
		}
	}
	thread_unlock(child, &lock);

	return rc;
}

static long ptrace_setregset(int pid, long type, long data)
{
	long rc = -EIO;
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;

	child = find_thread(pid, pid, &lock);
	if (!child)
		return -ESRCH;
	if (child->proc->status == PS_TRACED) {
		struct iovec iov;

		rc = copy_from_user(&iov, (struct iovec *)data, sizeof(iov));
		if (rc == 0) {
			rc = ptrace_write_regset(child, type, &iov);
		}
		if (rc == 0) {
			rc = copy_to_user(&((struct iovec *)data)->iov_len,
					&iov.iov_len, sizeof(iov.iov_len));
		}
	}
	thread_unlock(child, &lock);

	return rc;
}

static long ptrace_peektext(int pid, long addr, long data)
{
	long rc = -EIO;
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;
	unsigned long *p = (unsigned long *)data;

	child = find_thread(pid, pid, &lock);
	if (!child)
		return -ESRCH;
	if(child->proc->status == PS_TRACED){
		unsigned long value;
		rc = read_process_vm(child->vm, &value, (void *)addr, sizeof(value));
		if (rc != 0) { 
			dkprintf("ptrace_peektext: bad area  addr=0x%llx\n", addr);
		} else {
			rc = copy_to_user(p, &value, sizeof(value));
		}
	}
	thread_unlock(child, &lock);

	return rc;
}

static long ptrace_poketext(int pid, long addr, long data)
{
	long rc = -EIO;
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;

	child = find_thread(pid, pid, &lock);
	if (!child)
		return -ESRCH;
	if(child->proc->status == PS_TRACED){
		rc = patch_process_vm(child->vm, (void *)addr, &data, sizeof(data));
		if (rc) {
			dkprintf("ptrace_poketext: bad address 0x%llx\n", addr);
		}
	}
	thread_unlock(child, &lock);

	return rc;
}

static int ptrace_setoptions(int pid, int flags)
{
	int ret;
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;

	/* Only supported options are enabled.
	 * Following options are pretended to be supported for the time being:
	 * PTRACE_O_TRACESYSGOOD 
	 * PTRACE_O_TRACEFORK
	 * PTRACE_O_TRACEVFORK
	 * PTRACE_O_TRACECLONE
	 * PTRACE_O_TRACEEXEC
	 * PTRACE_O_TRACEVFORKDONE
	 */
	if (flags & ~(PTRACE_O_TRACESYSGOOD|
				PTRACE_O_TRACEFORK|
				PTRACE_O_TRACEVFORK|
				PTRACE_O_TRACECLONE|
				PTRACE_O_TRACEEXEC|
				PTRACE_O_TRACEVFORKDONE)) {
		kprintf("ptrace_setoptions: not supported flag %x\n", flags);
		ret = -EINVAL;
		goto out;
	}

	child = find_thread(pid, pid, &lock);
	if (!child || !child->proc || !(child->proc->ptrace & PT_TRACED)) {
		ret = -ESRCH;
		goto unlockout;
	}
	
	child->proc->ptrace &= ~PTRACE_O_MASK;	/* PT_TRACE_EXEC remains */
	child->proc->ptrace |= flags;
	ret = 0;

unlockout:
	if(child)
		thread_unlock(child, &lock);
out:
	return ret;
}

static int ptrace_attach(int pid)
{
	int error = 0;
	struct thread *thread;
	struct thread *mythread = cpu_local_var(current);
	struct process *proc = mythread->proc;
	struct process *child;
	struct process *parent;
	struct mcs_rwlock_node_irqsave lock;
	struct mcs_rwlock_node childlock;
	struct mcs_rwlock_node updatelock;
	struct siginfo info;

	thread = find_thread(pid, pid, &lock);
	if (!thread) {
		error = -ESRCH;
		goto out;
	}
	child = thread->proc;
	dkprintf("ptrace_attach,pid=%d,thread->proc->parent=%p\n", thread->proc->pid, thread->proc->parent);

	mcs_rwlock_writer_lock_noirq(&child->update_lock, &updatelock);
	if (thread->proc->ptrace & PT_TRACED) {
		mcs_rwlock_writer_unlock_noirq(&child->update_lock, &updatelock);
		thread_unlock(thread, &lock);
		error = -EPERM;
		goto out;
	}

	parent = child->parent;

	dkprintf("ptrace_attach,parent->pid=%d\n", parent->pid);

	mcs_rwlock_writer_lock_noirq(&parent->children_lock, &childlock);
	list_del(&child->siblings_list);
	list_add_tail(&child->ptraced_siblings_list, &parent->ptraced_children_list);
	mcs_rwlock_writer_unlock_noirq(&parent->children_lock, &childlock);

	mcs_rwlock_writer_lock_noirq(&proc->children_lock, &childlock);
	list_add_tail(&child->siblings_list, &proc->children_list);
	thread->proc->parent = proc;
	mcs_rwlock_writer_unlock_noirq(&proc->children_lock, &childlock);

	child->ptrace = PT_TRACED | PT_TRACE_EXEC;

	mcs_rwlock_writer_unlock_noirq(&thread->proc->update_lock, &updatelock);

	if (thread->ptrace_debugreg == NULL) {
		error = alloc_debugreg(thread);
		if (error < 0) {
			thread_unlock(thread, &lock);
			goto out;
		}
	}

	clear_single_step(thread);

	thread_unlock(thread, &lock);

	memset(&info, '\0', sizeof info);
	info.si_signo = SIGSTOP;
	info.si_code = SI_USER;
	info._sifields._kill.si_pid = proc->pid;
	error = do_kill(mythread, pid, -1, SIGSTOP, &info, 0);
	if (error < 0) {
		goto out;
	}

	sched_wakeup_thread(thread, PS_TRACED | PS_STOPPED);
  out:
	dkprintf("ptrace_attach,returning,error=%d\n", error);
	return error;
}


int ptrace_detach(int pid, int data)
{
	int error = 0;
	struct thread *thread;
	struct thread *mythread = cpu_local_var(current);
	struct process *proc = mythread->proc;;
	struct process *child;
	struct process *parent;
	struct mcs_rwlock_node_irqsave lock;
	struct mcs_rwlock_node childlock;
	struct mcs_rwlock_node updatelock;
	struct siginfo info;

	if (data > 64 || data < 0) {
		return -EIO;
	}

	thread = find_thread(pid, pid, &lock);
	if (!thread) {
		error = -ESRCH;
		goto out;
	}

	child = thread->proc;
	mcs_rwlock_writer_lock_noirq(&child->update_lock, &updatelock);
	parent = child->ppid_parent;
	if (!(child->ptrace & PT_TRACED) || child->parent != proc) {
		mcs_rwlock_writer_unlock_noirq(&child->update_lock, &updatelock);
		thread_unlock(thread, &lock);
		error = -ESRCH;
		goto out;
	}
	mcs_rwlock_writer_unlock_noirq(&child->update_lock, &updatelock);

	mcs_rwlock_writer_lock_noirq(&proc->children_lock, &childlock);
	list_del(&child->siblings_list);
	mcs_rwlock_writer_unlock_noirq(&proc->children_lock, &childlock);

	mcs_rwlock_writer_lock_noirq(&parent->children_lock, &childlock);
	list_del(&child->ptraced_siblings_list);
	list_add_tail(&child->siblings_list, &parent->children_list);
	child->parent = parent;
	mcs_rwlock_writer_unlock_noirq(&parent->children_lock, &childlock);

	child->ptrace = 0;

	if (thread->ptrace_debugreg) {
		kfree(thread->ptrace_debugreg);
		thread->ptrace_debugreg = NULL;
	}

	clear_single_step(thread);

	thread_unlock(thread, &lock);

	if (data != 0) {
		memset(&info, '\0', sizeof info);
		info.si_signo = data;
		info.si_code = SI_USER;
		info._sifields._kill.si_pid = proc->pid;
		error = do_kill(mythread, pid, -1, data, &info, 1);
		if (error < 0) {
			goto out;
		}
	}

	sched_wakeup_thread(thread, PS_TRACED | PS_STOPPED);
out:
	return error;
}

static long ptrace_geteventmsg(int pid, long data)
{
	unsigned long *msg_p = (unsigned long *)data;
	long rc = -ESRCH;
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;

	child = find_thread(pid, pid, &lock);
	if (!child) {
		return -ESRCH;
	}
	if (child->proc->status == PS_TRACED) {
		if (copy_to_user(msg_p, &child->proc->ptrace_eventmsg, sizeof(*msg_p))) {
			rc = -EFAULT;
		} else {
			rc = 0;
		}
	}
	thread_unlock(child, &lock);

	return rc;
}

static long
ptrace_getsiginfo(int pid, siginfo_t *data)
{
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;
	int rc = 0;

	child = find_thread(pid, pid, &lock);
	if (!child) {
		return -ESRCH;
	}

	if (child->proc->status != PS_TRACED) {
		rc = -ESRCH;
	}
	else if (child->ptrace_recvsig) {
		if (copy_to_user(data, &child->ptrace_recvsig->info, sizeof(siginfo_t))) {
			rc = -EFAULT;
		}
	}
	else {
		rc = -ESRCH;
	}
	thread_unlock(child, &lock);
	return rc;
}

static long
ptrace_setsiginfo(int pid, siginfo_t *data)
{
	struct thread *child;
	struct mcs_rwlock_node_irqsave lock;
	int rc = 0;

	child = find_thread(pid, pid, &lock);
	if (!child) {
		return -ESRCH;
	}

	if (child->proc->status != PS_TRACED) {
		rc = -ESRCH;
	}
	else {
		if (child->ptrace_sendsig == NULL) {
			child->ptrace_sendsig = kmalloc(sizeof(struct sig_pending), IHK_MC_AP_NOWAIT);
			if (child->ptrace_sendsig == NULL) {
				rc = -ENOMEM;
			}
		}

		if (!rc &&
		    copy_from_user(&child->ptrace_sendsig->info, data, sizeof(siginfo_t))) {
			rc = -EFAULT;
		}
		if (!rc &&
		    child->ptrace_recvsig){
			    if(copy_from_user(&child->ptrace_recvsig->info, data, sizeof(siginfo_t))) {
				rc = -EFAULT;
			}
		}
	}
	thread_unlock(child, &lock);
	return rc;
}

SYSCALL_DECLARE(ptrace)
{
	const long request = (long)ihk_mc_syscall_arg0(ctx);
	const int pid = (int)ihk_mc_syscall_arg1(ctx);
	const long addr = (long)ihk_mc_syscall_arg2(ctx);
	const long data = (long)ihk_mc_syscall_arg3(ctx);
	long error = -EOPNOTSUPP;

	switch(request) {
	case PTRACE_TRACEME:
		dkprintf("ptrace: PTRACE_TRACEME\n");
		error = ptrace_traceme();
		break;
	case PTRACE_KILL:
		dkprintf("ptrace: PTRACE_KILL\n");
		error = ptrace_wakeup_sig(pid, request, data);
		break;
	case PTRACE_CONT:
		dkprintf("ptrace: PTRACE_CONT: data=%d\n", data);
		error = ptrace_wakeup_sig(pid, request, data);
		break;
	case PTRACE_GETREGS:
		error = ptrace_getregs(pid, data);
		dkprintf("PTRACE_GETREGS: data=%p return=%p\n", data, error);
		break;
	case PTRACE_PEEKUSER:
		error = ptrace_peekuser(pid, addr, data);
		dkprintf("PTRACE_PEEKUSER: addr=%p return=%p\n", addr, error);
		break;
	case PTRACE_POKEUSER:
		error = ptrace_pokeuser(pid, addr, data);
		dkprintf("PTRACE_POKEUSER: addr=%p data=%p return=%p\n", addr, data, error);
		break;
	case PTRACE_SETOPTIONS:
		error = ptrace_setoptions(pid, data);
		dkprintf("PTRACE_SETOPTIONS: flags=%d return=%p\n", data, error);
		break;
	case PTRACE_PEEKTEXT:
		error = ptrace_peektext(pid, addr, data);
		dkprintf("PTRACE_PEEKTEXT: addr=%p return=%p\n", addr, error);
		break;
	case PTRACE_PEEKDATA:
		error = ptrace_peektext(pid, addr, data);
		dkprintf("PTRACE_PEEKDATA: addr=%p return=%p\n", addr, error);
		break;
	case PTRACE_POKETEXT:
		error = ptrace_poketext(pid, addr, data);
		dkprintf("PTRACE_POKETEXT: addr=%p data=%p\n", addr, data);
		break;
	case PTRACE_POKEDATA:
		error = ptrace_poketext(pid, addr, data);
		dkprintf("PTRACE_POKEDATA: addr=%p data=%p\n", addr, data);
		break;
	case PTRACE_SINGLESTEP:
		dkprintf("ptrace: PTRACE_SINGLESTEP: data=%d\n", data);
		error = ptrace_wakeup_sig(pid, request, data);
		break;
	case PTRACE_GETFPREGS:
		dkprintf("ptrace: PTRACE_GETFPREGS: data=%p\n", data);
		error = ptrace_getfpregs(pid, data);
		break;
	case PTRACE_SETFPREGS:
		dkprintf("ptrace: PTRACE_SETFPREGS: data=%p\n", data);
		error = ptrace_setfpregs(pid, data);
		break;
	case PTRACE_SETREGS:
		error = ptrace_setregs(pid, data);
		dkprintf("PTRACE_SETREGS: data=%p return=%p\n", data, error);
		break;
	case PTRACE_ATTACH:
		dkprintf("ptrace: PTRACE_ATTACH: pid=%d\n", pid);
		error = ptrace_attach(pid);
		break;
	case PTRACE_DETACH:
		dkprintf("ptrace: PTRACE_DETACH: data=%d\n", data);
		error = ptrace_detach(pid, data);
		break;
	case PTRACE_SYSCALL:
		dkprintf("ptrace: PTRACE_SYSCALL: data=%d\n", data);
		error = ptrace_wakeup_sig(pid, request, data);
		break;
	case PTRACE_GETSIGINFO:
		dkprintf("ptrace: PTRACE_GETSIGINFO: data=%p\n", data);
		error = ptrace_getsiginfo(pid, (siginfo_t *)data);
		break;
	case PTRACE_SETSIGINFO:
		dkprintf("ptrace: PTRACE_SETSIGINFO: data=%p\n", data);
		error = ptrace_setsiginfo(pid, (siginfo_t *)data);
		break;
	case PTRACE_GETREGSET:
		dkprintf("ptrace: PTRACE_GETREGSET: addr=0x%x, data=%p\n", addr, data);
		error = ptrace_getregset(pid, addr, data);
		break;
	case PTRACE_SETREGSET:
		dkprintf("ptrace: PTRACE_SETREGSET: addr=0x%x, data=%p\n", addr, data);
		error = ptrace_setregset(pid, addr, data);
		break;
	case PTRACE_ARCH_PRCTL:
		error = ptrace_arch_prctl(pid, data, addr);
		dkprintf("PTRACE_ARCH_PRCTL: data=%p addr=%p return=%p\n", data, addr, error);
		break;
	case PTRACE_GETEVENTMSG:
		dkprintf("ptrace: PTRACE_GETEVENTMSG: data=%p\n", data);
		error = ptrace_geteventmsg(pid, data);
		break;
	default:
		kprintf("ptrace: unimplemented ptrace(%d) called.\n", request);
		break;
	}

	dkprintf("ptrace(%d,%ld,%p,%p): returning %d\n", request, pid, addr, data, error);
	return error;
}

/* We do not have actual scheduling classes so we just make sure we store
 * policies and priorities in a POSIX/Linux complaint manner */
static int setscheduler(struct thread *thread, int policy, struct sched_param *param)
{
	if ((policy == SCHED_FIFO || policy == SCHED_RR) &&
		((param->sched_priority < 1) ||
		 (param->sched_priority > MAX_USER_RT_PRIO - 1))) {
		return -EINVAL;
	}
	
	if ((policy == SCHED_NORMAL || policy == SCHED_BATCH || policy == SCHED_IDLE) &&
		(param->sched_priority != 0)) {
		return -EINVAL;
	}

	memcpy(&thread->sched_param, param, sizeof(*param));
	thread->sched_policy = policy;

	return 0;
}

#define SCHED_CHECK_SAME_OWNER        0x01
#define SCHED_CHECK_ROOT              0x02

SYSCALL_DECLARE(sched_setparam)
{
	int retval = 0;
	int pid = (int)ihk_mc_syscall_arg0(ctx);
	struct sched_param *uparam = (struct sched_param *)ihk_mc_syscall_arg1(ctx);
	struct sched_param param;
	struct thread *thread = cpu_local_var(current);
	struct mcs_rwlock_node_irqsave lock;
	
	struct syscall_request request1 IHK_DMA_ALIGN;

	dkprintf("sched_setparam: pid: %d, uparam: 0x%lx\n", pid, uparam);

	if (!uparam || pid < 0) {
		return -EINVAL;
	}

	if (pid == 0)
		pid = thread->proc->pid;

	if (thread->proc->pid != pid) {
		thread = find_thread(pid, pid, &lock);
		if (!thread) {
			return -ESRCH;
		}
		// TODO: unlock 場所のチェック
		// 何をしようとしているのか理解
		thread_unlock(thread, &lock);
		
		/* Ask Linux about ownership.. */
		request1.number = __NR_sched_setparam;
		request1.args[0] = SCHED_CHECK_SAME_OWNER;
		request1.args[1] = pid;

		retval = do_syscall(&request1, ihk_mc_get_processor_id(), 0);
		if (retval != 0) {
			return retval;
		}
	}

	retval = copy_from_user(&param, uparam, sizeof(param));
	if (retval < 0) {
		return -EFAULT;
	}

	return setscheduler(thread, thread->sched_policy, &param);
}

SYSCALL_DECLARE(sched_getparam)
{
	int retval = 0;
	int pid = (int)ihk_mc_syscall_arg0(ctx);
	struct sched_param *param = (struct sched_param *)ihk_mc_syscall_arg1(ctx);
	struct thread *thread = cpu_local_var(current);
	struct mcs_rwlock_node_irqsave lock;

	if (!param || pid < 0) {
		return -EINVAL;
	}

	if (pid == 0)
		pid = thread->proc->pid;

	if (thread->proc->pid != pid) {
		thread = find_thread(pid, pid, &lock);
		if (!thread) {
			return -ESRCH;
		}
		thread_unlock(thread, &lock);
	}
	
	retval = copy_to_user(param, &thread->sched_param, sizeof(*param)) ? -EFAULT : 0;
	
	return retval;
}

SYSCALL_DECLARE(sched_setscheduler)
{
	int retval;
	int pid = (int)ihk_mc_syscall_arg0(ctx);
	int policy = ihk_mc_syscall_arg1(ctx);
	struct sched_param *uparam = (struct sched_param *)ihk_mc_syscall_arg2(ctx);
	struct sched_param param;
	struct thread *thread = cpu_local_var(current);
	struct mcs_rwlock_node_irqsave lock;
	
	struct syscall_request request1 IHK_DMA_ALIGN;
	
	if (!uparam || pid < 0) {
		return -EINVAL;
	}
	
	if (policy != SCHED_DEADLINE &&
			policy != SCHED_FIFO && policy != SCHED_RR &&
			policy != SCHED_NORMAL && policy != SCHED_BATCH &&
			policy != SCHED_IDLE) {
		return -EINVAL;
	}

	if (policy != SCHED_NORMAL) {
		
		/* Ask Linux about permissions */
		request1.number = __NR_sched_setparam;
		request1.args[0] = SCHED_CHECK_ROOT;

		retval = do_syscall(&request1, ihk_mc_get_processor_id(), 0);
		if (retval != 0) {
			return retval;
		}
	}
	
	retval = copy_from_user(&param, uparam, sizeof(param));
	if (retval < 0) {
		return -EFAULT;
	}

	if (pid == 0)
		pid = thread->proc->pid;

	if (thread->proc->pid != pid) {
		thread = find_thread(pid, pid, &lock);
		if (!thread) {
			return -ESRCH;
		}
		thread_unlock(thread, &lock);
		
		/* Ask Linux about ownership.. */
		request1.number = __NR_sched_setparam;
		request1.args[0] = SCHED_CHECK_SAME_OWNER;
		request1.args[1] = pid;

		retval = do_syscall(&request1, ihk_mc_get_processor_id(), 0);
		if (retval != 0) {
			return retval;
		}
	}

	return setscheduler(thread, policy, &param);
}

SYSCALL_DECLARE(sched_getscheduler)
{
	int pid = (int)ihk_mc_syscall_arg0(ctx);
	struct thread *thread = cpu_local_var(current);
	struct mcs_rwlock_node_irqsave lock;

	if (pid < 0) {
		return -EINVAL;
	}

	if (pid == 0)
		pid = thread->proc->pid;

	if (thread->proc->pid != pid) {
		thread = find_thread(pid, pid, &lock);
		if (!thread) {
			return -ESRCH;
		}
		thread_unlock(thread, &lock);
	}

	return thread->sched_policy;
}

SYSCALL_DECLARE(sched_get_priority_max)
{
	int ret = -EINVAL;
	int policy = ihk_mc_syscall_arg0(ctx);

	switch (policy) {
		case SCHED_FIFO:
		case SCHED_RR:
			ret = MAX_USER_RT_PRIO - 1;
			break;
		case SCHED_DEADLINE:
		case SCHED_NORMAL:
		case SCHED_BATCH:
		case SCHED_IDLE:
			ret = 0;
			break;
	}
	return ret;
}

SYSCALL_DECLARE(sched_get_priority_min)
{
	int ret = -EINVAL;
	int policy = ihk_mc_syscall_arg0(ctx);

	switch (policy) {
		case SCHED_FIFO:
		case SCHED_RR:
			ret = 1;
			break;
		case SCHED_DEADLINE:
		case SCHED_NORMAL:
		case SCHED_BATCH:
		case SCHED_IDLE:
			ret = 0;
	}
	return ret;
}

SYSCALL_DECLARE(sched_rr_get_interval)
{
	int pid = ihk_mc_syscall_arg0(ctx);
	struct timespec *utime = (struct timespec *)ihk_mc_syscall_arg1(ctx);
	struct timespec t;
	struct thread *thread = cpu_local_var(current);
	struct mcs_rwlock_node_irqsave lock;
	int retval = 0;

	if (pid < 0) 
		return -EINVAL;

	if (pid == 0)
		pid = thread->proc->pid;

	if (thread->proc->pid != pid) {
		thread = find_thread(pid, pid, &lock);
		if (!thread) {
			return -ESRCH;
		}
		thread_unlock(thread, &lock);
	}
	
	t.tv_sec = 0;
	t.tv_nsec = 0;
	if (thread->sched_policy == SCHED_RR) {
		t.tv_nsec = 10000;
	}
	
	retval = copy_to_user(utime, &t, sizeof(t)) ? -EFAULT : 0;
	
	return retval;
}

#define MIN2(x,y) (x) < (y) ? (x) : (y)
SYSCALL_DECLARE(sched_setaffinity)
{
	int tid = (int)ihk_mc_syscall_arg0(ctx);
	size_t len = (size_t)ihk_mc_syscall_arg1(ctx);
	cpu_set_t *u_cpu_set = (cpu_set_t *)ihk_mc_syscall_arg2(ctx);
	cpu_set_t k_cpu_set, cpu_set;
	struct thread *thread;
	int cpu_id;
	int empty_set = 1; 
	extern int num_processors;

kprintf("sched_setaffinity tid=%d len=%d set=%p\n", tid, len, u_cpu_set);
	if (sizeof(k_cpu_set) > len) {
		memset(&k_cpu_set, 0, sizeof(k_cpu_set));
	}

	len = MIN2(len, sizeof(k_cpu_set));

	if (copy_from_user(&k_cpu_set, u_cpu_set, len)) {
		kprintf("%s:%d copy_from_user failed.\n", __FILE__, __LINE__);
		return -EFAULT;
	}

	// XXX: We should build something like cpu_available_mask in advance
	CPU_ZERO(&cpu_set);
	for (cpu_id = 0; cpu_id < num_processors; cpu_id++) {
		if (CPU_ISSET(cpu_id, &k_cpu_set)) {
			CPU_SET(cpu_id, &cpu_set);
			dkprintf("sched_setaffinity(): tid %d: setting target core %d\n",
					cpu_local_var(current)->tid, cpu_id);
			empty_set = 0;
		}
	}
	
	/* Empty target set? */
	if (empty_set) {
		return -EINVAL;
	}

	if (tid == 0) {
		tid = cpu_local_var(current)->tid;
		thread = cpu_local_var(current);
		cpu_id = ihk_mc_get_processor_id();
		hold_thread(thread);
	}
	else {
		struct mcs_rwlock_node_irqsave lock;
		struct thread *mythread = cpu_local_var(current);

		thread = find_thread(0, tid, &lock);
		if(!thread)
			return -ESRCH;
		if(mythread->proc->euid != 0 &&
		   mythread->proc->euid != thread->proc->ruid &&
		   mythread->proc->euid != thread->proc->euid){
			thread_unlock(thread, &lock);
			return -EPERM;
		}
		hold_thread(thread);
		thread_unlock(thread, &lock);
		cpu_id = thread->cpu_id;
	}

	memcpy(&thread->cpu_set, &cpu_set, sizeof(cpu_set));

	if (!CPU_ISSET(cpu_id, &thread->cpu_set)) {
		dkprintf("sched_setaffinity(): tid %d sched_request_migrate\n",
				cpu_local_var(current)->tid, cpu_id);
		sched_request_migrate(cpu_id, thread);
	} 
	release_thread(thread);
	return 0;
}

// see linux-2.6.34.13/kernel/sched.c
SYSCALL_DECLARE(sched_getaffinity)
{
	int tid = (int)ihk_mc_syscall_arg0(ctx);
	size_t len = (size_t)ihk_mc_syscall_arg1(ctx);
	cpu_set_t k_cpu_set, *u_cpu_set = (cpu_set_t *)ihk_mc_syscall_arg2(ctx);
	struct thread *thread;
	int ret;

	if (!len)
		return -EINVAL;

	len = MIN2(len, sizeof(k_cpu_set));

	if(tid == 0){
		thread = cpu_local_var(current);
		hold_thread(thread);
	}
	else{
		struct mcs_rwlock_node_irqsave lock;
		struct thread *mythread = cpu_local_var(current);

		thread = find_thread(0, tid, &lock);
		if(!thread)
			return -ESRCH;
		if(mythread->proc->euid != 0 &&
		   mythread->proc->euid != thread->proc->ruid &&
		   mythread->proc->euid != thread->proc->euid){
			thread_unlock(thread, &lock);
			return -EPERM;
		}
		hold_thread(thread);
		thread_unlock(thread, &lock);
	}

	ret = copy_to_user(u_cpu_set, &thread->cpu_set, len);
	release_thread(thread);
	dkprintf("%s() ret: %d\n", __FUNCTION__, ret);
	if (ret < 0)
		return ret;
	return len;
}

SYSCALL_DECLARE(get_cpu_id)
{
	return ihk_mc_get_processor_id();
}

static void calculate_time_from_tsc(struct timespec *ts)
{
	long ver;
	unsigned long current_tsc;
	time_t sec_delta;
	long ns_delta;

	for (;;) {
		while ((ver = ihk_atomic64_read(&tod_data.version)) & 1) {
			/* settimeofday() is in progress */
			cpu_pause();
		}
		rmb();
		*ts = tod_data.origin;
		rmb();
		if (ver == ihk_atomic64_read(&tod_data.version)) {
			break;
		}

		/* settimeofday() has intervened */
		cpu_pause();
	}

	current_tsc = rdtsc();
	sec_delta = current_tsc / tod_data.clocks_per_sec;
	ns_delta = NS_PER_SEC * (current_tsc % tod_data.clocks_per_sec)
		/ tod_data.clocks_per_sec;
	/* calc. of ns_delta overflows if clocks_per_sec exceeds 18.44 GHz */

	ts->tv_sec += sec_delta;
	ts->tv_nsec += ns_delta;
	if (ts->tv_nsec >= NS_PER_SEC) {
		ts->tv_nsec -= NS_PER_SEC;
		++ts->tv_sec;
	}

	return;
}

SYSCALL_DECLARE(clock_gettime)
{
	/* TODO: handle clock_id */
	struct timespec *ts = (struct timespec *)ihk_mc_syscall_arg1(ctx);
	int clock_id = (int)ihk_mc_syscall_arg0(ctx);
	struct syscall_request request IHK_DMA_ALIGN;
	int error;
	struct timespec ats;

	if (!ts) {
		/* nothing to do */
		return 0;
	}

	/* Do it locally if supported */
	if (gettime_local_support && clock_id == CLOCK_REALTIME) {
		calculate_time_from_tsc(&ats);

		error = copy_to_user(ts, &ats, sizeof(ats));

		dkprintf("clock_gettime(): %d\n", error);
		return error;
	}
	else if(clock_id == CLOCK_PROCESS_CPUTIME_ID){
		struct thread *thread = cpu_local_var(current);
		struct process *proc = thread->proc;
		struct thread *child;
		struct mcs_rwlock_node lock;

		mcs_rwlock_reader_lock_noirq(&proc->children_lock, &lock);
		list_for_each_entry(child, &proc->threads_list, siblings_list){
			if(child != thread &&
			   child->status == PS_RUNNING &&
			   !child->in_kernel){
				child->times_update = 0;
				ihk_mc_interrupt_cpu(get_x86_cpu_local_variable(child->cpu_id)->apic_id, 0xd1);
			}
		}
		ats.tv_sec = proc->utime.tv_sec;
		ats.tv_nsec = proc->utime.tv_nsec;
		ts_add(&ats, &proc->stime);
		list_for_each_entry(child, &proc->threads_list, siblings_list){
			while(!child->times_update)
				cpu_pause();
			ts_add(&ats, &child->utime);
			ts_add(&ats, &child->stime);
		}
		mcs_rwlock_reader_unlock_noirq(&proc->children_lock, &lock);
		return copy_to_user(ts, &ats, sizeof ats);
	}
	else if(clock_id == CLOCK_THREAD_CPUTIME_ID){
		struct thread *thread = cpu_local_var(current);

		ats.tv_sec = thread->utime.tv_sec;
		ats.tv_nsec = thread->utime.tv_nsec;
		ts_add(&ats, &thread->stime);
		return copy_to_user(ts, &ats, sizeof ats);
	}

	/* Otherwise offload */
	request.number = __NR_clock_gettime;
	request.args[0] = ihk_mc_syscall_arg0(ctx);
	request.args[1] = ihk_mc_syscall_arg1(ctx);

	return do_syscall(&request, ihk_mc_get_processor_id(), 0);
}

SYSCALL_DECLARE(gettimeofday)
{
	struct timeval *tv = (struct timeval *)ihk_mc_syscall_arg0(ctx);
	struct syscall_request request IHK_DMA_ALIGN;
	struct timezone *tz = (struct timezone *)ihk_mc_syscall_arg1(ctx);
	struct timeval atv;
	int error;
	struct timespec ats;

	if (!tv && !tz) {
		/* nothing to do */
		return 0;
	}

	/* Do it locally if supported */
	if (!tz && gettime_local_support) {
		calculate_time_from_tsc(&ats);

		atv.tv_sec = ats.tv_sec;
		atv.tv_usec = ats.tv_nsec / 1000;

		error = copy_to_user(tv, &atv, sizeof(atv));

		dkprintf("gettimeofday(): %d\n", error);
		return error;
	}

	/* Otherwise offload */
	request.number = __NR_gettimeofday;
	request.args[0] = (unsigned long)tv;
	request.args[1] = (unsigned long)tz;

	return do_syscall(&request, ihk_mc_get_processor_id(), 0);
}

SYSCALL_DECLARE(settimeofday)
{
	long error;
	struct timeval * const utv = (void *)ihk_mc_syscall_arg0(ctx);
	struct timezone * const utz = (void *)ihk_mc_syscall_arg1(ctx);
	struct timeval tv;
	struct timespec newts;
	unsigned long tsc;

	dkprintf("sys_settimeofday(%p,%p)\n", utv, utz);
	ihk_mc_spinlock_lock_noirq(&tod_data_lock);
	if (ihk_atomic64_read(&tod_data.version) & 1) {
		panic("settimeofday");
	}

	if (utv && gettime_local_support) {
		if (copy_from_user(&tv, utv, sizeof(tv))) {
			error = -EFAULT;
			goto out;
		}
		newts.tv_sec = tv.tv_sec;
		newts.tv_nsec = (long)tv.tv_usec * 1000;

		tsc = rdtsc();
		newts.tv_sec -= tsc / tod_data.clocks_per_sec;
		newts.tv_nsec -= NS_PER_SEC * (tsc % tod_data.clocks_per_sec)
			/ tod_data.clocks_per_sec;
		if (newts.tv_nsec < 0) {
			--newts.tv_sec;
			newts.tv_nsec += NS_PER_SEC;
		}
	}

	error = syscall_generic_forwarding(n, ctx);

	if (!error && utv && gettime_local_support) {
		dkprintf("sys_settimeofday(%p,%p):origin <-- %ld.%ld\n",
				utv, utz, newts.tv_sec, newts.tv_nsec);
		ihk_atomic64_inc(&tod_data.version);
		wmb();
		tod_data.origin = newts;
		wmb();
		ihk_atomic64_inc(&tod_data.version);
	}

out:
	ihk_mc_spinlock_unlock_noirq(&tod_data_lock);
	dkprintf("sys_settimeofday(%p,%p): %ld\n", utv, utz, error);
	return error;
}

SYSCALL_DECLARE(nanosleep)
{
	struct timespec *tv = (struct timespec *)ihk_mc_syscall_arg0(ctx);
	struct timespec *rem = (struct timespec *)ihk_mc_syscall_arg1(ctx);
	struct syscall_request request IHK_DMA_ALIGN;

	/* Do it locally if supported */
	if (gettime_local_support) {
		unsigned long nanosecs;
		unsigned long nanosecs_rem;
		unsigned long tscs;
		long tscs_rem;
		struct timespec _tv;
		struct timespec _rem;
		int ret = 0;

		unsigned long ts = rdtsc();

		if (copy_from_user(&_tv, tv, sizeof(*tv))) {
			return -EFAULT;
		}

		if (_tv.tv_sec < 0 || _tv.tv_nsec >= NS_PER_SEC) {
			return -EINVAL;
		}

		nanosecs = _tv.tv_sec * NS_PER_SEC + _tv.tv_nsec;
		tscs = nanosecs * 1000 / ihk_mc_get_ns_per_tsc();

		/* Spin wait */
		while (rdtsc() - ts < tscs) {
			if (hassigpending(cpu_local_var(current))) {
				ret = -EINTR;
				break;
			}
		}

		if ((ret == -EINTR) && rem) {
			tscs_rem = tscs - (rdtsc() - ts);
			if (tscs_rem < 0) {
				tscs_rem = 0;
			}
			nanosecs_rem = tscs_rem * ihk_mc_get_ns_per_tsc() / 1000;

			_rem.tv_sec = nanosecs_rem / NS_PER_SEC;
			_rem.tv_nsec = nanosecs_rem % NS_PER_SEC;

			if (copy_to_user(rem, &_rem, sizeof(*rem))) {
				ret = -EFAULT;
			}
		}

		return ret;
	}

	/* Otherwise offload */
	request.number = __NR_nanosleep;
	request.args[0] = (unsigned long)tv;
	request.args[1] = (unsigned long)rem;

	return do_syscall(&request, ihk_mc_get_processor_id(), 0);
}

SYSCALL_DECLARE(sched_yield)
{
	schedule();

	return 0;
}

SYSCALL_DECLARE(mlock)
{
	const uintptr_t start0 = ihk_mc_syscall_arg0(ctx);
	const size_t len0 = ihk_mc_syscall_arg1(ctx);
	struct thread *thread = cpu_local_var(current);
	struct vm_regions *region = &thread->vm->region;
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

	ihk_mc_spinlock_lock_noirq(&thread->vm->memory_range_lock);

	/* check contiguous map */
	first = NULL;
	for (addr = start; addr < end; addr = range->end) {
		if (first == NULL) {
			range = lookup_process_memory_range(thread->vm, start, start+PAGE_SIZE);
			first = range;
		}
		else {
			range = next_process_memory_range(thread->vm, range);
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
			range = next_process_memory_range(thread->vm, changed);
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
			error = split_process_memory_range(thread->vm, range, addr, &range);
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
			error = split_process_memory_range(thread->vm, range, end, NULL);
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
			error = join_process_memory_range(thread->vm, changed, range);
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
	ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);

	if (!error) {
		error = populate_process_memory(thread->vm, (void *)start, len);
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
	struct thread *thread = cpu_local_var(current);
	struct vm_regions *region = &thread->vm->region;
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

	ihk_mc_spinlock_lock_noirq(&thread->vm->memory_range_lock);

	/* check contiguous map */
	first = NULL;
	for (addr = start; addr < end; addr = range->end) {
		if (first == NULL) {
			range = lookup_process_memory_range(thread->vm, start, start+PAGE_SIZE);
			first = range;
		}
		else {
			range = next_process_memory_range(thread->vm, range);
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
			range = next_process_memory_range(thread->vm, changed);
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
			error = split_process_memory_range(thread->vm, range, addr, &range);
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
			error = split_process_memory_range(thread->vm, range, end, NULL);
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
			error = join_process_memory_range(thread->vm, changed, range);
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
	ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);
out2:
	dkprintf("[%d]sys_munlock(%lx,%lx): %d\n",
			ihk_mc_get_processor_id(), start0, len0, error);
	return error;
}

SYSCALL_DECLARE(mlockall)
{
	const int flags = ihk_mc_syscall_arg0(ctx);
	struct thread *thread = cpu_local_var(current);
	uid_t euid = geteuid();

	if (!flags || (flags & ~(MCL_CURRENT|MCL_FUTURE))) {
		kprintf("mlockall(0x%x):invalid flags: EINVAL\n", flags);
		return -EINVAL;
	}

	if (!euid) {
		kprintf("mlockall(0x%x):priv user: 0\n", flags);
		return 0;
	}

	if (thread->proc->rlimit[MCK_RLIMIT_MEMLOCK].rlim_cur != 0) {
		kprintf("mlockall(0x%x):limits exists: ENOMEM\n", flags);
		return -ENOMEM;
	}

	kprintf("mlockall(0x%x):no lock permitted: EPERM\n", flags);
	return -EPERM;
} /* sys_mlockall() */

SYSCALL_DECLARE(munlockall)
{
	kprintf("munlockall(): 0\n");
	return 0;
} /* sys_munlockall() */

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
	struct thread * const thread = cpu_local_var(current);
	struct vm_range *range;
	int er;
	int need_populate = 0;

	dkprintf("sys_remap_file_pages(%#lx,%#lx,%#x,%#lx,%#x)\n",
			start0, size, prot, pgoff, flags);
	ihk_mc_spinlock_lock_noirq(&thread->vm->memory_range_lock);
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

	range = lookup_process_memory_range(thread->vm, start, end);
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
	error = remap_process_memory_range(thread->vm, range, start, end, off);
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
	ihk_mc_spinlock_unlock_noirq(&thread->vm->memory_range_lock);

	if (need_populate
			&& (er = populate_process_memory(
					thread->vm, (void *)start, size))) {
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
	struct thread *thread = cpu_local_var(current);
	struct process_vm *vm = thread->vm;
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
		error = add_process_memory_range(thread->vm, newstart, newend, -1,
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
			error = move_pte_range(vm->address_space->page_table, vm,
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
		error = populate_process_memory(thread->vm, (void *)lckstart, (lckend - lckstart));
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

SYSCALL_DECLARE(msync)
{
	const uintptr_t start0 = ihk_mc_syscall_arg0(ctx);
	const size_t len0 = ihk_mc_syscall_arg1(ctx);
	const int flags = ihk_mc_syscall_arg2(ctx);
	const size_t len = (len0 + PAGE_SIZE - 1) & PAGE_MASK;
	const uintptr_t start = start0;
	const uintptr_t end = start + len;
	struct thread *thread = cpu_local_var(current);
	struct process_vm *vm = thread->vm;
	int error;
	uintptr_t addr;
	struct vm_range *range;
	uintptr_t s;
	uintptr_t e;

	dkprintf("sys_msync(%#lx,%#lx,%#x)\n", start0, len0, flags);
	ihk_mc_spinlock_lock_noirq(&vm->memory_range_lock);

	if ((start0 & ~PAGE_MASK)
			|| (flags & ~(MS_ASYNC|MS_INVALIDATE|MS_SYNC))
			|| ((flags & MS_ASYNC) && (flags & MS_SYNC))) {
		error = -EINVAL;
		ekprintf("sys_msync(%#lx,%#lx,%#x):invalid args. %d\n",
				start0, len0, flags, error);
		goto out;
	}
	if (end < start) {
		error = -ENOMEM;
		ekprintf("sys_msync(%#lx,%#lx,%#x):invalid args. %d\n",
				start0, len0, flags, error);
		goto out;
	}

	/* check ranges */
	range = NULL;
	for (addr = start; addr < end; addr = range->end) {
		if (!range) {
			range = lookup_process_memory_range(vm, addr,
					addr+PAGE_SIZE);
		}
		else {
			range = next_process_memory_range(vm, range);
		}

		if (!range || (addr < range->start)) {
			error = -ENOMEM;
			ekprintf("sys_msync(%#lx,%#lx,%#x):"
					"invalid VMR %d %#lx-%#lx %#lx\n",
					start0, len0, flags, error,
					range?range->start:0,
					range?range->end:0,
					range?range->flag:0);
			goto out;
		}
		if ((flags & MS_INVALIDATE) && (range->flag & VR_LOCKED)) {
			error = -EBUSY;
			ekprintf("sys_msync(%#lx,%#lx,%#x):"
					"locked VMR %d %#lx-%#lx %#lx\n",
					start0, len0, flags, error,
					range->start, range->end, range->flag);
			goto out;
		}
	}

	/* do the sync */
	range = NULL;
	for (addr = start; addr < end; addr = range->end) {
		if (!range) {
			range = lookup_process_memory_range(vm, addr,
					addr+PAGE_SIZE);
		}
		else {
			range = next_process_memory_range(vm, range);
		}

		if ((range->flag & VR_PRIVATE) || !range->memobj
				|| !memobj_has_pager(range->memobj)) {
			dkprintf("sys_msync(%#lx,%#lx,%#x):"
					"unsyncable VMR %d %#lx-%#lx %#lx\n",
					start0, len0, flags, error,
					range->start, range->end, range->flag);
			/* nothing to do */
			continue;
		}

		s = addr;
		e = (range->end < end)? range->end: end;

		if (flags & (MS_ASYNC | MS_SYNC)) {
			error = sync_process_memory_range(vm, range, s, e);
			if (error) {
				ekprintf("sys_msync(%#lx,%#lx,%#x):sync failed. %d\n",
						start0, len0, flags, error);
				goto out;
			}
		}

		if (flags & MS_INVALIDATE) {
			error = invalidate_process_memory_range(
					vm, range, s, e);
			if (error) {
				ekprintf("sys_msync(%#lx,%#lx,%#x):"
						"invalidate failed. %d\n",
						start0, len0, flags, error);
				goto out;
			}
		}
	}

	error = 0;
out:
	ihk_mc_spinlock_unlock_noirq(&vm->memory_range_lock);
	dkprintf("sys_msync(%#lx,%#lx,%#x):%d\n", start0, len0, flags, error);
	return error;
} /* sys_msync() */

SYSCALL_DECLARE(getcpu)
{
	const uintptr_t cpup = ihk_mc_syscall_arg0(ctx);
	const uintptr_t nodep = ihk_mc_syscall_arg1(ctx);
	const int cpu = ihk_mc_get_processor_id();
	const int node = 0;
	int error;

	if (cpup) {
		error = copy_to_user((void *)cpup, &cpu, sizeof(cpu));
		if (error) {
			goto out;
		}
	}

	if (nodep) {
		error = copy_to_user((void *)nodep, &node, sizeof(node));
		if (error) {
			goto out;
		}
	}

	error = 0;
out:
	return error;
} /* sys_getcpu() */

SYSCALL_DECLARE(mbind)
{
	dkprintf("sys_mbind\n");
	return -ENOSYS;
} /* sys_mbind() */

SYSCALL_DECLARE(set_mempolicy)
{
	dkprintf("sys_set_mempolicy\n");
	return -ENOSYS;
} /* sys_set_mempolicy() */

SYSCALL_DECLARE(get_mempolicy)
{
	dkprintf("sys_get_mempolicy\n");
	return -ENOSYS;
} /* sys_get_mempolicy() */

SYSCALL_DECLARE(migrate_pages)
{
	dkprintf("sys_migrate_pages\n");
	return -ENOSYS;
} /* sys_migrate_pages() */

SYSCALL_DECLARE(move_pages)
{
	dkprintf("sys_move_pages\n");
	return -ENOSYS;
} /* sys_move_pages() */

#define PROCESS_VM_READ		0
#define PROCESS_VM_WRITE	1

static int do_process_vm_read_writev(int pid, 
		const struct iovec *local_iov,
		unsigned long liovcnt,
		const struct iovec *remote_iov,
		unsigned long riovcnt,
		unsigned long flags,
		int op)
{
	int ret = -EINVAL;	
	int li, ri;
	int pli, pri;
	off_t loff, roff;
	size_t llen = 0, rlen = 0;
	size_t copied = 0;
	size_t to_copy;
	struct thread *lthread = cpu_local_var(current);
	struct process *rproc;
	struct process *lproc = lthread->proc;
	struct process_vm *rvm = NULL;
	unsigned long rphys;
	unsigned long rpage_left;
	void *rva;
	struct vm_range *range;
	struct mcs_rwlock_node_irqsave lock;
	struct mcs_rwlock_node update_lock;

	/* Sanity checks */
	if (flags) {
		return -EINVAL;
	}
	
	if (liovcnt > IOV_MAX || riovcnt > IOV_MAX) {
		return -EINVAL;
	}

	/* Check if parameters are okay */
	ihk_mc_spinlock_lock_noirq(&lthread->vm->memory_range_lock);

	range = lookup_process_memory_range(lthread->vm, 
			(uintptr_t)local_iov, 
			(uintptr_t)(local_iov + liovcnt * sizeof(struct iovec)));

	if (!range) {
		ret = -EFAULT; 
		goto arg_out;
	}

	range = lookup_process_memory_range(lthread->vm, 
			(uintptr_t)remote_iov, 
			(uintptr_t)(remote_iov + riovcnt * sizeof(struct iovec)));

	if (!range) {
		ret = -EFAULT; 
		goto arg_out;
	}

	ret = 0;
arg_out:
	ihk_mc_spinlock_unlock_noirq(&lthread->vm->memory_range_lock);

	if (ret != 0) {
		goto out;
	}

	for (li = 0; li < liovcnt; ++li) {
		llen += local_iov[li].iov_len;
		dkprintf("local_iov[%d].iov_base: 0x%lx, len: %lu\n",
			li, local_iov[li].iov_base, local_iov[li].iov_len);
	}

	for (ri = 0; ri < riovcnt; ++ri) {
		rlen += remote_iov[ri].iov_len;
		dkprintf("remote_iov[%d].iov_base: 0x%lx, len: %lu\n",
			ri, remote_iov[ri].iov_base, remote_iov[ri].iov_len);
	}

	if (llen != rlen) {
		return -EINVAL;
	}
	
	/* Find remote process */
	rproc = find_process(pid, &lock);
	if (!rproc) {
		ret = -ESRCH;
		goto out;
	}

	mcs_rwlock_reader_lock_noirq(&rproc->update_lock, &update_lock);
	if(rproc->status == PS_EXITED ||
	   rproc->status == PS_ZOMBIE){
		mcs_rwlock_reader_unlock_noirq(&rproc->update_lock, &update_lock);
		process_unlock(rproc, &lock);
		ret = -ESRCH;
		goto out;
	}
	rvm = rproc->vm;
	hold_process_vm(rvm);
	mcs_rwlock_reader_unlock_noirq(&rproc->update_lock, &update_lock);
	process_unlock(rproc, &lock);

	if (lproc->euid != 0 &&
	    (lproc->ruid != rproc->ruid ||
	     lproc->ruid != rproc->euid ||
	     lproc->ruid != rproc->suid ||
	     lproc->rgid != rproc->rgid ||
	     lproc->rgid != rproc->egid ||
	     lproc->rgid != rproc->sgid)) {
		ret = -EPERM;
		goto out;
	}

	dkprintf("pid %d found, doing %s \n", pid, 
		(op == PROCESS_VM_READ) ? "PROCESS_VM_READ" : "PROCESS_VM_WRITE");
	
	pli = pri = -1; /* Previous indeces in iovecs */
	li = ri = 0; /* Current indeces in iovecs */
	loff = roff = 0; /* Offsets in current iovec */

	/* Now iterate and do the copy */
	while (copied < llen) {
		
		/* New local vector? */
		if (pli != li) {
			struct vm_range *range;
			
			ihk_mc_spinlock_lock_noirq(&lthread->vm->memory_range_lock);
			
			/* Is base valid? */
			range = lookup_process_memory_range(lthread->vm, 
					(uintptr_t)local_iov[li].iov_base, 
					(uintptr_t)(local_iov[li].iov_base + 1));

			if (!range) {
				ret = -EFAULT; 
				goto pli_out;
			}

			/* Is length valid? */
			range = lookup_process_memory_range(lthread->vm, 
					(uintptr_t)local_iov[li].iov_base, 
					(uintptr_t)(local_iov[li].iov_base + local_iov[li].iov_len));

			if (range == NULL) {
				ret = -EINVAL; 
				goto pli_out;
			}

			if (!(range->flag & ((op == PROCESS_VM_READ) ? 
				VR_PROT_WRITE : VR_PROT_READ))) {
				ret = -EFAULT;
				goto pli_out;
			}

			ret = 0;
pli_out:
			ihk_mc_spinlock_unlock_noirq(&lthread->vm->memory_range_lock);

			if (ret != 0) {
				goto out;
			}

			pli = li;
		}

		/* New remote vector? */
		if (pri != ri) {
			uint64_t reason = PF_POPULATE | PF_WRITE | PF_USER;
			void *addr;
			struct vm_range *range;

			ihk_mc_spinlock_lock_noirq(&rvm->memory_range_lock);

			/* Is base valid? */
			range = lookup_process_memory_range(rvm,
					(uintptr_t)remote_iov[li].iov_base,
					(uintptr_t)(remote_iov[li].iov_base + 1));

			if (!range) {
				ret = -EFAULT;
				goto pri_out;
			}

			/* Is length valid? */
			range = lookup_process_memory_range(lthread->vm,
					(uintptr_t)remote_iov[li].iov_base,
					(uintptr_t)(remote_iov[li].iov_base + remote_iov[li].iov_len));

			if (range == NULL) {
				ret = -EINVAL;
				goto pri_out;
			}

			if (!(range->flag & ((op == PROCESS_VM_READ) ?
				VR_PROT_READ : VR_PROT_WRITE))) {
				ret = -EFAULT;
				goto pri_out;
			}

			ret = 0;
pri_out:
			ihk_mc_spinlock_unlock_noirq(&rvm->memory_range_lock);

			if (ret != 0) {
				goto out;
			}

			/* Fault in pages */
			for (addr = (void *)
					((unsigned long)remote_iov[ri].iov_base & PAGE_MASK);
					addr < (remote_iov[ri].iov_base + remote_iov[ri].iov_len);
					addr += PAGE_SIZE) {

				ret = page_fault_process_vm(rvm, addr, reason);
				if (ret) {
					ret = -EFAULT;
					goto out;
				}
			}

			pri = ri;
		}

		/* Figure out how much we can copy at most in this iteration */
		to_copy = (local_iov[li].iov_len - loff);	
		if ((remote_iov[ri].iov_len - roff) < to_copy) {
			to_copy = remote_iov[ri].iov_len - roff;
		}

		rpage_left = ((((unsigned long)remote_iov[ri].iov_base + roff + 
			PAGE_SIZE) & PAGE_MASK) - 
			((unsigned long)remote_iov[ri].iov_base + roff));
		if (rpage_left < to_copy) {	
			to_copy = rpage_left;
		}

		/* TODO: remember page and do this only if necessary */
		ret = ihk_mc_pt_virt_to_phys(rvm->address_space->page_table, 
				remote_iov[ri].iov_base + roff, &rphys);

		if (ret) {
			ret = -EFAULT;
			goto out;
		}
		
		rva = phys_to_virt(rphys);
		
		memcpy((op == PROCESS_VM_READ) ? local_iov[li].iov_base + loff : rva,
			(op == PROCESS_VM_READ) ? rva : local_iov[li].iov_base + loff,
			to_copy);

		copied += to_copy;
		dkprintf("local_iov[%d]: 0x%lx %s remote_iov[%d]: 0x%lx, %lu copied\n",
			li, local_iov[li].iov_base + loff, 
			(op == PROCESS_VM_READ) ? "<-" : "->", 
			ri, remote_iov[ri].iov_base + roff, to_copy);

		loff += to_copy;
		roff += to_copy;

		if (loff == local_iov[li].iov_len) {
			li++;
			loff = 0;
		}
		
		if (roff == remote_iov[ri].iov_len) {
			ri++;
			roff = 0;
		}
	}

	release_process_vm(rvm);

	return copied;

out:
	if(rvm)
		release_process_vm(rvm);
	return ret;
}

SYSCALL_DECLARE(process_vm_writev)
{
	int pid = ihk_mc_syscall_arg0(ctx);
	const struct iovec *local_iov = 
		(const struct iovec *)ihk_mc_syscall_arg1(ctx);
	unsigned long liovcnt = ihk_mc_syscall_arg2(ctx);
	const struct iovec *remote_iov = 
		(const struct iovec *)ihk_mc_syscall_arg3(ctx);
	unsigned long riovcnt = ihk_mc_syscall_arg4(ctx);
	unsigned long flags = ihk_mc_syscall_arg5(ctx);

	return do_process_vm_read_writev(pid, local_iov, liovcnt,
		remote_iov, riovcnt, flags, PROCESS_VM_WRITE);
}

SYSCALL_DECLARE(process_vm_readv)
{
	int pid = ihk_mc_syscall_arg0(ctx);
	const struct iovec *local_iov = 
		(const struct iovec *)ihk_mc_syscall_arg1(ctx);
	unsigned long liovcnt = ihk_mc_syscall_arg2(ctx);
	const struct iovec *remote_iov = 
		(const struct iovec *)ihk_mc_syscall_arg3(ctx);
	unsigned long riovcnt = ihk_mc_syscall_arg4(ctx);
	unsigned long flags = ihk_mc_syscall_arg5(ctx);

	return do_process_vm_read_writev(pid, local_iov, liovcnt,
		remote_iov, riovcnt, flags, PROCESS_VM_READ);
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

void
reset_cputime()
{
	struct thread *thread;

	if(clv == NULL)
		return;

	if(!(thread = cpu_local_var(current)))
		return;

	thread->btime.tv_sec = 0;
	thread->btime.tv_nsec = 0;
}

/**
 * mode == 0: kernel -> user
 * mode == 1: user -> kernel
 * mode == 2: kernel -> kernel
 */
void
set_cputime(int mode)
{
	struct thread *thread;
	struct timespec ats;
	struct cpu_local_var *v;

	if(clv == NULL)
		return;

	v = get_this_cpu_local_var();
	if(!(thread = v->current))
		return;

	if(!gettime_local_support){
		thread->times_update = 1;
		return;
	}

	calculate_time_from_tsc(&ats);
	if(thread->btime.tv_sec != 0 && thread->btime.tv_nsec != 0){
		struct timespec dts;

		dts.tv_sec = ats.tv_sec;
		dts.tv_nsec = ats.tv_nsec;
		ts_sub(&dts, &thread->btime);
		if(mode == 1)
			ts_add(&thread->utime, &dts);
		else
			ts_add(&thread->stime, &dts);
	}
	if(mode == 2){
		thread->btime.tv_sec = 0;
		thread->btime.tv_nsec = 0;
	}
	else{
		thread->btime.tv_sec = ats.tv_sec;
		thread->btime.tv_nsec = ats.tv_nsec;
	}
	thread->times_update = 1;
	thread->in_kernel = mode;
}

long syscall(int num, ihk_mc_user_context_t *ctx)
{
	long l;

	set_cputime(1);
	if(cpu_local_var(current)->proc->status == PS_EXITED &&
	   (num != __NR_exit && num != __NR_exit_group)){
		check_signal(-EINVAL, NULL, 0);
		set_cputime(0);
		return -EINVAL;
	}

	cpu_enable_interrupt();

	if (cpu_local_var(current)->proc->ptrace) {
		ptrace_syscall_enter(cpu_local_var(current));
	}

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

	check_signal(l, NULL, num);
	check_need_resched();

	if (cpu_local_var(current)->proc->ptrace) {
		ptrace_syscall_exit(cpu_local_var(current));
	}

	set_cputime(0);
	return l;
}
