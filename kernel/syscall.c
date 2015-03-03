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

void check_signal(unsigned long rc, void *regs);
void do_signal(long rc, void *regs, struct process *proc, struct sig_pending *pending);
extern unsigned long do_kill(int pid, int tid, int sig, struct siginfo *info, int ptracecont);
extern struct sigpending *hassigpending(struct process *proc);
int copy_from_user(struct process *, void *, const void *, size_t);
int copy_to_user(struct process *, void *, const void *, size_t);
void do_setpgid(int, int);
extern long alloc_debugreg(struct process *proc);

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
	packet.pid = pid ? pid : cpu_local_var(current)->ftn->pid;
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
	struct process *proc = cpu_local_var(current);

	dkprintf("SC(%d)[%3d] sending syscall\n",
	        ihk_mc_get_processor_id(),
	        req->number);

	if(proc->nohost) // host is down
		return -EPIPE;

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
					cpu_local_var(current)->ftn->pid);
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

static int wait_zombie(struct process *proc, struct fork_tree_node *child, int *status, int options) {
    int ret;
    struct syscall_request request IHK_DMA_ALIGN;
    
    dkprintf("wait_zombie,found PS_ZOMBIE process: %d\n", child->pid);
    
    if (status) {
        *status = child->exit_status;
    }
    
	request.number = __NR_wait4;
	request.args[0] = child->pid;
	request.args[1] = 0;
	request.args[2] = options;
	/* Ask host to clean up exited child */
	ret = do_syscall(&request, ihk_mc_get_processor_id(), 0);

	if (ret != child->pid)
		kprintf("WARNING: host waitpid failed?\n");
	dkprintf("wait_zombie,child->pid=%d,status=%08x\n",
		 child->pid, status ? *status : -1);

    return ret;
}

static int wait_stopped(struct process *proc, struct fork_tree_node *child, int *status, int options)
{
	dkprintf("wait_stopped,proc->pid=%d,child->pid=%d,options=%08x\n",
			 proc->ftn->pid, child->pid, options);
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

static int wait_continued(struct process *proc, struct fork_tree_node *child, int *status, int options) {
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
	struct process *proc = cpu_local_var(current);
	struct fork_tree_node *child_iter, *next;
	int pgid = proc->ftn->pgid;
	int ret;
	struct waitq_entry waitpid_wqe;
	int empty = 1;
	int orgpid = pid;

	dkprintf("wait4,proc->pid=%d,pid=%d\n", proc->ftn->pid, pid);
 rescan:
	pid = orgpid;

	ihk_mc_spinlock_lock_noirq(&proc->ftn->lock);
	list_for_each_entry_safe(child_iter, next, &proc->ftn->children, siblings_list) {	

		if (!(!!(options & __WCLONE) ^ (child_iter->termsig == SIGCHLD))) {
			continue;
		}

		ihk_mc_spinlock_lock_noirq(&child_iter->lock);

		if ((pid < 0 && -pid == child_iter->pgid) ||
			pid == -1 ||
			(pid == 0 && pgid == child_iter->pgid) ||
			(pid > 0 && pid == child_iter->pid)) {

			empty = 0;

			if((options & WEXITED) &&
			   child_iter->status == PS_ZOMBIE) {
				ret = wait_zombie(proc, child_iter, status, options);
				if(ret == child_iter->pid) {
					if(!(options & WNOWAIT)){
						list_del(&child_iter->siblings_list);
						release_fork_tree_node(child_iter);
					}
					goto out_found;
				}
			}

			if((child_iter->signal_flags & SIGNAL_STOP_STOPPED) &&
			   (options & WUNTRACED)) {
				/* Not ptraced and in stopped state and WUNTRACED is specified */
				ret = wait_stopped(proc, child_iter, status, options);
				if(ret == child_iter->pid) {
					if(!(options & WNOWAIT)){
						child_iter->signal_flags &= ~SIGNAL_STOP_STOPPED;
					}
					goto out_found;
				}
			}

			if((child_iter->signal_flags & SIGNAL_STOP_CONTINUED) &&
			   (options & WCONTINUED)) {
				ret = wait_continued(proc, child_iter, status, options);
				if(ret == child_iter->pid) {
					if(!(options & WNOWAIT)){
						child_iter->signal_flags &= ~SIGNAL_STOP_CONTINUED;
					}
					goto out_found;
				}
			}
		}

		ihk_mc_spinlock_unlock_noirq(&child_iter->lock);
	}
	list_for_each_entry_safe(child_iter, next, &proc->ftn->ptrace_children, ptrace_siblings_list) {	

		if (!(!!(options & __WCLONE) ^ (child_iter->termsig == SIGCHLD))) {
			continue;
		}

		ihk_mc_spinlock_lock_noirq(&child_iter->lock);

		if ((pid < 0 && -pid == child_iter->pgid) ||
			pid == -1 ||
			(pid == 0 && pgid == child_iter->pgid) ||
			(pid > 0 && pid == child_iter->pid)) {

			empty = 0;

			if((options & WEXITED) &&
			   child_iter->status == PS_ZOMBIE) {
				ret = wait_zombie(proc, child_iter, status, options);
//				if(ret == child_iter->pid) {
					if(!(options & WNOWAIT)){
						list_del(&child_iter->ptrace_siblings_list);
						release_fork_tree_node(child_iter);
					}
					goto out_found;
//				}
			}

			if(child_iter->status & (PS_STOPPED | PS_TRACED)) {
				/* ptraced and in stopped or trace-stopped state */
				ret = wait_stopped(proc, child_iter, status, options);
//				if(ret == child_iter->pid) {
					if(!(options & WNOWAIT)){
						child_iter->signal_flags &= ~SIGNAL_STOP_STOPPED;
					}
					goto out_found;
//				}
			} else {
				/* ptraced and in running or sleeping state */
			}

			if((child_iter->signal_flags & SIGNAL_STOP_CONTINUED) &&
			   (options & WCONTINUED)) {
				ret = wait_continued(proc, child_iter, status, options);
//				if(ret == child_iter->pid) {
					if(!(options & WNOWAIT)){
						child_iter->signal_flags &= ~SIGNAL_STOP_CONTINUED;
					}
					goto out_found;
//				}
			}
		}

		ihk_mc_spinlock_unlock_noirq(&child_iter->lock);
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
	waitq_init_entry(&waitpid_wqe, proc);
	waitq_prepare_to_wait(&proc->ftn->waitpid_q, &waitpid_wqe, PS_INTERRUPTIBLE);

	ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);	
	if(hassigpending(proc)){
		waitq_finish_wait(&proc->ftn->waitpid_q, &waitpid_wqe);
		return -EINTR;
	}


	schedule();
	dkprintf("wait4(): woken up\n");

	waitq_finish_wait(&proc->ftn->waitpid_q, &waitpid_wqe);

	goto rescan;

 exit:
	return ret;
 out_found:
	dkprintf("wait4,out_found\n");
	ihk_mc_spinlock_unlock_noirq(&child_iter->lock);
 out_notfound:
	dkprintf("wait4,out_notfound\n");
	ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);
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
		copy_to_user(cpu_local_var(current), status, &st, sizeof(int));
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
		copy_to_user(cpu_local_var(current), infop, &info, sizeof info);
	}
	return 0;
}

static int ptrace_terminate_tracer(struct process *proc, struct fork_tree_node *tracer);

void
terminate(int rc, int sig, ihk_mc_user_context_t *ctx)
{
	struct syscall_request request IHK_DMA_ALIGN;
	struct process *proc = cpu_local_var(current);
	struct fork_tree_node *ftn = proc->ftn;
	struct fork_tree_node *child, *next;
	struct process *parent_owner;
	int error;

	dkprintf("terminate,pid=%d\n", proc->ftn->pid);
	request.number = __NR_exit_group;
	request.args[0] = ((rc & 0x00ff) << 8) | (sig & 0xff);

#ifdef DCFA_KMOD
	do_mod_exit(rc);
#endif

	/* XXX: send SIGKILL to all threads in this process */

	flush_process_memory(proc);	/* temporary hack */
	if(!proc->nohost)
		do_syscall(&request, ihk_mc_get_processor_id(), 0);

#define	IS_DETACHED_PROCESS(proc)	(1)	/* should be implemented in the future */

	/* Do a "wait" on all children and detach owner process */
	ihk_mc_spinlock_lock_noirq(&ftn->lock);
	list_for_each_entry_safe(child, next, &ftn->children, siblings_list) {
		list_del(&child->siblings_list);
		release_fork_tree_node(child);
	}
	list_for_each_entry_safe(child, next, &ftn->ptrace_children, ptrace_siblings_list) {
		list_del(&child->ptrace_siblings_list);
		if (ptrace_terminate_tracer(child->owner, ftn)) {
			release_fork_tree_node(child);
		}
	}
	ftn->owner = NULL;
	ihk_mc_spinlock_unlock_noirq(&ftn->lock);	

	/* Send signal to parent */
	if (ftn->parent) {
		int parent_owner_pid;
		ihk_mc_spinlock_lock_noirq(&ftn->lock);
		ftn->exit_status = ((rc & 0x00ff) << 8) | (sig & 0xff);
		ftn->status = PS_ZOMBIE;
		ihk_mc_spinlock_unlock_noirq(&ftn->lock);	

		/* Wake parent (if sleeping in wait4()) */
		dkprintf("terminate,wakeup\n");
		waitq_wakeup(&ftn->parent->waitpid_q);

		/* Signal parent if still attached */
		ihk_mc_spinlock_lock_noirq(&ftn->parent->lock);
		parent_owner = ftn->parent->owner;
		parent_owner_pid = parent_owner ? ftn->parent->pid : 0;
		ihk_mc_spinlock_unlock_noirq(&ftn->parent->lock);	
		if (parent_owner && (ftn->termsig != 0)) {
			struct siginfo info;

			memset(&info, '\0', sizeof info);
			info.si_signo = SIGCHLD;
			info.si_code = sig? ((sig & 0x80)? CLD_DUMPED: CLD_KILLED): CLD_EXITED;
			info._sifields._sigchld.si_pid = proc->ftn->pid;
			info._sifields._sigchld.si_status = ((rc & 0x00ff) << 8) | (sig & 0xff);
			dkprintf("terminate,kill %d,target pid=%d\n",
					ftn->termsig, parent_owner_pid);
			error = do_kill(ftn->parent->pid, -1, SIGCHLD, &info, 0);
/*
			sigchld_parent(ftn->parent->owner, 0);
*/
			dkprintf("terminate,klll %d,error=%d\n",
					ftn->termsig, error);
		}

		release_fork_tree_node(ftn->parent);
	} else {
		ihk_mc_spinlock_lock_noirq(&ftn->lock);
		ftn->status = PS_EXITED;
		ihk_mc_spinlock_unlock_noirq(&ftn->lock);	
    }
	release_fork_tree_node(ftn);
	release_process(proc);
	
	schedule();
}

void terminate_host(int pid)
{
	struct cpu_local_var *v;
	struct process *p;
	int i;
	unsigned long irqstate;
	extern int num_processors;
	int *tids;
	int n;
	siginfo_t info;

	memset(&info, '\0', sizeof info);
	info.si_signo = SIGKILL;
	info.si_code = SI_KERNEL;

	tids = kmalloc(sizeof(int) * num_processors, IHK_MC_AP_NOWAIT);
	if(!tids)
		return;

	for(n = 0, i = 0; i < num_processors; i++){
		v = get_cpu_local_var(i);
		irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
		list_for_each_entry(p, &(v->runq), sched_list){
			if(p->ftn->pid == pid){
				p->nohost = 1;
				tids[n] = p->ftn->tid;
				n++;
			}
		}
		ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
	}
	for(i = 0; i < n; i++){
		do_kill(pid, tids[i], SIGKILL, &info, 0);
	}

	kfree(tids);
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
		kprintf("clear_host_pte failed. %ld\n", lerror);
	}
	return;
}

SYSCALL_DECLARE(exit_group)
{
#if 0
	SYSCALL_HEADER;
#endif

	dkprintf("sys_exit_group,pid=%d\n", cpu_local_var(current)->ftn->pid);
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

	if (!error && (flags & (MAP_POPULATE) || flags & (MAP_LOCKED))) {
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
	return cpu_local_var(current)->ftn->pid;
}

SYSCALL_DECLARE(getppid)
{
	struct process *proc = cpu_local_var(current);
	int pid = 1; // fake init

	ihk_mc_spinlock_lock_noirq(&proc->ftn->lock);
	if (proc->ftn->ptrace & PT_TRACED) {
		if (proc->ftn->ppid_parent)
			pid = proc->ftn->ppid_parent->pid;
	} else {
		if (proc->ftn->parent) {
			pid = proc->ftn->parent->pid;
		}
	}
	ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);
	return pid;
}

void
settid(struct process *proc, int mode, int newcpuid, int oldcpuid)
{
	ihk_mc_user_context_t ctx;
	unsigned long rc;

	ihk_mc_syscall_arg0(&ctx) = mode;
	ihk_mc_syscall_arg1(&ctx) = proc->ftn->pid;
	ihk_mc_syscall_arg2(&ctx) = newcpuid;
	ihk_mc_syscall_arg3(&ctx) = oldcpuid;
	rc = syscall_generic_forwarding(__NR_gettid, &ctx);
	proc->ftn->tid = rc;
}

SYSCALL_DECLARE(gettid)
{
	return cpu_local_var(current)->ftn->tid;
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

extern void ptrace_report_signal(struct process *proc, int sig);
static int ptrace_report_exec(struct process *proc)
{
	int ptrace = proc->ftn->ptrace;

	if (ptrace & (PT_TRACE_EXEC|PTRACE_O_TRACEEXEC)) {
		int sig = (SIGTRAP | (PTRACE_EVENT_EXEC << 8));
		ptrace_report_signal(proc, sig);
	}
	return 0;
}


static void ptrace_syscall_enter(struct process *proc)
{
	int ptrace = proc->ftn->ptrace;

	if (ptrace & PT_TRACE_SYSCALL_ENTER) {
		int sig = (SIGTRAP | ((ptrace & PTRACE_O_TRACESYSGOOD) ? 0x80 : 0));
		ptrace_report_signal(proc, sig);
		ihk_mc_spinlock_lock_noirq(&proc->ftn->lock);	
		if (proc->ftn->ptrace & PT_TRACE_SYSCALL_ENTER) {
			proc->ftn->ptrace |= PT_TRACE_SYSCALL_EXIT;
		}
		ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);	
	}
}

static void ptrace_syscall_exit(struct process *proc)
{
	int ptrace = proc->ftn->ptrace;

	if (ptrace & PT_TRACE_SYSCALL_EXIT) {
		int sig = (SIGTRAP | ((ptrace & PTRACE_O_TRACESYSGOOD) ? 0x80 : 0));
		ptrace_report_signal(proc, sig);
	}
}

static int ptrace_check_clone_event(struct process *proc, int clone_flags)
{
	int event = 0;

	if (clone_flags & CLONE_VFORK) {
		/* vfork */
		if (proc->ftn->ptrace & PTRACE_O_TRACEVFORK) {
			event = PTRACE_EVENT_VFORK;
		}
		if (proc->ftn->ptrace & PTRACE_O_TRACEVFORKDONE) {
			event = PTRACE_EVENT_VFORK_DONE;
		}
	} else if ((clone_flags & CSIGNAL) == SIGCHLD) {
		/* fork */
		if (proc->ftn->ptrace & PTRACE_O_TRACEFORK) {
			event = PTRACE_EVENT_FORK;
		}
	} else {
		/* clone */
		if (proc->ftn->ptrace & PTRACE_O_TRACECLONE) {
			event = PTRACE_EVENT_CLONE;
		}
	}

	return event;
}

static int ptrace_report_clone(struct process *proc, struct process *new, int event)
{
	dkprintf("ptrace_report_clone,enter\n");
	int error = 0;
	long rc;
	struct siginfo info;

	/* Save reason why stopped and process state for wait4() to reap */
	ihk_mc_spinlock_lock_noirq(&proc->ftn->lock);
	proc->ftn->exit_status = (SIGTRAP | (event << 8));
	/* Transition process state */
	proc->ftn->status = PS_TRACED;
	proc->ftn->ptrace_eventmsg = new->ftn->pid;
	proc->ftn->ptrace &= ~PT_TRACE_SYSCALL_MASK;
	ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);	

	dkprintf("ptrace_report_clone,kill SIGCHLD\n");
	if (proc->ftn->parent) {
		/* kill SIGCHLD */
		ihk_mc_spinlock_lock_noirq(&proc->ftn->parent->lock);
		if (proc->ftn->parent->owner) {
			memset(&info, '\0', sizeof info);
			info.si_signo = SIGCHLD;
			info.si_code = CLD_TRAPPED;
			info._sifields._sigchld.si_pid = proc->ftn->pid;
			info._sifields._sigchld.si_status = proc->ftn->exit_status;
			rc = do_kill(proc->ftn->parent->pid, -1, SIGCHLD, &info, 0);
			if(rc < 0) {
				dkprintf("ptrace_report_clone,do_kill failed\n");
			}
		}
		ihk_mc_spinlock_unlock_noirq(&proc->ftn->parent->lock);	

		/* Wake parent (if sleeping in wait4()) */
		waitq_wakeup(&proc->ftn->parent->waitpid_q);
	}

	if (event != PTRACE_EVENT_VFORK_DONE) {
		/* PTRACE_EVENT_FORK or PTRACE_EVENT_VFORK or PTRACE_EVENT_CLONE */

		struct fork_tree_node *child, *next;

		/* set ptrace features to new process */
		ihk_mc_spinlock_lock_noirq(&new->ftn->lock);

		new->ftn->ptrace = proc->ftn->ptrace;
		new->ftn->ppid_parent = new->ftn->parent; /* maybe proc */

		if ((new->ftn->ptrace & PT_TRACED) && new->ptrace_debugreg == NULL) {
			alloc_debugreg(new);
		}

		ihk_mc_spinlock_lock_noirq(&new->ftn->parent->lock);
		list_for_each_entry_safe(child, next, &new->ftn->parent->children, siblings_list) {
			if(child == new->ftn) {
				list_del(&child->siblings_list);
				goto found;
			}
		}
		panic("ptrace_report_clone: missing parent-child relationship.");
found:
		ihk_mc_spinlock_unlock_noirq(&new->ftn->parent->lock);

		new->ftn->parent = proc->ftn->parent; /* new ptracing parent */

		ihk_mc_spinlock_lock_noirq(&new->ftn->parent->lock);
		list_add_tail(&new->ftn->ptrace_siblings_list, &new->ftn->parent->ptrace_children);
		ihk_mc_spinlock_unlock_noirq(&new->ftn->parent->lock);

		/* trace and SIGSTOP */
		new->ftn->exit_status = SIGSTOP;
		new->ftn->status = PS_TRACED;

		ihk_mc_spinlock_unlock_noirq(&new->ftn->lock);
	}

	return error;
}

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
	struct process *proc = cpu_local_var(current);
	struct process_vm *vm = proc->vm;
	struct vm_range *range;

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

	error = ptrace_report_exec(cpu_local_var(current));
	if(error) {
		kprintf("execve(): ERROR: ptrace_report_exec()\n");
	}

	/* Switch to new execution context */
	dkprintf("execve(): switching to new process\n");
	proc->execed = 1;
	
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
	struct process *new;
	struct syscall_request request1 IHK_DMA_ALIGN;
	int ptrace_event = 0;

    dkprintf("do_fork,flags=%08x,newsp=%lx,ptidptr=%lx,ctidptr=%lx,tls=%lx,curpc=%lx,cursp=%lx",
            clone_flags, newsp, parent_tidptr, child_tidptr, tlsblock_base, curpc, cursp);

	dkprintf("do_fork(): stack_pointr passed in: 0x%lX, stack pointer of caller: 0x%lx\n",
			 newsp, cursp);
	
	if (((clone_flags & CLONE_VM) && !(clone_flags & CLONE_THREAD)) ||
		(!(clone_flags & CLONE_VM) && (clone_flags & CLONE_THREAD))) {
		kprintf("%s: ERROR: CLONE_VM and CLONE_THREAD should be set together\n");
		return -EINVAL;
	}

	cpuid = obtain_clone_cpuid();
    if (cpuid == -1) {
		kprintf("do_fork,core not available\n");
        return -EAGAIN;
    }

	new = clone_process(cpu_local_var(current), curpc,
	                    newsp ? newsp : cursp, 
						clone_flags);
	
	if (!new) {
		release_cpuid(cpuid);
		return -ENOMEM;
	}

	new->ftn->pgid = cpu_local_var(current)->ftn->pgid;

	cpu_set(cpuid, &new->vm->cpu_set, &new->vm->cpu_set_lock);

	if (clone_flags & CLONE_VM) {
		new->ftn->pid = cpu_local_var(current)->ftn->pid;
		settid(new, 1, cpuid, -1);
	}
	/* fork() a new process on the host */
	else {
		request1.number = __NR_fork;
		new->ftn->pid = do_syscall(&request1, ihk_mc_get_processor_id(), 0);
		if (new->ftn->pid == -1) {
			kprintf("ERROR: forking host process\n");
			
			/* TODO: clean-up new */
			release_cpuid(cpuid);
			return -EFAULT;
		}

		/* In a single threaded process TID equals to PID */
		settid(new, 0, cpuid, -1);

		dkprintf("fork(): new pid: %d\n", new->ftn->pid);
		/* clear user space PTEs and set new rpgtable so that consequent 
		 * page faults will look up the right mappings */
		request1.number = __NR_munmap;
		request1.args[0] = new->vm->region.user_start;
		request1.args[1] = new->vm->region.user_end - 
			new->vm->region.user_start;
		/* 3rd parameter denotes new rpgtable of host process */
		request1.args[2] = virt_to_phys(new->vm->page_table);
		request1.args[3] = new->ftn->pid;

		dkprintf("fork(): requesting PTE clear and rpgtable (0x%lx) update\n",
				request1.args[2]);

		if (do_syscall(&request1, ihk_mc_get_processor_id(), new->ftn->pid)) {
			kprintf("ERROR: clearing PTEs in host process\n");
		}		
	}

	if (clone_flags & CLONE_PARENT_SETTID) {
		dkprintf("clone_flags & CLONE_PARENT_SETTID: 0x%lX\n",
		         parent_tidptr);
		
		*(int*)parent_tidptr = new->ftn->pid;
	}
	
	if (clone_flags & CLONE_CHILD_CLEARTID) {
		dkprintf("clone_flags & CLONE_CHILD_CLEARTID: 0x%lX\n", 
			     child_tidptr);

		new->thread.clear_child_tid = (int*)child_tidptr;
	}
	
	if (clone_flags & CLONE_CHILD_SETTID) {
		unsigned long phys;
		dkprintf("clone_flags & CLONE_CHILD_SETTID: 0x%lX\n",
				child_tidptr);

		if (ihk_mc_pt_virt_to_phys(new->vm->page_table, 
					(void *)child_tidptr, &phys)) { 
			kprintf("ERROR: looking up physical addr for child process\n");
			release_cpuid(cpuid);
			return -EFAULT; 
		}
	
		*((int*)phys_to_virt(phys)) = new->ftn->tid;
	}
	
	if (clone_flags & CLONE_SETTLS) {
		dkprintf("clone_flags & CLONE_SETTLS: 0x%lX\n", 
			     tlsblock_base);
		
		new->thread.tlsblock_base = tlsblock_base;
	}
	else { 
		new->thread.tlsblock_base = 
			cpu_local_var(current)->thread.tlsblock_base;
	}

	ihk_mc_syscall_ret(new->uctx) = 0;

	if (cpu_local_var(current)->ftn->ptrace) {
		ptrace_event = ptrace_check_clone_event(cpu_local_var(current), clone_flags);
		if (ptrace_event) {
			ptrace_report_clone(cpu_local_var(current), new, ptrace_event);
		}
	}

	dkprintf("clone: kicking scheduler!,cpuid=%d pid=%d tid=%d\n", cpuid, new->ftn->pid, new->ftn->tid);
	runq_add_proc(new, cpuid);

	if (ptrace_event) {
		schedule();
	}

	return new->ftn->tid;
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
	cpu_local_var(current)->thread.clear_child_tid = 
	                        (int*)ihk_mc_syscall_arg0(ctx);

	return cpu_local_var(current)->ftn->pid;
}

SYSCALL_DECLARE(kill)
{
	int pid = ihk_mc_syscall_arg0(ctx);
	int sig = ihk_mc_syscall_arg1(ctx);
	struct process *proc = cpu_local_var(current);
	struct siginfo info;
	int error;

	memset(&info, '\0', sizeof info);
	info.si_signo = sig;
	info.si_code = SI_USER;
	info._sifields._kill.si_pid = proc->ftn->pid;

	dkprintf("sys_kill,enter,pid=%d,sig=%d\n", pid, sig);
	error = do_kill(pid, -1, sig, &info, 0);
	dkprintf("sys_kill,returning,pid=%d,sig=%d,error=%d\n", pid, sig, error);
	return error;
}

// see linux-2.6.34.13/kernel/signal.c
SYSCALL_DECLARE(tgkill)
{
	int tgid = ihk_mc_syscall_arg0(ctx);
	int tid = ihk_mc_syscall_arg1(ctx);
	int sig = ihk_mc_syscall_arg2(ctx);
	struct process *proc = cpu_local_var(current);
	struct siginfo info;

	memset(&info, '\0', sizeof info);
	info.si_signo = sig;
	info.si_code = SI_TKILL;
	info._sifields._kill.si_pid = proc->ftn->pid;

	if(tid <= 0)
		return -EINVAL;
	if(tgid <= 0 && tgid != -1)
		return -EINVAL;

	return do_kill(tgid, tid, sig, &info, 0);
}

SYSCALL_DECLARE(setpgid)
{
	int pid = ihk_mc_syscall_arg0(ctx);
	int pgid = ihk_mc_syscall_arg1(ctx);
	long rc;
	struct process *proc = cpu_local_var(current);
	ihk_spinlock_t *lock;
	unsigned long irqstate = 0;
	struct process *tproc;

	if(pid == 0)
		pid = proc->ftn->pid;
	if(pgid == 0)
		pgid = pid;

	if(proc->ftn->pid != pid){
		tproc = findthread_and_lock(pid, pid, &lock, &irqstate);
		if(tproc){
			if(tproc->execed){
				process_unlock(lock, irqstate);
				return -EACCES;
			}
			process_unlock(lock, irqstate);
		}
		else
			return -ESRCH;
	}

	rc = syscall_generic_forwarding(__NR_setpgid, ctx);
	if(rc == 0){
		do_setpgid(pid, pgid);
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
	struct process *proc = cpu_local_var(current);
	struct k_sigaction *k;
	int	irqstate;
	ihk_mc_user_context_t ctx0;

	irqstate = ihk_mc_spinlock_lock(&proc->sighandler->lock);
	k = proc->sighandler->action + sig - 1;
	if(oact)
		memcpy(oact, k, sizeof(struct k_sigaction));
	if(act)
		memcpy(k, act, sizeof(struct k_sigaction));
	ihk_mc_spinlock_unlock(&proc->sighandler->lock, irqstate);

	if(act){
		ihk_mc_syscall_arg0(&ctx0) = sig;
		ihk_mc_syscall_arg1(&ctx0) = (unsigned long)act->sa.sa_handler;
		ihk_mc_syscall_arg2(&ctx0) = act->sa.sa_flags;
		syscall_generic_forwarding(__NR_rt_sigaction, &ctx0);
	}
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
	ihk_mc_user_context_t ctx0;

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
	wsig = proc->sigmask.__val[0];
	ihk_mc_spinlock_unlock(&proc->sighandler->lock, flag);

	ihk_mc_syscall_arg0(&ctx0) = wsig;
	syscall_generic_forwarding(__NR_rt_sigprocmask, &ctx0);
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

SYSCALL_DECLARE(signalfd)
{
	return -EOPNOTSUPP;
}

SYSCALL_DECLARE(signalfd4)
{
	return -EOPNOTSUPP;
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

	if(set == NULL)
		return -EFAULT;
	memset(&winfo, '\0', sizeof winfo);
	if(copy_from_user(proc, &wset, set, sizeof wset))
		return -EFAULT;
	if(timeout)
		if(copy_from_user(proc, wtimeout, timeout, sizeof wtimeout))
			return -EFAULT;


	if(info)
		if(copy_to_user(proc, info, &winfo, sizeof winfo))
			return -EFAULT;

	return -EOPNOTSUPP;
}

SYSCALL_DECLARE(rt_sigqueueinfo)
{
	int pid = (int)ihk_mc_syscall_arg0(ctx);
	int sig = (int)ihk_mc_syscall_arg1(ctx);
	void *winfo = (void *)ihk_mc_syscall_arg2(ctx);
	struct process *proc = cpu_local_var(current);
	struct siginfo info;

	if(pid <= 0)
		return -ESRCH;

	if(copy_from_user(proc, &info, winfo, sizeof info))
		return -EFAULT;

	return do_kill(pid, -1, sig, &info, 0);
}

static int
do_sigsuspend(struct process *proc, const sigset_t *set)
{
	__sigset_t wset;
	__sigset_t bset;
	int flag;
	struct sig_pending *pending;
	struct list_head *head;
	ihk_spinlock_t *lock;

	wset = set->__val[0];
	wset &= ~__sigmask(SIGKILL);
	wset &= ~__sigmask(SIGSTOP);
	bset = proc->sigmask.__val[0];
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
		proc->sigmask.__val[0] = bset;
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
	range = NULL;	/* for avoidance of warning */
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

		int r = do_syscall(&request, ihk_mc_get_processor_id(), 0);

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
	dkprintf("sys_exit,pid=%d\n", proc->ftn->pid);

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
	
	proc->ftn->status = PS_ZOMBIE;
	
	release_fork_tree_node(proc->ftn);
	release_process(proc);

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
	struct process *proc = cpu_local_var(current);
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
	if(i >= sizeof(rlimits) / sizeof(int))
		return -EINVAL;

	if(copy_from_user(proc, proc->rlimit + mcresource, rlm, sizeof(struct rlimit)))
		return -EFAULT;

	return 0;
}

SYSCALL_DECLARE(getrlimit)
{
	int resource = ihk_mc_syscall_arg0(ctx);
	struct rlimit *rlm = (struct rlimit *)ihk_mc_syscall_arg1(ctx);
	struct process *proc = cpu_local_var(current);
	int	i;
	int	mcresource;

	for(i = 0; i < sizeof(rlimits) / sizeof(int); i += 2)
		if(rlimits[i] == resource){
			mcresource = rlimits[i + 1];
			break;
		}
	if(i >= sizeof(rlimits) / sizeof(int))
		return -EINVAL;

// TODO: check limit
	if(copy_to_user(proc, rlm, proc->rlimit + mcresource, sizeof(struct rlimit)))
		return -EFAULT;

	return 0;
}

extern int ptrace_traceme(void);
extern void clear_single_step(struct process *proc);
extern void set_single_step(struct process *proc);

static int ptrace_wakeup_sig(int pid, long request, long data) {
	dkprintf("ptrace_wakeup_sig,pid=%d,data=%08x\n", pid, data);
	int error = 0;
	struct process *child;
	ihk_spinlock_t *savelock;
	unsigned long irqstate;
	struct siginfo info;

	child = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!child) {
		error = -ESRCH;
		goto out;
	}
	ihk_mc_spinlock_unlock(savelock, irqstate);

	if (data > 64 || data < 0) {
		error = -EINVAL;
		goto out;
	}

	switch (request) {
	case PTRACE_KILL:
		memset(&info, '\0', sizeof info);
		info.si_signo = SIGKILL;
		error = do_kill(pid, -1, SIGKILL, &info, 0);
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
		ihk_mc_spinlock_lock_noirq(&child->ftn->lock);
		child->ftn->ptrace &= ~PT_TRACE_SYSCALL_MASK;
		if (request == PTRACE_SYSCALL) {
			child->ftn->ptrace |= PT_TRACE_SYSCALL_ENTER;
		}
		ihk_mc_spinlock_unlock_noirq(&child->ftn->lock);
		if(data != 0 && data != SIGSTOP) {
			struct process *proc;

			/* TODO: Tracing process replace the original
			   signal with "data" */
			if (request == PTRACE_CONT && child->ptrace_sendsig) {
				memcpy(&info, &child->ptrace_sendsig->info, sizeof info);
				kfree(child->ptrace_sendsig);
				child->ptrace_sendsig = NULL;
			}
			else {
				proc = cpu_local_var(current);
				memset(&info, '\0', sizeof info);
				info.si_signo = data;
				info.si_code = SI_USER;
				info._sifields._kill.si_pid = proc->ftn->pid;
			}
			error = do_kill(pid, -1, data, &info, 1);
			if (error < 0) {
				goto out;
			}
		}
		break;
	default:
		break;
	}

	sched_wakeup_process(child, PS_TRACED | PS_STOPPED);
out:
	return error;
}

extern long ptrace_read_user(struct process *proc, long addr, unsigned long *value);
extern long ptrace_write_user(struct process *proc, long addr, unsigned long value);

static long ptrace_pokeuser(int pid, long addr, long data)
{
	long rc = -EIO;
	struct process *child;
	ihk_spinlock_t *savelock;
	unsigned long irqstate;

	if(addr > sizeof(struct user) - 8 || addr < 0)
		return -EFAULT;
	child = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!child)
		return -ESRCH;
	if(child->ftn->status == PS_TRACED){
		rc = ptrace_write_user(child, addr, (unsigned long)data);
	}
	ihk_mc_spinlock_unlock(savelock, irqstate);

	return rc;
}

static long ptrace_peekuser(int pid, long addr, long data)
{
	long rc = -EIO;
	struct process *child;
	struct process *proc = cpu_local_var(current);
	ihk_spinlock_t *savelock;
	unsigned long irqstate;
	unsigned long *p = (unsigned long *)data;

	if(addr > sizeof(struct user) - 8|| addr < 0)
		return -EFAULT;
	child = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!child)
		return -ESRCH;
	if(child->ftn->status == PS_TRACED){
		unsigned long value;
		rc = ptrace_read_user(child, addr, &value);
		if (rc == 0) {
			rc = copy_to_user(proc, p, (char *)&value, sizeof(value));
		}
	}
	ihk_mc_spinlock_unlock(savelock, irqstate);

	return rc;
}

static long ptrace_getregs(int pid, long data)
{
	struct user_regs_struct *regs = (struct user_regs_struct *)data;
	long rc = -EIO;
	struct process *child;
	struct process *proc = cpu_local_var(current);
	ihk_spinlock_t *savelock;
	unsigned long irqstate;

	child = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!child)
		return -ESRCH;
	if(child->ftn->status == PS_TRACED){
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
			rc = copy_to_user(proc, regs, &user_regs, sizeof(struct user_regs_struct));
		}
	}
	ihk_mc_spinlock_unlock(savelock, irqstate);

	return rc;
}

static long ptrace_setregs(int pid, long data)
{
	struct user_regs_struct *regs = (struct user_regs_struct *)data;
	long rc = -EIO;
	struct process *child;
	struct process *proc = cpu_local_var(current);
	ihk_spinlock_t *savelock;
	unsigned long irqstate;

	child = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!child)
		return -ESRCH;
	if(child->ftn->status == PS_TRACED){
		struct user_regs_struct user_regs;
		rc = copy_from_user(proc, &user_regs, regs, sizeof(struct user_regs_struct));
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
	ihk_mc_spinlock_unlock(savelock, irqstate);

	return rc;
}

static long ptrace_arch_prctl(int pid, long code, long addr)
{
	long rc = -EIO;
	struct process *child;
	ihk_spinlock_t *savelock;
	unsigned long irqstate;

	child = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!child)
		return -ESRCH;
	if (child->ftn->status == PS_TRACED) {
		switch (code) {
		case ARCH_GET_FS: {
			struct process *proc = cpu_local_var(current);
			unsigned long value;
			unsigned long *p = (unsigned long *)addr;
			rc = ptrace_read_user(child,
					offsetof(struct user_regs_struct, fs_base),
					&value);
			if (rc == 0) {
				rc = copy_to_user(proc, p, (char *)&value, sizeof(value));
			}
			break;
		}
		case ARCH_GET_GS: {
			struct process *proc = cpu_local_var(current);
			unsigned long value;
			unsigned long *p = (unsigned long *)addr;
			rc = ptrace_read_user(child,
					offsetof(struct user_regs_struct, gs_base),
					&value);
			if (rc == 0) {
				rc = copy_to_user(proc, p, (char *)&value, sizeof(value));
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
	ihk_mc_spinlock_unlock(savelock, irqstate);

	return rc;
}

static long ptrace_peektext(int pid, long addr, long data)
{
	long rc = -EIO;
	struct process *child;
	struct process *proc = cpu_local_var(current);
	ihk_spinlock_t *savelock;
	unsigned long irqstate;
	unsigned long *p = (unsigned long *)data;

	child = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!child)
		return -ESRCH;
	if(child->ftn->status == PS_TRACED){
		unsigned long value;
		ihk_mc_load_page_table(child->vm->page_table);
		rc = copy_from_user(child, &value, (void *)addr, sizeof(value));
		ihk_mc_load_page_table(proc->vm->page_table);
		if (rc != 0) { 
			dkprintf("ptrace_peektext: bad area  addr=0x%llx\n", addr);
		} else {
			rc = copy_to_user(proc, p, &value, sizeof(value));
		}
	}
	ihk_mc_spinlock_unlock(savelock, irqstate);

	return rc;
}

static long ptrace_poketext(int pid, long addr, long data)
{
	long rc = -EIO;
	struct process *child;
	ihk_spinlock_t *savelock;
	unsigned long irqstate;

	child = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!child)
		return -ESRCH;
	if(child->ftn->status == PS_TRACED){
#if 0
		/* XXX: revisit here, when fix #401.
		 * if read only, copy-on-write */
#else
		unsigned long phys;
		rc = ihk_mc_pt_virt_to_phys(child->vm->page_table, (void *)addr, &phys);
		if (rc != 0) {
			dkprintf("ptrace_poketext: bad address 0x%llx\n", addr);
		} else {
			*((long *)phys_to_virt(phys)) = data;
		}
#endif
	}
	ihk_mc_spinlock_unlock(savelock, irqstate);

	return rc;
}

static int ptrace_setoptions(int pid, int flags)
{
	int ret;
	struct process *child;
	ihk_spinlock_t *savelock;
	unsigned long irqstate;

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

	child = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!child || !child->ftn || !(child->ftn->ptrace & PT_TRACED)) {
		ret = -ESRCH;
		goto unlockout;
	}
	
	child->ftn->ptrace &= ~PTRACE_O_MASK;	/* PT_TRACE_EXEC remains */
	child->ftn->ptrace |= flags;
	ret = 0;

unlockout:
	ihk_mc_spinlock_unlock(savelock, irqstate);
out:
	return ret;
}

static int ptrace_attach(int pid)
{
	int error = 0;
	struct process *proc;
	struct fork_tree_node *child, *next;
	ihk_spinlock_t *savelock;
	unsigned long irqstate;
	struct siginfo info;

	proc = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!proc) {
		error = -ESRCH;
		goto out;
	}
	ihk_mc_spinlock_unlock(savelock, irqstate);
	dkprintf("ptrace_attach,pid=%d,proc->ftn->parent=%p\n", proc->ftn->pid, proc->ftn->parent);

	if (proc->ftn->ptrace & PT_TRACED) {
		error = -EPERM;
		goto out;
	}

	ihk_mc_spinlock_lock_noirq(&proc->ftn->lock);
	if (proc->ftn->parent) {
		dkprintf("ptrace_attach,parent->pid=%d\n", proc->ftn->parent->pid);

		ihk_mc_spinlock_lock_noirq(&proc->ftn->parent->lock);

		list_for_each_entry_safe(child, next, &proc->ftn->parent->children, siblings_list) {
			if(child == proc->ftn) {
				list_del(&child->siblings_list);
				goto found;
			}
		}
		kprintf("ptrace_attach,not found\n");
		error = -EPERM;
		goto out_notfound;
 found:
		ihk_mc_spinlock_unlock_noirq(&proc->ftn->parent->lock);
	} else {
		hold_fork_tree_node(proc->ftn);
	}

	proc->ftn->ptrace = PT_TRACED | PT_TRACE_EXEC;
	proc->ftn->ppid_parent = proc->ftn->parent;
	proc->ftn->parent = cpu_local_var(current)->ftn;

	ihk_mc_spinlock_lock_noirq(&proc->ftn->parent->lock);
	list_add_tail(&proc->ftn->ptrace_siblings_list, &proc->ftn->parent->ptrace_children);
	ihk_mc_spinlock_unlock_noirq(&proc->ftn->parent->lock);

	ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);

	if (proc->ptrace_debugreg == NULL) {
		error = alloc_debugreg(proc);
		if (error < 0) {
			goto out;
		}
	}

	clear_single_step(proc);

	memset(&info, '\0', sizeof info);
	info.si_signo = SIGSTOP;
	info.si_code = SI_USER;
	info._sifields._kill.si_pid = cpu_local_var(current)->ftn->pid;
	error = do_kill(pid, -1, SIGSTOP, &info, 0);
	if (error < 0) {
		goto out;
	}

	sched_wakeup_process(proc, PS_TRACED | PS_STOPPED);
  out:
	dkprintf("ptrace_attach,returning,error=%d\n", error);
	return error;

 out_notfound:
	ihk_mc_spinlock_unlock_noirq(&proc->ftn->parent->lock);
	ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);
	goto out;
}


static int ptrace_detach(int pid, int data)
{
	int error = 0;
	struct process *proc;
	struct fork_tree_node *child, *next;
	ihk_spinlock_t *savelock;
	unsigned long irqstate;
	struct siginfo info;

	proc = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!proc) {
		error = -ESRCH;
		goto out;
	}
	ihk_mc_spinlock_unlock(savelock, irqstate);

	if (!(proc->ftn->ptrace & PT_TRACED) ||
			proc->ftn->parent != cpu_local_var(current)->ftn) {
		error = -ESRCH;
		goto out;
	}

	if (data > 64 || data < 0) {
		error = -EIO;
		goto out;
	}

	ihk_mc_spinlock_lock_noirq(&proc->ftn->lock);
	ihk_mc_spinlock_lock_noirq(&proc->ftn->parent->lock);

	list_for_each_entry_safe(child, next, &proc->ftn->parent->ptrace_children, ptrace_siblings_list) {
		if (child == proc->ftn) {
			list_del(&child->ptrace_siblings_list);
			goto found;
		}
	}
	kprintf("ptrace_detach,not found\n");
	error = -EPERM;
	goto out_notfound;
found:
	ihk_mc_spinlock_unlock_noirq(&proc->ftn->parent->lock);

	proc->ftn->ptrace = 0;
	proc->ftn->parent = proc->ftn->ppid_parent;
	proc->ftn->ppid_parent = NULL;

	if (proc->ftn->parent) {
		ihk_mc_spinlock_lock_noirq(&proc->ftn->parent->lock);
		list_add_tail(&proc->ftn->siblings_list, &proc->ftn->parent->children);
		ihk_mc_spinlock_unlock_noirq(&proc->ftn->parent->lock);
	} else {
		release_fork_tree_node(proc->ftn);
	}

	ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);

	if (proc->ptrace_debugreg) {
		kfree(proc->ptrace_debugreg);
		proc->ptrace_debugreg = NULL;
	}

	clear_single_step(proc);

	if (data != 0) {
		memset(&info, '\0', sizeof info);
		info.si_signo = data;
		info.si_code = SI_USER;
		info._sifields._kill.si_pid = cpu_local_var(current)->ftn->pid;
		error = do_kill(pid, -1, data, &info, 1);
		if (error < 0) {
			goto out;
		}
	}

	sched_wakeup_process(proc, PS_TRACED | PS_STOPPED);
out:
	return error;
out_notfound:
	ihk_mc_spinlock_unlock_noirq(&proc->ftn->parent->lock);
	ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);
	goto out;
}

static int ptrace_terminate_tracer(struct process *proc, struct fork_tree_node *tracer)
{
	int error = 0;

	dkprintf("ptrace_terminate_tracer,pid=%d\n", proc->ftn->pid);
	if (!(proc->ftn->ptrace & PT_TRACED) ||
			proc->ftn->parent != tracer) {
		error = -ESRCH;
		goto out;
	}

	ihk_mc_spinlock_lock_noirq(&proc->ftn->lock);

	proc->ftn->ptrace = 0;
	proc->ftn->parent = proc->ftn->ppid_parent;
	proc->ftn->ppid_parent = NULL;

	if (proc->ftn->parent && proc->ftn->parent != tracer) {
		/* re-connect real parent */
		ihk_mc_spinlock_lock_noirq(&proc->ftn->parent->lock);
		list_add_tail(&proc->ftn->siblings_list, &proc->ftn->parent->children);
		ihk_mc_spinlock_unlock_noirq(&proc->ftn->parent->lock);
	} else {
		error = 1;	/* will call release_fork_tree_node() */
	}

	/* if signal stopped, change to PS_STOPPED  */
	if (proc->ftn->signal_flags & SIGNAL_STOP_STOPPED) {
		proc->ftn->status = PS_STOPPED;
	}

	ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);

	if (proc->ptrace_debugreg) {
		kfree(proc->ptrace_debugreg);
		proc->ptrace_debugreg = NULL;
	}

	clear_single_step(proc);

out:
	dkprintf("ptrace_terminate_tracer,error=%d\n", error);
	return error;
}

static long ptrace_geteventmsg(int pid, long data)
{
	unsigned long *msg_p = (unsigned long *)data;
	long rc = -ESRCH;
	struct process *child;
	struct process *proc = cpu_local_var(current);
	ihk_spinlock_t *savelock;
	unsigned long irqstate;

	child = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!child) {
		return -ESRCH;
	}
	if (child->ftn->status == PS_TRACED) {
		if (copy_to_user(proc, msg_p, &child->ftn->ptrace_eventmsg, sizeof(*msg_p))) {
			rc = -EFAULT;
		} else {
			rc = 0;
		}
	}
	ihk_mc_spinlock_unlock(savelock, irqstate);

	return rc;
}

static long
ptrace_getsiginfo(int pid, siginfo_t *data)
{
	ihk_spinlock_t *savelock;
	unsigned long irqstate;
	struct process *child;
	struct process *proc = cpu_local_var(current);
	int rc = 0;

	child = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!child) {
		return -ESRCH;
	}

	if (child->ftn->status != PS_TRACED) {
		rc = -ESRCH;
	}
	else if (child->ptrace_recvsig) {
		if (copy_to_user(proc, data, &child->ptrace_recvsig->info, sizeof(siginfo_t))) {
			rc = -EFAULT;
		}
	}
	else {
		rc = -ESRCH;
	}
	ihk_mc_spinlock_unlock(savelock, irqstate);
	return rc;
}

static long
ptrace_setsiginfo(int pid, siginfo_t *data)
{
	ihk_spinlock_t *savelock;
	unsigned long irqstate;
	struct process *child;
	struct process *proc = cpu_local_var(current);
	int rc = 0;

kprintf("ptrace_setsiginfo: sig=%d errno=%d code=%d\n", data->si_signo, data->si_errno, data->si_code);
	child = findthread_and_lock(pid, -1, &savelock, &irqstate);
	if (!child) {
		return -ESRCH;
	}

	if (child->ftn->status != PS_TRACED) {
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
		    copy_from_user(proc, &child->ptrace_sendsig->info, data, sizeof(siginfo_t))) {
			rc = -EFAULT;
		}
	}
	ihk_mc_spinlock_unlock(savelock, irqstate);
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
		dkprintf("ptrace: unimplemented ptrace(PTRACE_GETFPREGS) called.\n");
		break;
	case PTRACE_SETFPREGS:
		dkprintf("ptrace: unimplemented ptrace(PTRACE_SETFPREGS) called.\n");
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
	case PTRACE_GETFPXREGS:
		dkprintf("ptrace: unimplemented ptrace(PTRACE_GETFPXREGS) called.\n");
		break;
	case PTRACE_SYSCALL:
		dkprintf("ptrace: PTRACE_SYSCALL: data=%d\n", data);
		error = ptrace_wakeup_sig(pid, request, data);
		break;
	case PTRACE_GETSIGINFO:
		dkprintf("ptrace: unimplemented ptrace(PTRACE_GETSIGINFO) called.\n");
		error = ptrace_getsiginfo(pid, (siginfo_t *)data);
		break;
	case PTRACE_SETSIGINFO:
		dkprintf("ptrace: unimplemented ptrace(PTRACE_SETSIGINFO) called.\n");
		error = ptrace_setsiginfo(pid, (siginfo_t *)data);
		break;
	case PTRACE_GETREGSET:
		dkprintf("ptrace: unimplemented ptrace(PTRACE_GETREGSET) called.\n");
		break;
	case PTRACE_SETREGSET:
		dkprintf("ptrace: unimplemented ptrace(PTRACE_SETREGSET) called.\n");
		break;
	case PTRACE_GET_THREAD_AREA:
		dkprintf("ptrace: unimplemented ptrace(PTRACE_GET_THREAD_AREA) called.\n");
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
		dkprintf("ptrace: unimplemented ptrace called.\n");
		break;
	}

	dkprintf("ptrace(%d,%ld,%p,%p): returning %d\n", request, pid, addr, data, error);
	return error;
}

/* We do not have actual scheduling classes so we just make sure we store
 * policies and priorities in a POSIX/Linux complaint manner */
static int setscheduler(struct process *proc, int policy, struct sched_param *param)
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

	memcpy(&proc->sched_param, param, sizeof(*param));
	proc->sched_policy = policy;

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
	struct process *proc = cpu_local_var(current);
	unsigned long irqstate = 0;
	ihk_spinlock_t *lock;
	
	struct syscall_request request1 IHK_DMA_ALIGN;

	dkprintf("sched_setparam: pid: %d, uparam: 0x%lx\n", pid, uparam);

	if (!uparam || pid < 0) {
		return -EINVAL;
	}

	if (pid == 0)
		pid = proc->ftn->pid;

	if (proc->ftn->pid != pid) {
		proc = findthread_and_lock(pid, pid, &lock, &irqstate);
		if (!proc) {
			return -ESRCH;
		}
		process_unlock(lock, irqstate);
		
		/* Ask Linux about ownership.. */
		request1.number = __NR_sched_setparam;
		request1.args[0] = SCHED_CHECK_SAME_OWNER;
		request1.args[1] = pid;

		retval = do_syscall(&request1, ihk_mc_get_processor_id(), 0);
		if (retval != 0) {
			return retval;
		}
	}

	retval = copy_from_user(proc, &param, uparam, sizeof(param));
	if (retval < 0) {
		return -EFAULT;
	}

	return setscheduler(proc, proc->sched_policy, &param);
}

SYSCALL_DECLARE(sched_getparam)
{
	int retval = 0;
	int pid = (int)ihk_mc_syscall_arg0(ctx);
	struct sched_param *param = (struct sched_param *)ihk_mc_syscall_arg1(ctx);
	struct process *proc = cpu_local_var(current);
	unsigned long irqstate = 0;
	ihk_spinlock_t *lock;

	if (!param || pid < 0) {
		return -EINVAL;
	}

	if (pid == 0)
		pid = proc->ftn->pid;

	if (proc->ftn->pid != pid) {
		proc = findthread_and_lock(pid, pid, &lock, &irqstate);
		if (!proc) {
			return -ESRCH;
		}
		process_unlock(lock, irqstate);
	}
	
	retval = copy_to_user(proc, param, &proc->sched_param, sizeof(*param)) ? -EFAULT : 0;
	
	return retval;
}

SYSCALL_DECLARE(sched_setscheduler)
{
	int retval;
	int pid = (int)ihk_mc_syscall_arg0(ctx);
	int policy = ihk_mc_syscall_arg1(ctx);
	struct sched_param *uparam = (struct sched_param *)ihk_mc_syscall_arg2(ctx);
	struct sched_param param;
	struct process *proc = cpu_local_var(current);
	unsigned long irqstate = 0;
	ihk_spinlock_t *lock;
	
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
	
	retval = copy_from_user(proc, &param, uparam, sizeof(param));
	if (retval < 0) {
		return -EFAULT;
	}

	if (pid == 0)
		pid = proc->ftn->pid;

	if (proc->ftn->pid != pid) {
		proc = findthread_and_lock(pid, pid, &lock, &irqstate);
		if (!proc) {
			return -ESRCH;
		}
		process_unlock(lock, irqstate);
		
		/* Ask Linux about ownership.. */
		request1.number = __NR_sched_setparam;
		request1.args[0] = SCHED_CHECK_SAME_OWNER;
		request1.args[1] = pid;

		retval = do_syscall(&request1, ihk_mc_get_processor_id(), 0);
		if (retval != 0) {
			return retval;
		}
	}

	return setscheduler(proc, policy, &param);
}

SYSCALL_DECLARE(sched_getscheduler)
{
	int pid = (int)ihk_mc_syscall_arg0(ctx);
	struct process *proc = cpu_local_var(current);
	unsigned long irqstate = 0;
	ihk_spinlock_t *lock;

	if (pid < 0) {
		return -EINVAL;
	}

	if (pid == 0)
		pid = proc->ftn->pid;

	if (proc->ftn->pid != pid) {
		proc = findthread_and_lock(pid, pid, &lock, &irqstate);
		if (!proc) {
			return -ESRCH;
		}
		process_unlock(lock, irqstate);
	}

	return proc->sched_policy;
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
	struct process *proc = cpu_local_var(current);
	unsigned long irqstate = 0;
	ihk_spinlock_t *lock;
	int retval = 0;

	if (pid < 0) 
		return -EINVAL;

	if (pid == 0)
		pid = proc->ftn->pid;

	if (proc->ftn->pid != pid) {
		proc = findthread_and_lock(pid, pid, &lock, &irqstate);
		if (!proc) {
			return -ESRCH;
		}
		process_unlock(lock, irqstate);
	}
	
	t.tv_sec = 0;
	t.tv_nsec = 0;
	if (proc->sched_policy == SCHED_RR) {
		t.tv_nsec = 10000;
	}
	
	retval = copy_to_user(proc, utime, &t, sizeof(t)) ? -EFAULT : 0;
	
	return retval;
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
	unsigned long irqstate;
	extern int num_processors;

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
	for (cpu_id = 0; cpu_id < num_processors; cpu_id++)
		if (CPU_ISSET(cpu_id, &k_cpu_set))
			CPU_SET(cpu_id, &cpu_set);

	if(tid == 0)
		tid = cpu_local_var(current)->ftn->tid;

	for (cpu_id = 0; cpu_id < num_processors; cpu_id++) {
		irqstate = ihk_mc_spinlock_lock(&get_cpu_local_var(cpu_id)->runq_lock);
		list_for_each_entry(thread, &get_cpu_local_var(cpu_id)->runq, sched_list)
			if (thread->ftn->pid && thread->ftn->tid == tid)
				goto found; /* without unlocking runq_lock */
		ihk_mc_spinlock_unlock(&get_cpu_local_var(cpu_id)->runq_lock, irqstate);
	}
	kprintf("%s:%d Thread not found.\n", __FILE__, __LINE__);
	return -ESRCH;

found:
	memcpy(&thread->cpu_set, &cpu_set, sizeof(cpu_set));

	if (!CPU_ISSET(cpu_id, &thread->cpu_set)) {
		hold_process(thread);
		ihk_mc_spinlock_unlock(&get_cpu_local_var(cpu_id)->runq_lock, irqstate);
		sched_request_migrate(cpu_id, thread);
		release_process(thread);
		return 0;
	} else {
		ihk_mc_spinlock_unlock(&get_cpu_local_var(cpu_id)->runq_lock, irqstate);
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
	unsigned long irqstate;
	extern int num_processors;

	if (sizeof(k_cpu_set) > len) {
		kprintf("%s:%d Too small buffer.\n", __FILE__, __LINE__);
		return -EINVAL;
	}
	len = MIN2(len, sizeof(k_cpu_set));

	if(tid == 0)
		tid = cpu_local_var(current)->ftn->tid;

	for (i = 0; i < num_processors && !found; i++) {
		struct process *thread;
		irqstate = ihk_mc_spinlock_lock(&get_cpu_local_var(i)->runq_lock);
		list_for_each_entry(thread, &get_cpu_local_var(i)->runq, sched_list) {
			if (thread->ftn->pid && thread->ftn->tid == tid) {
				found = 1;
				memcpy(&k_cpu_set, &thread->cpu_set, sizeof(k_cpu_set));
				break;
			}
		}
		ihk_mc_spinlock_unlock(&get_cpu_local_var(i)->runq_lock, irqstate);
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
	schedule();

	return 0;
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

SYSCALL_DECLARE(msync)
{
	const uintptr_t start0 = ihk_mc_syscall_arg0(ctx);
	const size_t len0 = ihk_mc_syscall_arg1(ctx);
	const int flags = ihk_mc_syscall_arg2(ctx);
	const size_t len = (len0 + PAGE_SIZE - 1) & PAGE_MASK;
	const uintptr_t start = start0;
	const uintptr_t end = start + len;
	struct process *proc = cpu_local_var(current);
	struct process_vm *vm = proc->vm;
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
	struct process *proc = cpu_local_var(current);
	const int cpu = ihk_mc_get_processor_id();
	const int node = 0;
	int error;

	if (cpup) {
		error = copy_to_user(proc, (void *)cpup, &cpu, sizeof(cpu));
		if (error) {
			goto out;
		}
	}

	if (nodep) {
		error = copy_to_user(proc, (void *)nodep, &node, sizeof(node));
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

	if (cpu_local_var(current)->ftn->ptrace) {
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

	check_signal(l, NULL);
	check_need_resched();

	if (cpu_local_var(current)->ftn->ptrace) {
		ptrace_syscall_exit(cpu_local_var(current));
	}

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
