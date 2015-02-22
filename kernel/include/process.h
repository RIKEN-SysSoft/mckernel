/**
 * \file process.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Structures of process and virtual memory management
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef HEADER_PROCESS_H
#define HEADER_PROCESS_H

#include <ihk/context.h>
#include <ihk/cpu.h>
#include <ihk/mm.h>
#include <ihk/atomic.h>
#include <list.h>
#include <signal.h>
#include <memobj.h>
#include <affinity.h>
#include <syscall.h>

#define VR_NONE            0x0
#define VR_STACK           0x1
#define VR_RESERVED        0x2
#define VR_IO_NOCACHE      0x100
#define VR_REMOTE          0x200
#define VR_DEMAND_PAGING   0x1000
#define	VR_PRIVATE         0x2000
#define	VR_LOCKED          0x4000
#define	VR_FILEOFF         0x8000	/* remap_file_pages()ed range */
#define	VR_PROT_NONE       0x00000000
#define	VR_PROT_READ       0x00010000
#define	VR_PROT_WRITE      0x00020000
#define	VR_PROT_EXEC       0x00040000
#define	VR_PROT_MASK       0x00070000
#define	VR_MAXPROT_NONE    0x00000000
#define	VR_MAXPROT_READ    0x00100000
#define	VR_MAXPROT_WRITE   0x00200000
#define	VR_MAXPROT_EXEC    0x00400000
#define	VR_MAXPROT_MASK    0x00700000
#define	VR_MEMTYPE_WB      0x00000000	/* write-back */
#define	VR_MEMTYPE_UC      0x01000000	/* uncachable */
#define	VR_MEMTYPE_MASK    0x0f000000

#define	PROT_TO_VR_FLAG(prot)	(((unsigned long)(prot) << 16) & VR_PROT_MASK)
#define	VRFLAG_PROT_TO_MAXPROT(vrflag)	(((vrflag) & VR_PROT_MASK) << 4)
#define	VRFLAG_MAXPROT_TO_PROT(vrflag)	(((vrflag) & VR_MAXPROT_MASK) >> 4)

#define PS_RUNNING           0x1
#define PS_INTERRUPTIBLE     0x2
#define PS_UNINTERRUPTIBLE   0x4
#define PS_ZOMBIE            0x8
#define PS_EXITED            0x10
#define PS_STOPPED           0x20
#define PS_TRACED            0x40 /* Set to "not running" by a ptrace related event */

#define PS_NORMAL	(PS_INTERRUPTIBLE | PS_UNINTERRUPTIBLE)

#define PT_TRACED 0x80     /* The process is ptraced */
#define PT_TRACE_EXEC 0x100 /* Trace execve(2) */
#define PT_TRACE_SYSCALL_ENTER 0x200 /* Trace syscall enter */
#define PT_TRACE_SYSCALL_EXIT  0x400 /* Trace syscall exit */
#define PT_TRACE_SYSCALL_MASK  (PT_TRACE_SYSCALL_ENTER | PT_TRACE_SYSCALL_EXIT)

#define	PTRACE_TRACEME 0
#define	PTRACE_PEEKTEXT 1
#define	PTRACE_PEEKDATA 2
#define	PTRACE_PEEKUSER 3
#define	PTRACE_POKETEXT 4
#define	PTRACE_POKEDATA 5
#define	PTRACE_POKEUSER 6
#define PTRACE_CONT 7
#define PTRACE_KILL 8
#define	PTRACE_SINGLESTEP 9
#define	PTRACE_GETREGS 12
#define	PTRACE_SETREGS 13
#define	PTRACE_GETFPREGS 14
#define	PTRACE_SETFPREGS 15
#define	PTRACE_ATTACH 16
#define	PTRACE_DETACH 17
#define	PTRACE_GETFPXREGS 18
#define	PTRACE_SETFPXREGS 19
#define	PTRACE_SYSCALL 24
#define	PTRACE_GET_THREAD_AREA 25
#define	PTRACE_ARCH_PRCTL 30
#define	PTRACE_SETOPTIONS 0x4200
#define	PTRACE_GETEVENTMSG 0x4201
#define	PTRACE_GETSIGINFO 0x4202
#define	PTRACE_SETSIGINFO 0x4203
#define	PTRACE_GETREGSET 0x4204
#define	PTRACE_SETREGSET 0x4205

#define PTRACE_O_TRACESYSGOOD 1
#define PTRACE_O_TRACEFORK 2
#define PTRACE_O_TRACEVFORK 4
#define PTRACE_O_TRACECLONE 8
#define PTRACE_O_TRACEEXEC 0x10
#define PTRACE_O_TRACEVFORKDONE 0x20
#define PTRACE_O_TRACEEXIT 0x40
#define PTRACE_O_MASK 0x7f

#define	PTRACE_EVENT_FORK 1
#define	PTRACE_EVENT_VFORK 2
#define	PTRACE_EVENT_CLONE 3
#define	PTRACE_EVENT_EXEC 4
#define	PTRACE_EVENT_VFORK_DONE 5
#define	PTRACE_EVENT_EXIT 6

#define SIGNAL_STOP_STOPPED   0x1 /* The process has been stopped by SIGSTOP */
#define SIGNAL_STOP_CONTINUED 0x2 /* The process has been resumed by SIGCONT */

/* Waitpid options */
#define WNOHANG		0x00000001
#define WUNTRACED	0x00000002
#define WSTOPPED	WUNTRACED
#define WEXITED		0x00000004
#define WCONTINUED	0x00000008
#define WNOWAIT		0x01000000	/* Don't reap, just poll status.  */
#define	__WCLONE	0x80000000

/* idtype */
#define P_ALL 0
#define P_PID 1
#define P_PGID 2

/* If WIFEXITED(STATUS), the low-order 8 bits of the status.  */
#define	__WEXITSTATUS(status)	(((status) & 0xff00) >> 8)

/* If WIFSIGNALED(STATUS), the terminating signal.  */
#define	__WTERMSIG(status)	((status) & 0x7f)

/* If WIFSTOPPED(STATUS), the signal that stopped the child.  */
#define	__WSTOPSIG(status)	__WEXITSTATUS(status)

/* Nonzero if STATUS indicates normal termination.  */
#define	__WIFEXITED(status)	(__WTERMSIG(status) == 0)

/* Nonzero if STATUS indicates termination by a signal.  */
#define __WIFSIGNALED(status) \
  (((signed char) (((status) & 0x7f) + 1) >> 1) > 0)

/* Nonzero if STATUS indicates the child is stopped.  */
#define	__WIFSTOPPED(status)	(((status) & 0xff) == 0x7f)
#ifdef ATTACHED_MIC
//#define USE_LARGE_PAGES
#endif

#define USER_STACK_NR_PAGES 8192
#define KERNEL_STACK_NR_PAGES 25

#include <waitq.h>
#include <futex.h>

struct user_fpregs_struct
{
	unsigned short cwd;
	unsigned short swd;
	unsigned short ftw;
	unsigned short fop;
	unsigned long rip;
	unsigned long rdp;
	unsigned int mxcsr;
	unsigned int mxcr_mask;
	unsigned int st_space[32];
	unsigned int xmm_space[64];
	unsigned int padding[24];
};

struct user_regs_struct
{
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long orig_rax;
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
	unsigned long fs_base;
	unsigned long gs_base;
	unsigned long ds;
	unsigned long es;
	unsigned long fs;
	unsigned long gs;
};

struct user
{
	struct user_regs_struct regs;
	int u_fpvalid;
	struct user_fpregs_struct i387;
	unsigned long int u_tsize;
	unsigned long int u_dsize;
	unsigned long int u_ssize;
	unsigned long start_code;
	unsigned long start_stack;
	long int signal;
	int reserved;
	struct user_regs_struct* u_ar0;
	struct user_fpregs_struct* u_fpstate;
	unsigned long int  magic;
	char u_comm [32];
	unsigned long int  u_debugreg [8];
};

#define	AUXV_LEN	16

struct vm_range {
	struct list_head list;
	unsigned long start, end;
	unsigned long flag;
	struct memobj *memobj;
	off_t objoff;
};

struct vm_regions {
	unsigned long text_start, text_end;
	unsigned long data_start, data_end;
	unsigned long brk_start, brk_end;
	unsigned long map_start, map_end;
	unsigned long stack_start, stack_end;
	unsigned long user_start, user_end;
};

struct process_vm;

struct sig_handler {
	ihk_spinlock_t	lock;
	ihk_atomic_t	use;
	struct k_sigaction action[_NSIG];
};

struct sig_pending {
	struct list_head list;
	sigset_t sigmask;
	siginfo_t info;
	int ptracecont;
};

struct sig_shared {
	ihk_spinlock_t  lock;
	ihk_atomic_t    use;
	struct list_head sigpending;
};

typedef void pgio_func_t(void *arg);

/* Represents a node in the process fork tree, it may exist even after the 
 * corresponding process exited due to references from the parent and/or 
 * children and is used for implementing wait/waitpid without having a 
 * special "init" process */
struct fork_tree_node {
	ihk_spinlock_t lock;
	ihk_atomic_t refcount;
	int exit_status;
	int status;

	struct process *owner;
	int pid;
	int tid;
	int pgid;
	
	struct fork_tree_node *parent;
	struct list_head children;
	struct list_head siblings_list;
	
    /* The ptracing process behave as the parent of the ptraced process
       after using PTRACE_ATTACH except getppid. So we save it here. */
	struct fork_tree_node *ppid_parent;

    /* Manage ptraced processes in the separate list to make it easy to
       restore the orginal parent child relationship when 
       performing PTRACE_DETACH */
	struct list_head ptrace_children;
	struct list_head ptrace_siblings_list;

	struct waitq waitpid_q;

    /* Store exit_status for a group of threads when stopped by SIGSTOP.
       exit_status can't be used because values of exit_status of threads
       might divert while the threads are exiting by group_exit(). */
    int group_exit_status;

    /* Store ptrace flags.
     * The lower 8 bits are PTRACE_O_xxx of the PTRACE_SETOPTIONS request.
     * Other bits are for inner use of the McKernel.
     */
    int ptrace;

    /* Store ptrace event message.
       PTRACE_O_xxx will store event message here.
       PTRACE_GETEVENTMSG will get from here.
     */
    unsigned long ptrace_eventmsg;

    /* Store event related to signal. For example, 
       it represents that the proceess has been resumed by SIGCONT. */
    int signal_flags;

    /* Store signal sent to parent when the process terminates. */
    int termsig;
};

void hold_fork_tree_node(struct fork_tree_node *ftn);
void release_fork_tree_node(struct fork_tree_node *ftn);

/*
 * Scheduling policies
 */
#define SCHED_NORMAL		0
#define SCHED_FIFO		1
#define SCHED_RR		2
#define SCHED_BATCH		3
/* SCHED_ISO: reserved but not implemented yet */
#define SCHED_IDLE		5
#define SCHED_DEADLINE		6

/* Can be ORed in to make sure the process is reverted back to SCHED_NORMAL on fork */
#define SCHED_RESET_ON_FORK     0x40000000

/*
 * For the sched_{set,get}attr() calls
 */
#define SCHED_FLAG_RESET_ON_FORK	0x01

struct sched_param {
	int sched_priority;
};

struct process {
	int cpu_id;

	ihk_atomic_t refcount;
	struct process_vm *vm;

	ihk_mc_kernel_context_t ctx;
	ihk_mc_user_context_t  *uctx;
	
	// Runqueue list entry
	struct list_head sched_list;  
	int sched_policy;
	struct sched_param sched_param;
	
	ihk_spinlock_t spin_sleep_lock;
	int spin_sleep;

	struct thread {
		int	*clear_child_tid;
		unsigned long tlsblock_base, tlsblock_limit;
	} thread;

	volatile int sigevent;
	int nohost;
	int execed;
	sigset_t sigmask;
	stack_t sigstack;
	ihk_spinlock_t	sigpendinglock;
	struct list_head sigpending;
	struct sig_shared *sigshared;
	struct sig_handler *sighandler;

	struct rlimit rlimit[MCK_RLIM_MAX];
	pgio_func_t *pgio_fp;
	void *pgio_arg;

	struct fork_tree_node *ftn;

	cpu_set_t cpu_set;
	unsigned long saved_auxv[AUXV_LEN];

	unsigned long *ptrace_debugreg;	/* debug registers for ptrace */
};

struct process_vm {
	ihk_atomic_t refcount;

	struct page_table *page_table;
	struct list_head vm_range_list;
	struct vm_regions region;
	struct process *owner_process;		/* process that reside on the same page */
 	
    ihk_spinlock_t page_table_lock;
    ihk_spinlock_t memory_range_lock;
    // to protect the followings:
    // 1. addition of process "memory range" (extend_process_region, add_process_memory_range)
    // 2. addition of process page table (allocate_pages, update_process_page_table)
    // note that physical memory allocator (ihk_mc_alloc_pages, ihk_pagealloc_alloc)
    // is protected by its own lock (see ihk/manycore/generic/page_alloc.c)

	cpu_set_t cpu_set;
	ihk_spinlock_t cpu_set_lock;
};


struct process *create_process(unsigned long user_pc);
struct process *clone_process(struct process *org, unsigned long pc,
                              unsigned long sp, int clone_flags);
void destroy_process(struct process *proc);
void hold_process(struct process *proc);
void release_process(struct process *proc);
void flush_process_memory(struct process *proc);
void free_process_memory(struct process *proc);
void free_process_memory_ranges(struct process *proc);
int populate_process_memory(struct process *proc, void *start, size_t len);

int add_process_memory_range(struct process *process,
                             unsigned long start, unsigned long end,
                             unsigned long phys, unsigned long flag,
			     struct memobj *memobj, off_t objoff);
int remove_process_memory_range(struct process *process, unsigned long start,
		unsigned long end, int *ro_freedp);
int split_process_memory_range(struct process *process,
		struct vm_range *range, uintptr_t addr, struct vm_range **splitp);
int join_process_memory_range(struct process *process, struct vm_range *surviving,
		struct vm_range *merging);
int change_prot_process_memory_range(
		struct process *process, struct vm_range *range,
		unsigned long newflag);
int remap_process_memory_range(struct process_vm *vm, struct vm_range *range,
		uintptr_t start, uintptr_t end, off_t off);
int sync_process_memory_range(struct process_vm *vm, struct vm_range *range,
		uintptr_t start, uintptr_t end);
int invalidate_process_memory_range(struct process_vm *vm,
		struct vm_range *range, uintptr_t start, uintptr_t end);
struct vm_range *lookup_process_memory_range(
		struct process_vm *vm, uintptr_t start, uintptr_t end);
struct vm_range *next_process_memory_range(
		struct process_vm *vm, struct vm_range *range);
struct vm_range *previous_process_memory_range(
		struct process_vm *vm, struct vm_range *range);
int extend_up_process_memory_range(struct process_vm *vm,
		struct vm_range *range, uintptr_t newend);

int page_fault_process(struct process *proc, void *fault_addr, uint64_t reason);
int remove_process_region(struct process *proc,
                          unsigned long start, unsigned long end);
struct program_load_desc;
int init_process_stack(struct process *process, struct program_load_desc *pn,
                        int argc, char **argv, 
                        int envc, char **env);
unsigned long extend_process_region(struct process *proc,
                                    unsigned long start, unsigned long end,
                                    unsigned long address, unsigned long flag);
extern enum ihk_mc_pt_attribute arch_vrflag_to_ptattr(unsigned long flag, uint64_t fault, pte_t *ptep);
enum ihk_mc_pt_attribute common_vrflag_to_ptattr(unsigned long flag, uint64_t fault, pte_t *ptep);

void schedule(void);
void runq_add_proc(struct process *proc, int cpu_id);
void runq_del_proc(struct process *proc, int cpu_id);
int sched_wakeup_process(struct process *proc, int valid_states);

void sched_request_migrate(int cpu_id, struct process *proc);
void check_need_resched(void);

void cpu_set(int cpu, cpu_set_t *cpu_set, ihk_spinlock_t *lock);
void cpu_clear(int cpu, cpu_set_t *cpu_set, ihk_spinlock_t *lock);

struct process *findthread_and_lock(int pid, int tid, ihk_spinlock_t **savelock, unsigned long *irqstate);
void process_unlock(void *savelock, unsigned long irqstate);
void release_cpuid(int cpuid);

#endif
