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
#define VR_WRITE_COMBINED  0x400
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

// struct process.status, struct thread.status
#define PS_RUNNING           0x1
#define PS_INTERRUPTIBLE     0x2
#define PS_UNINTERRUPTIBLE   0x4
#define PS_ZOMBIE            0x8
#define PS_EXITED            0x10
#define PS_STOPPED           0x20
#define PS_TRACED            0x40 /* Set to "not running" by a ptrace related event */
#define PS_STOPPING          0x80
#define PS_TRACING           0x100

#define PS_NORMAL	(PS_INTERRUPTIBLE | PS_UNINTERRUPTIBLE)

// struct process.ptrace
#define PT_TRACED 0x80     /* The process is ptraced */
#define PT_TRACE_EXEC 0x100 /* Trace execve(2) */
#define PT_TRACE_SYSCALL_ENTER 0x200 /* Trace syscall enter */
#define PT_TRACE_SYSCALL_EXIT  0x400 /* Trace syscall exit */
#define PT_TRACE_SYSCALL_MASK  (PT_TRACE_SYSCALL_ENTER | PT_TRACE_SYSCALL_EXIT)

// ptrace(2) request
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

// ptrace(2) options
#define PTRACE_O_TRACESYSGOOD 1
#define PTRACE_O_TRACEFORK 2
#define PTRACE_O_TRACEVFORK 4
#define PTRACE_O_TRACECLONE 8
#define PTRACE_O_TRACEEXEC 0x10
#define PTRACE_O_TRACEVFORKDONE 0x20
#define PTRACE_O_TRACEEXIT 0x40
#define PTRACE_O_MASK 0x7f

// ptrace(2) events
#define	PTRACE_EVENT_FORK 1
#define	PTRACE_EVENT_VFORK 2
#define	PTRACE_EVENT_CLONE 3
#define	PTRACE_EVENT_EXEC 4
#define	PTRACE_EVENT_VFORK_DONE 5
#define	PTRACE_EVENT_EXIT 6

#define NT_X86_XSTATE 0x202 /* x86 XSAVE extended state */

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

struct resource_set;
struct process_hash;
struct thread_hash;
struct address_space;
struct process;
struct thread;
struct process_vm;
struct vm_regions;
struct vm_range;

#define HASH_SIZE	73

struct resource_set {
	struct list_head	list;
	char			*path;
	struct process_hash	*process_hash;
	struct thread_hash	*thread_hash;
	struct list_head	phys_mem_list;
	mcs_rwlock_lock_t		phys_mem_lock;
	cpu_set_t		cpu_set;
	mcs_rwlock_lock_t		cpu_set_lock;
	struct process		*pid1;
};

extern struct list_head	resource_set_list;
extern mcs_rwlock_lock_t	resource_set_lock;

struct process_hash {
	struct list_head	list[HASH_SIZE];
	mcs_rwlock_lock_t		lock[HASH_SIZE];
};

static inline int
process_hash(int pid)
{
	return pid % HASH_SIZE;
}

static inline int
thread_hash(int tid)
{
	return tid % HASH_SIZE;
}

struct thread_hash {
	struct list_head	list[HASH_SIZE];
	mcs_rwlock_lock_t		lock[HASH_SIZE];
};

struct address_space {
	struct page_table	*page_table;
	int			type;
#define ADDRESS_SPACE_NORMAL	1
#define ADDRESS_SPACE_PVAS	2
	int			nslots;
	int			pids[];
};

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
	unsigned long vm_start, vm_end;
	unsigned long text_start, text_end;
	unsigned long data_start, data_end;
	unsigned long brk_start, brk_end;
	unsigned long map_start, map_end;
	unsigned long stack_start, stack_end;
	unsigned long user_start, user_end;
};

struct process_vm;

struct sigfd {
	struct sigfd *next;
	int fd;
	__sigset_t mask;
};
#define SFD_CLOEXEC 02000000
#define SFD_NONBLOCK 04000

struct sig_common {
	ihk_spinlock_t	lock;
	ihk_atomic_t use;
	struct sigfd *sigfd;
	struct k_sigaction action[_NSIG];
	struct list_head sigpending;
};

struct sig_pending {
	struct list_head list;
	sigset_t sigmask;
	siginfo_t info;
	int ptracecont;
};

typedef void pgio_func_t(void *arg);

/* Represents a node in the process fork tree, it may exist even after the 
 * corresponding process exited due to references from the parent and/or 
 * children and is used for implementing wait/waitpid without having a 
 * special "init" process */
struct process {
	struct list_head hash_list;
	mcs_rwlock_lock_t update_lock; // lock for parent, status, ...?

	// process vm
	struct process_vm *vm;

	// threads and children
	struct list_head threads_list;
	mcs_rwlock_lock_t threads_lock; // lock for threads_list

	/* The ptracing process behave as the parent of the ptraced process
	   after using PTRACE_ATTACH except getppid. So we save it here. */
	struct process *parent;
	struct process *ppid_parent;
	struct list_head children_list;
	struct list_head ptraced_children_list;
	mcs_rwlock_lock_t children_lock; // lock for children_list and ptraced_children_list
	struct list_head siblings_list; // lock parent
	struct list_head ptraced_siblings_list; // lock ppid_parent

	ihk_atomic_t refcount;

	// process status and exit status
	int status;	// PS_RUNNING -> PS_EXITED -> PS_ZOMBIE
			// |       ^       ^
			// |       |---+   |
			// V           |   |
			// PS_STOPPING-)---+
			// (PS_TRACING)|   |
			// |           |   |
			// V       +----   |
			// PS_STOPPED -----+
			// (PS_TRACED)
	int exit_status;

	/* Store exit_status for a group of threads when stopped by SIGSTOP.
	   exit_status can't be used because values of exit_status of threads
	   might divert while the threads are exiting by group_exit(). */
	int group_exit_status;

	/* Manage ptraced processes in the separate list to make it easy to
	   restore the orginal parent child relationship when 
	   performing PTRACE_DETACH */
	struct waitq waitpid_q;

	// process info and credentials etc.
	int pid;
	int pgid;
	int ruid;
	int euid;
	int suid;
	int fsuid;
	int rgid;
	int egid;
	int sgid;
	int fsgid;
	int execed;
	int nohost;
	struct rlimit rlimit[MCK_RLIM_MAX];
	unsigned long saved_auxv[AUXV_LEN];
	char *saved_cmdline;
	long saved_cmdline_len;

	/* Store ptrace flags.
	 * The lower 8 bits are PTRACE_O_xxx of the PTRACE_SETOPTIONS request.
	 * Other bits are for inner use of the McKernel.
	 */
	int ptrace;

	/* Store ptrace event message.
	 * PTRACE_O_xxx will store event message here.
	 * PTRACE_GETEVENTMSG will get from here.
	 */
	unsigned long ptrace_eventmsg;

	/* Store event related to signal. For example, 
	   it represents that the proceess has been resumed by SIGCONT. */
	int signal_flags;

	/* Store signal sent to parent when the process terminates. */
	int termsig;

};

void hold_thread(struct thread *ftn);
void release_thread(struct thread *ftn);

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

struct thread {
	struct list_head hash_list;
	// thread info
	int cpu_id;
	int tid;
	int status;	// PS_RUNNING -> PS_EXITED
			// |       ^       ^
			// |       |       |
			// V       |       |
			// PS_STOPPED------+
			// PS_TRACED
			// PS_INTERRPUTIBLE
			// PS_UNINTERRUPTIBLE

	// process vm
	struct process_vm *vm;

	// context
	ihk_mc_kernel_context_t ctx;
	ihk_mc_user_context_t  *uctx;
	
	// sibling
	struct process *proc;
	struct list_head siblings_list; // lock process

	// Runqueue list entry
	struct list_head sched_list;	// lock cls
	int sched_policy;
	struct sched_param sched_param;
	
	ihk_spinlock_t spin_sleep_lock;
	int spin_sleep;

	ihk_atomic_t refcount;

	struct {
		int	*clear_child_tid;
		unsigned long tlsblock_base, tlsblock_limit;
	} thread;

	// thread info
	cpu_set_t cpu_set;
	fp_regs_struct *fp_regs;
	int in_syscall_offload;

	// signal
	struct sig_common *sigcommon;
	sigset_t sigmask;
	stack_t sigstack;
	struct list_head sigpending;
	ihk_spinlock_t	sigpendinglock;
	volatile int sigevent;

	// gpio
	pgio_func_t *pgio_fp;
	void *pgio_arg;

	// for ptrace
	unsigned long *ptrace_debugreg;	/* debug registers for ptrace */
	struct sig_pending *ptrace_recvsig;
	struct sig_pending *ptrace_sendsig;
};

struct process_vm {
	struct address_space *address_space;
	struct list_head vm_range_list;
	struct vm_regions region;
	struct process *proc;		/* process that reside on the same page */
 	
	ihk_spinlock_t page_table_lock;
	ihk_spinlock_t memory_range_lock;
    // to protect the followings:
    // 1. addition of process "memory range" (extend_process_region, add_process_memory_range)
    // 2. addition of process page table (allocate_pages, update_process_page_table)
    // note that physical memory allocator (ihk_mc_alloc_pages, ihk_pagealloc_alloc)
    // is protected by its own lock (see ihk/manycore/generic/page_alloc.c)

	ihk_atomic_t refcount;
	cpu_set_t cpu_set;
	ihk_spinlock_t cpu_set_lock;
	int exiting;
};


struct thread *create_thread(unsigned long user_pc);
struct thread *clone_thread(struct thread *org, unsigned long pc,
                              unsigned long sp, int clone_flags);
void destroy_thread(struct thread *thread);
void hold_thread(struct thread *thread);
void release_thread(struct thread *thread);
void flush_process_memory(struct process_vm *vm);
void hold_process_vm(struct process_vm *vm);
void release_process_vm(struct process_vm *vm);
void hold_process(struct process *);
void release_process(struct process *);
void free_process_memory_ranges(struct process_vm *vm);
int populate_process_memory(struct process_vm *vm, void *start, size_t len);

int add_process_memory_range(struct process_vm *vm,
                             unsigned long start, unsigned long end,
                             unsigned long phys, unsigned long flag,
			     struct memobj *memobj, off_t objoff);
int remove_process_memory_range(struct process_vm *vm, unsigned long start,
		unsigned long end, int *ro_freedp);
int split_process_memory_range(struct process_vm *vm,
		struct vm_range *range, uintptr_t addr, struct vm_range **splitp);
int join_process_memory_range(struct process_vm *vm, struct vm_range *surviving,
		struct vm_range *merging);
int change_prot_process_memory_range(
		struct process_vm *vm, struct vm_range *range,
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

int page_fault_process_vm(struct process_vm *fault_vm, void *fault_addr,
		uint64_t reason);
int remove_process_region(struct process_vm *vm,
                          unsigned long start, unsigned long end);
struct program_load_desc;
int init_process_stack(struct thread *thread, struct program_load_desc *pn,
                        int argc, char **argv, 
                        int envc, char **env);
unsigned long extend_process_region(struct process_vm *vm,
                                    unsigned long start, unsigned long end,
                                    unsigned long address, unsigned long flag);
extern enum ihk_mc_pt_attribute arch_vrflag_to_ptattr(unsigned long flag, uint64_t fault, pte_t *ptep);
enum ihk_mc_pt_attribute common_vrflag_to_ptattr(unsigned long flag, uint64_t fault, pte_t *ptep);

void schedule(void);
void runq_add_thread(struct thread *thread, int cpu_id);
void runq_del_thread(struct thread *thread, int cpu_id);
int sched_wakeup_thread(struct thread *thread, int valid_states);

void sched_request_migrate(int cpu_id, struct thread *thread);
void check_need_resched(void);

void cpu_set(int cpu, cpu_set_t *cpu_set, ihk_spinlock_t *lock);
void cpu_clear(int cpu, cpu_set_t *cpu_set, ihk_spinlock_t *lock);
void cpu_clear_and_set(int c_cpu, int s_cpu, 
		cpu_set_t *cpu_set, ihk_spinlock_t *lock);

void release_cpuid(int cpuid);

struct thread *find_thread(int pid, int tid, struct mcs_rwlock_node_irqsave *lock);
void thread_unlock(struct thread *thread, struct mcs_rwlock_node_irqsave *lock);
struct process *find_process(int pid, struct mcs_rwlock_node_irqsave *lock);
void process_unlock(struct process *proc, struct mcs_rwlock_node_irqsave *lock);
void chain_process(struct process *);
void chain_thread(struct thread *);
void proc_init();

#endif
