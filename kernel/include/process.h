#ifndef HEADER_PROCESS_H
#define HEADER_PROCESS_H

#include <ihk/context.h>
#include <ihk/cpu.h>
#include <ihk/mm.h>
#include <ihk/atomic.h>
#include <list.h>
#include <signal.h>

#define VR_NONE            0x0
#define VR_STACK           0x1
#define VR_RESERVED        0x2
#define VR_IO_NOCACHE      0x100
#define VR_REMOTE          0x200
#define VR_DEMAND_PAGING   0x1000
#define	VR_PROT_NONE       0x00000000
#define	VR_PROT_READ       0x00010000
#define	VR_PROT_WRITE      0x00020000
#define	VR_PROT_EXEC       0x00040000
#define	VR_PROT_MASK       0x00070000

#define	PROT_TO_VR_FLAG(prot)	(((unsigned long)(prot) << 16) & VR_PROT_MASK)

#define PS_RUNNING           0x1
#define PS_INTERRUPTIBLE     0x2
#define PS_UNINTERRUPTIBLE   0x4
#define PS_ZOMBIE            0x8
#define PS_EXITED            0x10

#define PS_NORMAL	(PS_INTERRUPTIBLE | PS_UNINTERRUPTIBLE)

#ifdef ATTACHED_MIC
//#define USE_LARGE_PAGES
#endif

#include <waitq.h>
#include <futex.h>

struct vm_range {
	struct list_head list;
	unsigned long start, end;
	unsigned long flag;
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
	// TODO: lock;
	int	use;
	struct k_sigaction action[_NSIG];
};

struct process {
	int pid;
	int status;
	int cpu_id;

	ihk_atomic_t refcount;
	struct process_vm *vm;

	ihk_mc_kernel_context_t ctx;
	ihk_mc_user_context_t  *uctx;
	
	// Runqueue list entry
	struct list_head sched_list;  
	
	ihk_spinlock_t spin_sleep_lock;
	int spin_sleep;

	struct thread {
		int	*clear_child_tid;
		unsigned long tlsblock_base, tlsblock_limit;
	} thread;

	int signal;
	struct sig_handler *sighandler;
	ihk_mc_kernel_context_t sigctx;
	char	sigstack[512];
	unsigned long sigrc; // return code of rt_sigreturn (x86_64: rax reg.)
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
};


struct process *create_process(unsigned long user_pc);
struct process *clone_process(struct process *org,
                              unsigned long pc, unsigned long sp);
void destroy_process(struct process *proc);
void hold_process(struct process *proc);
void free_process(struct process *proc);
void free_process_memory(struct process *proc);

int add_process_memory_range(struct process *process,
                             unsigned long start, unsigned long end,
                             unsigned long phys, unsigned long flag);
int remove_process_memory_range(
		struct process *process, unsigned long start, unsigned long end);
struct vm_range *lookup_process_memory_range(
		struct process *proc, uintptr_t start, uintptr_t end);
int remove_process_region(struct process *proc,
                          unsigned long start, unsigned long end);
struct program_load_desc;
int init_process_stack(struct process *process, struct program_load_desc *pn,
                        int argc, char **argv, 
                        int envc, char **env);
unsigned long extend_process_region(struct process *proc,
                                    unsigned long start, unsigned long end,
                                    unsigned long address, unsigned long flag);

void schedule(void);
void runq_add_proc(struct process *proc, int cpu_id);
void runq_del_proc(struct process *proc, int cpu_id);
int sched_wakeup_process(struct process *proc, int valid_states);

#endif
