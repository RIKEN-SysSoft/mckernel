#ifndef HEADER_PROCESS_H
#define HEADER_PROCESS_H

#include <aal/context.h>
#include <aal/cpu.h>
#include <aal/mm.h>
#include <aal/atomic.h>
#include <list.h>

#define VR_STACK           0x1
#define VR_RESERVED        0x2
#define VR_IO_NOCACHE      0x100
#define VR_REMOTE          0x200

#define PS_ZOMBIE          0x1

struct vm_range {
	struct list_head list;
	unsigned long start, end;
	unsigned long phys;
	unsigned long flag;
};

struct vm_regions {
	unsigned long text_start, text_end;
	unsigned long data_start, data_end;
	unsigned long brk_start, brk_end;
	unsigned long map_start, map_end;
	unsigned long stack_start, stack_end;
	unsigned long tlsblock_base, tlsblock_limit;
};

struct process_vm {
	aal_atomic_t refcount;

	struct page_table *page_table;
	struct list_head vm_range_list;
	struct vm_regions region;
};

struct process {
	int pid;
	int status;

	struct process_vm *vm;

	aal_mc_kernel_context_t ctx;
	aal_mc_user_context_t  *uctx;
	
	struct thread {
		int	*clear_child_tid;
	} thread;
};

struct process *create_process(unsigned long user_pc);
struct process *clone_process(struct process *org,
                              unsigned long pc, unsigned long sp);
void destroy_process(struct process *proc);
void free_process_memory(struct process *proc);

int add_process_memory_range(struct process *process,
                             unsigned long start, unsigned long end,
                             unsigned long phys, unsigned long flag);
int remove_process_region(struct process *proc,
                          unsigned long start, unsigned long end);
void init_process_stack(struct process *process);
unsigned long extend_process_region(struct process *proc,
                                    unsigned long start, unsigned long end,
                                    unsigned long address);

void schedule(void);

#endif
