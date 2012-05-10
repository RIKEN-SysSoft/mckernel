#include <process.h>
#include <string.h>
#include <errno.h>
#include <kmalloc.h>
#include <cls.h>
#include <aal/debug.h>
#include <page.h>
#include <cpulocal.h>

#define DEBUG_PRINT_PROCESS

#ifdef DEBUG_PRINT_PROCESS
#define dkprintf kprintf
#else
#define dkprintf(...)
#endif


#define USER_STACK_NR_PAGES 4
#define KERNEL_STACK_NR_PAGES 4

extern long do_arch_prctl(unsigned long code, unsigned long address);

void init_process_vm(struct process_vm *vm)
{
	int i;

	aal_atomic_set(&vm->refcount, 1);
	INIT_LIST_HEAD(&vm->vm_range_list);
	vm->page_table = aal_mc_pt_create();
	
	/* Initialize futex queues */
	for (i = 0; i < (1 << FUTEX_HASHBITS); ++i)
		futex_queue_init(&vm->futex_queues[i]);

}

struct process *create_process(unsigned long user_pc)
{
	struct process *proc;

	proc = aal_mc_alloc_pages(KERNEL_STACK_NR_PAGES, 0);
	if (!proc)
		return NULL;

	memset(proc, 0, sizeof(struct process));

	aal_mc_init_user_process(&proc->ctx, &proc->uctx,
	                         ((char *)proc) + 
							 KERNEL_STACK_NR_PAGES * PAGE_SIZE, user_pc, 0);

	proc->vm = (struct process_vm *)(proc + 1);

	init_process_vm(proc->vm);

	return proc;
}

struct process *clone_process(struct process *org, unsigned long pc,
                              unsigned long sp)
{
	struct process *proc;

	proc = aal_mc_alloc_pages(KERNEL_STACK_NR_PAGES, 0);

	memset(proc, 0, KERNEL_STACK_NR_PAGES);

	/* NOTE: sp is the user mode stack! */
	aal_mc_init_user_process(&proc->ctx, &proc->uctx,
	                         ((char *)proc) + 
							 KERNEL_STACK_NR_PAGES * PAGE_SIZE, pc, sp);

	memcpy(proc->uctx, org->uctx, sizeof(*org->uctx));
	aal_mc_modify_user_context(proc->uctx, AAL_UCR_STACK_POINTER, sp);
	aal_mc_modify_user_context(proc->uctx, AAL_UCR_PROGRAM_COUNTER, pc);
	
	aal_atomic_inc(&org->vm->refcount);
	proc->vm = org->vm;

	return proc;
}

extern void __host_update_process_range(struct process *process,
                                        struct vm_range *range);

void update_process_page_table(struct process *process, struct vm_range *range,
                               enum aal_mc_pt_attribute flag)
{
	unsigned long p, pa = range->phys;

	p = range->start;
	while (p < range->end) {
		aal_mc_pt_set_page(process->vm->page_table, (void *)p,
		                   pa, PTATTR_WRITABLE | PTATTR_USER | flag);

		pa += PAGE_SIZE;
		p += PAGE_SIZE;
	}
}

int add_process_memory_range(struct process *process,
                             unsigned long start, unsigned long end,
                             unsigned long phys, unsigned long flag)
{
	struct vm_range *range;

	range = kmalloc(sizeof(struct vm_range), 0);
	if (!range) {
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&range->list);
	range->start = start;
	range->end = end;
	range->phys = phys;
	range->flag = flag;

	dkprintf("range: 0x%lX - 0x%lX => 0x%lX - 0x%lX (%ld)\n",
	        range->start, range->end, range->phys, range->phys + 
	        range->end - range->start, range->end - range->start);

	if (flag & VR_REMOTE) {
		update_process_page_table(process, range, AAL_PTA_REMOTE);
	} else if (flag & VR_IO_NOCACHE) {
		update_process_page_table(process, range, PTATTR_UNCACHABLE);
	} else {
		update_process_page_table(process, range, 0);
	}

	if (!(flag & VR_REMOTE)) {
		__host_update_process_range(process, range);
	}

	list_add_tail(&range->list, &process->vm->vm_range_list);

	return 0;
}



void init_process_stack(struct process *process)
{
	char *stack = aal_mc_alloc_pages(USER_STACK_NR_PAGES, 0);
	unsigned long *p = (unsigned long *)(stack + 
	                   (USER_STACK_NR_PAGES * PAGE_SIZE));

	memset(stack, 0, USER_STACK_NR_PAGES * PAGE_SIZE);

	add_process_memory_range(process, USER_END - 
	                         (USER_STACK_NR_PAGES * PAGE_SIZE),
	                         USER_END,
	                         virt_to_phys(stack), VR_STACK);

	/* TODO: fill with actual value of argc, argv, envp */
	p[-1] = 0;     /* AT_NULL */
	p[-2] = 0;
	p[-3] = USER_END - sizeof(unsigned long) * 2;
	p[-4] = 0;     /* env: "" */
	p[-5] = 0x41;  /* argv(0): "a" */
	p[-6] = 0;     /* envp: NULL */
	p[-7] = 0;     /* argv[1] = NULL */
	p[-8] = USER_END - sizeof(unsigned long) * 5; /* argv[0] = END - 16 */
	p[-9] = 1;     /* argc */

	aal_mc_modify_user_context(process->uctx, AAL_UCR_STACK_POINTER,
	                           USER_END - sizeof(unsigned long) * 9);
	process->vm->region.stack_end = USER_END;
	process->vm->region.stack_start = USER_END - 
	                                  (USER_STACK_NR_PAGES * PAGE_SIZE);
}


unsigned long extend_process_region(struct process *proc,
                                    unsigned long start, unsigned long end,
                                    unsigned long address)
{
	unsigned long aligned_end, aligned_new_end;
	void *p;

	if (!address || address < start || address >= USER_END) {
		return end;
	}

	aligned_end = ((end + PAGE_SIZE - 1) & PAGE_MASK);

	if (aligned_end >= address) {
		return address;
	}

	aligned_new_end = (address + PAGE_SIZE - 1) & PAGE_MASK;
	
	p = allocate_pages((aligned_new_end - aligned_end) >> PAGE_SHIFT, 0);

	if (!p) {
		return end;
	}
	
	/* Clear content! */
	memset(p, 0, aligned_new_end - aligned_end);

	add_process_memory_range(proc, aligned_end, aligned_new_end,
	                         virt_to_phys(p), 0);
	
	return address;
}

int remove_process_region(struct process *proc,
                          unsigned long start, unsigned long end)
{
	if ((start & (PAGE_SIZE - 1)) || (end & (PAGE_SIZE - 1))) {
		return -EINVAL;
	}

	/* We defer freeing to the time of exit */
	while (start < end) {
		aal_mc_pt_clear_page(proc->vm->page_table, (void *)start);
		start += PAGE_SIZE;
	}

	return 0;
}

extern void print_free_list(void);
void free_process_memory(struct process *proc)
{
	struct vm_range *range, *next;

	if (!aal_atomic_dec_and_test(&proc->vm->refcount)) {
		return;
	}

	list_for_each_entry_safe(range, next, &proc->vm->vm_range_list,
	                         list) {
		if (!(range->flag & VR_REMOTE) &&
		    !(range->flag & VR_IO_NOCACHE) &&
		    !(range->flag & VR_RESERVED)) {
			aal_mc_free_pages(phys_to_virt(range->phys),
			                  (range->end - range->start)
			                  >> PAGE_SHIFT);
		}
		list_del(&range->list);
		aal_mc_free(range);
	}
	/* TODO: Free page tables */
	proc->status = PS_ZOMBIE;
}

void destroy_process(struct process *proc)
{
	aal_mc_free_pages(proc, 1);
}

static void idle(void)
{
	//unsigned int	flags;
	//flags = aal_mc_spinlock_lock(&cpu_status_lock);
	//aal_mc_spinlock_unlock(&cpu_status_lock, flags);
	cpu_local_var(status) = CPU_STATUS_IDLE;

	while (1) {
		cpu_enable_interrupt();
		schedule();
		//cpu_local_var(status) = CPU_STATUS_IDLE;
		cpu_halt();
	}
}

void sched_init(void)
{
	struct process *idle_process = &cpu_local_var(idle);

	memset(idle_process, 0, sizeof(struct process));
	memset(&cpu_local_var(idle_vm), 0, sizeof(struct process_vm));

	idle_process->vm = &cpu_local_var(idle_vm);

	aal_mc_init_context(&idle_process->ctx, NULL, idle);
	idle_process->pid = aal_mc_get_processor_id();

	INIT_LIST_HEAD(&cpu_local_var(runq));
	cpu_local_var(runq_len) = 0;
	aal_mc_spinlock_init(&cpu_local_var(runq_lock));
}

void schedule(void)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	struct process *next, *prev, *proc, *tmp = NULL;
	int switch_ctx = 0;
	unsigned long irqstate;

	irqstate = aal_mc_spinlock_lock(&(v->runq_lock));

	next = NULL;
	prev = v->current;

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

	/* Pick a new running process */
	list_for_each_entry_safe(proc, tmp, &(v->runq), sched_list) {
		if (proc->status == PS_RUNNING) {
			next = proc;
			break;
		}
	}

	/* No process? Run idle.. */
	if (!next) {
		next = &cpu_local_var(idle);
	}

	if (prev != next) {
		switch_ctx = 1;
		v->current = next;
	}
	
	aal_mc_spinlock_unlock(&(v->runq_lock), irqstate);

	if (switch_ctx) {
		dkprintf("[%d] schedule: %d => %d \n",
		        aal_mc_get_processor_id(),
		        prev ? prev->pid : 0, next ? next->pid : 0);

		aal_mc_load_page_table(next->vm->page_table);
		
		kprintf("[%d] schedule: tlsblock_base: 0x%lX\n", 
		        aal_mc_get_processor_id(), next->thread.tlsblock_base); 

		/* Set up new TLS.. */
		do_arch_prctl(ARCH_SET_FS, next->thread.tlsblock_base);
		
		if (prev) {
			aal_mc_switch_context(&prev->ctx, &next->ctx);
		} 
		else {
			aal_mc_switch_context(NULL, &next->ctx);
		}
	}
}


int sched_wakeup_process(struct process *proc, int valid_states)
{
	int status;
	unsigned long irqstate;
	struct cpu_local_var *v = get_cpu_local_var(proc->cpu_id);

	irqstate = aal_mc_spinlock_lock(&(v->runq_lock));
	
	if (proc->status & valid_states) {
		proc->status = PS_RUNNING;
		status = 0;
	} 
	else {
		status = -EINVAL;
	}

	aal_mc_spinlock_unlock(&(v->runq_lock), irqstate);

	if (!status && (proc->cpu_id != aal_mc_get_processor_id())) {
		aal_mc_interrupt_cpu(get_x86_cpu_local_variable(proc->cpu_id)->apic_id,
		                     0xd1);
	}

	return status;
}



/* Runq lock must be held here */
void __runq_add_proc(struct process *proc, int cpu_id)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	list_add_tail(&proc->sched_list, &v->runq);
	++v->runq_len;
	proc->cpu_id = cpu_id;
	proc->status = PS_RUNNING;
	get_cpu_local_var(cpu_id)->status = CPU_STATUS_RUNNING;

	dkprintf("runq_add_proc(): pid %d added to CPU[%d]'s runq\n", 
             proc->pid, cpu_id);
}

void runq_add_proc(struct process *proc, int cpu_id)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	unsigned long irqstate;
	
	irqstate = aal_mc_spinlock_lock(&(v->runq_lock));
	__runq_add_proc(proc, cpu_id);
	aal_mc_spinlock_unlock(&(v->runq_lock), irqstate);

	/* Kick scheduler */
	if (cpu_id != aal_mc_get_processor_id())
		aal_mc_interrupt_cpu(
		         get_x86_cpu_local_variable(cpu_id)->apic_id, 0xd1);
}

/* NOTE: shouldn't remove a running process! */
void runq_del_proc(struct process *proc, int cpu_id)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	unsigned long irqstate;
	
	irqstate = aal_mc_spinlock_lock(&(v->runq_lock));
	list_del(&proc->sched_list);
	--v->runq_len;
	
	if (!v->runq_len)
		get_cpu_local_var(cpu_id)->status = CPU_STATUS_IDLE;

	aal_mc_spinlock_unlock(&(v->runq_lock), irqstate);
}

