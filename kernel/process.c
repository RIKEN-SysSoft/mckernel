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

//#define DEBUG_PRINT_PROCESS

#ifdef DEBUG_PRINT_PROCESS
#define dkprintf kprintf
#else
#define dkprintf(...)
#endif


#define USER_STACK_NR_PAGES 8192
#define KERNEL_STACK_NR_PAGES 24

extern long do_arch_prctl(unsigned long code, unsigned long address);

static int init_process_vm(struct process *owner, struct process_vm *vm)
{
	void *pt = ihk_mc_pt_create(IHK_MC_AP_NOWAIT);

	if(pt == NULL)
		return -ENOMEM;

	ihk_mc_spinlock_init(&vm->memory_range_lock);
	ihk_mc_spinlock_init(&vm->page_table_lock);

	ihk_atomic_set(&vm->refcount, 1);
	INIT_LIST_HEAD(&vm->vm_range_list);
	vm->page_table = pt;
	hold_process(owner);
	vm->owner_process = owner;
	
	return 0;
}

struct process *create_process(unsigned long user_pc)
{
	struct process *proc;

	proc = ihk_mc_alloc_pages(KERNEL_STACK_NR_PAGES, IHK_MC_AP_NOWAIT);
	if (!proc)
		return NULL;

	memset(proc, 0, sizeof(struct process));
	ihk_atomic_set(&proc->refcount, 2);	/* one for exit, another for wait */

	ihk_mc_init_user_process(&proc->ctx, &proc->uctx,
	                         ((char *)proc) + 
							 KERNEL_STACK_NR_PAGES * PAGE_SIZE, user_pc, 0);

	proc->vm = (struct process_vm *)(proc + 1);

	if(init_process_vm(proc, proc->vm) != 0){
		ihk_mc_free_pages(proc, KERNEL_STACK_NR_PAGES);
		return NULL;
	}

	ihk_mc_spinlock_init(&proc->spin_sleep_lock);
	proc->spin_sleep = 0;

	return proc;
}

struct process *clone_process(struct process *org, unsigned long pc,
                              unsigned long sp)
{
	struct process *proc;

	if((proc = ihk_mc_alloc_pages(KERNEL_STACK_NR_PAGES, IHK_MC_AP_NOWAIT)) == NULL){
		return NULL;
	}

	memset(proc, 0, sizeof(struct process));
	ihk_atomic_set(&proc->refcount, 2);	/* one for exit, another for wait */

	/* NOTE: sp is the user mode stack! */
	ihk_mc_init_user_process(&proc->ctx, &proc->uctx,
	                         ((char *)proc) + 
							 KERNEL_STACK_NR_PAGES * PAGE_SIZE, pc, sp);

	memcpy(proc->uctx, org->uctx, sizeof(*org->uctx));
	ihk_mc_modify_user_context(proc->uctx, IHK_UCR_STACK_POINTER, sp);
	ihk_mc_modify_user_context(proc->uctx, IHK_UCR_PROGRAM_COUNTER, pc);
	
	ihk_atomic_inc(&org->vm->refcount);
	proc->vm = org->vm;

	ihk_mc_spinlock_init(&proc->spin_sleep_lock);
	proc->spin_sleep = 0;

	return proc;
}

extern void __host_update_process_range(struct process *process,
                                        struct vm_range *range);

int update_process_page_table(struct process *process,
                          struct vm_range *range, enum ihk_mc_pt_attribute flag)
{
	unsigned long p, pa = range->phys;
	unsigned long pp;
	unsigned long flags = ihk_mc_spinlock_lock(&process->vm->page_table_lock);
	const enum ihk_mc_pt_attribute attr
		= flag | PTATTR_WRITABLE | PTATTR_USER | PTATTR_FOR_USER;

	p = range->start;
	while (p < range->end) {
#ifdef USE_LARGE_PAGES
		/* Use large PTE if both virtual and physical addresses are large page 
		 * aligned and more than LARGE_PAGE_SIZE is left from the range */
		if ((p & (LARGE_PAGE_SIZE - 1)) == 0 && 
				(pa & (LARGE_PAGE_SIZE - 1)) == 0 &&
				(range->end - p) >= LARGE_PAGE_SIZE) {

			if (ihk_mc_pt_set_large_page(process->vm->page_table, (void *)p,
					pa, attr) != 0) {
				goto err;
			}

			dkprintf("large page set for 0x%lX -> 0x%lX\n", p, pa);

			pa += LARGE_PAGE_SIZE;
			p += LARGE_PAGE_SIZE;
		}
		else {
#endif		
			if(ihk_mc_pt_set_page(process->vm->page_table, (void *)p,
			      pa, attr) != 0){
				goto err;
			}

			pa += PAGE_SIZE;
			p += PAGE_SIZE;
#ifdef USE_LARGE_PAGES
		}
#endif
	}
	ihk_mc_spinlock_unlock(&process->vm->page_table_lock, flags);
	return 0;

err:
	pp = range->start;
	pa = range->phys;
	while(pp < p){
#ifdef USE_LARGE_PAGES
		if ((p & (LARGE_PAGE_SIZE - 1)) == 0 && 
				(pa & (LARGE_PAGE_SIZE - 1)) == 0 &&
				(range->end - p) >= LARGE_PAGE_SIZE) {
			ihk_mc_pt_clear_large_page(process->vm->page_table, (void *)pp);
			pa += LARGE_PAGE_SIZE;
			pp += LARGE_PAGE_SIZE;
		}
		else{
#endif
			ihk_mc_pt_clear_page(process->vm->page_table, (void *)pp);
			pa += PAGE_SIZE;
			pp += PAGE_SIZE;
#ifdef USE_LARGE_PAGES
		}
#endif
	}

	ihk_mc_spinlock_unlock(&process->vm->page_table_lock, flags);
	return -ENOMEM;
}

int remove_process_memory_range(struct process *process, unsigned long start, unsigned long end)
{
	struct process_vm * const vm = process->vm;
	struct vm_range *range;
	struct vm_range *next;
	int error;
	unsigned long freestart;
	unsigned long freephys;
	unsigned long freesize;
	struct vm_range *freerange;
	struct vm_range *newrange;

	list_for_each_entry_safe(range, next, &vm->vm_range_list, list) {
		if ((range->end <= start) || (end <= range->start)) {
			/* no overlap */
			continue;
		}

		error = 0;
		freerange = NULL;
		freesize = 0;

		if (start <= range->start) {
			/* partial or whole delete from range->start */
			freestart = range->start;
			freephys = range->phys;
			freesize = end - range->start;

			if (freesize >= (range->end - range->start)) {
				freesize = range->end - range->start;
				list_del(&range->list);
				freerange = range;
			}
			else {
				range->start += freesize;
				range->phys += freesize;
			}
		}
		else if (range->end <= end) {
			/* partial delete up to range->end */
			freestart = start;
			freephys = range->phys + (start - range->start);
			freesize = range->end - start;

			range->end = start;
		}
		else {
			/* delete the middle part of the 'range' */
			freestart = start;
			freephys = range->phys + (start - range->start);
			freesize = end - start;

			newrange = kmalloc(sizeof(struct vm_range), IHK_MC_AP_NOWAIT);
			if (!newrange) {
				kprintf("remove_process_memory_range:kmalloc failed\n");
				return -ENOMEM;
			}
			newrange->start = end;
			newrange->end = range->end;
			newrange->phys = range->phys + (end - range->start);
			newrange->flag = range->flag;
			list_add_tail(&newrange->list, &vm->vm_range_list);

			range->end = start;
		}

        /* FIXME: traverse page table entries and release physical memory area if present
         then mark the page table entry non-present */
		if (freesize > 0 && !(range->flag & VR_DEMAND_PAGING)) {
            dkprintf("remove_process_memory_range,remove_process_region\n");
			error = remove_process_region(process, freestart, (freestart + freesize));
			if (error) {
				kprintf("remove_process_memory_range:remove_process_region failed: %d\n", error);
				/* through */
			}

			if (!(range->flag & (VR_REMOTE | VR_IO_NOCACHE | VR_RESERVED)) && !(range->flag & VR_DEMAND_PAGING)) {
                dkprintf("remove_process_memory_range,ihk_mc_free_pages\n");
				// XXX: need TLB shootdown?
				ihk_mc_free_pages(phys_to_virt(freephys), freesize>>PAGE_SHIFT);
			}
		}
		if (freerange != NULL) {
			ihk_mc_free(freerange);
		}
		if (error) {
			return error;
		}
	}

	return 0;
}

int add_process_memory_range(struct process *process,
                             unsigned long start, unsigned long end,
                             unsigned long phys, unsigned long flag)
{
	struct vm_range *range;
	int rc;

	if ((start < process->vm->region.user_start)
			|| (process->vm->region.user_end < end)) {
		kprintf("range(%#lx - %#lx) is not in user avail(%#lx - %#lx)\n",
				start, end, process->vm->region.user_start,
				process->vm->region.user_end);
		return -EINVAL;
	}

	range = kmalloc(sizeof(struct vm_range), IHK_MC_AP_NOWAIT);
	if (!range) {
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&range->list);
	range->start = start;
	range->end = end;
	range->phys = phys;
	range->flag = flag;

    if(range->flag & VR_DEMAND_PAGING) {
	dkprintf("range: 0x%lX - 0x%lX => physicall memory area is allocated on demand (%ld)\n",
	        range->start, range->end, range->end - range->start);
    } else {
	dkprintf("range: 0x%lX - 0x%lX => 0x%lX - 0x%lX (%ld)\n",
	        range->start, range->end, range->phys, range->phys + 
	        range->end - range->start, range->end - range->start);
    }

	if (flag & VR_REMOTE) {
		rc = update_process_page_table(process, range, IHK_PTA_REMOTE);
	} else if (flag & VR_IO_NOCACHE) {
		rc = update_process_page_table(process, range, PTATTR_UNCACHABLE);
	} else if(flag & VR_DEMAND_PAGING){
	  //demand paging no need to update process table now
	  kprintf("demand paging do not update process page table\n");
      rc = 0;
	} else {
		rc = update_process_page_table(process, range, 0);
	}
	if(rc != 0){
		kfree(range);
		return rc;
	}

#if 0 // disable __host_update_process_range() in add_process_memory_range(), because it has no effect on the actual mapping on the MICs side. 
	if (!(flag & VR_REMOTE)) {
		__host_update_process_range(process, range);
	}
#endif
	
	list_add_tail(&range->list, &process->vm->vm_range_list);
	
	/* Clear content! */
	if (!(flag & VR_REMOTE) && !(flag & VR_DEMAND_PAGING))
		memset((void*)phys_to_virt(range->phys), 0, end - start);

	return 0;
}



int init_process_stack(struct process *process, struct program_load_desc *pn,
                        int argc, char **argv, 
                        int envc, char **env)
{
	int s_ind = 0;
	int arg_ind;
	unsigned long size = USER_STACK_NR_PAGES * PAGE_SIZE;
	char *stack = ihk_mc_alloc_pages(USER_STACK_NR_PAGES, IHK_MC_AP_NOWAIT);
	unsigned long *p = (unsigned long *)(stack + size);
	unsigned long end = process->vm->region.user_end;
	unsigned long start = end - size;
	int rc;

	if(stack == NULL)
		return -ENOMEM;

	memset(stack, 0, size);

	if((rc = add_process_memory_range(process, start, end, virt_to_phys(stack), VR_STACK)) != 0){
		ihk_mc_free_pages(stack, USER_STACK_NR_PAGES);
		return rc;
	}

	s_ind = -1;
	p[s_ind--] = 0;     /* AT_NULL */
	p[s_ind--] = 0;
	p[s_ind--] = pn->at_phnum; /* AT_PHNUM */
	p[s_ind--] = AT_PHNUM;
	p[s_ind--] = pn->at_phent;  /* AT_PHENT */
	p[s_ind--] = AT_PHENT;
	p[s_ind--] = pn->at_phdr;  /* AT_PHDR */
	p[s_ind--] = AT_PHDR;	
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

	ihk_mc_modify_user_context(process->uctx, IHK_UCR_STACK_POINTER,
	                           end + sizeof(unsigned long) * s_ind);
	process->vm->region.stack_end = end;
	process->vm->region.stack_start = start;
	return 0;
}


unsigned long extend_process_region(struct process *proc,
                                    unsigned long start, unsigned long end,
                                    unsigned long address, unsigned long flag)
{
	unsigned long aligned_end, aligned_new_end;
	void *p;
	int rc;

	if (!address || address < start || address >= USER_END) {
		return end;
	}

	aligned_end = ((end + PAGE_SIZE - 1) & PAGE_MASK);

	if (aligned_end >= address) {
		return address;
	}

	aligned_new_end = (address + PAGE_SIZE - 1) & PAGE_MASK;

#ifdef USE_LARGE_PAGES
	if (aligned_new_end - aligned_end >= LARGE_PAGE_SIZE) {
	  if(flag & VR_DEMAND_PAGING){panic("demand paging for large page is not available!");}
		unsigned long p_aligned;
		unsigned long old_aligned_end = aligned_end;

		if ((aligned_end & (LARGE_PAGE_SIZE - 1)) != 0) {

			aligned_end = (aligned_end + (LARGE_PAGE_SIZE - 1)) & LARGE_PAGE_MASK;
			/* Fill in the gap between old_aligned_end and aligned_end
			 * with regular pages */
			if((p = allocate_pages((aligned_end - old_aligned_end) >> PAGE_SHIFT,
                                 IHK_MC_AP_NOWAIT)) == NULL){
				return end;
			}
			if((rc = add_process_memory_range(proc, old_aligned_end,
                                        aligned_end, virt_to_phys(p), VR_NONE)) != 0){
				free_pages(p, (aligned_end - old_aligned_end) >> PAGE_SHIFT);
				return end;
			}
			
			dkprintf("filled in gap for LARGE_PAGE_SIZE aligned start: 0x%lX -> 0x%lX\n",
					old_aligned_end, aligned_end);
		}
	
		/* Add large region for the actual mapping */
		aligned_new_end = (aligned_new_end + (aligned_end - old_aligned_end) +
				(LARGE_PAGE_SIZE - 1)) & LARGE_PAGE_MASK;
		address = aligned_new_end;

		if((p = allocate_pages((aligned_new_end - aligned_end + LARGE_PAGE_SIZE) >> PAGE_SHIFT,
                            IHK_MC_AP_NOWAIT)) == NULL){
			return end;
		}

		p_aligned = ((unsigned long)p + (LARGE_PAGE_SIZE - 1)) & LARGE_PAGE_MASK;

		if (p_aligned > (unsigned long)p) {
			free_pages(p, (p_aligned - (unsigned long)p) >> PAGE_SHIFT);
		}
		free_pages(
			(void *)(p_aligned + aligned_new_end - aligned_end),
			(LARGE_PAGE_SIZE - (p_aligned - (unsigned long)p)) >> PAGE_SHIFT);

		if((rc = add_process_memory_range(proc, aligned_end,
                               aligned_new_end, virt_to_phys((void *)p_aligned),
                               flag)) != 0){
			free_pages(p, (aligned_new_end - aligned_end + LARGE_PAGE_SIZE) >> PAGE_SHIFT);
			return end;
		}

		dkprintf("largePTE area: 0x%lX - 0x%lX (s: %lu) -> 0x%lX - \n",
				aligned_end, aligned_new_end, 
				(aligned_new_end - aligned_end), 
				virt_to_phys((void *)p_aligned));

		return address;
	}
#endif
	if(flag & VR_DEMAND_PAGING){
	  // demand paging no need to allocate page now
	  kprintf("demand page do not allocate page\n");
	  p=0;
	}else{

	p = allocate_pages((aligned_new_end - aligned_end) >> PAGE_SHIFT, IHK_MC_AP_NOWAIT);

	if (!p) {
		return end;
	}
    }	
	if((rc = add_process_memory_range(proc, aligned_end, aligned_new_end,
                                      (p==0?0:virt_to_phys(p)), flag)) != 0){
		free_pages(p, (aligned_new_end - aligned_end) >> PAGE_SHIFT);
		return end;
	}
	
	return address;
}

// Original version retained because dcfa (src/mccmd/client/ibmic/main.c) calls this 
int remove_process_region(struct process *proc,
                          unsigned long start, unsigned long end)
{
	if ((start & (PAGE_SIZE - 1)) || (end & (PAGE_SIZE - 1))) {
		return -EINVAL;
	}

	ihk_mc_spinlock_lock_noirq(&proc->vm->page_table_lock);
	/* We defer freeing to the time of exit */
	// XXX: check error
	ihk_mc_pt_clear_range(proc->vm->page_table, (void *)start, (void *)end);
	ihk_mc_spinlock_unlock_noirq(&proc->vm->page_table_lock);

	return 0;
}

extern void print_free_list(void);
void free_process_memory(struct process *proc)
{
	struct vm_range *range, *next;
	struct process_vm *vm = proc->vm;

	if (vm == NULL) {
		return;
	}

	proc->vm = NULL;
	if (!ihk_atomic_dec_and_test(&vm->refcount)) {
		return;
	}

	list_for_each_entry_safe(range, next, &vm->vm_range_list,
	                         list) {
		if (!(range->flag & (VR_REMOTE | VR_IO_NOCACHE | VR_RESERVED
						| VR_DEMAND_PAGING))) {
			ihk_mc_free_pages(phys_to_virt(range->phys),
			                  (range->end - range->start)
			                  >> PAGE_SHIFT);
		}
		list_del(&range->list);
		ihk_mc_free(range);
	}

	ihk_mc_pt_destroy(vm->page_table);
	free_process(vm->owner_process);
}

void hold_process(struct process *proc)
{
	if (proc->status & (PS_ZOMBIE | PS_EXITED)) {
		panic("hold_process: already exited process");
	}

	ihk_atomic_inc(&proc->refcount);
	return;
}

void destroy_process(struct process *proc)
{
	ihk_mc_free_pages(proc, KERNEL_STACK_NR_PAGES);
}

void free_process(struct process *proc)
{
	if (!ihk_atomic_dec_and_test(&proc->refcount)) {
		return;
	}

	destroy_process(proc);
}

static void idle(void)
{
	//unsigned int	flags;
	//flags = ihk_mc_spinlock_lock(&cpu_status_lock);
	//ihk_mc_spinlock_unlock(&cpu_status_lock, flags);
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

	ihk_mc_init_context(&idle_process->ctx, NULL, idle);
	idle_process->pid = ihk_mc_get_processor_id();

	INIT_LIST_HEAD(&cpu_local_var(runq));
	cpu_local_var(runq_len) = 0;
	ihk_mc_spinlock_init(&cpu_local_var(runq_lock));

#ifdef TIMER_CPU_ID
	if (ihk_mc_get_processor_id() == TIMER_CPU_ID) {
		init_timers();
		wake_timers_loop();
	}
#endif
}

void schedule(void)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	struct process *next, *prev, *proc, *tmp = NULL;
	int switch_ctx = 0;
	unsigned long irqstate;
	struct process *last;

	irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));

	next = NULL;
	prev = v->current;

	/* All runnable processes are on the runqueue */
	if (prev && prev != &cpu_local_var(idle)) {
		list_del(&prev->sched_list);
		--v->runq_len;	
		
		/* Round-robin if not exited yet */
		if (!(prev->status & (PS_ZOMBIE | PS_EXITED))) {
			list_add_tail(&prev->sched_list, &(v->runq));
			++v->runq_len;
		}

		if (!v->runq_len) {
			v->status = CPU_STATUS_IDLE;
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
	
	if (switch_ctx) {
		dkprintf("[%d] schedule: %d => %d \n",
		        ihk_mc_get_processor_id(),
		        prev ? prev->pid : 0, next ? next->pid : 0);

		ihk_mc_load_page_table(next->vm->page_table);
		
		dkprintf("[%d] schedule: tlsblock_base: 0x%lX\n", 
		         ihk_mc_get_processor_id(), next->thread.tlsblock_base); 

		/* Set up new TLS.. */
		do_arch_prctl(ARCH_SET_FS, next->thread.tlsblock_base);
		
		ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
		
		if (prev) {
			last = ihk_mc_switch_context(&prev->ctx, &next->ctx, prev);
		} 
		else {
			last = ihk_mc_switch_context(NULL, &next->ctx, prev);
		}

		if ((last != NULL) && (last->status & (PS_ZOMBIE | PS_EXITED))) {
			free_process_memory(last);
			free_process(last);
		}
	}
	else {
		ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
	}
}


int sched_wakeup_process(struct process *proc, int valid_states)
{
	int status;
	int spin_slept = 0;
	unsigned long irqstate;
	struct cpu_local_var *v = get_cpu_local_var(proc->cpu_id);
	
	irqstate = ihk_mc_spinlock_lock(&(proc->spin_sleep_lock));
	if (proc->spin_sleep) {
		dkprintf("sched_wakeup_process() spin wakeup: cpu_id: %d\n", 
				proc->cpu_id);

		spin_slept = 1;
		proc->spin_sleep = 0;
		status = 0;	
	}
	ihk_mc_spinlock_unlock(&(proc->spin_sleep_lock), irqstate);
	
	if (spin_slept)
		return status;

	irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
	
	if (proc->status & valid_states) {
		xchg4((int *)(&proc->status), PS_RUNNING);
		status = 0;
	} 
	else {
		status = -EINVAL;
	}

	ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);

	if (!status && (proc->cpu_id != ihk_mc_get_processor_id())) {
		ihk_mc_interrupt_cpu(get_x86_cpu_local_variable(proc->cpu_id)->apic_id,
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
	
	irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
	__runq_add_proc(proc, cpu_id);
	ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);

	/* Kick scheduler */
	if (cpu_id != ihk_mc_get_processor_id())
		ihk_mc_interrupt_cpu(
		         get_x86_cpu_local_variable(cpu_id)->apic_id, 0xd1);
}

/* NOTE: shouldn't remove a running process! */
void runq_del_proc(struct process *proc, int cpu_id)
{
	struct cpu_local_var *v = get_cpu_local_var(cpu_id);
	unsigned long irqstate;
	
	irqstate = ihk_mc_spinlock_lock(&(v->runq_lock));
	list_del(&proc->sched_list);
	--v->runq_len;
	
	if (!v->runq_len)
		get_cpu_local_var(cpu_id)->status = CPU_STATUS_IDLE;

	ihk_mc_spinlock_unlock(&(v->runq_lock), irqstate);
}

