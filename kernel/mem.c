/**
 * \file mem.c
 *  License details are found in the file LICENSE.
 * \brief
 *  memory management
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 * 	Copyright (C) 2011 - 2012  Taku Shimosawa
 * \author Balazs Gerofi  <bgerofi@riken.jp> \par
 * 	Copyright (C) 2012  RIKEN AICS
 * \author Masamichi Takagi  <m-takagi@ab.jp.nec.com> \par
 * 	Copyright (C) 2012 - 2013  NEC Corporation
 * \author Balazs Gerofi  <bgerofi@is.s.u-tokyo.ac.jp> \par
 * 	Copyright (C) 2013  The University of Tokyo
 * \author Gou Nakamura  <go.nakamura.yw@hitachi-solutions.com> \par
 * 	Copyright (C) 2013 Hitachi, Ltd.
 */
/*
 * HISTORY:
 */

#include <kmsg.h>
#include <kmalloc.h>
#include <string.h>
#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <ihk/lock.h>
#include <ihk/mm.h>
#include <ihk/page_alloc.h>
#include <registers.h>
#ifdef ATTACHED_MIC
#include <sysdeps/mic/mic/micconst.h>
#include <sysdeps/mic/mic/micsboxdefine.h>
#endif
#include <cls.h>
#include <page.h>
#include <bitops.h>
#include <cpulocal.h>
#include <init.h>
#include <cas.h>

//#define DEBUG_PRINT_MEM

#ifdef DEBUG_PRINT_MEM
#define	dkprintf(...)	kprintf(__VA_ARGS__)
#define	ekprintf(...)	kprintf(__VA_ARGS__)
#else
#define dkprintf(...)	do { if (0) kprintf(__VA_ARGS__); } while (0)
#define	ekprintf(...)	kprintf(__VA_ARGS__)
#endif

static struct ihk_page_allocator_desc *pa_allocator;
static unsigned long pa_start, pa_end;
static struct page *pa_pages;

extern int ihk_mc_pt_print_pte(struct page_table *pt, void *virt);

struct tlb_flush_entry tlb_flush_vector[IHK_TLB_FLUSH_IRQ_VECTOR_SIZE];

static void reserve_pages(unsigned long start, unsigned long end, int type)
{
	if (start < pa_start) {
		start = pa_allocator->start;
	}
	if (end > pa_end) {
		end = pa_allocator->last;
	}
	if (start >= end) {
		return;
	}
	dkprintf("reserve: %016lx - %016lx (%ld pages)\n", start, end,
	        (end - start) >> PAGE_SHIFT);
	ihk_pagealloc_reserve(pa_allocator, start, end);
}

void *allocate_aligned_pages(int npages, int p2align, enum ihk_mc_ap_flag flag)
{
	unsigned long pa = ihk_pagealloc_alloc(pa_allocator, npages, p2align);
	/* all_pagealloc_alloc returns zero when error occured, 
	   and callee (in mcos/kernel/process.c) so propagate it */
	if(pa)
		return phys_to_virt(pa);
	if(flag != IHK_MC_AP_NOWAIT)
		panic("Not enough space\n");
	return NULL;
}

void *allocate_pages(int npages, enum ihk_mc_ap_flag flag)
{
	return allocate_aligned_pages(npages, PAGE_P2ALIGN, flag);
}

void free_pages(void *va, int npages)
{
	struct list_head *pendings = &cpu_local_var(pending_free_pages);
	struct page *page;

	page = phys_to_page(virt_to_phys(va));
	if (!page) {
		panic("free_pages:struct page not found");
	}
	if (page->mode != PM_NONE) {
		panic("free_pages:not PM_NONE");
	}
	if (pendings->next != NULL) {
		page->mode = PM_PENDING_FREE;
		page->offset = npages;
		list_add_tail(&page->list, pendings);
		return;
	}

	ihk_pagealloc_free(pa_allocator, virt_to_phys(va), npages);
}

void begin_free_pages_pending(void) {
	struct list_head *pendings = &cpu_local_var(pending_free_pages);

	if (pendings->next != NULL) {
		panic("begin_free_pages_pending");
	}
	INIT_LIST_HEAD(pendings);
	return;
}

void finish_free_pages_pending(void)
{
	struct list_head *pendings = &cpu_local_var(pending_free_pages);
	struct page *page;
	struct page *next;

	if (pendings->next == NULL) {
		return;
	}

	list_for_each_entry_safe(page, next, pendings, list) {
		if (page->mode != PM_PENDING_FREE) {
			panic("free_pending_pages:not PM_PENDING_FREE");
		}
		page->mode = PM_NONE;
		list_del(&page->list);
		ihk_pagealloc_free(pa_allocator, page_to_phys(page), page->offset);
	}

	pendings->next = pendings->prev = NULL;
	return;
}

static struct ihk_mc_pa_ops allocator = {
	.alloc_page = allocate_aligned_pages,
	.free_page = free_pages,
};

void sbox_write(int offset, unsigned int value);

static void query_free_mem_interrupt_handler(void *priv)
{
#ifdef ATTACHED_MIC
	dkprintf("query free mem handler!\n");

	int pages = ihk_pagealloc_query_free(pa_allocator);
	
	dkprintf("free pages: %d\n", pages);

	sbox_write(SBOX_SCRATCH0, pages);
	sbox_write(SBOX_SCRATCH1, 1);
#endif
}

static struct ihk_mc_interrupt_handler query_free_mem_handler = {
	.func = query_free_mem_interrupt_handler,
	.priv = NULL,
};

void set_signal(int sig, void *regs, struct siginfo *info);
void check_signal(unsigned long, void *, int);
int gencore(struct process *, void *, struct coretable **, int *);
void freecore(struct coretable **);

/**
 * \brief Generate a core file and tell the host to write it out.
 *
 * \param proc A current process structure.
 * \param regs A pointer to a x86_regs structure.
 */

void coredump(struct process *proc, void *regs)
{
	struct syscall_request request IHK_DMA_ALIGN;
	int ret;
	struct coretable *coretable;
	int chunks;

	ret = gencore(proc, regs, &coretable, &chunks);
	if (ret != 0) {
		dkprintf("could not generate a core file image\n");
		return;
	}
	request.number = __NR_coredump;
	request.args[0] = chunks;
	request.args[1] = virt_to_phys(coretable);
	/* no data for now */
	ret = do_syscall(&request, proc->cpu_id, proc->ftn->pid);
	if (ret == 0) {
		kprintf("dumped core.\n");
	} else {
		kprintf("core dump failed.\n");
	}
	freecore(&coretable);
}

static void unhandled_page_fault(struct process *proc, void *fault_addr, void *regs)
{
	const uintptr_t address = (uintptr_t)fault_addr;
	struct process_vm *vm = proc->vm;
	struct vm_range *range;
	char found;
	unsigned long irqflags;
	unsigned long error = ((struct x86_user_context *)regs)->gpr.error;

	irqflags = kprintf_lock();
	dkprintf("[%d] Page fault for 0x%lX\n",
			ihk_mc_get_processor_id(), address);
	dkprintf("%s for %s access in %s mode (reserved bit %s set), "
			"it %s an instruction fetch\n",
			(error & PF_PROT ? "protection fault" : "no page found"),
			(error & PF_WRITE ? "write" : "read"),
			(error & PF_USER ? "user" : "kernel"),
			(error & PF_RSVD ? "was" : "wasn't"),
			(error & PF_INSTR ? "was" : "wasn't"));

	found = 0;
	list_for_each_entry(range, &vm->vm_range_list, list) {
		if (range->start <= address && range->end > address) {
			found = 1;
			dkprintf("address is in range, flag: 0x%X! \n",
					range->flag);
			ihk_mc_pt_print_pte(vm->page_table, (void*)address);
			break;
		}
	}
	if (!found) {
		dkprintf("address is out of range! \n");
	}

	kprintf_unlock(irqflags);

	/* TODO */
	ihk_mc_debug_show_interrupt_context(regs);


	//dkprintf("now dump a core file\n");
	//coredump(proc, regs);

#ifdef DEBUG_PRINT_MEM
	{
		uint64_t *sp = (void *)REGS_GET_STACK_POINTER(regs);

		kprintf("*rsp:%lx,*rsp+8:%lx,*rsp+16:%lx,*rsp+24:%lx,\n",
				sp[0], sp[1], sp[2], sp[3]);
	}
#endif

	return;
}

void remote_flush_tlb_cpumask(struct process_vm *vm, 
		unsigned long addr, int cpu_id)
{
	unsigned long cpu;
	int flush_ind;
	struct tlb_flush_entry *flush_entry;
	cpu_set_t _cpu_set;

	if (addr) {
		flush_ind = (addr >> PAGE_SHIFT) % IHK_TLB_FLUSH_IRQ_VECTOR_SIZE;
	}
	/* Zero address denotes full TLB flush */
	else {	
		/* Random.. */
		flush_ind = (rdtsc()) % IHK_TLB_FLUSH_IRQ_VECTOR_SIZE;
	}
	
	flush_entry = &tlb_flush_vector[flush_ind]; 

	/* Take a copy of the cpu set so that we don't hold the lock
	 * all the way while interrupting other cores */
	ihk_mc_spinlock_lock_noirq(&vm->cpu_set_lock);
	memcpy(&_cpu_set, &vm->cpu_set, sizeof(cpu_set_t));
	ihk_mc_spinlock_unlock_noirq(&vm->cpu_set_lock);
	
	dkprintf("trying to aquire flush_entry->lock flush_ind: %d\n", flush_ind);
	
	ihk_mc_spinlock_lock_noirq(&flush_entry->lock);

	flush_entry->vm = vm;
	flush_entry->addr = addr;
	ihk_atomic_set(&flush_entry->pending, 0);

	dkprintf("lock aquired, iterating cpu mask.. flush_ind: %d\n", flush_ind);
	
	/* Loop through CPUs in this address space and interrupt them for
	 * TLB flush on the specified address */
	for_each_set_bit(cpu, (const unsigned long*)&_cpu_set.__bits, CPU_SETSIZE) {
		
		if (ihk_mc_get_processor_id() == cpu) 
			continue;

		ihk_atomic_inc(&flush_entry->pending);
		dkprintf("remote_flush_tlb_cpumask: flush_ind: %d, addr: 0x%lX, interrupting cpu: %d\n",
		        flush_ind, addr, cpu);

		ihk_mc_interrupt_cpu(get_x86_cpu_local_variable(cpu)->apic_id, 
		                     flush_ind + IHK_TLB_FLUSH_IRQ_VECTOR_START);
	}
	
#ifdef DEBUG_IC_TLB
	{
		unsigned long tsc;
		tsc = rdtsc() + 12884901888;  /* 1.2GHz =>10 sec */
#endif

		/* Wait for all cores */
		while (ihk_atomic_read(&flush_entry->pending) != 0) {
			cpu_pause();

#ifdef DEBUG_IC_TLB
			if (rdtsc() > tsc) {
				kprintf("waited 10 secs for remote TLB!! -> panic_all()\n"); 
				panic_all_cores("waited 10 secs for remote TLB!!\n"); 
			}
#endif
		}
#ifdef DEBUG_IC_TLB
	}
#endif
	
	ihk_mc_spinlock_unlock_noirq(&flush_entry->lock);
}

void tlb_flush_handler(int vector)
{
	int flags = cpu_disable_interrupt_save();

	struct tlb_flush_entry *flush_entry = &tlb_flush_vector[vector - 
		IHK_TLB_FLUSH_IRQ_VECTOR_START];
	
	dkprintf("decreasing pending cnt for %d\n", 
			vector - IHK_TLB_FLUSH_IRQ_VECTOR_START);

	/* Decrease counter */
	ihk_atomic_dec(&flush_entry->pending);

	dkprintf("flusing TLB for addr: 0x%lX\n", flush_entry->addr);
		
	if (flush_entry->addr) {
		flush_tlb_single(flush_entry->addr & PAGE_MASK);	
	}
	/* Zero address denotes full TLB flush */
	else {
		flush_tlb();
	}
	
	cpu_restore_interrupt(flags);
}

static void page_fault_handler(void *fault_addr, uint64_t reason, void *regs)
{
	struct process *proc = cpu_local_var(current);
	int error;

	dkprintf("[%d]page_fault_handler(%p,%lx,%p)\n",
			ihk_mc_get_processor_id(), fault_addr, reason, regs);

	preempt_disable();

	cpu_enable_interrupt();

	error = page_fault_process_vm(proc->vm, fault_addr, reason);
	if (error) {
		struct siginfo info;

		if (error == -ECANCELED) {
			kprintf("process is exiting, terminate.\n");

			ihk_mc_spinlock_lock_noirq(&proc->ftn->lock);
			proc->ftn->status = PS_ZOMBIE;
			ihk_mc_spinlock_unlock_noirq(&proc->ftn->lock);	
			release_fork_tree_node(proc->ftn->parent);
			release_fork_tree_node(proc->ftn);
			//release_process(proc);

			schedule();
		}

		kprintf("[%d]page_fault_handler(%p,%lx,%p):"
				"fault vm failed. %d\n",
				ihk_mc_get_processor_id(), fault_addr,
				reason, regs, error);
		unhandled_page_fault(proc, fault_addr, regs);
		memset(&info, '\0', sizeof info);
		if (error == -ERANGE) {
			info.si_signo = SIGBUS;
			info.si_code = BUS_ADRERR;
			info._sifields._sigfault.si_addr = fault_addr;
			set_signal(SIGBUS, regs, &info);
		}
		else {
			struct process_vm *vm = proc->vm;
			struct vm_range *range;

			info.si_signo = SIGSEGV;
			info.si_code = SEGV_MAPERR;
			list_for_each_entry(range, &vm->vm_range_list, list) {
				if (range->start <= (unsigned long)fault_addr && range->end > (unsigned long)fault_addr) {
					info.si_code = SEGV_ACCERR;
					break;
				}
			}
			info._sifields._sigfault.si_addr = fault_addr;
			set_signal(SIGSEGV, regs, &info);
		}
		check_signal(0, regs, 0);
		goto out;
	}

	error = 0;
out:
	preempt_enable();
	dkprintf("[%d]page_fault_handler(%p,%lx,%p): (%d)\n",
			ihk_mc_get_processor_id(), fault_addr, reason,
			regs, error);
	check_need_resched();
	return;
}

static void page_allocator_init(void)
{
	unsigned long page_map_pa, pages;
	void *page_map;
	unsigned int i;
	uint64_t start;
	uint64_t end;

	start = ihk_mc_get_memory_address(IHK_MC_GMA_AVAIL_START, 0);
	end = ihk_mc_get_memory_address(IHK_MC_GMA_AVAIL_END, 0);

	start &= PAGE_MASK;
	pa_start = start & LARGE_PAGE_MASK;
	pa_end = (end + PAGE_SIZE - 1) & PAGE_MASK;

#ifndef ATTACHED_MIC
	page_map_pa = ihk_mc_get_memory_address(IHK_MC_GMA_HEAP_START, 0);
#else
	/* 
	 * Can't allocate in reserved area 
	 * TODO: figure this out automatically! 
	*/
	page_map_pa = 0x100000;
#endif
	page_map = phys_to_virt(page_map_pa);

	pa_allocator = __ihk_pagealloc_init(pa_start, pa_end - pa_start,
	                                    PAGE_SIZE, page_map, &pages);

	reserve_pages(page_map_pa, page_map_pa + pages * PAGE_SIZE, 0);
	if (pa_start < start) {
		reserve_pages(pa_start, start, 0);
	}

	/* BIOS reserved ranges */
	for (i = 1; i <= ihk_mc_get_memory_address(IHK_MC_NR_RESERVED_AREAS, 0); 
	     ++i) {

		reserve_pages(ihk_mc_get_memory_address(IHK_MC_RESERVED_AREA_START, i),
		              ihk_mc_get_memory_address(IHK_MC_RESERVED_AREA_END, i), 0);
	}
	
	ihk_mc_reserve_arch_pages(pa_start, pa_end, reserve_pages);

	kprintf("Available pages: %ld pages\n",
	        ihk_pagealloc_count(pa_allocator));

	/* Notify the ihk to use my page allocator */
	ihk_mc_set_page_allocator(&allocator);

	/* And prepare some exception handlers */
	ihk_mc_set_page_fault_handler(page_fault_handler);

	/* Register query free mem handler */
	ihk_mc_register_interrupt_handler(ihk_mc_get_vector(IHK_GV_QUERY_FREE_MEM),
		&query_free_mem_handler);
}

struct page *phys_to_page(uintptr_t phys)
{
	int64_t ix;

	if ((phys < pa_start) || (pa_end <= phys)) {
		return NULL;
	}

	ix = (phys - pa_start) >> PAGE_SHIFT;
	return &pa_pages[ix];
}

uintptr_t page_to_phys(struct page *page)
{
	int64_t ix;
	uintptr_t phys;

	ix = page - pa_pages;
	phys = pa_start + (ix << PAGE_SHIFT);
	if ((phys < pa_start) || (pa_end <= phys)) {
		ekprintf("page_to_phys(%p):not a pa_pages[]:%p %lx-%lx\n",
				page, pa_pages, pa_start, pa_end);
		panic("page_to_phys");
	}
	return phys;
}

int page_unmap(struct page *page)
{
	dkprintf("page_unmap(%p %x %d)\n", page, page->mode, page->count);
	if (ihk_atomic_sub_return(1, &page->count) > 0) {
		/* other mapping exist */
		dkprintf("page_unmap(%p %x %d): 0\n",
				page, page->mode, page->count);
		return 0;
	}

	/* no mapping exist */
	if (page->mode != PM_MAPPED) {
		return 1;
	}

	list_del(&page->list);
	page->mode = PM_NONE;
	dkprintf("page_unmap(%p %x %d): 1\n", page, page->mode, page->count);
	return 1;
}

static void page_init(void)
{
	size_t npages;
	size_t allocsize;
	size_t allocpages;

	if (sizeof(ihk_atomic_t) != sizeof(uint32_t)) {
		panic("sizeof(ihk_atomic_t) is not 32 bit");
	}
	npages = (pa_end - pa_start) >> PAGE_SHIFT;
	allocsize = sizeof(struct page) * npages;
	allocpages = (allocsize + PAGE_SIZE - 1) >> PAGE_SHIFT;

	pa_pages = allocate_pages(allocpages, IHK_MC_AP_CRITICAL);
	memset(pa_pages, 0, allocsize);
	return;
}

static char *memdebug = NULL;

void register_kmalloc(void)
{
	if(memdebug){
		allocator.alloc = __kmalloc;
		allocator.free = __kfree;
	}
	else{
		allocator.alloc = ___kmalloc;
		allocator.free = ___kfree;
	}
}

static struct ihk_page_allocator_desc *vmap_allocator;

static void virtual_allocator_init(void)
{
	vmap_allocator = ihk_pagealloc_init(MAP_VMAP_START,
	                                    MAP_VMAP_SIZE, PAGE_SIZE);
	/* Make sure that kernel first-level page table copying works */
	ihk_mc_pt_prepare_map(NULL, (void *)MAP_VMAP_START, MAP_VMAP_SIZE,
	                      IHK_MC_PT_FIRST_LEVEL);
}

void *ihk_mc_map_virtual(unsigned long phys, int npages,
                         enum ihk_mc_pt_attribute attr)
{
	void *p;
	unsigned long i, offset;

	offset = (phys & (PAGE_SIZE - 1));
	phys = phys & PAGE_MASK;

	p = (void *)ihk_pagealloc_alloc(vmap_allocator, npages, PAGE_P2ALIGN);
	if (!p) {
		return NULL;
	}
	for (i = 0; i < npages; i++) {
		if(ihk_mc_pt_set_page(NULL, (char *)p + (i << PAGE_SHIFT),
		                   phys + (i << PAGE_SHIFT), attr) != 0){
			int j;
			for(j = 0; j < i; j++){
				ihk_mc_pt_clear_page(NULL, (char *)p + (j << PAGE_SHIFT));
			}
			ihk_pagealloc_free(vmap_allocator, virt_to_phys(p), npages);
			return NULL;
		}
	}
	return (char *)p + offset;
}

void ihk_mc_unmap_virtual(void *va, int npages, int free_physical)
{
	unsigned long i;

	va = (void *)((unsigned long)va & PAGE_MASK);
	for (i = 0; i < npages; i++) {
		ihk_mc_pt_clear_page(NULL, (char *)va + (i << PAGE_SHIFT));
	}
	
	if (free_physical)
		ihk_pagealloc_free(vmap_allocator, (unsigned long)va, npages);
}

#ifdef ATTACHED_MIC
/* moved from ihk_knc/manycore/mic/setup.c */
/*static*/ void *sbox_base = (void *)SBOX_BASE;
void sbox_write(int offset, unsigned int value)
{
	*(volatile unsigned int *)(sbox_base + offset) = value;
}
unsigned int sbox_read(int offset)
{
	return *(volatile unsigned int *)(sbox_base + offset);
}

/* insert entry into map which maps mic physical address to host physical address */

unsigned int free_bitmap_micpa = ((~((1ULL<<(NUM_SMPT_ENTRIES_IN_USE - NUM_SMPT_ENTRIES_MICPA))-1))&((1ULL << NUM_SMPT_ENTRIES_IN_USE) - 1));

void ihk_mc_map_micpa(unsigned long host_pa, unsigned long* mic_pa) {
    int i;
    for(i = NUM_SMPT_ENTRIES_IN_USE - 1; i >= NUM_SMPT_ENTRIES_IN_USE - NUM_SMPT_ENTRIES_MICPA; i--) {
        if((free_bitmap_micpa >> i) & 1) {
            free_bitmap_micpa &= ~(1ULL << i);
            *mic_pa = MIC_SYSTEM_BASE + MIC_SYSTEM_PAGE_SIZE * i;
            break;
        }
    }
    kprintf("ihk_mc_map_micpa,1,i=%d,host_pa=%lx,mic_pa=%llx\n", i, host_pa, *mic_pa);
    if(i == NUM_SMPT_ENTRIES_IN_USE - NUM_SMPT_ENTRIES_MICPA - 1) {
        *mic_pa = 0;
        return; 
    }
    sbox_write(SBOX_SMPT00 + ((*mic_pa - MIC_SYSTEM_BASE) >> MIC_SYSTEM_PAGE_SHIFT) * 4, BUILD_SMPT(SNOOP_ON, host_pa >> MIC_SYSTEM_PAGE_SHIFT));
    *mic_pa += (host_pa & (MIC_SYSTEM_PAGE_SIZE-1));
}

int ihk_mc_free_micpa(unsigned long mic_pa) {
    int smpt_ndx = ((mic_pa - MIC_SYSTEM_BASE) >> MIC_SYSTEM_PAGE_SHIFT);
    if(smpt_ndx >= NUM_SMPT_ENTRIES_IN_USE || 
       smpt_ndx <  NUM_SMPT_ENTRIES_IN_USE - NUM_SMPT_ENTRIES_MICPA) {
        dkprintf("ihk_mc_free_micpa,mic_pa=%llx,out of range\n", mic_pa); 
        return -1;
    }
    free_bitmap_micpa |= (1ULL << smpt_ndx);
    kprintf("ihk_mc_free_micpa,index=%d,freed\n", smpt_ndx);
    return 0;
}

void ihk_mc_clean_micpa(void){
	free_bitmap_micpa = ((~((1ULL<<(NUM_SMPT_ENTRIES_IN_USE - NUM_SMPT_ENTRIES_MICPA))-1))&((1ULL << NUM_SMPT_ENTRIES_IN_USE) - 1));
	kprintf("ihk_mc_clean_micpa\n");
}
#endif

void mem_init(void)
{
	page_allocator_init();
	page_init();

	/* Prepare the kernel virtual map space */
	virtual_allocator_init();
}

struct location {
	struct location *next;
	int line;
	int cnt;
	char file[0];
};

struct alloc {
	struct alloc *next;
	struct malloc_header *p;
	struct location *loc;
	int size;
	int runcount;
};

#define HASHNUM 129

static struct alloc *allochash[HASHNUM];
static struct location *lochash[HASHNUM];
static ihk_spinlock_t alloclock;
int runcount;
static unsigned char *page;
static int space;

static void *dalloc(unsigned long size)
{
	void *r;
	static int pos = 0;
	unsigned long irqstate;

	irqstate = ihk_mc_spinlock_lock(&alloclock);
	size = (size + 7) & 0xfffffffffffffff8L;
	if (pos + size > space) {
		page = allocate_pages(1, IHK_MC_AP_NOWAIT);
		space = 4096;
		pos = 0;
	}
	r = page + pos;
	pos += size;
	ihk_mc_spinlock_unlock(&alloclock, irqstate);

	return r;
}

void *_kmalloc(int size, enum ihk_mc_ap_flag flag, char *file, int line)
{
	char *r = ___kmalloc(size, flag);
	struct malloc_header *h;
	unsigned long hash;
	char *t;
	struct location *lp;
	struct alloc *ap;
	unsigned long alcsize;
	unsigned long chksize;

	if (!memdebug)
		return r;

	if (!r)
		return r;

	h = ((struct malloc_header *)r) - 1;
	alcsize = h->size * sizeof(struct malloc_header);
	chksize = alcsize - size;
	memset(r + size, '\x5a', chksize);

	for (hash = 0, t = file; *t; t++) {
		hash <<= 1;
		hash += *t;
	}
	hash += line;
	hash %= HASHNUM;
	for (lp = lochash[hash]; lp; lp = lp->next)
		if (lp->line == line &&
		   !strcmp(lp->file, file))
			break;
	if (!lp) {
		lp = dalloc(sizeof(struct location) + strlen(file) + 1);
		memset(lp, '\0', sizeof(struct location));
		lp->line = line;
		strcpy(lp->file, file);
		do {
			lp->next = lochash[hash];
		} while (!compare_and_swap(lochash + hash, (unsigned long)lp->next, (unsigned long)lp));
	}

	hash = (unsigned long)h % HASHNUM;
	do {
		for (ap = allochash[hash]; ap; ap = ap->next)
			if (!ap->p)
				break;
	} while (ap && !compare_and_swap(&ap->p, 0UL, (unsigned long)h));
	if (!ap) {
		ap = dalloc(sizeof(struct alloc));
		memset(ap, '\0', sizeof(struct alloc));
		ap->p = h;
		do {
			ap->next = allochash[hash];
		} while (!compare_and_swap(allochash + hash, (unsigned long)ap->next, (unsigned long)ap));
	}

	ap->loc = lp;
	ap->size = size;
	ap->runcount = runcount;

	return r;
}

int _memcheck(void *ptr, char *msg, char *file, int line, int flags)
{
	struct malloc_header *h = ((struct malloc_header *)ptr) - 1;
	struct malloc_header *next;
	unsigned long hash = (unsigned long)h % HASHNUM;
	struct alloc *ap;
	static unsigned long check = 0x5a5a5a5a5a5a5a5aUL;
	unsigned long alcsize;
	unsigned long chksize;


	if (h->check != 0x5a5a5a5a) {
		int i;
		unsigned long max = 0;
		unsigned long cur = (unsigned long)h;
		struct alloc *maxap = NULL;

		for (i = 0; i < HASHNUM; i++)
			for (ap = allochash[i]; ap; ap = ap->next)
				if ((unsigned long)ap->p < cur &&
				   (unsigned long)ap->p > max) {
					max = (unsigned long)ap->p;
					maxap = ap;
				}

		kprintf("%s: detect buffer overrun, alc=%s:%d size=%ld h=%p, s=%ld\n", msg, maxap->loc->file, maxap->loc->line, maxap->size, maxap->p, maxap->p->size);
		kprintf("broken header: h=%p next=%p size=%ld cpu_id=%d\n", h, h->next, h->size, h->cpu_id);
	}

	for (ap = allochash[hash]; ap; ap = ap->next)
		if (ap->p == h)
			break;
	if (!ap) {
		if(file)
			kprintf("%s: address not found, %s:%d p=%p\n", msg, file, line, ptr);
		else
			kprintf("%s: address not found p=%p\n", msg, ptr);
		return 1;
	}

	alcsize = h->size * sizeof(struct malloc_header);
	chksize = alcsize - ap->size;
	if (chksize > 8)
		chksize = 8;
	next = (struct malloc_header *)((char *)ptr + alcsize);

	if (next->check != 0x5a5a5a5a ||
	    memcmp((char *)ptr + ap->size, &check, chksize)) {
		unsigned long buf = 0x5a5a5a5a5a5a5a5aUL;
		unsigned char *p;
		unsigned char *q;
		memcpy(&buf, (char *)ptr + ap->size, chksize);
		p = (unsigned char *)&(next->check);
		q = (unsigned char *)&buf;

		if (file)
			kprintf("%s: broken, %s:%d alc=%s:%d %02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x size=%ld\n", msg, file, line, ap->loc->file, ap->loc->line, q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7], p[0], p[1], p[2], p[3], ap->size);
		else
			kprintf("%s: broken, alc=%s:%d %02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x size=%ld\n", msg, ap->loc->file, ap->loc->line, q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7], p[0], p[1], p[2], p[3], ap->size);


		if (next->check != 0x5a5a5a5a)
			kprintf("next->HEADER: next=%p size=%ld cpu_id=%d\n", next->next, next->size, next->cpu_id);

		return 1;
	}

	if(flags & 1){
		ap->p = NULL;
		ap->loc = NULL;
		ap->size = 0;
	}
	return 0;
}

int memcheckall()
{
	int i;
	struct alloc *ap;
	int r = 0;

kprintf("memcheckall\n");
	for(i = 0; i < HASHNUM; i++)
		for(ap = allochash[i]; ap; ap = ap->next)
			if(ap->p)
				r |= _memcheck(ap->p + 1, "memcheck", NULL, 0, 2);
kprintf("done\n");
	return r;
}

int freecheck(int runcount)
{
	int i;
	struct alloc *ap;
	struct location *lp;
	int r = 0;

	for (i = 0; i < HASHNUM; i++)
		for (lp = lochash[i]; lp; lp = lp->next)
			lp->cnt = 0;

	for (i = 0; i < HASHNUM; i++)
		for (ap = allochash[i]; ap; ap = ap->next)
			if (ap->p && ap->runcount == runcount) {
				ap->loc->cnt++;
				r++;
			}

	if (r) {
		kprintf("memory leak?\n");
		for (i = 0; i < HASHNUM; i++)
			for (lp = lochash[i]; lp; lp = lp->next)
				if (lp->cnt)
					kprintf(" alc=%s:%d cnt=%d\n", lp->file, lp->line, lp->cnt);
	}

	return r;
}

void _kfree(void *ptr, char *file, int line)
{
	if (memdebug)
		_memcheck(ptr, "KFREE", file, line, 1);
	___kfree(ptr);
}

void *__kmalloc(int size, enum ihk_mc_ap_flag flag)
{
	return kmalloc(size, flag);
}

void __kfree(void *ptr)
{
	kfree(ptr);
}

void kmalloc_init(void)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	struct malloc_header *h = &v->free_list;
	ihk_mc_spinlock_init(&v->free_list_lock);
	int i;

	h->check = 0x5a5a5a5a;
	h->next = &v->free_list;
	h->size = 0;

	register_kmalloc();

	memdebug = find_command_line("memdebug");
	for (i = 0; i < HASHNUM; i++) {
		allochash[i] = NULL;
		lochash[i] = NULL;
	}
	page = allocate_pages(16, IHK_MC_AP_NOWAIT);
	space = 16 * 4096;
	ihk_mc_spinlock_init(&alloclock);
}


void *___kmalloc(int size, enum ihk_mc_ap_flag flag)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	struct malloc_header *h = &v->free_list, *prev, *p;
	int u, req_page;
	unsigned long flags;

	if (size >= PAGE_SIZE * 4) {
		return NULL;
	}

	u = (size + sizeof(*h) - 1) / sizeof(*h);

	flags = ihk_mc_spinlock_lock(&v->free_list_lock);

	prev = h;
	h = h->next;

	while (1) {
		if (h == &v->free_list) {
			req_page = ((u + 2) * sizeof(*h) + PAGE_SIZE - 1)
				>> PAGE_SHIFT;

			h = allocate_pages(req_page, flag);
			if(h == NULL)
				return NULL;
			h->check = 0x5a5a5a5a;
			prev->next = h;
			h->size = (req_page * PAGE_SIZE) / sizeof(*h) - 2;
			/* Guard entry */
			p = h + h->size + 1;
			p->check = 0x5a5a5a5a;
			p->next = &v->free_list;
			p->size = 0;
			h->next = p;
		}

		if (h->size >= u) {
			if (h->size == u || h->size == u + 1) {
				prev->next = h->next;
				h->cpu_id = ihk_mc_get_processor_id();

				ihk_mc_spinlock_unlock(&v->free_list_lock, flags);
				return h + 1;
			} else { /* Divide */
				h->size -= u + 1;
				
				p = h + h->size + 1;
				p->check = 0x5a5a5a5a;
				p->size = u;
				p->cpu_id = ihk_mc_get_processor_id();

				ihk_mc_spinlock_unlock(&v->free_list_lock, flags);
				return p + 1;
			}
		}
		prev = h;
		h = h->next;
	}
}

void ___kfree(void *ptr)
{
	struct malloc_header *p = (struct malloc_header *)ptr;
	struct cpu_local_var *v = get_cpu_local_var((--p)->cpu_id);
	struct malloc_header *h = &v->free_list;
	int combined = 0;
	unsigned long flags;

	flags = ihk_mc_spinlock_lock(&v->free_list_lock);
	h = h->next;

	while ((p < h || p > h->next) && h != &v->free_list) {
		h = h->next;
	}

	if (h + h->size + 1 == p && h->size != 0) {
		combined = 1;
		h->size += p->size + 1;
		h->check = 0x5a5a5a5a;
	}
	if (h->next == p + p->size + 1 && h->next->size != 0) {
		if (combined) {
			h->check = 0x5a5a5a5a;
			h->size += h->next->size + 1;
			h->next = h->next->next;
		} else { 
			p->check = 0x5a5a5a5a;
			p->size += h->next->size + 1;
			p->next = h->next->next;
			h->next = p;
		}
	} else if (!combined) {
		p->next = h->next;
		h->next = p;
	}
	ihk_mc_spinlock_unlock(&v->free_list_lock, flags);
}

void print_free_list(void)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	struct malloc_header *h = &v->free_list;

	h = h->next;

	kprintf("free_list : \n");
	while (h != &v->free_list) {
		kprintf("  %p : %p, %d ->\n", h, h->next, h->size);
		h = h->next;
	}
	kprintf("\n");
}
