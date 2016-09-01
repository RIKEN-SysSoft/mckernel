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

extern void unhandled_page_fault(struct thread *, void *, void *);
extern int interrupt_from_user(void *);

struct tlb_flush_entry tlb_flush_vector[IHK_TLB_FLUSH_IRQ_VECTOR_SIZE];

int anon_on_demand = 0;

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

static void *allocate_aligned_pages(int npages, int p2align, 
		enum ihk_mc_ap_flag flag)
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

static void *allocate_pages(int npages, enum ihk_mc_ap_flag flag)
{
	return allocate_aligned_pages(npages, PAGE_P2ALIGN, flag);
}

static void free_pages(void *va, int npages)
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
	int pages = ihk_pagealloc_query_free(pa_allocator);
	
	kprintf("McKernel free pages: %d\n", pages);

	if (find_command_line("memdebug")) {
		extern void kmalloc_memcheck(void);

		kmalloc_memcheck();
	}

#ifdef ATTACHED_MIC
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
int gencore(struct thread *, void *, struct coretable **, int *);
void freecore(struct coretable **);

/**
 * \brief Generate a core file and tell the host to write it out.
 *
 * \param proc A current process structure.
 * \param regs A pointer to a x86_regs structure.
 */

void coredump(struct thread *thread, void *regs)
{
	struct syscall_request request IHK_DMA_ALIGN;
	int ret;
	struct coretable *coretable;
	int chunks;

	ret = gencore(thread, regs, &coretable, &chunks);
	if (ret != 0) {
		dkprintf("could not generate a core file image\n");
		return;
	}
	request.number = __NR_coredump;
	request.args[0] = chunks;
	request.args[1] = virt_to_phys(coretable);
	/* no data for now */
	ret = do_syscall(&request, thread->cpu_id, thread->proc->pid);
	if (ret == 0) {
		kprintf("dumped core.\n");
	} else {
		kprintf("core dump failed.\n");
	}
	freecore(&coretable);
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
	ihk_mc_spinlock_lock_noirq(&vm->address_space->cpu_set_lock);
	memcpy(&_cpu_set, &vm->address_space->cpu_set, sizeof(cpu_set_t));
	ihk_mc_spinlock_unlock_noirq(&vm->address_space->cpu_set_lock);
	
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
		if (flush_entry->addr) {
			flush_tlb_single(flush_entry->addr & PAGE_MASK);
		}
		/* Zero address denotes full TLB flush */
		else {
			flush_tlb();
		}

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
	struct thread *thread = cpu_local_var(current);
	int error;

	set_cputime(interrupt_from_user(regs)? 1: 2);
	dkprintf("[%d]page_fault_handler(%p,%lx,%p)\n",
			ihk_mc_get_processor_id(), fault_addr, reason, regs);

	preempt_disable();

	cpu_enable_interrupt();

	error = page_fault_process_vm(thread->vm, fault_addr, reason);
	if (error) {
		struct siginfo info;

		if (error == -ECANCELED) {
			dkprintf("process is exiting, terminate.\n");

			preempt_enable();
			terminate(0, SIGSEGV);
			// no return
		}

		kprintf("%s fault VM failed for TID: %d, addr: 0x%lx, "
				"reason: %d, error: %d\n", __FUNCTION__,
				thread->tid, fault_addr, reason, error);
		unhandled_page_fault(thread, fault_addr, regs);
		preempt_enable();
		memset(&info, '\0', sizeof info);
		if (error == -ERANGE) {
			info.si_signo = SIGBUS;
			info.si_code = BUS_ADRERR;
			info._sifields._sigfault.si_addr = fault_addr;
			set_signal(SIGBUS, regs, &info);
		}
		else {
			struct process_vm *vm = thread->vm;
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
		if(interrupt_from_user(regs)){
			cpu_enable_interrupt();
			check_signal(0, regs, 0);
		}
		goto out;
	}

	error = 0;
	preempt_enable();
out:
	dkprintf("[%d]page_fault_handler(%p,%lx,%p): (%d)\n",
			ihk_mc_get_processor_id(), fault_addr, reason,
			regs, error);
	check_need_resched();
	set_cputime(0);
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

	kprintf("Available memory: %ld bytes in %ld pages\n",
	        (ihk_pagealloc_count(pa_allocator) * PAGE_SIZE), 
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

	pa_pages = ihk_mc_alloc_pages(allocpages, IHK_MC_AP_CRITICAL);
	memset(pa_pages, 0, allocsize);
	return;
}

static char *memdebug = NULL;

static void *___kmalloc(int size, enum ihk_mc_ap_flag flag);
static void ___kfree(void *ptr);

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
	
	if (free_physical) {
		ihk_pagealloc_free(vmap_allocator, (unsigned long)va, npages);
		flush_tlb_single((unsigned long)va);
	}
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

	if (find_command_line("anon_on_demand")) {
		kprintf("Demand paging on ANONYMOUS mappings enabled.\n");
		anon_on_demand = 1;
	}
}

#define KMALLOC_TRACK_HASH_SHIFT	(8)
#define KMALLOC_TRACK_HASH_SIZE     (1 << KMALLOC_TRACK_HASH_SHIFT)
#define KMALLOC_TRACK_HASH_MASK     (KMALLOC_TRACK_HASH_SIZE - 1)

struct list_head kmalloc_track_hash[KMALLOC_TRACK_HASH_SIZE];
ihk_spinlock_t kmalloc_track_hash_locks[KMALLOC_TRACK_HASH_SIZE];

struct list_head kmalloc_addr_hash[KMALLOC_TRACK_HASH_SIZE];
ihk_spinlock_t kmalloc_addr_hash_locks[KMALLOC_TRACK_HASH_SIZE];

int kmalloc_track_initialized = 0;
int kmalloc_runcount = 0;

struct kmalloc_track_addr_entry {
	void *addr;
	int runcount;
	struct list_head list; /* track_entry's list */
	struct kmalloc_track_entry *entry;
	struct list_head hash; /* address hash */
};

struct kmalloc_track_entry {
	char *file;
	int line;
	int size;
	ihk_atomic_t alloc_count;
	struct list_head hash;
	struct list_head addr_list;
	ihk_spinlock_t addr_list_lock;
};

void kmalloc_init(void)
{
	struct cpu_local_var *v = get_this_cpu_local_var();

	register_kmalloc();

	INIT_LIST_HEAD(&v->free_list);
	INIT_LIST_HEAD(&v->remote_free_list);
	ihk_mc_spinlock_init(&v->remote_free_list_lock);

	v->kmalloc_initialized = 1;

	if (!kmalloc_track_initialized) {
		int i;

		memdebug = find_command_line("memdebug");

		kmalloc_track_initialized = 1;
		for (i = 0; i < KMALLOC_TRACK_HASH_SIZE; ++i) {
			ihk_mc_spinlock_init(&kmalloc_track_hash_locks[i]);
			INIT_LIST_HEAD(&kmalloc_track_hash[i]);
			ihk_mc_spinlock_init(&kmalloc_addr_hash_locks[i]);
			INIT_LIST_HEAD(&kmalloc_addr_hash[i]);
		}
	}
}

/* NOTE: Hash lock must be held */
struct kmalloc_track_entry *__kmalloc_track_find_entry(
		int size, char *file, int line)
{
	struct kmalloc_track_entry *entry_iter, *entry = NULL;
	int hash = (strlen(file) + line + size) & KMALLOC_TRACK_HASH_MASK;

	list_for_each_entry(entry_iter, &kmalloc_track_hash[hash], hash) {
		if (!strcmp(entry_iter->file, file) &&
				entry_iter->size == size &&
				entry_iter->line == line) {
			entry = entry_iter;
			break;
		}
	}

	if (entry) {
		dkprintf("%s found entry %s:%d size: %d\n", __FUNCTION__,
				file, line, size);
	}
	else {
		dkprintf("%s couldn't find entry %s:%d size: %d\n", __FUNCTION__,
				file, line, size);
	}

	return entry;
}

/* Top level routines called from macro */
void *_kmalloc(int size, enum ihk_mc_ap_flag flag, char *file, int line)
{
	unsigned long irqflags;
	struct kmalloc_track_entry *entry;
	struct kmalloc_track_addr_entry *addr_entry;
	int hash, addr_hash;
	void *r = ___kmalloc(size, flag);

	if (!memdebug)
		return r;

	if (!r)
		return r;

	hash = (strlen(file) + line + size) & KMALLOC_TRACK_HASH_MASK;
	irqflags = ihk_mc_spinlock_lock(&kmalloc_track_hash_locks[hash]);

	entry = __kmalloc_track_find_entry(size, file, line);

	if (!entry) {
		entry = ___kmalloc(sizeof(*entry), IHK_MC_AP_NOWAIT);
		if (!entry) {
			kprintf("%s: ERROR: allocating tracking entry\n");
			goto out;
		}

		entry->line = line;
		entry->size = size;
		ihk_atomic_set(&entry->alloc_count, 0);
		ihk_mc_spinlock_init(&entry->addr_list_lock);
		INIT_LIST_HEAD(&entry->addr_list);

		entry->file = ___kmalloc(strlen(file) + 1, IHK_MC_AP_NOWAIT);
		if (!entry->file) {
			kprintf("%s: ERROR: allocating file string\n");
			___kfree(entry);
			ihk_mc_spinlock_unlock(&kmalloc_track_hash_locks[hash], irqflags);
			goto out;
		}

		strcpy(entry->file, file);
		entry->file[strlen(file)] = 0;
		list_add(&entry->hash, &kmalloc_track_hash[hash]);
		dkprintf("%s entry %s:%d size: %d added\n", __FUNCTION__,
			file, line, size);
	}
	ihk_mc_spinlock_unlock(&kmalloc_track_hash_locks[hash], irqflags);

	ihk_atomic_inc(&entry->alloc_count);

	/* Add new addr entry for this allocation entry */
	addr_entry = ___kmalloc(sizeof(*addr_entry), IHK_MC_AP_NOWAIT);
	if (!addr_entry) {
		kprintf("%s: ERROR: allocating addr entry\n");
		goto out;
	}

	addr_entry->addr = r;
	addr_entry->runcount = kmalloc_runcount;
	addr_entry->entry = entry;

	irqflags = ihk_mc_spinlock_lock(&entry->addr_list_lock);
	list_add(&addr_entry->list, &entry->addr_list);
	ihk_mc_spinlock_unlock(&entry->addr_list_lock, irqflags);

	/* Add addr entry to address hash */
	addr_hash = ((unsigned long)r >> 5) & KMALLOC_TRACK_HASH_MASK;
	irqflags = ihk_mc_spinlock_lock(&kmalloc_addr_hash_locks[addr_hash]);
	list_add(&addr_entry->hash, &kmalloc_addr_hash[addr_hash]);
	ihk_mc_spinlock_unlock(&kmalloc_addr_hash_locks[addr_hash], irqflags);

	dkprintf("%s addr_entry %p added\n", __FUNCTION__, r);

out:
	return r;
}

void _kfree(void *ptr, char *file, int line)
{
	unsigned long irqflags;
	struct kmalloc_track_entry *entry;
	struct kmalloc_track_addr_entry *addr_entry_iter, *addr_entry = NULL;
	int hash;

	if (!memdebug) {
		goto out;
	}

	hash = ((unsigned long)ptr >> 5) & KMALLOC_TRACK_HASH_MASK;
	irqflags = ihk_mc_spinlock_lock(&kmalloc_addr_hash_locks[hash]);
	list_for_each_entry(addr_entry_iter,
			&kmalloc_addr_hash[hash], hash) {
		if (addr_entry_iter->addr == ptr) {
			addr_entry = addr_entry_iter;
			break;
		}
	}

	if (addr_entry) {
		list_del(&addr_entry->hash);
	}
	ihk_mc_spinlock_unlock(&kmalloc_addr_hash_locks[hash], irqflags);

	if (!addr_entry) {
		kprintf("%s: ERROR: kfree()ing invalid pointer\n", __FUNCTION__);
		panic("panic");
	}

	entry = addr_entry->entry;

	irqflags = ihk_mc_spinlock_lock(&entry->addr_list_lock);
	list_del(&addr_entry->list);
	ihk_mc_spinlock_unlock(&entry->addr_list_lock, irqflags);

	dkprintf("%s addr_entry %p removed\n", __FUNCTION__, addr_entry->addr);
	___kfree(addr_entry);

	/* Do we need to remove tracking entry as well? */
	if (!ihk_atomic_dec_and_test(&entry->alloc_count)) {
		goto out;
	}

	hash = (strlen(entry->file) + entry->line + entry->size) &
		KMALLOC_TRACK_HASH_MASK;
	irqflags = ihk_mc_spinlock_lock(&kmalloc_track_hash_locks[hash]);
	list_del(&entry->hash);
	ihk_mc_spinlock_unlock(&kmalloc_track_hash_locks[hash], irqflags);

	dkprintf("%s entry %s:%d size: %d removed\n", __FUNCTION__,
			entry->file, entry->line, entry->size);
	___kfree(entry->file);
	___kfree(entry);

out:
	___kfree(ptr);
}

void kmalloc_memcheck(void)
{
	int i;
	unsigned long irqflags;
	struct kmalloc_track_entry *entry = NULL;

	for (i = 0; i < KMALLOC_TRACK_HASH_SIZE; ++i) {
		irqflags = ihk_mc_spinlock_lock(&kmalloc_track_hash_locks[i]);
		list_for_each_entry(entry, &kmalloc_track_hash[i], hash) {
			struct kmalloc_track_addr_entry *addr_entry = NULL;
			int cnt = 0;

			ihk_mc_spinlock_lock_noirq(&entry->addr_list_lock);
			list_for_each_entry(addr_entry, &entry->addr_list, list) {

			dkprintf("%s memory leak: %p @ %s:%d size: %d runcount: %d\n",
				__FUNCTION__,
				addr_entry->addr,
				entry->file,
				entry->line,
				entry->size,
				addr_entry->runcount);

				if (kmalloc_runcount != addr_entry->runcount)
					continue;

				cnt++;
			}
			ihk_mc_spinlock_unlock_noirq(&entry->addr_list_lock);

			if (!cnt)
				continue;

			kprintf("%s memory leak: %s:%d size: %d cnt: %d, runcount: %d\n",
				__FUNCTION__,
				entry->file,
				entry->line,
				entry->size,
				cnt,
				kmalloc_runcount);
		}
		ihk_mc_spinlock_unlock(&kmalloc_track_hash_locks[i], irqflags);
	}

	++kmalloc_runcount;
}

/* Redirection routines registered in alloc structure */
void *__kmalloc(int size, enum ihk_mc_ap_flag flag)
{
	return kmalloc(size, flag);
}

void __kfree(void *ptr)
{
	kfree(ptr);
}


static void ___kmalloc_insert_chunk(struct list_head *free_list,
	struct kmalloc_header *chunk)
{
	struct kmalloc_header *chunk_iter, *next_chunk = NULL;

	/* Find out where to insert */
	list_for_each_entry(chunk_iter, free_list, list) {
		if ((void *)chunk < (void *)chunk_iter) {
			next_chunk = chunk_iter;
			break;
		}
	}

	/* Add in front of next */
	if (next_chunk) {
		list_add_tail(&chunk->list, &next_chunk->list);
	}
	/* Add after the head */
	else {
		list_add(&chunk->list, free_list);
	}

	return;
}

static void ___kmalloc_init_chunk(struct kmalloc_header *h, int size)
{
	h->size = size;
	h->front_magic = 0x5c5c5c5c;
	h->end_magic = 0x6d6d6d6d;
	h->cpu_id = ihk_mc_get_processor_id();
}

static void ___kmalloc_consolidate_list(struct list_head *list)
{
	struct kmalloc_header *chunk_iter, *chunk, *next_chunk;

reiterate:
	chunk_iter = NULL;
	chunk = NULL;

	list_for_each_entry(next_chunk, list, list) {

		if (chunk_iter && (((void *)chunk_iter + sizeof(struct kmalloc_header)
						+ chunk_iter->size) == (void *)next_chunk)) {
			chunk = chunk_iter;
			break;
		}

		chunk_iter = next_chunk;
	}

	if (!chunk) {
		return;
	}

	chunk->size += (next_chunk->size + sizeof(struct kmalloc_header));
	list_del(&next_chunk->list);
	goto reiterate;
}


void kmalloc_consolidate_free_list(void)
{
	struct kmalloc_header *chunk, *tmp;
	unsigned long irqflags =
		ihk_mc_spinlock_lock(&cpu_local_var(remote_free_list_lock));

	/* Clean up remotely deallocated chunks */
	list_for_each_entry_safe(chunk, tmp,
			&cpu_local_var(remote_free_list), list) {

		list_del(&chunk->list);
		___kmalloc_insert_chunk(&cpu_local_var(free_list), chunk);
	}

	/* Free list lock ensures IRQs are disabled */
	___kmalloc_consolidate_list(&cpu_local_var(free_list));

	ihk_mc_spinlock_unlock(&cpu_local_var(remote_free_list_lock), irqflags);
}

#define KMALLOC_MIN_SHIFT   (5)
#define KMALLOC_MIN_SIZE    (1 << KMALLOC_TRACK_HASH_SHIFT)
#define KMALLOC_MIN_MASK    (KMALLOC_MIN_SIZE - 1)

/* Actual low-level allocation routines */
static void *___kmalloc(int size, enum ihk_mc_ap_flag flag)
{
	struct kmalloc_header *chunk_iter;
	struct kmalloc_header *chunk = NULL;
	int npages;
	unsigned long kmalloc_irq_flags = cpu_disable_interrupt_save();

	/* KMALLOC_MIN_SIZE bytes aligned size. */
	if (size & KMALLOC_MIN_MASK) {
		size = ((size + KMALLOC_MIN_SIZE - 1) & ~(KMALLOC_MIN_MASK));
	}

	chunk = NULL;
	/* Find a chunk that is big enough */
	list_for_each_entry(chunk_iter, &cpu_local_var(free_list), list) {
		if (chunk_iter->size >= size) {
			chunk = chunk_iter;
			break;
		}
	}

split_and_return:
	/* Did we find one? */
	if (chunk) {
		/* Do we need to split it? Only if there is enough space for
		 * another header and some actual content */
		if (chunk->size > (size + sizeof(struct kmalloc_header))) {
			struct kmalloc_header *leftover;

			leftover = (struct kmalloc_header *)
				((void *)chunk + sizeof(struct kmalloc_header) + size);
			___kmalloc_init_chunk(leftover,
				(chunk->size - size - sizeof(struct kmalloc_header)));
			list_add(&leftover->list, &chunk->list);
			chunk->size = size;
		}

		list_del(&chunk->list);
		cpu_restore_interrupt(kmalloc_irq_flags);
		return ((void *)chunk + sizeof(struct kmalloc_header));
	}


	/* Allocate new memory and add it to free list */
	npages = (size + sizeof(struct kmalloc_header) + (PAGE_SIZE - 1))
		>> PAGE_SHIFT;
	chunk = ihk_mc_alloc_pages(npages, flag);

	if (!chunk) {
		cpu_restore_interrupt(kmalloc_irq_flags);
		return NULL;
	}

	___kmalloc_init_chunk(chunk,
			(npages * PAGE_SIZE - sizeof(struct kmalloc_header)));
	___kmalloc_insert_chunk(&cpu_local_var(free_list), chunk);

	goto split_and_return;
}

static void ___kfree(void *ptr)
{
	struct kmalloc_header *chunk =
		(struct kmalloc_header*)(ptr - sizeof(struct kmalloc_header));
	unsigned long kmalloc_irq_flags = cpu_disable_interrupt_save();

	/* Sanity check */
	if (chunk->front_magic != 0x5c5c5c5c || chunk->end_magic != 0x6d6d6d6d) {
		kprintf("%s: memory corruption at address 0x%p\n", __FUNCTION__, ptr);
		panic("panic");
	}

	/* Does this chunk belong to this CPU? */
	if (chunk->cpu_id == ihk_mc_get_processor_id()) {

		___kmalloc_insert_chunk(&cpu_local_var(free_list), chunk);
		___kmalloc_consolidate_list(&cpu_local_var(free_list));
	}
	else {
		struct cpu_local_var *v = get_cpu_local_var(chunk->cpu_id);
		unsigned long irqflags;

		irqflags = ihk_mc_spinlock_lock(&v->remote_free_list_lock);
		list_add(&chunk->list, &v->remote_free_list);
		ihk_mc_spinlock_unlock(&v->remote_free_list_lock, irqflags);
	}

	cpu_restore_interrupt(kmalloc_irq_flags);
}


void ___kmalloc_print_free_list(struct list_head *list)
{
	struct kmalloc_header *chunk_iter;
	unsigned long irqflags = kprintf_lock();

	__kprintf("%s: [ \n", __FUNCTION__);
	list_for_each_entry(chunk_iter, &cpu_local_var(free_list), list) {
		__kprintf("%s: 0x%lx:%d (VA PFN: %lu, off: %lu)\n", __FUNCTION__,
			(unsigned long)chunk_iter,
			chunk_iter->size,
			(unsigned long)chunk_iter >> PAGE_SHIFT,
			(unsigned long)chunk_iter % PAGE_SIZE);
	}
	__kprintf("%s: ] \n", __FUNCTION__);
	kprintf_unlock(irqflags);
}

