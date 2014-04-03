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

//#define DEBUG_PRINT_MEM

#ifdef DEBUG_PRINT_MEM
#define	dkprintf(...)	kprintf(__VA_ARGS__)
#define	ekprintf(...)	kprintf(__VA_ARGS__)
#else
#define dkprintf(...)
#define	ekprintf(...)	kprintf(__VA_ARGS__)
#endif

static struct ihk_page_allocator_desc *pa_allocator;
static unsigned long pa_start, pa_end;
static struct page *pa_pages;

extern int ihk_mc_pt_print_pte(struct page_table *pt, void *virt);

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
		page->count = npages;
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
		ihk_pagealloc_free(pa_allocator, page_to_phys(page), page->count);
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

void set_signal(int sig, void *regs);
void check_signal(unsigned long rc, void *regs);

static void unhandled_page_fault(struct process *proc, void *fault_addr, void *regs)
{
	const uintptr_t address = (uintptr_t)fault_addr;
	struct process_vm *vm = proc->vm;
	struct vm_range *range;
	char found;
	int irqflags;
	unsigned long error = ((struct x86_regs *)regs)->error;

	irqflags = kprintf_lock();
	__kprintf("[%d] Page fault for 0x%lX\n",
			ihk_mc_get_processor_id(), address);
	__kprintf("%s for %s access in %s mode (reserved bit %s set), "
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
			__kprintf("address is in range, flag: 0x%X! \n",
					range->flag);
			ihk_mc_pt_print_pte(vm->page_table, (void*)address);
			break;
		}
	}
	if (!found) {
		__kprintf("address is out of range! \n");
	}

	kprintf_unlock(irqflags);

	/* TODO */
	ihk_mc_debug_show_interrupt_context(regs);

#ifdef DEBUG_PRINT_MEM
	{
		uint64_t *sp = (void *)REGS_GET_STACK_POINTER(regs);

		kprintf("*rsp:%lx,*rsp+8:%lx,*rsp+16:%lx,*rsp+24:%lx,\n",
				sp[0], sp[1], sp[2], sp[3]);
	}
#endif

	return;
}

static void page_fault_handler(void *fault_addr, uint64_t reason, void *regs)
{
	struct process *proc = cpu_local_var(current);
	int error;

	dkprintf("[%d]page_fault_handler(%p,%lx,%p)\n",
			ihk_mc_get_processor_id(), fault_addr, reason, regs);

	error = page_fault_process(proc, fault_addr, reason);
	if (error) {
		kprintf("[%d]page_fault_handler(%p,%lx,%p):"
				"fault proc failed. %d\n",
				ihk_mc_get_processor_id(), fault_addr,
				reason, regs, error);
		unhandled_page_fault(proc, fault_addr, regs);
		if (error == -ERANGE) {
			set_signal(SIGBUS, regs);
		}
		else {
			set_signal(SIGSEGV, regs);
		}
		check_signal(0, regs);
		goto out;
	}

	error = 0;
out:
	dkprintf("[%d]page_fault_handler(%p,%lx,%p): (%d)\n",
			ihk_mc_get_processor_id(), fault_addr, reason,
			regs, error);
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
	if (page->mode != PM_MAPPED) {
		return 1;
	}

	if (--page->count > 0) {
		/* other mapping exist */
		dkprintf("page_unmap(%p %x %d): 0\n",
				page, page->mode, page->count);
		return 0;
	}

	/* no mapping exist */
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

	npages = (pa_end - pa_start) >> PAGE_SHIFT;
	allocsize = sizeof(struct page) * npages;
	allocpages = (allocsize + PAGE_SIZE - 1) >> PAGE_SHIFT;

	pa_pages = allocate_pages(allocpages, IHK_MC_AP_CRITICAL);
	memset(pa_pages, 0, allocsize);
	return;
}

void register_kmalloc(void)
{
	allocator.alloc = kmalloc;
	allocator.free = kfree;
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

void kmalloc_init(void)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	struct malloc_header *h = &v->free_list;

	h->next = &v->free_list;
	h->size = 0;

	register_kmalloc();
}

void *kmalloc(int size, enum ihk_mc_ap_flag flag)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	struct malloc_header *h = &v->free_list, *prev, *p;
	int u, req_page;
	unsigned long flags;


	if (size >= PAGE_SIZE * 4) {
		return NULL;
	}

	u = (size + sizeof(*h) - 1) / sizeof(*h);

	flags = cpu_disable_interrupt_save();

	prev = h;
	h = h->next;

	while (1) {
		if (h == &v->free_list) {
			req_page = ((u + 2) * sizeof(*h) + PAGE_SIZE - 1)
				>> PAGE_SHIFT;

			h = allocate_pages(req_page, flag);
			if(h == NULL)
				return NULL;
			prev->next = h;
			h->size = (req_page * PAGE_SIZE) / sizeof(*h) - 2;
			/* Guard entry */
			p = h + h->size + 1;
			p->next = &v->free_list;
			p->size = 0;
			h->next = p;
		}

		if (h->size >= u) {
			if (h->size == u || h->size == u + 1) {
				prev->next = h->next;

				cpu_restore_interrupt(flags);
				return h + 1;
			} else { /* Divide */
				h->size -= u + 1;
				
				p = h + h->size + 1;
				p->size = u;

				cpu_restore_interrupt(flags);
				return p + 1;
			}
		}
		prev = h;
		h = h->next;
	}
}

void kfree(void *ptr)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	struct malloc_header *h = &v->free_list, *p = ptr;
	int combined = 0;
	unsigned long flags;

	flags = cpu_disable_interrupt_save();
	h = h->next;
	
	p--;

	while ((p < h || p > h->next) && h != &v->free_list) {
		h = h->next;
	}

	if (h + h->size + 1 == p && h->size != 0) {
		combined = 1;
		h->size += p->size + 1;
	}
	if (h->next == p + p->size + 1 && h->next->size != 0) {
		if (combined) {
			h->size += h->next->size + 1;
			h->next = h->next->next;
		} else { 
			p->size += h->next->size + 1;
			p->next = h->next->next;
			h->next = p;
		}
	} else if (!combined) {
		p->next = h->next;
		h->next = p;
	}
	cpu_restore_interrupt(flags);
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
