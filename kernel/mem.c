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

//#define DEBUG_PRINT_MEM

#ifdef DEBUG_PRINT_MEM
#define dkprintf kprintf
#else
#define dkprintf(...)
#endif

static struct ihk_page_allocator_desc *pa_allocator;
static unsigned long pa_start, pa_end;

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
	ihk_pagealloc_free(pa_allocator, virt_to_phys(va), npages);
}

static struct ihk_mc_pa_ops allocator = {
	.alloc_page = allocate_aligned_pages,
	.free_page = free_pages,
};

void sbox_write(int offset, unsigned int value);

static void query_free_mem_interrupt_handler(void *priv)
{
	dkprintf("query free mem handler!\n");

	int pages = ihk_pagealloc_query_free(pa_allocator);
	
	dkprintf("free pages: %d\n", pages);

	sbox_write(SBOX_SCRATCH0, pages);
	sbox_write(SBOX_SCRATCH1, 1);
}

static struct ihk_mc_interrupt_handler query_free_mem_handler = {
	.func = query_free_mem_interrupt_handler,
	.priv = NULL,
};



static void page_fault_handler(unsigned long address, void *regs, 
                               unsigned long rbp)
{
	struct vm_range *range, *next;
	char found = 0;
	int irqflags;
	unsigned long error = ((struct x86_regs *)regs)->error;

	irqflags = kprintf_lock();
	__kprintf("[%d] Page fault for 0x%lX, (rbp: 0x%lX)\n", 
	          ihk_mc_get_processor_id(), address, rbp); 

	__kprintf("%s for %s access in %s mode (reserved bit %s set), it %s an instruction fetch\n", 
	          (error & PF_PROT ? "protection fault" : "no page found"),
			  (error & PF_WRITE ? "write" : "read"),
			  (error & PF_USER ? "user" : "kernel"),
			  (error & PF_RSVD ? "was" : "wasn't"),
			  (error & PF_INSTR ? "was" : "wasn't"));

	list_for_each_entry_safe(range, next, 
	                         &cpu_local_var(current)->vm->vm_range_list, 
							 list) {
		
		if (range->start <= address && range->end > address) {
			__kprintf("address is in range, flag: 0x%X! \n", range->flag);
			if(range->flag & VR_DEMAND_PAGING){
			  //allocate page for demand paging
			  __kprintf("demand paging\n");
			  void* pa = allocate_pages(1, IHK_MC_AP_CRITICAL);
			  if(!pa){
			    kprintf_unlock(irqflags);
			    panic("allocate_pages failed");
			  }
			  __kprintf("physical memory area obtained %lx\n", virt_to_phys(pa));

              {
                  enum ihk_mc_pt_attribute flag = 0;
                  struct process *process = cpu_local_var(current);
                  unsigned long flags = ihk_mc_spinlock_lock(&process->vm->page_table_lock);
                  const enum ihk_mc_pt_attribute attr = flag | PTATTR_WRITABLE | PTATTR_USER | PTATTR_FOR_USER;

                  int rc = ihk_mc_pt_set_page(process->vm->page_table, (void*)(address & PAGE_MASK), virt_to_phys(pa), attr);
                  if(rc != 0) {
                      ihk_mc_spinlock_unlock(&process->vm->page_table_lock, flags);
                      __kprintf("ihk_mc_pt_set_page failed,rc=%d,%p,%lx,%08x\n", rc, (void*)(address & PAGE_MASK), virt_to_phys(pa), attr);
                      ihk_mc_pt_print_pte(process->vm->page_table, (void*)address);
                      goto fn_fail;
                  }
                  ihk_mc_spinlock_unlock(&process->vm->page_table_lock, flags);
                  __kprintf("update_process_page_table success\n");
              }
			  kprintf_unlock(irqflags);
              memset(pa, 0, PAGE_SIZE);
			  return;
			}
			found = 1;
			ihk_mc_pt_print_pte(cpu_local_var(current)->vm->page_table, 
			                    (void*)address);
			break;
		}
	}
	
	if (!found)
		__kprintf("address is out of range! \n");

 fn_fail:
	kprintf_unlock(irqflags);

	/* TODO */
	ihk_mc_debug_show_interrupt_context(regs);

#ifdef DEBUG_PRINT_MEM
	{
	  const struct x86_regs *_regs = regs;
	  dkprintf("*rsp:%lx,*rsp+8:%lx,*rsp+16:%lx,*rsp+24:%lx,\n",
		  *((unsigned long*)_regs->rsp),
		  *((unsigned long*)_regs->rsp+8),
		  *((unsigned long*)_regs->rsp+16),
		  *((unsigned long*)_regs->rsp+24)
		  );
	}
#endif

	panic("");
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
