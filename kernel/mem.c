#include <kmsg.h>
#include <string.h>
#include <aal/cpu.h>
#include <aal/debug.h>
#include <aal/lock.h>
#include <aal/mm.h>
#include <aal/page_alloc.h>

#include <cls.h>

static struct aal_page_allocator_desc *pa_allocator;
static unsigned long pa_start, pa_end;

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
	kprintf("reserve: %016lx - %016lx (%ld pages)\n", start, end,
	        (end - start) >> PAGE_SHIFT);
	aal_pagealloc_reserve(pa_allocator, start, end);
}

void *allocate_pages(int npages, enum aal_mc_ap_flag flag)
{
	return phys_to_virt(aal_pagealloc_alloc(pa_allocator, npages));
}

void free_pages(void *va, int npages)
{
	aal_pagealloc_free(pa_allocator, virt_to_phys(va), npages);
}

static struct aal_mc_pa_ops allocator = {
	.alloc = allocate_pages,
	.free = free_pages,
};

static void page_fault_handler(unsigned long address, void *regs)
{
	kprintf("Page fault for %016lx\n", address);
	/* TODO */
	aal_mc_debug_show_interrupt_context(regs);
	panic("page fault");
}

static void page_allocator_init(void)
{
	unsigned long page_map_pa, pages;
	void *page_map;

	pa_start = aal_mc_get_memory_address(AAL_MC_GMA_AVAIL_START, 0);
	pa_end = aal_mc_get_memory_address(AAL_MC_GMA_AVAIL_END, 0);

	pa_start &= PAGE_MASK;
	pa_end = (pa_end + PAGE_SIZE - 1) & PAGE_MASK;

	page_map_pa = aal_mc_get_memory_address(AAL_MC_GMA_HEAP_START, 0);
	page_map = phys_to_virt(page_map_pa);

	pa_allocator = __aal_pagealloc_init(pa_start, pa_end - pa_start,
	                                    PAGE_SIZE, page_map, &pages);

	reserve_pages(page_map_pa, page_map_pa + pages * PAGE_SIZE, 0);
	
	aal_mc_reserve_arch_pages(pa_start, pa_end, reserve_pages);

	kprintf("Available pages: %ld pages\n",
	        aal_pagealloc_count(pa_allocator));

	/* Notify the aal to use my page allocator */
	aal_mc_set_page_allocator(&allocator);

	/* And prepare some exception handlers */
	aal_mc_set_page_fault_handler(page_fault_handler);
}

static struct aal_page_allocator_desc *vmap_allocator;

static void virtual_allocator_init(void)
{
	vmap_allocator = aal_pagealloc_init(MAP_VMAP_START,
	                                    MAP_VMAP_SIZE, PAGE_SIZE);
}

void *aal_mc_map_virtual(unsigned long phys, int npages,
                         enum aal_mc_pt_attribute attr)
{
	void *p;
	unsigned long i;

	p = (void *)aal_pagealloc_alloc(vmap_allocator, npages);
	if (!p) {
		return NULL;
	}
	for (i = 0; i < npages; i++) {
		aal_mc_pt_set_page(NULL, (char *)p + (i << PAGE_SHIFT),
		                   phys + (i << PAGE_SHIFT), attr);
	}
	return p;
}

void aal_mc_unmap_virtual(void *va, int npages)
{
	unsigned long i;

	for (i = 0; i < npages; i++) {
		aal_mc_pt_clear_page(NULL, (char *)va + (i << PAGE_SHIFT));
	}
	aal_pagealloc_free(vmap_allocator, virt_to_phys(va), npages);
}

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
}

void *kmalloc(int size, int flag)
{
	struct cpu_local_var *v = get_this_cpu_local_var();
	struct malloc_header *h = &v->free_list, *prev, *p;
	int u, req_page;

	if (size >= PAGE_SIZE * 4) {
		return NULL;
	}

	u = (size + sizeof(*h) - 1) / sizeof(*h);

	prev = h;
	h = h->next;

	while (1) {
		if (h == &v->free_list) {
			req_page = ((u + 1) * sizeof(*h) + PAGE_SIZE - 1)
				>> PAGE_SHIFT;

			h = allocate_pages(req_page, 0);
			prev->next = h;
			h->size = (req_page * PAGE_SIZE) / sizeof(*h) - 2;
			/* Guard entry */
			p = h + h->size + 1;
			p->next = &v->free_list;
			h->next = p;
		}

		if (h->size >= u) {
			if (h->size == u || h->size == u + 1) {
				prev->next = h->next;
				return h + 1;
			} else { /* Divide */
				h->size -= u + 1;
				
				p = h + h->size + 1;
				p->size = u;

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
		combined = 1;
		h->size += h->next->size + 1;
		h->next = h->next->next;
	}
	if (!combined) {
		p->next = h->next;
		h->next = p;
	}
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
