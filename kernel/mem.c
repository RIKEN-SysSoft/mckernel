#include <kmsg.h>
#include <string.h>
#include <aal/cpu.h>
#include <aal/debug.h>
#include <aal/lock.h>
#include <aal/mm.h>

static unsigned long pa_start, pa_end;
static unsigned long *page_map;
static aal_spinlock_t page_lock;

static void reserve_pages(unsigned long start, unsigned long end, int type)
{
	unsigned long *m;

	if (start < pa_start) {
		start = pa_start;
	}
	if (end > pa_end) {
		end = pa_end;
	}
	if (start >= end) {
		return;
	}

	kprintf("reserved: %lx - %lx ", start, end);

	start = (start - pa_start) >> PAGE_SHIFT;
	end = (end - pa_start + PAGE_SIZE - 1) >> PAGE_SHIFT;

	kprintf(" (%d pages)\n", end - start);

	m = page_map + (start >> 6);
	/* XXX: Also silly */
	for (; start < end; start++) {
		*m |= (1 << (start & 63));
		if ((start & 63) == 63)
			m++;
	}
}

static unsigned long count_available_pages(void)
{
	unsigned long i, j, n = 0;
	unsigned long size = pa_end - pa_start;

	/* XXX: Very silly counting */
	for (i = 0; i < (size >> PAGE_SHIFT) / 64; i++) {
		for (j = 0; j < 64; j++) {
			if (!(page_map[i] & (1UL << j))) {
				n++;
			}
		}
	}
	
	return n;
}

static int is_reserved_page(unsigned long phys)
{
	unsigned long idx;

	if (phys < pa_start || phys >= pa_end) {
		return 1;
	} else {
		idx = (phys - pa_start) >> PAGE_SHIFT;
		return !!(page_map[idx >> 6] & (1UL << (idx & 63)));
	}
}

static unsigned long last_ap_pa;

void *allocate_page(enum aal_mc_ap_flag flag)
{
	unsigned long idx, flags;

	/* XXX: wrap around */
	flags = aal_mc_spinlock_lock(&page_lock);

	while (is_reserved_page(last_ap_pa) && last_ap_pa < pa_end) {
		last_ap_pa += PAGE_SIZE;
	}
	if (last_ap_pa >= pa_end) {
		aal_mc_spinlock_unlock(&page_lock, flags);
		return NULL;
	}
	idx = (last_ap_pa - pa_start) >> PAGE_SHIFT;
	page_map[idx >> 6] |= (1UL << (idx & 63));

	aal_mc_spinlock_unlock(&page_lock, flags);

	return phys_to_virt(last_ap_pa);
}

void free_page(void *va)
{
	unsigned long idx, phys, flags;
	
	phys = virt_to_phys(va);
	if (phys < pa_start || phys >= pa_end) {
		return;
	}
	idx = (phys - pa_start) >> PAGE_SHIFT;

	flags = aal_mc_spinlock_lock(&page_lock);
	page_map[idx >> 6] &= ~(1UL << (idx & 63));
	aal_mc_spinlock_unlock(&page_lock, flags);
}

static struct aal_mc_pa_ops allocator = {
	.alloc = allocate_page,
	.free = free_page,
};

static void page_fault_handler(unsigned long address, void *regs)
{
	kprintf("Page fault for %016lx\n", address);
	/* TODO */
	panic("page fault");
}

void mem_init(void)
{
	unsigned long pages, page_map_pa;
	
	aal_mc_spinlock_init(&page_lock);

	pa_start = aal_mc_get_memory_address(AAL_MC_GMA_AVAIL_START, 0);
	pa_end = aal_mc_get_memory_address(AAL_MC_GMA_AVAIL_END, 0);

	pa_start &= PAGE_MASK;
	pa_end = (pa_end + PAGE_SIZE - 1) & PAGE_MASK;

	pages = (pa_end - pa_start) >> PAGE_SHIFT;

	kprintf("mem_init: %lx - %lx, %d pages\n", pa_start, pa_end, pages);

	page_map_pa = aal_mc_get_memory_address(AAL_MC_GMA_HEAP_START, 0);
	page_map = phys_to_virt(page_map_pa);
	memset(page_map, 0, pages / 8);
	/* TODO: Reserve if 'pages' is not a multiple of 8 */

	kprintf("page_map: %p\n", page_map);
	reserve_pages(page_map_pa, page_map_pa + pages / 8, 0);
	
	aal_mc_reserve_arch_pages(pa_start, pa_end, reserve_pages);

	kprintf("Available pages: %ld pages\n", count_available_pages());
	last_ap_pa = pa_start;

	/* Notify the aal to use my page allocator */
	aal_mc_set_page_allocator(&allocator);

	/* And prepare some exception handlers */
	aal_mc_set_page_fault_handler(page_fault_handler);
}
