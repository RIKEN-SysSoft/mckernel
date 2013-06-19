#include <ihk/cpu.h>
#include <ihk/debug.h>
#include <ihk/mm.h>
#include <types.h>
#include <memory.h>
#include <string.h>
#include <errno.h>
#include <list.h>

static char *last_page;
extern char _head[], _end[];

static struct ihk_mc_pa_ops *pa_ops;

extern unsigned long x86_kernel_phys_base;

void *early_alloc_page(void)
{
	void *p;

	if (!last_page) {
		last_page = (char *)(((unsigned long)_end + PAGE_SIZE - 1)
		                     & PAGE_MASK);
		/* Convert the virtual address from text's to straight maps */
		last_page = phys_to_virt(virt_to_phys(last_page));
	} else if (last_page == (void *)-1) {
		panic("Early allocator is already finalized. Do not use it.\n");
	}
	p = last_page;
	last_page += PAGE_SIZE;

	return p;
}

void *arch_alloc_page(enum ihk_mc_ap_flag flag)
{
	if (pa_ops)
		return pa_ops->alloc_page(1, flag);
	else
		return early_alloc_page();
}
void arch_free_page(void *ptr)
{
	if (pa_ops)
		pa_ops->free_page(ptr, 1);
}

void *ihk_mc_alloc_pages(int npages, enum ihk_mc_ap_flag flag)
{
	if (pa_ops)
		return pa_ops->alloc_page(npages, flag);
	else
		return NULL;
}

void ihk_mc_free_pages(void *p, int npages)
{
	if (pa_ops)
		pa_ops->free_page(p, npages);
}

void *ihk_mc_allocate(int size, enum ihk_mc_ap_flag flag)
{
	if (pa_ops && pa_ops->alloc)
		return pa_ops->alloc(size, flag);
	else
		return ihk_mc_alloc_pages(1, flag);
}

void ihk_mc_free(void *p)
{
	if (pa_ops && pa_ops->free)
		return pa_ops->free(p);
	else
		return ihk_mc_free_pages(p, 1);
}

void *get_last_early_heap(void)
{
	return last_page;
}

void flush_tlb(void)
{
	unsigned long cr3;

	asm volatile("movq %%cr3, %0; movq %0, %%cr3" : "=r"(cr3) : : "memory");
}

void flush_tlb_single(unsigned long addr)
{
   asm volatile("invlpg (%0)" :: "r" (addr) : "memory");
}

struct page_table {
	pte_t entry[PT_ENTRIES];
};

static struct page_table *init_pt;

static unsigned long setup_l2(struct page_table *pt,
                              unsigned long page_head, unsigned long start,
                              unsigned long end)
{
	int i;
	unsigned long phys;

	for (i = 0; i < PT_ENTRIES; i++) {
		phys = page_head + ((unsigned long)i << PTL2_SHIFT);

		if (phys + PTL2_SIZE <= start || phys >= end) {
			pt->entry[i] = 0;
			continue;
		}

		pt->entry[i] = phys | PFL2_KERN_ATTR | PFL2_SIZE;
	}

	return virt_to_phys(pt);
}

static unsigned long setup_l3(struct page_table *pt,
                              unsigned long page_head, unsigned long start,
                              unsigned long end)
{
	int i;
	unsigned long phys, pt_phys;

	for (i = 0; i < PT_ENTRIES; i++) {
		phys = page_head + ((unsigned long)i << PTL3_SHIFT);

		if (phys + PTL3_SIZE <= start || phys >= end) {
			pt->entry[i] = 0;
			continue;
		}
		pt_phys = setup_l2(arch_alloc_page(IHK_MC_AP_CRITICAL), phys, start, end);

		pt->entry[i] = pt_phys | PFL3_PDIR_ATTR;
	}

	return virt_to_phys(pt);
}

static void init_normal_area(struct page_table *pt)
{
	unsigned long map_start, map_end, phys, pt_phys;
	int ident_index, virt_index;

	map_start = ihk_mc_get_memory_address(IHK_MC_GMA_MAP_START, 0);
	map_end = ihk_mc_get_memory_address(IHK_MC_GMA_MAP_END, 0);

	kprintf("map_start = %lx, map_end = %lx\n", map_start, map_end);
	ident_index = map_start >> PTL4_SHIFT;
	virt_index = (MAP_ST_START >> PTL4_SHIFT) & (PT_ENTRIES - 1);

	memset(pt, 0, sizeof(struct page_table));

	for (phys = (map_start & ~(PTL4_SIZE - 1)); phys < map_end;
	     phys += PTL4_SIZE) {
		pt_phys = setup_l3(arch_alloc_page(IHK_MC_AP_CRITICAL), phys,
		                   map_start, map_end);

		pt->entry[ident_index++] = pt_phys | PFL4_PDIR_ATTR;
		pt->entry[virt_index++] = pt_phys | PFL4_PDIR_ATTR;
	}
}

static struct page_table *__alloc_new_pt(enum ihk_mc_ap_flag ap_flag)
{
	struct page_table *newpt = arch_alloc_page(ap_flag);

	if(newpt)
		memset(newpt, 0, sizeof(struct page_table));

	return newpt;
}

/*
 * XXX: Confusingly, L4 and L3 automatically add PRESENT,
 *      but L2 and L1 do not!
 */

#define ATTR_MASK (PTATTR_WRITABLE | PTATTR_USER | PTATTR_ACTIVE)
#if 0
static unsigned long attr_to_l4attr(enum ihk_mc_pt_attribute attr)
{
	return (attr & ATTR_MASK) | PFL4_PRESENT;
}
static unsigned long attr_to_l3attr(enum ihk_mc_pt_attribute attr)
{
	return (attr & ATTR_MASK) | PFL3_PRESENT;
}
#endif
static unsigned long attr_to_l2attr(enum ihk_mc_pt_attribute attr)
{
	unsigned long r = (attr & (ATTR_MASK | PTATTR_LARGEPAGE));

	if ((attr & PTATTR_UNCACHABLE) && (attr & PTATTR_LARGEPAGE)) {
		return r | PFL2_PCD | PFL2_PWT; 
	}
	return r;
}
static unsigned long attr_to_l1attr(enum ihk_mc_pt_attribute attr)
{
	if (attr & PTATTR_UNCACHABLE) {
		return (attr & ATTR_MASK) | PFL1_PCD | PFL1_PWT;
	} else { 
		return (attr & ATTR_MASK);
	}
}

#define GET_VIRT_INDICES(virt, l4i, l3i, l2i, l1i) \
	l4i = ((virt) >> PTL4_SHIFT) & (PT_ENTRIES - 1); \
	l3i = ((virt) >> PTL3_SHIFT) & (PT_ENTRIES - 1); \
	l2i = ((virt) >> PTL2_SHIFT) & (PT_ENTRIES - 1); \
	l1i = ((virt) >> PTL1_SHIFT) & (PT_ENTRIES - 1)

#define	GET_INDICES_VIRT(l4i, l3i, l2i, l1i)		\
		( ((uint64_t)(l4i) << PTL4_SHIFT)	\
		| ((uint64_t)(l3i) << PTL3_SHIFT)	\
		| ((uint64_t)(l2i) << PTL2_SHIFT)	\
		| ((uint64_t)(l1i) << PTL1_SHIFT)	\
		)

void set_pte(pte_t *ppte, unsigned long phys, int attr)
{
	if (attr & PTATTR_LARGEPAGE) {
		*ppte = phys | attr_to_l2attr(attr) | PFL2_SIZE;
	}
	else {
		*ppte = phys | attr_to_l1attr(attr);
	}
}


#if 0
/* 
 * get_pte() 
 *
 * Descripton: walks the page tables (creates tables if not existing)
 *             and returns a pointer to the PTE corresponding to the
 *             virtual address.
 */
pte_t *get_pte(struct page_table *pt, void *virt, int attr, enum ihk_mc_ap_flag ap_flag)
{
	int l4idx, l3idx, l2idx, l1idx;
	unsigned long v = (unsigned long)virt;
	struct page_table *newpt;

	if (!pt) {
		pt = init_pt;
	}

	GET_VIRT_INDICES(v, l4idx, l3idx, l2idx, l1idx);

    /* TODO: more detailed attribute check */
	if (pt->entry[l4idx] & PFL4_PRESENT) {
		pt = phys_to_virt(pt->entry[l4idx] & PAGE_MASK);
	} else {
		if((newpt = __alloc_new_pt(ap_flag)) == NULL)
			return NULL;
		pt->entry[l4idx] = virt_to_phys(newpt) | attr_to_l4attr(attr);
		pt = newpt;
	}

	if (pt->entry[l3idx] & PFL3_PRESENT) {
		pt = phys_to_virt(pt->entry[l3idx] & PAGE_MASK);
	} else {
		if((newpt = __alloc_new_pt(ap_flag)) == NULL)
			return NULL;
		pt->entry[l3idx] = virt_to_phys(newpt) | attr_to_l3attr(attr);
		pt = newpt;
	}

	/* PTATTR_LARGEPAGE */
	if (attr & PTATTR_LARGEPAGE) {
		return &(pt->entry[l2idx]);
	}

	/* Requested regular page, but large is allocated? */
	if (pt->entry[l2idx] & PFL2_SIZE) {
		return NULL;
	}

	if (pt->entry[l2idx] & PFL2_PRESENT) {
		pt = phys_to_virt(pt->entry[l2idx] & PAGE_MASK);
	} else {
		if((newpt = __alloc_new_pt(ap_flag)) == NULL)
			return NULL;
		pt->entry[l2idx] = virt_to_phys(newpt) | attr_to_l2attr(attr)
			| PFL2_PRESENT;
		pt = newpt;
	}

	return &(pt->entry[l1idx]);
}
#endif

static int __set_pt_page(struct page_table *pt, void *virt, unsigned long phys,
                         int attr)
{
	int l4idx, l3idx, l2idx, l1idx;
	unsigned long v = (unsigned long)virt;
	struct page_table *newpt;
	enum ihk_mc_ap_flag ap_flag;

	ap_flag = (attr & PTATTR_FOR_USER) ?
	                IHK_MC_AP_NOWAIT: IHK_MC_AP_CRITICAL;

	if (!pt) {
		pt = init_pt;
	}
	if (attr & PTATTR_LARGEPAGE) {
		phys &= LARGE_PAGE_MASK;
	} else {
		phys &= PAGE_MASK;
	}

	GET_VIRT_INDICES(v, l4idx, l3idx, l2idx, l1idx);

	/* TODO: more detailed attribute check */
	if (pt->entry[l4idx] & PFL4_PRESENT) {
		pt = phys_to_virt(pt->entry[l4idx] & PAGE_MASK);
	} else {
		if((newpt = __alloc_new_pt(ap_flag)) == NULL)
			return -ENOMEM;
		pt->entry[l4idx] = virt_to_phys(newpt) | PFL4_PDIR_ATTR;
		pt = newpt;
	}

	if (pt->entry[l3idx] & PFL3_PRESENT) {
		pt = phys_to_virt(pt->entry[l3idx] & PAGE_MASK);
	} else {
		if((newpt = __alloc_new_pt(ap_flag)) == NULL)
			return -ENOMEM;
		pt->entry[l3idx] = virt_to_phys(newpt) | PFL3_PDIR_ATTR;
		pt = newpt;
	}

	if (attr & PTATTR_LARGEPAGE) {
		if (pt->entry[l2idx] & PFL2_PRESENT) {
			if ((pt->entry[l2idx] & PAGE_MASK) != phys) {
				return -EBUSY;
			} else {
				return 0;
			}
		} else {
			pt->entry[l2idx] = phys | attr_to_l2attr(attr)
				| PFL2_SIZE;
			return 0;
		}
	}

	if (pt->entry[l2idx] & PFL2_PRESENT) {
		pt = phys_to_virt(pt->entry[l2idx] & PAGE_MASK);
	} else {
		if((newpt = __alloc_new_pt(ap_flag)) == NULL)
			return -ENOMEM;
		pt->entry[l2idx] = virt_to_phys(newpt) | PFL2_PDIR_ATTR;
		pt = newpt;
	}

	if (pt->entry[l1idx] & PFL1_PRESENT) {
		if ((pt->entry[l1idx] & PAGE_MASK) != phys) {
			return -EBUSY;
		} else {
			return 0;
		}
	}
	pt->entry[l1idx] = phys | attr_to_l1attr(attr);
	return 0;
}

static int __clear_pt_page(struct page_table *pt, void *virt, int largepage)
{
	int l4idx, l3idx, l2idx, l1idx;
	unsigned long v = (unsigned long)virt;

	if (!pt) {
		pt = init_pt;
	}
	if (largepage) {
		v &= LARGE_PAGE_MASK;
	} else {
		v &= PAGE_MASK;
	}

	GET_VIRT_INDICES(v, l4idx, l3idx, l2idx, l1idx);

	if (!(pt->entry[l4idx] & PFL4_PRESENT)) {
		return -EINVAL;
	}
	pt = phys_to_virt(pt->entry[l4idx] & PAGE_MASK);

	if (!(pt->entry[l3idx] & PFL3_PRESENT)) {
		return -EINVAL;
	}
	pt = phys_to_virt(pt->entry[l3idx] & PAGE_MASK);

	if (largepage) {
		if (!(pt->entry[l2idx] & PFL2_PRESENT)) {
			return -EINVAL;
		} else {
			pt->entry[l2idx] = 0;
			return 0;
		}
	}
	
	if (!(pt->entry[l2idx] & PFL2_PRESENT)) {
		return -EINVAL;
	}

	pt = phys_to_virt(pt->entry[l2idx] & PAGE_MASK);

	pt->entry[l1idx] = 0;

	return 0;
}

int ihk_mc_pt_virt_to_phys(struct page_table *pt,
                           void *virt, unsigned long *phys)
{
	int l4idx, l3idx, l2idx, l1idx;
	unsigned long v = (unsigned long)virt;

	if (!pt) {
		pt = init_pt;
	}

	GET_VIRT_INDICES(v, l4idx, l3idx, l2idx, l1idx);

	if (!(pt->entry[l4idx] & PFL4_PRESENT)) {
		return -EFAULT;
	}
	pt = phys_to_virt(pt->entry[l4idx] & PAGE_MASK);

	if (!(pt->entry[l3idx] & PFL3_PRESENT)) {
		return -EFAULT;
	}
	pt = phys_to_virt(pt->entry[l3idx] & PAGE_MASK);

	if (!(pt->entry[l2idx] & PFL2_PRESENT)) {
		return -EFAULT;
	}
	if ((pt->entry[l2idx] & PFL2_SIZE)) {
		*phys = (pt->entry[l2idx] & LARGE_PAGE_MASK) | 
			(v & (LARGE_PAGE_SIZE - 1));
		return 0;
	}
	pt = phys_to_virt(pt->entry[l2idx] & PAGE_MASK);

	if (!(pt->entry[l1idx] & PFL1_PRESENT)) {
		return -EFAULT;
	}

	*phys = (pt->entry[l1idx] & PAGE_MASK) | (v & (PAGE_SIZE - 1));
	return 0;
}

int ihk_mc_pt_print_pte(struct page_table *pt, void *virt)
{
	int l4idx, l3idx, l2idx, l1idx;
	unsigned long v = (unsigned long)virt;

	if (!pt) {
		pt = init_pt;
	}

	GET_VIRT_INDICES(v, l4idx, l3idx, l2idx, l1idx);

	if (!(pt->entry[l4idx] & PFL4_PRESENT)) {
		__kprintf("0x%lX l4idx not present! \n", (unsigned long)virt);
		return -EFAULT;
	}
	pt = phys_to_virt(pt->entry[l4idx] & PAGE_MASK);

	__kprintf("l3 table: 0x%lX l3idx: %d \n", virt_to_phys(pt), l3idx);
	if (!(pt->entry[l3idx] & PFL3_PRESENT)) {
		__kprintf("0x%lX l3idx not present! \n", (unsigned long)virt);
		return -EFAULT;
	}
	pt = phys_to_virt(pt->entry[l3idx] & PAGE_MASK);
	
	__kprintf("l2 table: 0x%lX l2idx: %d \n", virt_to_phys(pt), l2idx);
	if (!(pt->entry[l2idx] & PFL2_PRESENT)) {
		__kprintf("0x%lX l2idx not present! \n", (unsigned long)virt);
		return -EFAULT;
	}
	if ((pt->entry[l2idx] & PFL2_SIZE)) {
		return 0;
	}
	pt = phys_to_virt(pt->entry[l2idx] & PAGE_MASK);

	__kprintf("l1 table: 0x%lX l1idx: %d \n", virt_to_phys(pt), l1idx);
	if (!(pt->entry[l1idx] & PFL1_PRESENT)) {
		__kprintf("0x%lX PTE (l1) not present! entry: 0x%lX\n", 
		          (unsigned long)virt, pt->entry[l1idx]);
		return -EFAULT;
	}

	return 0;
}

int set_pt_large_page(struct page_table *pt, void *virt, unsigned long phys,
                      enum ihk_mc_pt_attribute attr)
{
	return __set_pt_page(pt, virt, phys, attr | PTATTR_LARGEPAGE
	                     | PTATTR_ACTIVE);
}

int ihk_mc_pt_set_large_page(page_table_t pt, void *virt,
                       unsigned long phys, enum ihk_mc_pt_attribute attr)
{
	return __set_pt_page(pt, virt, phys, attr | PTATTR_LARGEPAGE
	                     | PTATTR_ACTIVE);
}

int ihk_mc_pt_set_page(page_table_t pt, void *virt,
                       unsigned long phys, enum ihk_mc_pt_attribute attr)
{
	return __set_pt_page(pt, virt, phys, attr | PTATTR_ACTIVE);
}

int ihk_mc_pt_prepare_map(page_table_t p, void *virt, unsigned long size,
                          enum ihk_mc_pt_prepare_flag flag)
{
	int l4idx, l4e, ret = 0;
	unsigned long v = (unsigned long)virt;
	struct page_table *pt = p, *newpt;
	unsigned long l;
	enum ihk_mc_pt_attribute attr = PTATTR_WRITABLE;

	if (!pt) {
		pt = init_pt;
	}

	l4idx = ((v) >> PTL4_SHIFT) & (PT_ENTRIES - 1);

	if (flag == IHK_MC_PT_FIRST_LEVEL) {
		l4e = ((v + size) >> PTL4_SHIFT)  & (PT_ENTRIES - 1);

		for (; l4idx <= l4e; l4idx++) {
			if (pt->entry[l4idx] & PFL4_PRESENT) {
				return 0;
			} else {
				newpt = __alloc_new_pt(IHK_MC_AP_CRITICAL);
				if (!newpt) {
					ret = -ENOMEM;
				} else { 
					pt->entry[l4idx] = virt_to_phys(newpt)
						| PFL4_PDIR_ATTR;
				}
			}
		}
	} else {
		/* Call without ACTIVE flag */
		l = v + size;
		for (; v < l; v += PAGE_SIZE) {
			if ((ret = __set_pt_page(pt, (void *)v, 0, attr))) {
				break;
			}
		}
	}
	return ret;
}

struct page_table *ihk_mc_pt_create(enum ihk_mc_ap_flag ap_flag)
{
	struct page_table *pt = ihk_mc_alloc_pages(1, ap_flag);

	if(pt == NULL)
		return NULL;

	memset(pt->entry, 0, PAGE_SIZE);
	/* Copy the kernel space */
	memcpy(pt->entry + PT_ENTRIES / 2, init_pt->entry + PT_ENTRIES / 2,
	       sizeof(pt->entry[0]) * PT_ENTRIES / 2);

	return pt;
}

static void destroy_page_table(int level, struct page_table *pt)
{
	int ix;
	unsigned long entry;
	struct page_table *lower;

	if ((level < 1) || (4 < level)) {
		panic("destroy_page_table: level is out of range");
	}
	if (pt == NULL) {
		panic("destroy_page_table: pt is NULL");
	}

	if (level > 1) {
		for (ix = 0; ix < PT_ENTRIES; ++ix) {
			entry = pt->entry[ix];
			if (!(entry & PF_PRESENT)) {
				/* entry is not valid */
				continue;
			}
			if (entry & PF_SIZE) {
				/* not a page table */
				continue;
			}
			lower = (struct page_table *)phys_to_virt(entry & PT_PHYSMASK);
			destroy_page_table(level-1, lower);
		}
	}

	arch_free_page(pt);
	return;
}

void ihk_mc_pt_destroy(struct page_table *pt)
{
	const int level = 4;	/* PML4 */

	/* clear shared entry */
	memset(pt->entry + PT_ENTRIES / 2, 0, sizeof(pt->entry[0]) * PT_ENTRIES / 2);

	destroy_page_table(level, pt);
	return;
}

int ihk_mc_pt_clear_page(page_table_t pt, void *virt)
{
	return __clear_pt_page(pt, virt, 0);
}

int ihk_mc_pt_clear_large_page(page_table_t pt, void *virt)
{
	return __clear_pt_page(pt, virt, 1);
}

static int clear_range_l1(struct page_table *pt, uint64_t base, uint64_t start, uint64_t end)
{
	int six;
	int eix;
	int ret;
	int i;

	six = (start <= base)? 0: (start - base) >> PTL1_SHIFT;
	eix = ((base + PTL2_SIZE) <= end)? PT_ENTRIES
		: ((end - base) + (PTL1_SIZE - 1)) >> PTL1_SHIFT;

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		if (!(pt->entry[i] & PFL1_PRESENT)) {
			continue;
		}

		pt->entry[i] = 0;
		ret = 0;
	}

	return ret;
}

static int clear_range_l2(struct page_table *pt, uint64_t base, uint64_t start, uint64_t end)
{
	int six;
	int eix;
	int ret;
	int i;
	uint64_t off;
	struct page_table *q;
	int error;

	six = (start <= base)? 0: (start - base) >> PTL2_SHIFT;
	eix = ((base + PTL3_SIZE) <= end)? PT_ENTRIES
		: ((end - base) + (PTL2_SIZE - 1)) >> PTL2_SHIFT;

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		if (!(pt->entry[i] & PFL2_PRESENT)) {
			continue;
		}

		off = i * PTL2_SIZE;

		if (pt->entry[i] & PFL2_SIZE) {
			if (((base + off) < start) || (end < (base + off + PTL2_SIZE))) {
				kprintf("clear_range_l2(%p,%lx,%lx,%lx):"
						"not a 2MiB page boundary\n",
						pt, base, start, end);
				ret = -ERANGE;
				break;
			}

			pt->entry[i] = 0;
			ret = 0;
			continue;
		}

		q = phys_to_virt(pt->entry[i] & PT_PHYSMASK);

		if ((start <= (base + off)) && ((base + off + PTL2_SIZE) <= end)) {
			pt->entry[i] = 0;
			ret = 0;
			arch_free_page(q);
		}
		else {
			error = clear_range_l1(q, base+off, start, end);
			if (!error) {
				ret = 0;
			}
			else if (error != -ENOENT) {
				ret = error;
				break;
			}
		}
	}

	return ret;
}

static int clear_range_l3(struct page_table *pt, uint64_t base, uint64_t start, uint64_t end)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	struct page_table *q;

	six = (start <= base)? 0: (start - base) >> PTL3_SHIFT;
	eix = ((base + PTL4_SIZE) <= end)? PT_ENTRIES
		: ((end - base) + (PTL3_SIZE - 1)) >> PTL3_SHIFT;

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		if (!(pt->entry[i] & PFL3_PRESENT)) {
			continue;
		}

		q = phys_to_virt(pt->entry[i] & PT_PHYSMASK);
		error = clear_range_l2(q, base+(i*PTL3_SIZE), start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

static int clear_range_l4(struct page_table *pt, uint64_t base, uint64_t start, uint64_t end)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	struct page_table *q;

	six = (start <= base)? 0: (start - base) >> PTL4_SHIFT;
	eix = ((end - base) + (PTL4_SIZE - 1)) >> PTL4_SHIFT;
	if ((eix <= 0) || (PT_ENTRIES < eix)) {
		eix = PT_ENTRIES;
	}

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		if (!(pt->entry[i] & PFL4_PRESENT)) {
			continue;
		}

		q = phys_to_virt(pt->entry[i] & PT_PHYSMASK);
		error = clear_range_l3(q, base+(i*PTL4_SIZE), start, end);
		if (!error) {
			ret = 0;
		}
		else if (error != -ENOENT) {
			ret = error;
			break;
		}
	}

	return ret;
}

static int lookup_pte(struct page_table *pt, void *virt, pte_t **ptep, void **pgbasep, uint64_t *pgsizep)
{
	int l4idx, l3idx, l2idx, l1idx;

	GET_VIRT_INDICES((uint64_t)virt, l4idx, l3idx, l2idx, l1idx);

	if (!(pt->entry[l4idx] & PFL4_PRESENT)) {
		return -ENOENT;
	}

	pt = phys_to_virt(pt->entry[l4idx] & PT_PHYSMASK);
	if (!(pt->entry[l3idx] & PFL3_PRESENT)) {
		return -ENOENT;
	}

	pt = phys_to_virt(pt->entry[l3idx] & PT_PHYSMASK);
	if (!(pt->entry[l2idx] & PFL2_PRESENT) || (pt->entry[l2idx] & PFL2_SIZE)) {
		*ptep = &pt->entry[l2idx];
		*pgbasep = (void *)GET_INDICES_VIRT(l4idx, l3idx, l2idx, 0);
		*pgsizep = PTL2_SIZE;
		return 0;
	}

	pt = phys_to_virt(pt->entry[l2idx] & PT_PHYSMASK);
	*ptep = &pt->entry[l1idx];
	*pgbasep = (void *)GET_INDICES_VIRT(l4idx, l3idx, l2idx, l1idx);
	*pgsizep = PTL1_SIZE;

	return 0;
}

static int is_middle_of_the_page(struct page_table *pt, void *virt)
{
	int error;
	pte_t *pte;
	void *pgbase;
	uint64_t pgsize;

	error = lookup_pte(pt, virt, &pte, &pgbase, &pgsize);
	if (error) {
		return 0;
	}

	if (!(*pte & PF_PRESENT)) {
		return 0;
	}

	return pgbase != virt;
}

int ihk_mc_pt_clear_range(page_table_t pt, void *start0, void *end0)
{
	const uint64_t start = (uint64_t)start0;
	const uint64_t end = (uint64_t)end0;
	int error;

	if ((USER_END <= start) || (USER_END < end) || (end <= start)) {
		kprintf("ihk_mc_pt_clear_range(%p,%p,%p):invalid start and/or end.\n",
				pt, start0, end0);
		return -EINVAL;
	}

	if (((start % LARGE_PAGE_SIZE) != 0) && is_middle_of_the_page(pt, start0)) {
		kprintf("ihk_mc_pt_clear_range(%p,%p,%p):start0 is not a page boundary\n",
				pt, start0, end0);
		return -EINVAL;
	}

	if (((end % LARGE_PAGE_SIZE) != 0) && is_middle_of_the_page(pt, end0)) {
		kprintf("ihk_mc_pt_clear_range(%p,%p,%p):end0 is not a page boundary\n",
				pt, start0, end0);
		return -EINVAL;
	}

	error = clear_range_l4(pt, 0, start, end);
	return error;
}

void load_page_table(struct page_table *pt)
{
	unsigned long pt_addr;

	if (!pt) {
		pt = init_pt;
	}

	pt_addr = virt_to_phys(pt);

	asm volatile ("movq %0, %%cr3" : : "r"(pt_addr) : "memory");
}

void ihk_mc_load_page_table(struct page_table *pt)
{
	load_page_table(pt);
}

struct page_table *get_init_page_table(void)
{
	return init_pt;
}

static unsigned long fixed_virt;
static void init_fixed_area(struct page_table *pt)
{
	fixed_virt = MAP_FIXED_START;

	return;
}

void init_text_area(struct page_table *pt)
{
	unsigned long __end, phys, virt;
	int i, nlpages;

	__end = ((unsigned long)_end + LARGE_PAGE_SIZE * 2 - 1)
		& LARGE_PAGE_MASK;
	nlpages = (__end - MAP_KERNEL_START) >> LARGE_PAGE_SHIFT;

	kprintf("TEXT: # of large pages = %d\n", nlpages);
	kprintf("TEXT: Base address = %lx\n", x86_kernel_phys_base);

	phys = x86_kernel_phys_base;
	virt = MAP_KERNEL_START;
	for (i = 0; i < nlpages; i++) {
		set_pt_large_page(pt, (void *)virt, phys, PTATTR_WRITABLE);

		virt += LARGE_PAGE_SIZE;
		phys += LARGE_PAGE_SIZE;
	}
}

void *map_fixed_area(unsigned long phys, unsigned long size, int uncachable)
{
	unsigned long poffset, paligned;
	int i, npages;
	int flag = PTATTR_WRITABLE | PTATTR_ACTIVE;
	void *v = (void *)fixed_virt;

	poffset = phys & (PAGE_SIZE - 1);
	paligned = phys & PAGE_MASK;
	npages = (poffset + size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	if (uncachable) {
		flag |= PTATTR_UNCACHABLE;
	}

	kprintf("map_fixed: %lx => %p (%d pages)\n", paligned, v, npages);

	for (i = 0; i < npages; i++) {
		if(__set_pt_page(init_pt, (void *)fixed_virt, paligned, flag)){
			return NULL;
		}

		fixed_virt += PAGE_SIZE;
		paligned += PAGE_SIZE;
	}
	
	flush_tlb();

	return (char *)v + poffset;
}

void init_low_area(struct page_table *pt)
{
	set_pt_large_page(pt, 0, 0, PTATTR_WRITABLE);
}

void init_page_table(void)
{
	init_pt = arch_alloc_page(IHK_MC_AP_CRITICAL);
	
	memset(init_pt, 0, sizeof(PAGE_SIZE));

	/* Normal memory area */
	init_normal_area(init_pt);
	init_fixed_area(init_pt);
	init_low_area(init_pt);
	init_text_area(init_pt);

	load_page_table(init_pt);
	kprintf("Page table is now at %p\n", init_pt);
}

extern void __reserve_arch_pages(unsigned long, unsigned long,
                                 void (*)(unsigned long, unsigned long, int));

void ihk_mc_reserve_arch_pages(unsigned long start, unsigned long end,
                               void (*cb)(unsigned long, unsigned long, int))
{
	/* Reserve Text + temporal heap */
	cb(virt_to_phys(_head), virt_to_phys(get_last_early_heap()), 0);
	/* Reserve trampoline area to boot the second ap */
	cb(AP_TRAMPOLINE, AP_TRAMPOLINE + AP_TRAMPOLINE_SIZE, 0);
	/* Reserve the null page */
	cb(0, PAGE_SIZE, 0);
	/* Micro-arch specific */
	__reserve_arch_pages(start, end, cb);
}

void ihk_mc_set_page_allocator(struct ihk_mc_pa_ops *ops)
{
	last_page = (void *)-1;
	pa_ops = ops;
}

unsigned long virt_to_phys(void *v)
{
	unsigned long va = (unsigned long)v;
	
	if (va >= MAP_KERNEL_START) {
		return va - MAP_KERNEL_START + x86_kernel_phys_base;
	} else {
		return va - MAP_ST_START;
	}
}
void *phys_to_virt(unsigned long p)
{
	return (void *)(p + MAP_ST_START);
}
