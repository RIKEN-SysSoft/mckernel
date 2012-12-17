/*
 * AAL - Generic page allocator (manycore version)
 * (C) Copyright 2011 Taku Shimosawa.
 */
#include <types.h>
#include <string.h>
#include <aal/debug.h>
#include <aal/lock.h>
#include <aal/mm.h>
#include <aal/page_alloc.h>
#include <memory.h>
#include <bitops.h>

void *allocate_pages(int npages, enum aal_mc_ap_flag flag);
void free_pages(void *, int npages);

#define MAP_INDEX(n)    ((n) >> 6)
#define MAP_BIT(n)      ((n) & 0x3f)
#define ADDRESS(desc, index, bit)    \
	((desc)->start + (((index) * 64 + (bit)) << ((desc)->shift)))

void *__aal_pagealloc_init(unsigned long start, unsigned long size,
                           unsigned long unit, void *initial,
                           unsigned long *pdescsize)
{
	/* Unit must be power of 2, and size and start must be unit-aligned */
	struct aal_page_allocator_desc *desc;
	int i, page_shift, descsize, mapsize, mapaligned;
	int flag = 0;

	if (!unit) {
		return NULL;
	}
	page_shift = fls(unit) - 1;

	/* round up to 64-bit */
	mapsize = (size >> page_shift);
	mapaligned = ((mapsize + 63) >> 6) << 3;
	descsize = sizeof(*desc) + mapaligned;
	
	descsize = (descsize + PAGE_SIZE - 1) >> PAGE_SHIFT;

	if (initial) {
		desc = initial;
		*pdescsize = descsize;
	} else {
		desc = (void *)allocate_pages(descsize, 0);
	}
	flag = descsize;
	memset(desc, 0, descsize * PAGE_SIZE);

	if (!desc) {
		kprintf("AAL: failed to allocate page-allocator-desc "\
		        "(%lx, %lx, %lx)\n", start, size, unit);
		return NULL;
	}

	desc->start = start;
	desc->last = 0;
	desc->count = mapaligned >> 3;
	desc->shift = page_shift;
	desc->flag = flag;

	kprintf("Page allocator: %lx - %lx (%d)\n", start, start + size,
	        page_shift);

	aal_mc_spinlock_init(&desc->lock);

	/* Reserve align padding area */
	for (i = mapsize; i < mapaligned * 8; i++) {
		desc->map[MAP_INDEX(i)] |= (1UL << MAP_BIT(i));
	}

	return desc;
}

void *aal_pagealloc_init(unsigned long start, unsigned long size,
                         unsigned long unit)
{
	return __aal_pagealloc_init(start, size, unit, NULL, NULL);
}

void aal_pagealloc_destroy(void *__desc)
{
	struct aal_page_allocator_desc *desc = __desc;

	free_pages(desc, desc->flag);
}

static unsigned long __aal_pagealloc_large(struct aal_page_allocator_desc *desc,
                                           int nblocks)
{
	unsigned long flags;
	unsigned int i, j, mi;

	flags = aal_mc_spinlock_lock(&desc->lock);
	for (i = 0, mi = desc->last; i < desc->count; i++, mi++) {
		if (mi >= desc->count) {
			mi = 0;
		}
		if (mi + nblocks >= desc->count) {
			continue;
		}
		for (j = mi; j < mi + nblocks; j++) {
			if (desc->map[j]) {
				break;
			}
		}
		if (j == mi + nblocks) {
			for (j = mi; j < mi + nblocks; j++) {
				desc->map[j] = (unsigned long)-1;
			}
			aal_mc_spinlock_unlock(&desc->lock, flags);
			return ADDRESS(desc, mi, 0);
		}
	}
	aal_mc_spinlock_unlock(&desc->lock, flags);

	return 0;
}

unsigned long aal_pagealloc_alloc(void *__desc, int npages)
{
	struct aal_page_allocator_desc *desc = __desc;
	unsigned int i, mi;
	int j;
	unsigned long v, mask, flags;

	/* If requested page is more than the half of the element,
	 * we allocate the whole element (ulong) */
	if (npages >= 32) {
		return __aal_pagealloc_large(desc, (npages + 63) >> 6);
	}

	mask = (1UL << npages) - 1;

	flags = aal_mc_spinlock_lock(&desc->lock);
	for (i = 0, mi = desc->last; i < desc->count; i++, mi++) {
		if (mi >= desc->count) {
			mi = 0;
		}
		
		v = desc->map[mi];
		if (v == (unsigned long)-1)
			continue;
		
		for (j = 0; j <= 64 - npages; j++) {
			if (!(v & (mask << j))) { /* free */
				desc->map[mi] |= (mask << j);

				aal_mc_spinlock_unlock(&desc->lock, flags);
				return ADDRESS(desc, mi, j);
			}
		}
	}
	aal_mc_spinlock_unlock(&desc->lock, flags);

	/* We use null pointer for failure */
	return 0;
}

void aal_pagealloc_reserve(void *__desc, unsigned long start, unsigned long end)
{
	int i, n;
	struct aal_page_allocator_desc *desc = __desc;
	unsigned long flags;

	n = (end + (1 << desc->shift) - 1 - desc->start) >> desc->shift;
	i = ((start - desc->start) >> desc->shift);
	if (i < 0 || n < 0) {
		return;
	}

	flags = aal_mc_spinlock_lock(&desc->lock);
	for (; i < n; i++) {
		if (!(i & 63) && i + 63 < n) {
			desc->map[MAP_INDEX(i)] = (unsigned long)-1L;
			i += 63;
		} else {
			desc->map[MAP_INDEX(i)] |= (1UL << MAP_BIT(i));
		}
	}
	aal_mc_spinlock_unlock(&desc->lock, flags);
}

void aal_pagealloc_free(void *__desc, unsigned long address, int npages)
{
	struct aal_page_allocator_desc *desc = __desc;
	int i;
	unsigned mi;
	unsigned long flags;

	/* XXX: Parameter check */
	if (npages >= 32) {
		npages = (npages + 63) & ~63;
	}
	flags = aal_mc_spinlock_lock(&desc->lock);
	mi = (address - desc->start) >> desc->shift;
	for (i = 0; i < npages; i++, mi++) {
		desc->map[MAP_INDEX(mi)] &= ~(1UL << MAP_BIT(mi));
	}
	aal_mc_spinlock_unlock(&desc->lock, flags);
}

unsigned long aal_pagealloc_count(void *__desc)
{
	struct aal_page_allocator_desc *desc = __desc;
	unsigned long i, j, n = 0;
	unsigned long flags;

	flags = aal_mc_spinlock_lock(&desc->lock);
	/* XXX: Very silly counting */
	for (i = 0; i < desc->count; i++) {
		for (j = 0; j < 64; j++) {
			if (!(desc->map[i] & (1UL << j))) {
				n++;
			}
		}
	}
	aal_mc_spinlock_unlock(&desc->lock, flags);
	
	return n;
}

void __aal_pagealloc_zero_free_pages(void *__desc)
{
	struct aal_page_allocator_desc *desc = __desc;
	unsigned int mi;
	int j;
	unsigned long v, flags;

kprintf("zeroing free memory... ");

	flags = aal_mc_spinlock_lock(&desc->lock);
	for (mi = 0; mi < desc->count; mi++) {
		
		v = desc->map[mi];
		if (v == (unsigned long)-1)
			continue;
		
		for (j = 0; j < 64; j++) {
			if (!(v & ((unsigned long)1 << j))) { /* free */

				memset(phys_to_virt(ADDRESS(desc, mi, j)), 0, PAGE_SIZE); 
			}
		}
	}
	aal_mc_spinlock_unlock(&desc->lock, flags);

kprintf("\nzeroing done\n");
}


