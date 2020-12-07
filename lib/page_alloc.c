/**
 * \file page_alloc.c
 *  License details are found in the file LICENSE.
 * \brief
 *  IHK - Generic page allocator (manycore version)
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#include <types.h>
#include <string.h>
#include <ihk/debug.h>
#include <ihk/lock.h>
#include <ihk/mm.h>
#include <ihk/page_alloc.h>
#include <memory.h>
#include <bitops.h>
#include <errno.h>
#include <cls.h>

//#define DEBUG_PRINT_PAGE_ALLOC

#ifdef DEBUG_PRINT_PAGE_ALLOC
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

void free_pages(void *, int npages);

#define MAP_INDEX(n)    ((n) >> 6)
#define MAP_BIT(n)      ((n) & 0x3f)
#define ADDRESS(desc, index, bit)    \
	((desc)->start + (((uintptr_t)(index) * 64 + (bit)) << ((desc)->shift)))

void *__ihk_pagealloc_init(unsigned long start, unsigned long size,
                           unsigned long unit, void *initial,
                           unsigned long *pdescsize)
{
	/* Unit must be power of 2, and size and start must be unit-aligned */
	struct ihk_page_allocator_desc *desc;
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
		desc = (void *)ihk_mc_alloc_pages(descsize, IHK_MC_AP_CRITICAL);
	}
	if (!desc) {
		kprintf("IHK: failed to allocate page-allocator-desc "\
		        "(%lx, %lx, %lx)\n", start, size, unit);
		return NULL;
	}

	flag = descsize;
	memset(desc, 0, descsize * PAGE_SIZE);

	desc->start = start;
	desc->end = start + size;
	desc->last = 0;
	desc->count = mapaligned >> 3;
	desc->shift = page_shift;
	desc->flag = flag;

	//kprintf("page allocator @ %lx - %lx (%d)\n", start, start + size,
	//        page_shift);

	mcs_lock_init(&desc->lock);

	/* Reserve align padding area */
	for (i = mapsize; i < mapaligned * 8; i++) {
		desc->map[MAP_INDEX(i)] |= (1UL << MAP_BIT(i));
	}

	return desc;
}

void *ihk_pagealloc_init(unsigned long start, unsigned long size,
                         unsigned long unit)
{
	return __ihk_pagealloc_init(start, size, unit, NULL, NULL);
}

void ihk_pagealloc_destroy(void *__desc)
{
	struct ihk_page_allocator_desc *desc = __desc;

	ihk_mc_free_pages(desc, desc->flag);
}

static unsigned long __ihk_pagealloc_large(struct ihk_page_allocator_desc *desc,
                                           int npages, int p2align)
{
	unsigned int i, j, mi;
	int nblocks;
	int nfrags;
	unsigned long mask;
	unsigned long align_mask = ((PAGE_SIZE << p2align) - 1);
	mcs_lock_node_t node;

	nblocks = (npages / 64);
	mask = -1;
	nfrags = (npages % 64);
	if (nfrags > 0) {
		++nblocks;
		mask = (1UL << nfrags) - 1;
	}

	mcs_lock_lock(&desc->lock, &node);
	for (i = 0, mi = desc->last; i < desc->count; i++, mi++) {
		if (mi >= desc->count) {
			mi = 0;
		}
		if ((mi + nblocks >= desc->count) || (ADDRESS(desc, mi, 0) & align_mask)) {
			continue;
		}
		for (j = mi; j < mi + nblocks - 1; j++) {
			if (desc->map[j]) {
				break;
			}
		}
		if ((j == (mi + nblocks - 1)) && !(desc->map[j] & mask)) {
			for (j = mi; j < mi + nblocks - 1; j++) {
				desc->map[j] = (unsigned long)-1;
			}
			desc->map[j] |= mask;
			mcs_lock_unlock(&desc->lock, &node);
			return ADDRESS(desc, mi, 0);
		}
	}
	mcs_lock_unlock(&desc->lock, &node);

	return 0;
}

unsigned long ihk_pagealloc_alloc(void *__desc, int npages, int p2align)
{
	struct ihk_page_allocator_desc *desc = __desc;
	unsigned int i, mi;
	int j;
	unsigned long v, mask;
	int jalign;
	mcs_lock_node_t node;

	if ((npages >= 32) || (p2align >= 5)) {
		return __ihk_pagealloc_large(desc, npages, p2align);
	}

	mask = (1UL << npages) - 1;
	jalign = (p2align <= 0)? 1: (1 << p2align);

	mcs_lock_lock(&desc->lock, &node);
	for (i = 0, mi = desc->last; i < desc->count; i++, mi++) {
		if (mi >= desc->count) {
			mi = 0;
		}
		
		v = desc->map[mi];
		if (v == (unsigned long)-1)
			continue;
		
		for (j = 0; j <= 64 - npages; j++) {
			if (j % jalign) {
				continue;
			}
			if (!(v & (mask << j))) { /* free */
				desc->map[mi] |= (mask << j);

				mcs_lock_unlock(&desc->lock, &node);
				return ADDRESS(desc, mi, j);
			}
		}
	}
	mcs_lock_unlock(&desc->lock, &node);

	/* We use null pointer for failure */
	return 0;
}

void ihk_pagealloc_reserve(void *__desc, unsigned long start, unsigned long end)
{
	int i, n;
	struct ihk_page_allocator_desc *desc = __desc;
	mcs_lock_node_t node;

	n = (end + (1 << desc->shift) - 1 - desc->start) >> desc->shift;
	i = ((start - desc->start) >> desc->shift);
	if (i < 0 || n < 0) {
		return;
	}

	mcs_lock_lock(&desc->lock, &node);
	for (; i < n; i++) {
		if (!(i & 63) && i + 63 < n) {
			desc->map[MAP_INDEX(i)] = (unsigned long)-1L;
			i += 63;
		} else {
			desc->map[MAP_INDEX(i)] |= (1UL << MAP_BIT(i));
		}
	}
	mcs_lock_unlock(&desc->lock, &node);
}

void ihk_pagealloc_free(void *__desc, unsigned long address, int npages)
{
	struct ihk_page_allocator_desc *desc = __desc;
	int i;
	unsigned mi;
	mcs_lock_node_t node;

	/* XXX: Parameter check */
	mcs_lock_lock(&desc->lock, &node);
	mi = (address - desc->start) >> desc->shift;
	for (i = 0; i < npages; i++, mi++) {
		if (!(desc->map[MAP_INDEX(mi)] & (1UL << MAP_BIT(mi)))) {
			kprintf("%s: double-freeing page 0x%lx\n",
				__FUNCTION__, address + i * PAGE_SIZE);
			panic("panic");
		}
		else {
			desc->map[MAP_INDEX(mi)] &= ~(1UL << MAP_BIT(mi));
		}
	}
	mcs_lock_unlock(&desc->lock, &node);
}

unsigned long ihk_pagealloc_count(void *__desc)
{
	struct ihk_page_allocator_desc *desc = __desc;
	unsigned long i, j, n = 0;
	mcs_lock_node_t node;

	mcs_lock_lock(&desc->lock, &node);
	/* XXX: Very silly counting */
	for (i = 0; i < desc->count; i++) {
		for (j = 0; j < 64; j++) {
			if (!(desc->map[i] & (1UL << j))) {
				n++;
			}
		}
	}
	mcs_lock_unlock(&desc->lock, &node);
	
	return n;
}

int ihk_pagealloc_query_free(void *__desc)
{
	struct ihk_page_allocator_desc *desc = __desc;
	unsigned int mi;
	int j;
	unsigned long v;
	int npages = 0;
	mcs_lock_node_t node;

	mcs_lock_lock(&desc->lock, &node);
	for (mi = 0; mi < desc->count; mi++) {
		
		v = desc->map[mi];
		if (v == (unsigned long)-1)
			continue;
		
		for (j = 0; j < 64; j++) {
			if (!(v & ((unsigned long)1 << j))) { /* free */
				npages++;
			}
		}
	}
	mcs_lock_unlock(&desc->lock, &node);

	return npages;
}

void __ihk_pagealloc_zero_free_pages(void *__desc)
{
	struct ihk_page_allocator_desc *desc = __desc;
	unsigned int mi;
	int j;
	unsigned long v;
	mcs_lock_node_t node;

kprintf("zeroing free memory... ");

	mcs_lock_lock(&desc->lock, &node);
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
	mcs_lock_unlock(&desc->lock, &node);

kprintf("\nzeroing done\n");
}


#ifdef IHK_RBTREE_ALLOCATOR

/*
 * Simple red-black tree based physical memory management routines.
 *
 * Allocation grabs first suitable chunk (splits chunk if alignment requires it).
 * Deallocation merges with immediate neighbours.
 *
 * NOTE: invariant property: free_chunk structures are placed in the very front
 * of their corresponding memory (i.e., they are on the free memory chunk itself).
 */

size_t __count_free_bytes(struct rb_root *root)
{
	struct free_chunk *chunk;
	struct rb_node *node;
	size_t size = 0;

	for (node = rb_first(root); node; node = rb_next(node)) {
		chunk = container_of(node, struct free_chunk, node);

		size += chunk->size;
	}

	return size;
}

/*
 * Free pages.
 * NOTE: locking must be managed by the caller.
 */
static int __page_alloc_rbtree_free_range(struct rb_root *root,
		unsigned long addr, unsigned long size)
{
	struct rb_node **iter = &(root->rb_node), *parent = NULL;
	struct free_chunk *new_chunk;

	/* Figure out where to put new node */
	while (*iter) {
		struct free_chunk *ichunk = container_of(*iter, struct free_chunk, node);
		parent = *iter;

		if ((addr >= ichunk->addr) && (addr < ichunk->addr + ichunk->size)) {
			kprintf("%s: ERROR: free memory chunk: 0x%lx:%lu"
					" and requested range to be freed: 0x%lx:%lu are "
					"overlapping (double-free?)\n",
					__FUNCTION__,
					ichunk->addr, ichunk->size, addr, size);
			return EINVAL;
		}

		/* Is ichunk contigous from the left? */
		if (ichunk->addr + ichunk->size == addr) {
			struct rb_node *right;
			/* Extend it to the right */
			ichunk->size += size;
			dkprintf("%s: chunk extended to right: 0x%lx:%lu\n",
					__FUNCTION__, ichunk->addr, ichunk->size);

			/* Have the right chunk of ichunk and ichunk become contigous? */
			right = rb_next(*iter);
			if (right) {
				struct free_chunk *right_chunk =
					container_of(right, struct free_chunk, node);

				if (ichunk->addr + ichunk->size == right_chunk->addr) {
					ichunk->size += right_chunk->size;
					rb_erase(right, root);
					dkprintf("%s: chunk merged to right: 0x%lx:%lu\n",
							__FUNCTION__, ichunk->addr, ichunk->size);
				}
			}

			return 0;
		}

		/* Is ichunk contigous from the right? */
		if (addr + size == ichunk->addr) {
			struct rb_node *left;
			/* Extend it to the left */
			ichunk->addr -= size;
			ichunk->size += size;
			dkprintf("%s: chunk extended to left: 0x%lx:%lu\n",
					__FUNCTION__, ichunk->addr, ichunk->size);

			/* Have the left chunk of ichunk and ichunk become contigous? */
			left = rb_prev(*iter);
			if (left) {
				struct free_chunk *left_chunk =
					container_of(left, struct free_chunk, node);

				if (left_chunk->addr + left_chunk->size == ichunk->addr) {
					ichunk->addr -= left_chunk->size;
					ichunk->size += left_chunk->size;
					rb_erase(left, root);
					dkprintf("%s: chunk merged to left: 0x%lx:%lu\n",
							__FUNCTION__, ichunk->addr, ichunk->size);
				}
			}

			/* Move chunk structure to the front */
			new_chunk = (struct free_chunk *)phys_to_virt(ichunk->addr);
			*new_chunk = *ichunk;
			rb_replace_node(&ichunk->node, &new_chunk->node, root);
			dkprintf("%s: chunk moved to front: 0x%lx:%lu\n",
					__FUNCTION__, new_chunk->addr, new_chunk->size);

			return 0;
		}

		if (addr < ichunk->addr)
			iter = &((*iter)->rb_left);
		else
			iter = &((*iter)->rb_right);
	}

	new_chunk = (struct free_chunk *)phys_to_virt(addr);
	new_chunk->addr = addr;
	new_chunk->size = size;
	dkprintf("%s: new chunk: 0x%lx:%lu\n",
		__FUNCTION__, new_chunk->addr, new_chunk->size);

	/* Add new node and rebalance tree. */
	rb_link_node(&new_chunk->node, parent, iter);
	rb_insert_color(&new_chunk->node, root);

	return 0;
}

/*
 * Mark address range as used (i.e., allocated).
 *
 * chunk is the free memory chunk in which
 * [aligned_addr, aligned_addr + size] resides.
 *
 * NOTE: locking must be managed by the caller.
 */
static int __page_alloc_rbtree_mark_range_allocated(struct rb_root *root,
		struct free_chunk *chunk,
		unsigned long aligned_addr, unsigned long size)
{
	struct free_chunk *left_chunk = NULL, *right_chunk = NULL;

	/* Is there leftover on the right? */
	if ((aligned_addr + size) < (chunk->addr + chunk->size)) {
		right_chunk = (struct free_chunk *)phys_to_virt(aligned_addr + size);
		right_chunk->addr = aligned_addr + size;
		right_chunk->size = (chunk->addr + chunk->size) - (aligned_addr + size);
	}

	/* Is there leftover on the left? */
	if (aligned_addr != chunk->addr) {
		left_chunk = chunk;
	}

	/* Update chunk's size, possibly becomes zero */
	chunk->size = (aligned_addr - chunk->addr);

	if (left_chunk) {
		/* Left chunk reuses chunk, add right chunk */
		if (right_chunk) {
			dkprintf("%s: adding right chunk: 0x%lx:%lu\n",
					__FUNCTION__, right_chunk->addr, right_chunk->size);
			if (__page_alloc_rbtree_free_range(root,
					right_chunk->addr, right_chunk->size)) {
				kprintf("%s: ERROR: adding right chunk: 0x%lx:%lu\n",
						__FUNCTION__, right_chunk->addr, right_chunk->size);
				return EINVAL;
			}
		}
	}
	else {
		/* Replace left with right */
		if (right_chunk) {
			rb_replace_node(&chunk->node, &right_chunk->node, root);
			dkprintf("%s: chunk replaced with right: 0x%lx:%lu\n",
					__FUNCTION__, right_chunk->addr, right_chunk->size);
		}
		/* No left chunk and no right chunk => chunk was exact match, delete it */
		else {
			rb_erase(&chunk->node, root);
			dkprintf("%s: chunk deleted: 0x%lx:%lu\n",
					__FUNCTION__, chunk->addr, chunk->size);
		}
	}

	return 0;
}

/*
 * Allocate pages.
 *
 * NOTE: locking must be managed by the caller.
 */
static unsigned long __page_alloc_rbtree_alloc_pages(struct rb_root *root,
		int npages, int p2align)
{
	struct free_chunk *chunk;
	struct rb_node *node;
	unsigned long size = PAGE_SIZE * npages;
	unsigned long align_size = (PAGE_SIZE << p2align);
	unsigned long align_mask = ~(align_size - 1);
	unsigned long aligned_addr = 0;

	for (node = rb_first(root); node; node = rb_next(node)) {
		chunk = container_of(node, struct free_chunk, node);
		aligned_addr = (chunk->addr + (align_size - 1)) & align_mask;

		/* Is this a suitable chunk? */
		if ((aligned_addr + size) <= (chunk->addr + chunk->size)) {
			break;
		}
	}

	/* No matching chunk at all? */
	if (!node) {
		return 0;
	}

	dkprintf("%s: allocating: 0x%lx:%lu\n",
			__FUNCTION__, aligned_addr, size);
	if (__page_alloc_rbtree_mark_range_allocated(root, chunk,
			aligned_addr, size)) {
		kprintf("%s: ERROR: allocating 0x%lx:%lu\n",
			__FUNCTION__, aligned_addr, size);
		return 0;
	}

	return aligned_addr;
}

/*
 * Reserve pages.
 *
 * NOTE: locking must be managed by the caller.
 */
static unsigned long __page_alloc_rbtree_reserve_pages(struct rb_root *root,
		unsigned long aligned_addr, int npages)
{
	struct free_chunk *chunk;
	struct rb_node *node;
	unsigned long size = PAGE_SIZE * npages;

	for (node = rb_first(root); node; node = rb_next(node)) {
		chunk = container_of(node, struct free_chunk, node);

		/* Is this the containing chunk? */
		if (aligned_addr >= chunk->addr &&
				(aligned_addr + size) <= (chunk->addr + chunk->size)) {
			break;
		}
	}

	/* No matching chunk at all? */
	if (!node) {
		kprintf("%s: WARNING: attempted to reserve non-free"
				" physical range: 0x%lx:%lu\n",
				__FUNCTION__,
				aligned_addr, size);
		return 0;
	}

	dkprintf("%s: reserving: 0x%lx:%lu\n",
			__FUNCTION__, aligned_addr, size);
	if (__page_alloc_rbtree_mark_range_allocated(root, chunk,
			aligned_addr, size)) {
		kprintf("%s: ERROR: reserving 0x%lx:%lu\n",
			__FUNCTION__, aligned_addr, size);
		return 0;
	}

	return aligned_addr;
}


/*
 * External routines.
 */
int ihk_numa_add_free_pages(struct ihk_mc_numa_node *node,
		unsigned long addr, unsigned long size)
{
	if (__page_alloc_rbtree_free_range(&node->free_chunks, addr, size)) {
		kprintf("%s: ERROR: adding 0x%lx:%lu\n",
			__FUNCTION__, addr, size);
		return EINVAL;
	}

	if (addr < node->min_addr)
		node->min_addr = addr;

	if (addr + size > node->max_addr)
		node->max_addr = addr + size;

	node->nr_pages += (size >> PAGE_SHIFT);
	node->nr_free_pages += (size >> PAGE_SHIFT);
	dkprintf("%s: added free pages 0x%lx:%lu\n",
		__FUNCTION__, addr, size);
	return 0;
}


unsigned long ihk_numa_alloc_pages(struct ihk_mc_numa_node *node,
	int npages, int p2align)
{
	unsigned long addr = 0;
	mcs_lock_node_t mcs_node;

#ifdef ENABLE_PER_CPU_ALLOC_CACHE
	/* Check CPU local cache first */
	if (cpu_local_var_initialized) {
		unsigned long irqflags;

		irqflags = cpu_disable_interrupt_save();
		addr = __page_alloc_rbtree_alloc_pages(&cpu_local_var(free_chunks),
				npages, p2align);
		cpu_restore_interrupt(irqflags);

		if (addr) {
			dkprintf("%s: 0x%lx:%d allocated from cache\n",
				__func__, addr, npages);
			return addr;
		}
	}
#endif

	mcs_lock_lock(&node->lock, &mcs_node);

	if (node->nr_free_pages < npages) {
		goto unlock_out;
	}

	addr = __page_alloc_rbtree_alloc_pages(&node->free_chunks,
			npages, p2align);

	/* Does not necessarily succeed due to alignment */
	if (addr) {
		node->nr_free_pages -= npages;
#if 0
		{
			size_t free_bytes = __count_free_bytes(&node->free_chunks);
			if (free_bytes != node->nr_free_pages * PAGE_SIZE) {
				kprintf("%s: inconsistent free count? node: %lu vs. cnt: %lu\n",
						__func__, node->nr_free_pages * PAGE_SIZE, free_bytes);
				panic("");
			}
		}
#endif
		dkprintf("%s: allocated pages 0x%lx:%lu\n",
				__FUNCTION__, addr, npages << PAGE_SHIFT);
	}

unlock_out:
	mcs_lock_unlock(&node->lock, &mcs_node);

	return addr;
}

void ihk_numa_free_pages(struct ihk_mc_numa_node *node,
	unsigned long addr, int npages)
{
	mcs_lock_node_t mcs_node;

#ifdef ENABLE_PER_CPU_ALLOC_CACHE
	/* CPU local cache */
	if (cpu_local_var_initialized) {
		unsigned long irqflags;

		irqflags = cpu_disable_interrupt_save();
		if (__page_alloc_rbtree_free_range(&cpu_local_var(free_chunks), addr,
					npages << PAGE_SHIFT)) {
			kprintf("%s: ERROR: freeing 0x%lx:%lu to CPU local cache\n",
					__FUNCTION__, addr, npages << PAGE_SHIFT);
			cpu_restore_interrupt(irqflags);
		}
		else {
			dkprintf("%s: 0x%lx:%d freed to cache\n",
				__func__, addr, npages);
			cpu_restore_interrupt(irqflags);
			return;
		}
	}
#endif

	if (addr < node->min_addr ||
			(addr + (npages << PAGE_SHIFT)) > node->max_addr) {
		return;
	}

	if (npages <= 0) {
		return;
	}

	mcs_lock_lock(&node->lock, &mcs_node);
	if (__page_alloc_rbtree_free_range(&node->free_chunks, addr,
				npages << PAGE_SHIFT)) {
		kprintf("%s: ERROR: freeing 0x%lx:%lu\n",
				__FUNCTION__, addr, npages << PAGE_SHIFT);
	}
	else {
		node->nr_free_pages += npages;
#if 0
		{
			size_t free_bytes = __count_free_bytes(&node->free_chunks);
			if (free_bytes != node->nr_free_pages * PAGE_SIZE) {
				kprintf("%s: inconsistent free count? node: %lu vs. cnt: %lu\n",
						__func__, node->nr_free_pages * PAGE_SIZE, free_bytes);
				panic("");
			}
		}
#endif
		dkprintf("%s: freed pages 0x%lx:%lu\n",
				__FUNCTION__, addr, npages << PAGE_SHIFT);
	}
	mcs_lock_unlock(&node->lock, &mcs_node);
}

#endif // IHK_RBTREE_ALLOCATOR
