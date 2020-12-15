/* mem.c COPYRIGHT FUJITSU LIMITED 2015-2018 */
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
#include <rusage_private.h>
#include <syscall.h>
#include <profile.h>
#include <process.h>
#include <limits.h>
#include <sysfs.h>
#include <ihk/debug.h>
#include <llist.h>
#include <bootparam.h>

//#define DEBUG_PRINT_MEM

#ifdef DEBUG_PRINT_MEM
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

static unsigned long pa_start, pa_end;
static struct ihk_mc_numa_node memory_nodes[512];

extern int ihk_mc_pt_print_pte(struct page_table *pt, void *virt);
extern int interrupt_from_user(void *);

struct tlb_flush_entry tlb_flush_vector[IHK_TLB_FLUSH_IRQ_VECTOR_SIZE];

int anon_on_demand = 0;
#ifdef ENABLE_FUGAKU_HACKS
int hugetlbfs_on_demand;
#endif
int sysctl_overcommit_memory = OVERCOMMIT_ALWAYS;

static struct ihk_mc_pa_ops *pa_ops;

extern void *early_alloc_pages(int nr_pages);
extern void early_alloc_invalidate(void);

static char *memdebug = NULL;

static void *___kmalloc(int size, ihk_mc_ap_flag flag);
static void ___kfree(void *ptr);

static void *___ihk_mc_alloc_aligned_pages_node(int npages,
		int p2align, ihk_mc_ap_flag flag, int node, int is_user, uintptr_t virt_addr);
static void *___ihk_mc_alloc_pages(int npages, ihk_mc_ap_flag flag, int is_user);
static void ___ihk_mc_free_pages(void *p, int npages, int is_user);

extern unsigned long ihk_mc_get_ns_per_tsc(void);

/*
 * Page allocator tracking routines
 */

#define PAGEALLOC_TRACK_HASH_SHIFT  (8)
#define PAGEALLOC_TRACK_HASH_SIZE   (1 << PAGEALLOC_TRACK_HASH_SHIFT)
#define PAGEALLOC_TRACK_HASH_MASK   (PAGEALLOC_TRACK_HASH_SIZE - 1)

struct list_head pagealloc_track_hash[PAGEALLOC_TRACK_HASH_SIZE];
ihk_spinlock_t pagealloc_track_hash_locks[PAGEALLOC_TRACK_HASH_SIZE];

struct list_head pagealloc_addr_hash[PAGEALLOC_TRACK_HASH_SIZE];
ihk_spinlock_t pagealloc_addr_hash_locks[PAGEALLOC_TRACK_HASH_SIZE];

int pagealloc_track_initialized = 0;
int pagealloc_runcount = 0;

struct pagealloc_track_addr_entry {
	void *addr;
	int runcount;
	struct list_head list; /* track_entry's list */
	struct pagealloc_track_entry *entry;
	struct list_head hash; /* address hash */
	int npages;
};

struct pagealloc_track_entry {
	char *file;
	int line;
	ihk_atomic_t alloc_count;
	struct list_head hash;
	struct list_head addr_list;
	ihk_spinlock_t addr_list_lock;
};

struct dump_pase_info {
	struct ihk_dump_page_set *dump_page_set;
	struct ihk_dump_page *dump_pages;
};

/** Get the index in the map array */
#define MAP_INDEX(n)    ((n) >> 6)
/** Get the bit number in a map element */
#define MAP_BIT(n)      ((n) & 0x3f)

void pagealloc_track_init(void)
{
	if (!pagealloc_track_initialized) {
		int i;

		pagealloc_track_initialized = 1;
		for (i = 0; i < PAGEALLOC_TRACK_HASH_SIZE; ++i) {
			ihk_mc_spinlock_init(&pagealloc_track_hash_locks[i]);
			INIT_LIST_HEAD(&pagealloc_track_hash[i]);
			ihk_mc_spinlock_init(&pagealloc_addr_hash_locks[i]);
			INIT_LIST_HEAD(&pagealloc_addr_hash[i]);
		}
	}
}

/* NOTE: Hash lock must be held */
struct pagealloc_track_entry *__pagealloc_track_find_entry(
		char *file, int line)
{
	struct pagealloc_track_entry *entry_iter, *entry = NULL;
	int hash = (strlen(file) + line) & PAGEALLOC_TRACK_HASH_MASK;

	list_for_each_entry(entry_iter, &pagealloc_track_hash[hash], hash) {
		if (!strcmp(entry_iter->file, file) &&
				entry_iter->line == line) {
			entry = entry_iter;
			break;
		}
	}

	if (entry) {
		dkprintf("%s found entry %s:%d\n", __FUNCTION__,
				file, line);
	}
	else {
		dkprintf("%s couldn't find entry %s:%d\n", __FUNCTION__,
				file, line);
	}

	return entry;
}

/* Top level routines called from macros */
void *_ihk_mc_alloc_aligned_pages_node(int npages, int p2align,
	ihk_mc_ap_flag flag, int node, int is_user, uintptr_t virt_addr,
	char *file, int line)
{
	unsigned long irqflags;
	struct pagealloc_track_entry *entry;
	struct pagealloc_track_addr_entry *addr_entry;
	int hash, addr_hash;
	void *r = ___ihk_mc_alloc_aligned_pages_node(npages,
					p2align, flag, node, is_user, virt_addr);

	if (!memdebug || !pagealloc_track_initialized)
		return r;

	if (!r)
		return r;

	hash = (strlen(file) + line) & PAGEALLOC_TRACK_HASH_MASK;
	irqflags = ihk_mc_spinlock_lock(&pagealloc_track_hash_locks[hash]);

	entry = __pagealloc_track_find_entry(file, line);

	if (!entry) {
		entry = ___kmalloc(sizeof(*entry), IHK_MC_AP_NOWAIT);
		if (!entry) {
			kprintf("%s: ERROR: allocating tracking entry\n");
			goto out;
		}

		entry->line = line;
		ihk_atomic_set(&entry->alloc_count, 1);
		ihk_mc_spinlock_init(&entry->addr_list_lock);
		INIT_LIST_HEAD(&entry->addr_list);

		entry->file = ___kmalloc(strlen(file) + 1, IHK_MC_AP_NOWAIT);
		if (!entry->file) {
			kprintf("%s: ERROR: allocating file string\n");
			___kfree(entry);
			ihk_mc_spinlock_unlock(&pagealloc_track_hash_locks[hash], irqflags);
			goto out;
		}

		strcpy(entry->file, file);
		entry->file[strlen(file)] = 0;
		list_add(&entry->hash, &pagealloc_track_hash[hash]);
		dkprintf("%s entry %s:%d npages: %d added\n", __FUNCTION__,
			file, line, npages);
	}
	else {
		ihk_atomic_inc(&entry->alloc_count);
	}
	ihk_mc_spinlock_unlock(&pagealloc_track_hash_locks[hash], irqflags);

	/* Add new addr entry for this allocation entry */
	addr_entry = ___kmalloc(sizeof(*addr_entry), IHK_MC_AP_NOWAIT);
	if (!addr_entry) {
		kprintf("%s: ERROR: allocating addr entry\n");
		goto out;
	}

	addr_entry->addr = r;
	addr_entry->runcount = pagealloc_runcount;
	addr_entry->entry = entry;
	addr_entry->npages = npages;

	irqflags = ihk_mc_spinlock_lock(&entry->addr_list_lock);
	list_add(&addr_entry->list, &entry->addr_list);
	ihk_mc_spinlock_unlock(&entry->addr_list_lock, irqflags);

	/* Add addr entry to address hash */
	addr_hash = ((unsigned long)r >> 5) & PAGEALLOC_TRACK_HASH_MASK;
	irqflags = ihk_mc_spinlock_lock(&pagealloc_addr_hash_locks[addr_hash]);
	list_add(&addr_entry->hash, &pagealloc_addr_hash[addr_hash]);
	ihk_mc_spinlock_unlock(&pagealloc_addr_hash_locks[addr_hash], irqflags);

	dkprintf("%s addr_entry %p added\n", __FUNCTION__, r);

out:
	return r;
}

void _ihk_mc_free_pages(void *ptr, int npages, int is_user,
                        char *file, int line)
{
	unsigned long irqflags;
	struct pagealloc_track_entry *entry;
	struct pagealloc_track_addr_entry *addr_entry_iter, *addr_entry = NULL;
	struct pagealloc_track_addr_entry *addr_entry_next = NULL;
	int hash;
	int rehash_addr_entry = 0;

	if (!memdebug || !pagealloc_track_initialized) {
		goto out;
	}

	hash = ((unsigned long)ptr >> 5) & PAGEALLOC_TRACK_HASH_MASK;
	irqflags = ihk_mc_spinlock_lock(&pagealloc_addr_hash_locks[hash]);
	list_for_each_entry(addr_entry_iter,
			&pagealloc_addr_hash[hash], hash) {
		if (addr_entry_iter->addr == ptr) {
			addr_entry = addr_entry_iter;
			break;
		}
	}

	if (addr_entry) {
		if (npages > addr_entry->npages) {
			kprintf("%s: ERROR: trying to deallocate %d pages"
					" for a %d pages allocation at %s:%d\n",
					__FUNCTION__,
					npages, addr_entry->npages,
					file, line);
			panic("invalid deallocation");
		}

		if (addr_entry->npages > npages) {
			addr_entry->addr += (npages * PAGE_SIZE);
			addr_entry->npages -= npages;

			/* Only rehash if haven't freed all pages yet */
			if (addr_entry->npages) {
				rehash_addr_entry = 1;
			}
		}

		list_del(&addr_entry->hash);
	}
	ihk_mc_spinlock_unlock(&pagealloc_addr_hash_locks[hash], irqflags);

	if (!addr_entry) {
		/*
		 * Deallocations that don't start at the allocated address are
		 * valid but can't be found in addr hash, scan the entire table
		 * and split the matching entry
		 */
		for (hash = 0; hash < PAGEALLOC_TRACK_HASH_SIZE; ++hash) {
			irqflags = ihk_mc_spinlock_lock(&pagealloc_addr_hash_locks[hash]);
			list_for_each_entry(addr_entry_iter,
					&pagealloc_addr_hash[hash], hash) {
				if (addr_entry_iter->addr < ptr &&
					(addr_entry_iter->addr + addr_entry_iter->npages * PAGE_SIZE)
					>= ptr + (npages * PAGE_SIZE)) {
					addr_entry = addr_entry_iter;
					break;
				}
			}

			if (addr_entry) {
				list_del(&addr_entry->hash);
			}
			ihk_mc_spinlock_unlock(&pagealloc_addr_hash_locks[hash], irqflags);

			if (addr_entry) break;
		}

		/* Still not? Invalid deallocation */
		if (!addr_entry) {
			kprintf("%s: ERROR: invalid deallocation for addr: 0x%lx @ %s:%d\n",
				__FUNCTION__, ptr, file, line);
			panic("panic: invalid deallocation");
		}

		dkprintf("%s: found covering addr_entry: 0x%lx:%d\n", __FUNCTION__,
			addr_entry->addr, addr_entry->npages);

		entry = addr_entry->entry;

		/*
		 * Now split, allocate new entry and rehash.
		 * Is there a remaining piece after the deallocation?
		 */
		if ((ptr + (npages * PAGE_SIZE)) <
				(addr_entry->addr + (addr_entry->npages * PAGE_SIZE))) {
			int addr_hash;

			addr_entry_next =
				___kmalloc(sizeof(*addr_entry_next), IHK_MC_AP_NOWAIT);
			if (!addr_entry_next) {
				kprintf("%s: ERROR: allocating addr entry prev\n", __FUNCTION__);
				goto out;
			}

			addr_entry_next->addr = ptr + (npages * PAGE_SIZE);
			addr_entry_next->npages = ((addr_entry->addr +
				(addr_entry->npages * PAGE_SIZE)) -
				(ptr + npages * PAGE_SIZE)) / PAGE_SIZE;
			addr_entry_next->runcount = addr_entry->runcount;

			addr_hash = ((unsigned long)addr_entry_next->addr >> 5) &
				PAGEALLOC_TRACK_HASH_MASK;
			irqflags = ihk_mc_spinlock_lock(&pagealloc_addr_hash_locks[addr_hash]);
			list_add(&addr_entry_next->hash, &pagealloc_addr_hash[addr_hash]);
			ihk_mc_spinlock_unlock(&pagealloc_addr_hash_locks[addr_hash], irqflags);

			/* Add to allocation entry */
			addr_entry_next->entry = entry;
			ihk_atomic_inc(&entry->alloc_count);
			ihk_mc_spinlock_lock_noirq(&entry->addr_list_lock);
			list_add(&addr_entry_next->list, &entry->addr_list);
			ihk_mc_spinlock_unlock_noirq(&entry->addr_list_lock);

			dkprintf("%s: addr_entry_next: 0x%lx:%d\n", __FUNCTION__,
					addr_entry_next->addr, addr_entry_next->npages);
		}

		/*
		 * We know that addr_entry->addr != ptr, addr_entry will cover
		 * the region before the deallocation.
		 */
		addr_entry->npages = (ptr - addr_entry->addr) / PAGE_SIZE;
		rehash_addr_entry = 1;

		dkprintf("%s: modified addr_entry: 0x%lx:%d\n", __FUNCTION__,
			addr_entry->addr, addr_entry->npages);
	}

	entry = addr_entry->entry;

	if (rehash_addr_entry) {
		int addr_hash = ((unsigned long)addr_entry->addr >> 5) &
			PAGEALLOC_TRACK_HASH_MASK;
		irqflags = ihk_mc_spinlock_lock(&pagealloc_addr_hash_locks[addr_hash]);
		list_add(&addr_entry->hash, &pagealloc_addr_hash[addr_hash]);
		ihk_mc_spinlock_unlock(&pagealloc_addr_hash_locks[addr_hash], irqflags);
		goto out;
	}

	irqflags = ihk_mc_spinlock_lock(&entry->addr_list_lock);
	list_del(&addr_entry->list);
	ihk_mc_spinlock_unlock(&entry->addr_list_lock, irqflags);

	dkprintf("%s addr_entry %p removed\n", __FUNCTION__, addr_entry->addr);
	___kfree(addr_entry);

	/* Do we need to remove tracking entry as well? */
	hash = (strlen(entry->file) + entry->line) &
		PAGEALLOC_TRACK_HASH_MASK;
	irqflags = ihk_mc_spinlock_lock(&pagealloc_track_hash_locks[hash]);

	if (!ihk_atomic_dec_and_test(&entry->alloc_count)) {
		ihk_mc_spinlock_unlock(&pagealloc_track_hash_locks[hash], irqflags);
		goto out;
	}

	list_del(&entry->hash);
	ihk_mc_spinlock_unlock(&pagealloc_track_hash_locks[hash], irqflags);

	dkprintf("%s entry %s:%d removed\n", __FUNCTION__,
			entry->file, entry->line);
	___kfree(entry->file);
	___kfree(entry);

out:
	___ihk_mc_free_pages(ptr, npages, is_user);
}

void pagealloc_memcheck(void)
{
	int i;
	unsigned long irqflags;
	struct pagealloc_track_entry *entry = NULL;

	for (i = 0; i < PAGEALLOC_TRACK_HASH_SIZE; ++i) {
		irqflags = ihk_mc_spinlock_lock(&pagealloc_track_hash_locks[i]);
		list_for_each_entry(entry, &pagealloc_track_hash[i], hash) {
			struct pagealloc_track_addr_entry *addr_entry = NULL;
			int cnt = 0;

			ihk_mc_spinlock_lock_noirq(&entry->addr_list_lock);
			list_for_each_entry(addr_entry, &entry->addr_list, list) {

			dkprintf("%s memory leak: %p @ %s:%d runcount: %d\n",
				__FUNCTION__,
				addr_entry->addr,
				entry->file,
				entry->line,
				addr_entry->runcount);

				if (pagealloc_runcount != addr_entry->runcount)
					continue;

				cnt++;
			}
			ihk_mc_spinlock_unlock_noirq(&entry->addr_list_lock);

			if (!cnt)
				continue;

			kprintf("%s memory leak: %s:%d cnt: %d, runcount: %d\n",
				__FUNCTION__,
				entry->file,
				entry->line,
				cnt,
				pagealloc_runcount);
		}
		ihk_mc_spinlock_unlock(&pagealloc_track_hash_locks[i], irqflags);
	}

	++pagealloc_runcount;
}



/* Actual allocation routines */
static void *___ihk_mc_alloc_aligned_pages_node(int npages, int p2align,
	ihk_mc_ap_flag flag, int node, int is_user, uintptr_t virt_addr)
{
	if (pa_ops)
		return pa_ops->alloc_page(npages, p2align, flag, node, is_user, virt_addr);
	else
		return early_alloc_pages(npages);
}

static void *___ihk_mc_alloc_pages(int npages, ihk_mc_ap_flag flag,
	int is_user)
{
	return ___ihk_mc_alloc_aligned_pages_node(npages, PAGE_P2ALIGN, flag, -1, is_user, -1);
}

static void ___ihk_mc_free_pages(void *p, int npages, int is_user)
{
	if (pa_ops)
		pa_ops->free_page(p, npages, is_user);
}

void ihk_mc_set_page_allocator(struct ihk_mc_pa_ops *ops)
{
	pagealloc_track_init();
	early_alloc_invalidate();
	pa_ops = ops;
}

/* Internal allocation routines */
static void reserve_pages(struct ihk_page_allocator_desc *pa_allocator,
		unsigned long start, unsigned long end, int type)
{
	if (start < pa_allocator->start) {
		start = pa_allocator->start;
	}
	if (end > pa_allocator->end) {
		end = pa_allocator->end;
	}
	if (start >= end) {
		return;
	}
	dkprintf("reserve: %016lx - %016lx (%ld pages)\n", start, end,
	        (end - start) >> PAGE_SHIFT);
	ihk_pagealloc_reserve(pa_allocator, start, end);
}

extern int cpu_local_var_initialized;
static void *mckernel_allocate_aligned_pages_node(int npages, int p2align,
		ihk_mc_ap_flag flag, int pref_node, int is_user, uintptr_t virt_addr)
{
	unsigned long pa = 0;
	int i = 0, node;
#ifndef IHK_RBTREE_ALLOCATOR
	struct ihk_page_allocator_desc *pa_allocator;
#endif
	int numa_id;

	struct vm_range_numa_policy *range_policy_iter = NULL;
	int numa_mem_policy = -1;
	struct process_vm *vm;
	struct vm_range *range = NULL;
	int chk_shm = 0;

	if(npages <= 0)
		return NULL;

	/* Not yet initialized or idle process */
	if (!cpu_local_var_initialized ||
			!cpu_local_var(current) ||
			!cpu_local_var(current)->vm)
		goto distance_based;

	/* No explicitly requested NUMA or user policy? */
	if ((pref_node == -1) && (!(flag & IHK_MC_AP_USER) ||
				cpu_local_var(current)->vm->numa_mem_policy == MPOL_DEFAULT)) {

		if (virt_addr != -1) {
			vm = cpu_local_var(current)->vm;
			range_policy_iter = vm_range_policy_search(vm, virt_addr);
			if (range_policy_iter) {
				range = lookup_process_memory_range(vm, (uintptr_t)virt_addr, ((uintptr_t)virt_addr) + 1);
				if (range) {
					if( (range->memobj) && (range->memobj->flags == MF_SHM)) {
						chk_shm = 1;
					}
				}
			}
		}


		if ((!((range_policy_iter) && (range_policy_iter->numa_mem_policy != MPOL_DEFAULT))) && (chk_shm == 0))
			goto distance_based;
	}

	node = ihk_mc_get_numa_id();
	if (!memory_nodes[node].nodes_by_distance)
		goto order_based;

	/* Explicit valid node? */
	if (pref_node > -1 && pref_node < ihk_mc_get_nr_numa_nodes()) {
#ifdef IHK_RBTREE_ALLOCATOR
		{
			if (rusage_check_oom(pref_node, npages, is_user) == -ENOMEM) {
				pa = 0;
			} else {
				pa = ihk_numa_alloc_pages(&memory_nodes[pref_node], npages, p2align);
			}
#else
		list_for_each_entry(pa_allocator,
				&memory_nodes[pref_node].allocators, list) {
			if (rusage_check_oom(pref_node, npages, is_user) == -ENOMEM) {
				pa = 0;
			} else {
				pa = ihk_pagealloc_alloc(pa_allocator, npages, p2align);
			}
#endif
			if (pa) {
				rusage_page_add(pref_node, npages, is_user);
				dkprintf("%s: explicit (node: %d) CPU @ node %d allocated "
						"%d pages from node %d\n",
						__FUNCTION__,
						pref_node,
						ihk_mc_get_numa_id(),
						npages, node);

				return phys_to_virt(pa);
			}
			else {
#ifdef PROFILE_ENABLE
				profile_event_add(PROFILE_mpol_alloc_missed,
						  npages * PAGE_SIZE);
#endif
				dkprintf("%s: couldn't fulfill explicit NUMA request for %d pages\n",
						__FUNCTION__, npages);
			}
		}
	}

	if ((virt_addr != -1) && (chk_shm == 0)) {

		vm = cpu_local_var(current)->vm;

		if (!(range_policy_iter)) {
			range_policy_iter = vm_range_policy_search(vm, virt_addr);
		}

		if (range_policy_iter) {
			range = lookup_process_memory_range(vm, (uintptr_t)virt_addr, ((uintptr_t)virt_addr) + 1);
			if ((range && (range->memobj->flags == MF_SHM))) {
				chk_shm = 1;
			} else {
				numa_mem_policy = range_policy_iter->numa_mem_policy;
			}
		}
	}

	if (numa_mem_policy == -1)
		numa_mem_policy = cpu_local_var(current)->vm->numa_mem_policy;

	switch (numa_mem_policy) {
		case MPOL_BIND:
		case MPOL_PREFERRED:

			/* Look at nodes in the order of distance but consider
			 * only the ones requested in user policy */
			for (i = 0; i < ihk_mc_get_nr_numa_nodes(); ++i) {

				/* Not part of user requested policy? */
				if (!test_bit(memory_nodes[node].nodes_by_distance[i].id,
						cpu_local_var(current)->proc->vm->numa_mask)) {
					continue;
				}

				numa_id = memory_nodes[node].nodes_by_distance[i].id;
#ifdef IHK_RBTREE_ALLOCATOR
				{
					if (rusage_check_oom(numa_id, npages, is_user) == -ENOMEM) {
						pa = 0;
					} else {
						pa = ihk_numa_alloc_pages(&memory_nodes[memory_nodes[node].
																nodes_by_distance[i].id], npages, p2align);
					}
#else
				list_for_each_entry(pa_allocator,
						&memory_nodes[numa_id].allocators, list) {
					if (rusage_check_oom(numa_id, npages, is_user) == -ENOMEM) {
						pa = 0;
					} else {
						pa = ihk_pagealloc_alloc(pa_allocator, npages, p2align);
					}
#endif

					if (pa) {
						rusage_page_add(numa_id, npages, is_user);
						dkprintf("%s: policy: CPU @ node %d allocated "
								"%d pages from node %d\n",
								__FUNCTION__,
								ihk_mc_get_numa_id(),
								npages, node);


						break;
					}
				}

				if (pa) break;
			}
			break;

		case MPOL_INTERLEAVE:
			/* TODO: */
			break;

		default:
			break;
	}

	if (pa) {
		return phys_to_virt(pa);
	}
	else {
#ifdef PROFILE_ENABLE
		profile_event_add(PROFILE_mpol_alloc_missed,
				  npages * PAGE_SIZE);
#endif
		dkprintf("%s: couldn't fulfill user policy for %d pages\n",
			__FUNCTION__, npages);
	}

distance_based:
	node = ihk_mc_get_numa_id();

	/* Look at nodes in the order of distance */
	if (!memory_nodes[node].nodes_by_distance)
		goto order_based;

	for (i = 0; i < ihk_mc_get_nr_numa_nodes(); ++i) {
		numa_id = memory_nodes[node].nodes_by_distance[i].id;

#ifdef IHK_RBTREE_ALLOCATOR
		{
			if (rusage_check_oom(numa_id, npages, is_user) == -ENOMEM) {
				pa = 0;
			} else {
				pa = ihk_numa_alloc_pages(&memory_nodes[memory_nodes[node].
														nodes_by_distance[i].id], npages, p2align);
			}
#else
		list_for_each_entry(pa_allocator,
		                    &memory_nodes[numa_id].allocators, list) {
			if (rusage_check_oom(numa_id, npages, is_user) == -ENOMEM) {
				pa = 0;
			} else {
				pa = ihk_pagealloc_alloc(pa_allocator, npages, p2align);
			}
#endif


			if (pa) {
				rusage_page_add(numa_id, npages, is_user);
				dkprintf("%s: distance: CPU @ node %d allocated "
						"%d pages from node %d\n",
						__FUNCTION__,
						ihk_mc_get_numa_id(),
						npages,
						memory_nodes[node].nodes_by_distance[i].id);
				break;
			}
			else {
			if (i == 0)
#ifndef ENABLE_FUGAKU_HACKS
				kprintf("%s: distance: CPU @ node %d failed to allocate "
#else
				dkprintf("%s: distance: CPU @ node %d failed to allocate "
#endif
						"%d pages from node %d\n",
						__FUNCTION__,
						ihk_mc_get_numa_id(),
						npages,
						memory_nodes[node].nodes_by_distance[i].id);
			}
		}

		if (pa) break;
	}

	if (pa)
		return phys_to_virt(pa);

order_based:
	node = ihk_mc_get_numa_id();

	/* Fall back to regular order */
	for (i = 0; i < ihk_mc_get_nr_numa_nodes(); ++i) {
		numa_id = (node + i) % ihk_mc_get_nr_numa_nodes();
#ifdef IHK_RBTREE_ALLOCATOR
		{
			if (rusage_check_oom(numa_id, npages, is_user) == -ENOMEM) {
				pa = 0;
			} else {
				pa = ihk_numa_alloc_pages(&memory_nodes[(node + i) %
														ihk_mc_get_nr_numa_nodes()], npages, p2align);
			}
#else
		list_for_each_entry(pa_allocator,
		                    &memory_nodes[numa_id].allocators, list) {
			if (rusage_check_oom(numa_id, npages, is_user) == -ENOMEM) {
				pa = 0;
			} else {
				pa = ihk_pagealloc_alloc(pa_allocator, npages, p2align);
			}
#endif

			if (pa) {
				rusage_page_add(numa_id, npages, is_user);
				break;
			}
		}

		if (pa) break;
	}

	if (pa)
		return phys_to_virt(pa);
	/*
	if(flag != IHK_MC_AP_NOWAIT)
		panic("Not enough space\n");
	*/
	dkprintf("OOM\n", __FUNCTION__);
	return NULL;
}

/*
 * Get NUMA node structure offsetted by index in the order of distance
 */
struct ihk_mc_numa_node *ihk_mc_get_numa_node_by_distance(int i)
{
	int numa_id;

	if (!cpu_local_var_initialized)
		return NULL;

	if (i < 0 || i > ihk_mc_get_nr_numa_nodes()) {
		return NULL;
	}

	numa_id = ihk_mc_get_numa_id();
	if (!memory_nodes[numa_id].nodes_by_distance)
		return NULL;

	return &memory_nodes[memory_nodes[numa_id].nodes_by_distance[i].id];
}

static void __mckernel_free_pages_in_allocator(void *va, int npages,
                                               int is_user)
{
	int i;
	unsigned long pa_start = virt_to_phys(va);
	unsigned long pa_end = pa_start + (npages * PAGE_SIZE);

#ifdef IHK_RBTREE_ALLOCATOR
	for (i = 0; i < ihk_mc_get_nr_memory_chunks(); ++i) {
		unsigned long start, end;
		int numa_id;

		ihk_mc_get_memory_chunk(i, &start, &end, &numa_id);
		if (start > pa_start || end < pa_end) {
			continue;
		}

		ihk_numa_free_pages(&memory_nodes[numa_id], pa_start, npages);
		rusage_page_sub(numa_id, npages, is_user);
		break;
	}
#else
	struct ihk_page_allocator_desc *pa_allocator;

	/* Find corresponding memory allocator */
	for (i = 0; i < ihk_mc_get_nr_numa_nodes(); ++i) {

		list_for_each_entry(pa_allocator,
				&memory_nodes[i].allocators, list) {

			if (pa_start >= pa_allocator->start &&
					pa_end <= pa_allocator->end) {
				ihk_pagealloc_free(pa_allocator, pa_start, npages);
				rusage_page_sub(i, npages, is_user);
				return;
			}
		}
	}
#endif
}


static void mckernel_free_pages(void *va, int npages, int is_user)
{
	struct list_head *pendings = &cpu_local_var(pending_free_pages);
	struct page *page;

	page = phys_to_page(virt_to_phys(va));
	if (page) {
		if (page->mode != PM_NONE) {
			kprintf("%s: WARNING: page phys 0x%lx is not PM_NONE",
					__FUNCTION__, page->phys);
		}
		if (pendings->next != NULL) {
			page->mode = PM_PENDING_FREE;
			page->offset = npages;
			list_add_tail(&page->list, pendings);
			return;
		}
	}

	__mckernel_free_pages_in_allocator(va, npages, is_user);
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
		__mckernel_free_pages_in_allocator(phys_to_virt(page_to_phys(page)),
				page->offset, IHK_MC_PG_USER);
	}

	pendings->next = pendings->prev = NULL;
	return;
}

static struct ihk_mc_pa_ops allocator = {
	.alloc_page = mckernel_allocate_aligned_pages_node,
	.free_page = mckernel_free_pages,
};

void sbox_write(int offset, unsigned int value);

static int page_hash_count_pages(void);
static void query_free_mem_interrupt_handler(void *priv)
{
	int i, pages = 0;

	/* Iterate memory allocators */
	for (i = 0; i < ihk_mc_get_nr_numa_nodes(); ++i) {
#ifdef IHK_RBTREE_ALLOCATOR
		pages += memory_nodes[i].nr_free_pages;
#else
		struct ihk_page_allocator_desc *pa_allocator;

		list_for_each_entry(pa_allocator,
				&memory_nodes[i].allocators, list) {
			int __pages = ihk_pagealloc_query_free(pa_allocator);
			kprintf("McKernel free pages in (0x%lx - 0x%lx): %d\n",
					pa_allocator->start, pa_allocator->end, __pages);
			pages += __pages;
		}
#endif
	}

	kprintf("McKernel free pages in total: %d\n", pages);
#ifdef ENABLE_FUGAKU_HACKS
	panic("PANIC");
#endif

	if (find_command_line("memdebug")) {
		extern void kmalloc_memcheck(void);

		kmalloc_memcheck();
		pagealloc_memcheck();
	}

	kprintf("Page hash: %d pages active\n", page_hash_count_pages());

#ifdef ATTACHED_MIC
	sbox_write(SBOX_SCRATCH0, pages);
	sbox_write(SBOX_SCRATCH1, 1);
#endif
}

static struct ihk_mc_interrupt_handler query_free_mem_handler = {
	.func = query_free_mem_interrupt_handler,
	.priv = NULL,
};

int gencore(struct process *proc, struct coretable **coretable,
	    int *chunks, char *cmdline, int sig);
void freecore(struct coretable **);
struct siginfo;
typedef struct siginfo siginfo_t;
unsigned long do_kill(struct thread *thread, int pid, int tid,
			int sig, siginfo_t *info, int ptracecont);

void coredump_wait(struct thread *thread)
{
	unsigned long flags;
	DECLARE_WAITQ_ENTRY(coredump_wq_entry, cpu_local_var(current));

	if (__sync_bool_compare_and_swap(&thread->coredump_status,
					 COREDUMP_RUNNING,
					 COREDUMP_DESCHEDULED)) {
		flags = cpu_disable_interrupt_save();
		dkprintf("%s: sleeping,tid=%d\n", __func__, thread->tid);
		waitq_init(&thread->coredump_wq);
		waitq_prepare_to_wait(&thread->coredump_wq, &coredump_wq_entry,
				      PS_INTERRUPTIBLE);
		cpu_restore_interrupt(flags);
		schedule();
		waitq_finish_wait(&thread->coredump_wq, &coredump_wq_entry);
		thread->coredump_status = COREDUMP_RUNNING;
		dkprintf("%s: woken up,tid=%d\n", __func__, thread->tid);
	}
}

void coredump_wakeup(struct thread *thread)
{
	if (__sync_bool_compare_and_swap(&thread->coredump_status,
					 COREDUMP_DESCHEDULED,
					 COREDUMP_TO_BE_WOKEN)) {
		dkprintf("%s: waking up tid %d\n", __func__, thread->tid);
		waitq_wakeup(&thread->coredump_wq);
	}
}

/**
 * \brief Generate a core file and tell the host to write it out.
 *
 * \param proc A current process structure.
 * \param regs A pointer to a x86_regs structure.
 */

int coredump(struct thread *thread, void *regs, int sig)
{
	struct process *proc = thread->proc;
	struct syscall_request request IHK_DMA_ALIGN;
	int ret;
	struct coretable *coretable;
	int chunks;
	struct mcs_rwlock_node_irqsave lock, lock_dump;
	struct thread *thread_iter;
	int i, n, rank;
	int *ids = NULL;

	dkprintf("%s: pid=%d,tid=%d,coredump_barrier_count=%d\n",
		__func__, proc->pid, thread->tid, proc->coredump_barrier_count);

	if (proc->rlimit[MCK_RLIMIT_CORE].rlim_cur == 0) {
		ret = -EBUSY;
		goto out;
	}

	/* Wait until all threads save its register. */
	/* mutex coredump */
	mcs_rwlock_reader_lock(&proc->coredump_lock, &lock_dump);
	rank = __sync_fetch_and_add(&proc->coredump_barrier_count, 1);
	if (rank == 0) {
		n = 0;

		mcs_rwlock_reader_lock(&proc->threads_lock, &lock);
		list_for_each_entry(thread_iter, &proc->threads_list,
				    siblings_list) {
			if (thread_iter != thread) {
				n++;
			}
		}
		if (n) {
			ids = kmalloc(sizeof(int) * n, IHK_MC_AP_NOWAIT);
			if (!ids) {
				mcs_rwlock_reader_unlock(&proc->threads_lock,
							 &lock);
				kprintf("%s: ERROR: allocating tid table\n",
					__func__);
				ret = -ENOMEM;
				goto out;
			}
			i = 0;
			list_for_each_entry(thread_iter, &proc->threads_list,
					    siblings_list) {
				if (thread_iter != thread) {
					ids[i] = thread_iter->tid;
					i++;
				}
			}
		}
		mcs_rwlock_reader_unlock(&proc->threads_lock, &lock);
		/* Note that when the target is sleeping on the source CPU,
		 * it will wake up and handle the signal when this thread yields
		 * in coredump_wait()
		 */
		for (i = 0; i < n; i++) {
			dkprintf("%s: calling do_kill, target tid=%d\n",
				__func__, ids[i]);
			do_kill(thread, proc->pid, ids[i], sig, NULL, 0);
		}
	}
	mcs_rwlock_reader_unlock(&proc->coredump_lock, &lock_dump);

	while (1) {
		n = 0;
		mcs_rwlock_reader_lock(&proc->threads_lock, &lock);
		list_for_each_entry(thread_iter, &proc->threads_list,
				    siblings_list) {
			n++;
		}
		mcs_rwlock_reader_unlock(&proc->threads_lock, &lock);
		if (n == proc->coredump_barrier_count) {
			list_for_each_entry(thread_iter, &proc->threads_list,
					    siblings_list) {
				coredump_wakeup(thread_iter);
			}
			break;
		}
		coredump_wait(thread);
	}

	/* Followers wait until dump is done to keep struct thread alive */
	if (rank != 0) {
		ret = 0;
		goto skip;
	}

	if ((ret = gencore(proc, &coretable, &chunks,
			proc->saved_cmdline, sig))) {
		kprintf("%s: ERROR: gencore returned %d\n", __func__, ret);
		goto out;
	}

	request.number = __NR_coredump;
	request.args[0] = chunks;
	request.args[1] = virt_to_phys(coretable);
	request.args[2] = virt_to_phys(thread->proc->saved_cmdline);
	request.args[3] = (unsigned long)thread->proc->saved_cmdline_len;

	/* no data for now */
	ret = do_syscall(&request, thread->cpu_id);
	if (ret == 0) {
		kprintf("%s: INFO: coredump done\n", __func__);
	} else {
		kprintf("%s: ERROR: do_syscall failed (%d)\n",
			__func__, ret);
	}
	freecore(&coretable);

 skip:
	__sync_fetch_and_add(&proc->coredump_barrier_count2, 1);
	while (1) {
		if (n == proc->coredump_barrier_count2) {
			list_for_each_entry(thread_iter, &proc->threads_list,
					    siblings_list) {
				coredump_wakeup(thread_iter);
			}
			break;
		}
		coredump_wait(thread);
	}

 out:
	kfree(ids);
	return ret;
}

void remote_flush_tlb_cpumask(struct process_vm *vm,
		unsigned long addr, int cpu_id)
{
	unsigned long __addr = addr;
	return remote_flush_tlb_array_cpumask(vm, &__addr, 1, cpu_id);
}

void remote_flush_tlb_array_cpumask(struct process_vm *vm,
		unsigned long *addr,
		int nr_addr,
		int cpu_id)
{
	unsigned long cpu;
	int flush_ind;
	struct tlb_flush_entry *flush_entry;
	cpu_set_t _cpu_set;

	if (addr[0]) {
		flush_ind = (addr[0] >> PAGE_SHIFT) % IHK_TLB_FLUSH_IRQ_VECTOR_SIZE;
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
	flush_entry->nr_addr = nr_addr;
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

		ihk_mc_interrupt_cpu(cpu, 
				     ihk_mc_get_vector(flush_ind + IHK_TLB_FLUSH_IRQ_VECTOR_START));
	}

#ifdef DEBUG_IC_TLB
	{
		unsigned long tsc;
		tsc = rdtsc() + 12884901888;  /* 1.2GHz =>10 sec */
#endif
		if (flush_entry->addr[0]) {
			int i;

			for (i = 0; i < flush_entry->nr_addr; ++i) {
				flush_tlb_single(flush_entry->addr[i] & PAGE_MASK);
			}
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
#ifdef PROFILE_ENABLE
	unsigned long t_s = 0;
	if (cpu_local_var(current)->profile) {
		t_s = rdtsc();
	}
#endif // PROFILE_ENABLE
	int flags = cpu_disable_interrupt_save();

	struct tlb_flush_entry *flush_entry = &tlb_flush_vector[vector -
		IHK_TLB_FLUSH_IRQ_VECTOR_START];

	if (flush_entry->addr[0]) {
		int i;

		for (i = 0; i < flush_entry->nr_addr; ++i) {
			flush_tlb_single(flush_entry->addr[i] & PAGE_MASK);
			dkprintf("flusing TLB for addr: 0x%lX\n", flush_entry->addr[i]);
		}
	}
	/* Zero address denotes full TLB flush */
	else {
		flush_tlb();
	}

	/* Decrease counter */
	dkprintf("decreasing pending cnt for %d\n",
			vector - IHK_TLB_FLUSH_IRQ_VECTOR_START);
	ihk_atomic_dec(&flush_entry->pending);

	cpu_restore_interrupt(flags);
#ifdef PROFILE_ENABLE
	{
		if (cpu_local_var(current)->profile) {
			unsigned long t_e = rdtsc();
			profile_event_add(PROFILE_tlb_invalidate, (t_e - t_s));
			cpu_local_var(current)->profile_elapsed_ts +=
				(t_e - t_s);
		}
	}
#endif // PROFILE_ENABLE
}
#ifdef ENABLE_FUGAKU_HACKS
extern unsigned long arch_get_instruction_address(const void *reg);
#endif

static void unhandled_page_fault(struct thread *thread, void *fault_addr,
				 uint64_t reason, void *regs)
{
	const uintptr_t address = (uintptr_t)fault_addr;
	struct process_vm *vm = thread->vm;
	struct vm_range *range;
	unsigned long irqflags;

	irqflags = kprintf_lock();
	__kprintf("Page fault for 0x%lx\n", address);
	__kprintf("%s for %s access in %s mode (reserved bit %s set), "
			"it %s an instruction fetch\n",
			(reason & PF_PROT ? "protection fault" :
			 "no page found"),
			(reason & PF_WRITE ? "write" : "read"),
			(reason & PF_USER ? "user" : "kernel"),
			(reason & PF_RSVD ? "was" : "wasn't"),
			(reason & PF_INSTR ? "was" : "wasn't"));

	range = lookup_process_memory_range(vm, address, address+1);
	if (range) {
		__kprintf("address is in range, flag: 0x%lx (%s)\n",
				range->flag,
				range->memobj ? range->memobj->path : "");
		ihk_mc_pt_print_pte(vm->address_space->page_table,
				    (void *)address);
	} else {
		__kprintf("address is out of range!\n");
	}

#ifdef ENABLE_FUGAKU_HACKS
	{
		unsigned long pc = arch_get_instruction_address(regs);
		range = lookup_process_memory_range(vm, pc, pc + 1);
		if (range) {
			__kprintf("PC: 0x%lx (%lx in %s)\n",
					pc,
					(range->memobj && range->memobj->flags & MF_REG_FILE) ?
					pc - range->start + range->objoff :
					pc - range->start,
					(range->memobj && range->memobj->path) ?
						range->memobj->path : "(unknown)");
		}
	}
#endif

	kprintf_unlock(irqflags);

	/* TODO */
	ihk_mc_debug_show_interrupt_context(regs);

	if (!(reason & PF_USER)) {
		cpu_local_var(kernel_mode_pf_regs) = regs;
#ifndef ENABLE_FUGAKU_HACKS
		panic("panic: kernel mode PF");
#else
		kprintf("panic: kernel mode PF");
		for (;;) cpu_pause();
		//panic("panic: kernel mode PF");
#endif
	}

	//dkprintf("now dump a core file\n");
	//coredump(proc, regs);

#ifdef DEBUG_PRINT_MEM
	{
		uint64_t *sp = (void *)REGS_GET_STACK_POINTER(regs);

		kprintf("*rsp:%lx,*rsp+8:%lx,*rsp+16:%lx,*rsp+24:%lx,\n",
				sp[0], sp[1], sp[2], sp[3]);
	}
#endif
}


static void page_fault_handler(void *fault_addr, uint64_t reason, void *regs)
{
	struct thread *thread = cpu_local_var(current);
#ifdef ENABLE_TOFU
	unsigned long addr = (unsigned long)fault_addr;
#endif
	int error;
#ifdef PROFILE_ENABLE
	uint64_t t_s = 0;
	if (thread && thread->profile)
		t_s = rdtsc();
#endif // PROFILE_ENABLE

	set_cputime(interrupt_from_user(regs) ?
		CPUTIME_MODE_U2K : CPUTIME_MODE_K2K_IN);
	dkprintf("%s: addr: %p, reason: %lx, regs: %p\n",
			__FUNCTION__, fault_addr, reason, regs);

	preempt_disable();
#ifdef ENABLE_FUGAKU_HACKS
	++cpu_local_var(in_page_fault);
	if (cpu_local_var(in_page_fault) > 1) {
		kprintf("%s: PF in PF??\n", __func__);
		cpu_disable_interrupt();
		if (!(reason & PF_USER)) {
			cpu_local_var(kernel_mode_pf_regs) = regs;
			panic("panic: kernel mode PF in PF");
		}
		while (1) {
			panic("PANIC");
		}
	}
#endif

	cpu_enable_interrupt();

#ifdef ENABLE_TOFU
	if (!(reason & PF_USER) &&
			(addr > 0xffff000000000000 &&
			 addr < 0xffff800000000000)) {
		int error;
		int ihk_mc_linux_pt_virt_to_phys_size(struct page_table *pt,
				const void *virt,
				unsigned long *phys,
				unsigned long *size);

		unsigned long phys, size;
		enum ihk_mc_pt_attribute attr = PTATTR_WRITABLE | PTATTR_ACTIVE;

		if (ihk_mc_linux_pt_virt_to_phys_size(ihk_mc_get_linux_kernel_pgt(),
					fault_addr, &phys, &size) < 0) {
			kprintf("%s: failed to resolve 0x%lx from Linux PT..\n",
				__func__, addr);
			goto out_linux;	
		}

retry_linux:
		if ((error = ihk_mc_pt_set_page(NULL, fault_addr, phys, attr)) < 0) {
			if (error == -EBUSY) {
				kprintf("%s: WARNING: updating 0x%lx -> 0x%lx"
						" to reflect Linux kernel mapping..\n",
						__func__, addr, phys);
				ihk_mc_clear_kernel_range(fault_addr, fault_addr + PAGE_SIZE);
				goto retry_linux;
			}
			else {
				kprintf("%s: failed to set up 0x%lx -> 0x%lx Linux kernel mapping..\n",
						__func__, addr, phys);
				goto out_linux;
			}
		}

		dkprintf("%s: Linux kernel mapping 0x%lx -> 0x%lx set\n",
				__func__, addr, phys);
		goto out_ok;
	}
out_linux:
#endif

	if ((uintptr_t)fault_addr < PAGE_SIZE || !thread) {
		error = -EINVAL;
	} else {
		error = page_fault_process_vm(thread->vm, fault_addr, reason);
	}
	if (error) {
		struct siginfo info;

		if (error == -ECANCELED) {
			dkprintf("process is exiting, terminate.\n");

			preempt_enable();
			terminate(0, SIGSEGV);
			// no return
		}

		kprintf("%s fault VM failed for TID: %d, addr: 0x%lx, reason: %d, error: %d\n",
			__func__, thread ? thread->tid : -1, fault_addr,
			reason, error);
		unhandled_page_fault(thread, fault_addr, reason, regs);
		preempt_enable();

#ifdef ENABLE_FUGAKU_DEBUG
		//kprintf("%s: sending SIGSTOP to TID: %d\n", __func__, thread->tid);
		//do_kill(thread, thread->proc->pid, thread->tid, SIGSTOP, NULL, 0);
		//goto out;
#endif

		memset(&info, '\0', sizeof info);
		if (error == -ERANGE) {
			info.si_signo = SIGBUS;
			info.si_code = BUS_ADRERR;
			info._sifields._sigfault.si_addr = fault_addr;
			set_signal(SIGBUS, regs, &info);
		}
		else {
			struct vm_range *range = NULL;

			info.si_signo = SIGSEGV;
			info.si_code = SEGV_MAPERR;
			if (thread)
				range = lookup_process_memory_range(thread->vm,
						(uintptr_t)fault_addr,
						((uintptr_t)fault_addr) + 1);
			if (range)
				info.si_code = SEGV_ACCERR;
			info._sifields._sigfault.si_addr = fault_addr;
			set_signal(SIGSEGV, regs, &info);
		}
		goto out;
	}

#ifdef ENABLE_TOFU
out_ok:
#endif
	error = 0;
#ifdef ENABLE_FUGAKU_HACKS
	--cpu_local_var(in_page_fault);
#endif
	preempt_enable();
out:
	dkprintf("%s: addr: %p, reason: %lx, regs: %p -> error: %d\n",
			__FUNCTION__, fault_addr, reason, regs, error);
	if(interrupt_from_user(regs)){
		cpu_enable_interrupt();
		check_need_resched();
		check_signal(0, regs, -1);
	}
	set_cputime(interrupt_from_user(regs) ?
		CPUTIME_MODE_K2U : CPUTIME_MODE_K2K_OUT);
#ifdef PROFILE_ENABLE
	if (thread && thread->profile)
		profile_event_add(PROFILE_page_fault, (rdtsc() - t_s));
#endif // PROFILE_ENABLE
	return;
}

static struct ihk_page_allocator_desc *page_allocator_init(uint64_t start, 
		uint64_t end)
{
	struct ihk_page_allocator_desc *pa_allocator;
	unsigned long page_map_pa, pages;
	void *page_map;
	unsigned int i;
	extern char _end[];
	unsigned long phys_end = virt_to_phys(_end);

	start &= PAGE_MASK;
	pa_start = (start + PAGE_SIZE - 1) & PAGE_MASK;
	pa_end = end & PAGE_MASK;

#ifdef ATTACHED_MIC
	/* 
	 * Can't allocate in reserved area 
	 * TODO: figure this out automatically! 
	*/
	page_map_pa = 0x100000;
#else
	if (pa_start <= phys_end && phys_end <= pa_end) {
		page_map_pa = virt_to_phys(get_last_early_heap());
	}
	else {
		page_map_pa = pa_start;
	}
#endif

	page_map = phys_to_virt(page_map_pa);

	pa_allocator = __ihk_pagealloc_init(pa_start, pa_end - pa_start,
	                                    PAGE_SIZE, page_map, &pages);

	reserve_pages(pa_allocator, page_map_pa, 
			page_map_pa + pages * PAGE_SIZE, 0);

	if (pa_start < start) {
		reserve_pages(pa_allocator, pa_start, start, 0);
	}

	/* BIOS reserved ranges */
	for (i = 1; i <= ihk_mc_get_memory_address(IHK_MC_NR_RESERVED_AREAS, 0); 
	     ++i) {
		reserve_pages(pa_allocator,
				ihk_mc_get_memory_address(IHK_MC_RESERVED_AREA_START, i),
				ihk_mc_get_memory_address(IHK_MC_RESERVED_AREA_END, i), 0);
	}
	
	ihk_mc_reserve_arch_pages(pa_allocator, pa_start, pa_end, reserve_pages);

	return pa_allocator;
}

static void numa_init(void)
{
	int i, j;

	for (i = 0; i < ihk_mc_get_nr_numa_nodes(); ++i) {
		int linux_numa_id, type;

		if (ihk_mc_get_numa_node(i, &linux_numa_id, &type) != 0) {
			kprintf("%s: error: obtaining NUMA info for node %d\n",
					__FUNCTION__, i);
			panic("");
		}

		memory_nodes[i].id = i;
		memory_nodes[i].linux_numa_id = linux_numa_id;
		memory_nodes[i].type = type;
		INIT_LIST_HEAD(&memory_nodes[i].allocators);
		memory_nodes[i].nodes_by_distance = 0;
#ifdef IHK_RBTREE_ALLOCATOR
		ihk_atomic_set(&memory_nodes[i].zeroing_workers, 0);
		ihk_atomic_set(&memory_nodes[i].nr_to_zero_pages, 0);
		memory_nodes[i].free_chunks.rb_node = 0;
		init_llist_head(&memory_nodes[i].zeroed_list);
		init_llist_head(&memory_nodes[i].to_zero_list);
		mcs_lock_init(&memory_nodes[i].lock);
		memory_nodes[i].min_addr = 0xFFFFFFFFFFFFFFFF;
		memory_nodes[i].max_addr = 0;
		memory_nodes[i].nr_pages = 0;
		memory_nodes[i].nr_free_pages = 0;
#endif
	}

	for (j = 0; j < ihk_mc_get_nr_memory_chunks(); ++j) {
		unsigned long start, end;
		int numa_id;
#ifndef IHK_RBTREE_ALLOCATOR
		struct ihk_page_allocator_desc *allocator;
#endif

		ihk_mc_get_memory_chunk(j, &start, &end, &numa_id);

		if (virt_to_phys(get_last_early_heap()) >= start &&
				virt_to_phys(get_last_early_heap()) < end) {
			dkprintf("%s: start from 0x%lx\n",
					__FUNCTION__, virt_to_phys(get_last_early_heap()));
			start = virt_to_phys(get_last_early_heap());
		}

#ifdef IHK_RBTREE_ALLOCATOR
		ihk_numa_add_free_pages(&memory_nodes[numa_id], start, end - start);
#else
		allocator = page_allocator_init(start, end);
		list_add_tail(&allocator->list, &memory_nodes[numa_id].allocators);
#endif

#ifdef IHK_RBTREE_ALLOCATOR
		kprintf("Physical memory: 0x%lx - 0x%lx, %lu bytes, %d pages available @ NUMA: %d\n",
				start, end,
				end - start,
				(end - start) >> PAGE_SHIFT,
				numa_id);
#else
		kprintf("Physical memory: 0x%lx - 0x%lx, %lu bytes, %d pages available @ NUMA: %d\n",
				start, end,
				ihk_pagealloc_count(allocator) * PAGE_SIZE,
				ihk_pagealloc_count(allocator),
				numa_id);
#endif
#ifdef IHK_RBTREE_ALLOCATOR
		rusage_total_memory_add(end - start);
#else
		rusage_total_memory_add(ihk_pagealloc_count(allocator) *
				PAGE_SIZE);
#endif
	}

	for (i = 0; i < ihk_mc_get_nr_numa_nodes(); ++i) {
#ifdef IHK_RBTREE_ALLOCATOR
		kprintf("NUMA: %d, Linux NUMA: %d, type: %d, "
				"available bytes: %lu, pages: %d\n",
				i, memory_nodes[i].linux_numa_id, memory_nodes[i].type,
				memory_nodes[i].nr_free_pages * PAGE_SIZE,
				memory_nodes[i].nr_free_pages);
#else
		kprintf("NUMA: %d, Linux NUMA: %d, type: %d\n",
				i, memory_nodes[i].linux_numa_id, memory_nodes[i].type);
#endif
	}
}

static void numa_distances_init()
{
	int i, j, swapped;

	for (i = 0; i < ihk_mc_get_nr_numa_nodes(); ++i) {
		/* TODO: allocate on target node */
		memory_nodes[i].nodes_by_distance =
			ihk_mc_alloc_pages((sizeof(struct node_distance) *
						ihk_mc_get_nr_numa_nodes() + PAGE_SIZE - 1)
					>> PAGE_SHIFT, IHK_MC_AP_NOWAIT);

		if (!memory_nodes[i].nodes_by_distance) {
			kprintf("%s: error: allocating nodes_by_distance\n",
				__FUNCTION__);
			continue;
		}

		for (j = 0; j < ihk_mc_get_nr_numa_nodes(); ++j) {
			memory_nodes[i].nodes_by_distance[j].id = j;
			memory_nodes[i].nodes_by_distance[j].distance =
				ihk_mc_get_numa_distance(i, j);
		}

		/* Sort by distance and node ID */
		swapped = 1;
		while (swapped) {
			swapped = 0;
			for (j = 1; j < ihk_mc_get_nr_numa_nodes(); ++j) {
				if ((memory_nodes[i].nodes_by_distance[j - 1].distance >
							memory_nodes[i].nodes_by_distance[j].distance) ||
						((memory_nodes[i].nodes_by_distance[j - 1].distance ==
						  memory_nodes[i].nodes_by_distance[j].distance) &&
						 (memory_nodes[i].nodes_by_distance[j - 1].id >
						  memory_nodes[i].nodes_by_distance[j].id))) {
					memory_nodes[i].nodes_by_distance[j - 1].id ^=
						memory_nodes[i].nodes_by_distance[j].id;
					memory_nodes[i].nodes_by_distance[j].id ^=
						memory_nodes[i].nodes_by_distance[j - 1].id;
					memory_nodes[i].nodes_by_distance[j - 1].id ^=
						memory_nodes[i].nodes_by_distance[j].id;

					memory_nodes[i].nodes_by_distance[j - 1].distance ^=
						memory_nodes[i].nodes_by_distance[j].distance;
					memory_nodes[i].nodes_by_distance[j].distance ^=
						memory_nodes[i].nodes_by_distance[j - 1].distance;
					memory_nodes[i].nodes_by_distance[j - 1].distance ^=
						memory_nodes[i].nodes_by_distance[j].distance;
					swapped = 1;
				}
			}
		}
		{
			char buf[1024];
			char *pbuf = buf;

			pbuf += snprintf(pbuf, 1024, "NUMA %d distances: ", i);
			for (j = 0; j < ihk_mc_get_nr_numa_nodes(); ++j) {
				pbuf += snprintf(pbuf, 1024 - (pbuf - buf),
						"%d (%d), ",
						memory_nodes[i].nodes_by_distance[j].id,
						memory_nodes[i].nodes_by_distance[j].distance);
			}
			kprintf("%s\n", buf);
		}
	}
}

static ssize_t numa_sysfs_show_meminfo(struct sysfs_ops *ops,
		void *instance, void *buf, size_t size)
{
#ifdef IHK_RBTREE_ALLOCATOR
	struct ihk_mc_numa_node *node =
		(struct ihk_mc_numa_node *)instance;
	char *sbuf = (char *)buf;
#endif
	int len = 0;

#ifdef IHK_RBTREE_ALLOCATOR
	len += snprintf(&sbuf[len], size - len, "Node %d MemTotal:%15d kB\n",
			node->id,
			node->nr_pages << (PAGE_SHIFT - 10));
	len += snprintf(&sbuf[len], size - len, "Node %d MemFree:%16d kB\n",
			node->id,
			node->nr_free_pages << (PAGE_SHIFT - 10));
	len += snprintf(&sbuf[len], size - len, "Node %d MemUsed:%16d kB\n",
			node->id,
			(node->nr_pages - node->nr_free_pages)
				<< (PAGE_SHIFT - 10));
#endif

	return len;
}

struct sysfs_ops numa_sysfs_meminfo = {
	.show = &numa_sysfs_show_meminfo,
};

void numa_sysfs_setup(void) {
	int i;
	int error;
	char path[PATH_MAX];

	for (i = 0; i < ihk_mc_get_nr_numa_nodes(); ++i) {
		snprintf(path, PATH_MAX,
			 "/sys/devices/system/node/node%d/meminfo", i);

		error = sysfs_createf(&numa_sysfs_meminfo, &memory_nodes[i],
				0444, path);
		if (error) {
			kprintf("%s: ERROR: creating %s\n", __FUNCTION__, path);
		}
	}
}

#define PHYS_PAGE_HASH_SHIFT	(10)
#define PHYS_PAGE_HASH_SIZE     (1 << PHYS_PAGE_HASH_SHIFT)
#define PHYS_PAGE_HASH_MASK     (PHYS_PAGE_HASH_SIZE - 1)

/*
 * Page hash only tracks pages that are mapped in non-anymous mappings
 * and thus it is initially empty.
 */
struct list_head page_hash[PHYS_PAGE_HASH_SIZE];
ihk_spinlock_t page_hash_locks[PHYS_PAGE_HASH_SIZE];

static void page_init(void)
{
	int i;

	for (i = 0; i < PHYS_PAGE_HASH_SIZE; ++i) {
		ihk_mc_spinlock_init(&page_hash_locks[i]);
		INIT_LIST_HEAD(&page_hash[i]);
	}

	return;
}

static int page_hash_count_pages(void)
{
	int i;
	int cnt = 0;

	for (i = 0; i < PHYS_PAGE_HASH_SIZE; ++i) {
		unsigned long irqflags;
		struct page *page_iter;

		irqflags = ihk_mc_spinlock_lock(&page_hash_locks[i]);

		list_for_each_entry(page_iter, &page_hash[i], hash) {
			++cnt;
		}

		ihk_mc_spinlock_unlock(&page_hash_locks[i], irqflags);
	}

	return cnt;
}

/* XXX: page_hash_lock must be held */
static struct page *__phys_to_page(uintptr_t phys)
{
	int hash = (phys >> PAGE_SHIFT) & PHYS_PAGE_HASH_MASK;
	struct page *page_iter, *page = NULL;

	list_for_each_entry(page_iter, &page_hash[hash], hash) {
		if (page_iter->phys == phys) {
			page = page_iter;
			break;
		}
	}

	return page;
}

struct page *phys_to_page(uintptr_t phys)
{
	int hash = (phys >> PAGE_SHIFT) & PHYS_PAGE_HASH_MASK;
	struct page *page = NULL;
	unsigned long irqflags;

	irqflags = ihk_mc_spinlock_lock(&page_hash_locks[hash]);
	page = __phys_to_page(phys);
	ihk_mc_spinlock_unlock(&page_hash_locks[hash], irqflags);

	return page;
}

uintptr_t page_to_phys(struct page *page)
{
	return page ? page->phys : 0;
}

/*
 * Allocate page and add to hash if it doesn't exist yet.
 * NOTE: page->count is zero for new pages and the caller
 * is responsible to increase it.
 */
struct page *phys_to_page_insert_hash(uint64_t phys)
{
	int hash = (phys >> PAGE_SHIFT) & PHYS_PAGE_HASH_MASK;
	struct page *page = NULL;
	unsigned long irqflags;

	irqflags = ihk_mc_spinlock_lock(&page_hash_locks[hash]);
	page = __phys_to_page(phys);
	if (!page) {
		int hash = (phys >> PAGE_SHIFT) & PHYS_PAGE_HASH_MASK;
		page = kmalloc(sizeof(*page), IHK_MC_AP_CRITICAL);
		if (!page) {
			kprintf("%s: error allocating page\n", __FUNCTION__);
			goto out;
		}

		list_add(&page->hash, &page_hash[hash]);
		page->phys = phys;
		page->mode = PM_NONE;
		INIT_LIST_HEAD(&page->list);
		ihk_atomic_set(&page->count, 0);
	}
out:
	ihk_mc_spinlock_unlock(&page_hash_locks[hash], irqflags);

	return page;
}

int page_unmap(struct page *page)
{
	int hash = (page->phys >> PAGE_SHIFT) & PHYS_PAGE_HASH_MASK;
	unsigned long irqflags;

	irqflags = ihk_mc_spinlock_lock(&page_hash_locks[hash]);
	dkprintf("page_unmap(%p %x %d)\n", page, page->mode, page->count);
	if (ihk_atomic_sub_return(1, &page->count) > 0) {
		/* other mapping exist */
		dkprintf("page_unmap(%p %x %d): 0\n",
				page, page->mode, page->count);
		ihk_mc_spinlock_unlock(&page_hash_locks[hash], irqflags);
		return 0;
	}

	/* no mapping exist  TODO: why is this check??
	if (page->mode != PM_MAPPED) {
		return 1;
	}
	*/

	dkprintf("page_unmap(%p %x %d): 1\n", page, page->mode, page->count);

	list_del(&page->hash);
	ihk_mc_spinlock_unlock(&page_hash_locks[hash], irqflags);
	return 1;
}

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
	void *va;
	unsigned long i, offset;

	offset = (phys & (PAGE_SIZE - 1));
	phys = phys & PAGE_MASK;

	va = (void *)ihk_pagealloc_alloc(vmap_allocator, npages, PAGE_P2ALIGN);
	if (!va) {
		return NULL;
	}
	for (i = 0; i < npages; i++) {
		if (ihk_mc_pt_set_page(NULL, (char *)va + (i << PAGE_SHIFT),
				       phys + (i << PAGE_SHIFT), attr) != 0) {
			int j;

			for (j = 0; j < i; j++) {
				ihk_mc_pt_clear_page(NULL, (char *)va +
						     (j << PAGE_SHIFT));
			}
			ihk_pagealloc_free(vmap_allocator, (unsigned long)va,
					   npages);
			return NULL;
		}

		flush_tlb_single((unsigned long)(va + (i << PAGE_SHIFT)));
	}
	barrier();	/* Temporary fix for Thunder-X */
	return (char *)va + offset;
}

void ihk_mc_unmap_virtual(void *va, int npages)
{
	unsigned long i;

	va = (void *)((unsigned long)va & PAGE_MASK);
	for (i = 0; i < npages; i++) {
		ihk_mc_pt_clear_page(NULL, (char *)va + (i << PAGE_SHIFT));
		flush_tlb_single((unsigned long)(va + (i << PAGE_SHIFT)));
	}

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

static void rusage_init()
{
	unsigned long phys;
	const struct ihk_mc_cpu_info *cpu_info = ihk_mc_get_cpu_info();

	if (!cpu_info) {
		panic("rusage_init: PANIC: ihk_mc_get_cpu_info returned NULL");
	}

	memset(&rusage, 0, sizeof(rusage));
	rusage.num_processors = cpu_info->ncpus;
	rusage.num_numa_nodes = ihk_mc_get_nr_numa_nodes();
	rusage.ns_per_tsc = ihk_mc_get_ns_per_tsc();
	phys = virt_to_phys(&rusage);
	ihk_set_rusage(phys, sizeof(struct rusage_global));
	dkprintf("%s: rusage.total_memory=%ld\n", __FUNCTION__, rusage.total_memory);
}

extern void monitor_init(void);
void mem_init(void)
{
	monitor_init();

	/* It must precedes numa_init() because rusage.total_memory is initialized in numa_init() */
	rusage_init();

	/* Initialize NUMA information and memory allocator bitmaps */
	numa_init();

	/* Notify the ihk to use my page allocator */
	ihk_mc_set_page_allocator(&allocator);

	/* And prepare some exception handlers */
	ihk_mc_set_page_fault_handler(page_fault_handler);

	/* Register query free mem handler */
	ihk_mc_register_interrupt_handler(ihk_mc_get_vector(IHK_GV_QUERY_FREE_MEM),
			&query_free_mem_handler);

	/* Init page frame hash */
	page_init();

	/* Prepare the kernel virtual map space */
	virtual_allocator_init();

	if (find_command_line("anon_on_demand")) {
		kprintf("Demand paging on ANONYMOUS mappings enabled.\n");
		anon_on_demand = 1;
	}
	
#ifdef ENABLE_FUGAKU_HACKS
	if (find_command_line("hugetlbfs_on_demand")) {
		kprintf("Demand paging on hugetlbfs mappings enabled.\n");
		hugetlbfs_on_demand = 1;
	}
#endif

	/* Init distance vectors */
	numa_distances_init();
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
void *_kmalloc(int size, ihk_mc_ap_flag flag, char *file, int line)
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
			ihk_mc_spinlock_unlock(&kmalloc_track_hash_locks[hash], irqflags);
			kprintf("%s: ERROR: allocating tracking entry\n");
			goto out;
		}

		entry->line = line;
		entry->size = size;
		ihk_atomic_set(&entry->alloc_count, 1);
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
		INIT_LIST_HEAD(&entry->hash);
		list_add(&entry->hash, &kmalloc_track_hash[hash]);
		dkprintf("%s entry %s:%d size: %d added\n", __FUNCTION__,
			file, line, size);
	}
	else {
		ihk_atomic_inc(&entry->alloc_count);
	}
	ihk_mc_spinlock_unlock(&kmalloc_track_hash_locks[hash], irqflags);

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

	if (!ptr) {
		return;
	}

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
		kprintf("%s: ERROR: kfree()ing invalid pointer at %s:%d\n",
			__FUNCTION__, file, line);
		panic("panic");
	}

	entry = addr_entry->entry;

	irqflags = ihk_mc_spinlock_lock(&entry->addr_list_lock);
	list_del(&addr_entry->list);
	ihk_mc_spinlock_unlock(&entry->addr_list_lock, irqflags);

	dkprintf("%s addr_entry %p removed\n", __FUNCTION__, addr_entry->addr);
	___kfree(addr_entry);

	/* Do we need to remove tracking entry as well? */
	hash = (strlen(entry->file) + entry->line + entry->size) &
		KMALLOC_TRACK_HASH_MASK;
	irqflags = ihk_mc_spinlock_lock(&kmalloc_track_hash_locks[hash]);

	if (!ihk_atomic_dec_and_test(&entry->alloc_count)) {
		ihk_mc_spinlock_unlock(&kmalloc_track_hash_locks[hash], irqflags);
		goto out;
	}

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
void *__kmalloc(int size, ihk_mc_ap_flag flag)
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
	/* Add tail */
	else {
		list_add_tail(&chunk->list, free_list);
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
#define KMALLOC_MIN_SIZE    (1 << KMALLOC_MIN_SHIFT)
#define KMALLOC_MIN_MASK    (KMALLOC_MIN_SIZE - 1)

/* Actual low-level allocation routines */
static void *___kmalloc(int size, ihk_mc_ap_flag flag)
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
	/* Use low-level page allocator to avoid tracking */
	chunk = ___ihk_mc_alloc_pages(npages, flag, IHK_MC_PG_KERNEL);

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
	struct kmalloc_header *chunk;
	unsigned long kmalloc_irq_flags;

	if (!ptr)
		return;

	chunk = (struct kmalloc_header*)(ptr - sizeof(struct kmalloc_header));
	kmalloc_irq_flags = cpu_disable_interrupt_save();

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

#ifdef IHK_RBTREE_ALLOCATOR
int is_mckernel_memory(unsigned long start, unsigned long end)
{
	int i;

	for (i = 0; i < ihk_mc_get_nr_memory_chunks(); ++i) {
		unsigned long chunk_start, chunk_end;
		int numa_id;

		ihk_mc_get_memory_chunk(i, &chunk_start, &chunk_end, &numa_id);
		if ((chunk_start <= start && start < chunk_end) &&
		    (chunk_start <= end && end <= chunk_end)) {
			return 1;
		}
	}
	return 0;
}
#else /* IHK_RBTREE_ALLOCATOR */
int is_mckernel_memory(unsigned long start, unsigned long end)
{
	int i;

	for (i = 0; i < ihk_mc_get_nr_numa_nodes(); ++i) {
		struct ihk_page_allocator_desc *pa_allocator;
		unsigned long area_start = pa_allocator->start;
		unsigned long area_end = pa_allocator->end;

		list_for_each_entry(pa_allocator,
				    &memory_nodes[i].allocators, list) {
			if ((area_start <= start && start < area_end) &&
			    (area_start <= end && end <= area_end)) {
				return 1;
			}
		}
	}
	return 0;
}
#endif /* IHK_RBTREE_ALLOCATOR */

void ihk_mc_query_mem_areas(void){

	int cpu_id;
	struct ihk_dump_page_set *dump_page_set;
	struct dump_pase_info dump_pase_info;

	/*
	 * Performed only on the last CPU to make sure
	 * all other cores are already stopped.
	 */
	cpu_id = ihk_mc_get_processor_id();

	if (num_processors - 1 != cpu_id)
		return;

	dump_page_set = ihk_mc_get_dump_page_set();
	
	if (DUMP_LEVEL_USER_UNUSED_EXCLUDE == ihk_mc_get_dump_level()) {
		if (dump_page_set->count) {

			dump_pase_info.dump_page_set = dump_page_set;
			dump_pase_info.dump_pages = ihk_mc_get_dump_page();

			/* Get user page information */
			ihk_mc_query_mem_user_page((void *)&dump_pase_info);
			/* Get unused page information */
			ihk_mc_query_mem_free_page((void *)&dump_pase_info);
		}
	}

	dump_page_set->completion_flag = IHK_DUMP_PAGE_SET_COMPLETED;
	dkprintf("%s: IHK_DUMP_PAGE_SET_COMPLETED\n", __func__);

	return;
}

void ihk_mc_clear_dump_page_completion(void)
{
	struct ihk_dump_page_set *dump_page_set;

	dump_page_set = ihk_mc_get_dump_page_set();
	dump_page_set->completion_flag = IHK_DUMP_PAGE_SET_INCOMPLETE;
}

void ihk_mc_query_mem_user_page(void *dump_pase_info) {

	struct resource_set *rset = cpu_local_var(resource_set);
	struct process_hash *phash = rset->process_hash;
	struct process *p; 
	struct process_vm *vm;
	int i;

	for (i=0; i<HASH_SIZE; i++) {

		list_for_each_entry(p, &phash->list[i], hash_list){
			vm = p->vm;
			if (vm) {
				if(vm->address_space->page_table) {
					visit_pte_range_safe(vm->address_space->page_table, 0,
					(void *)USER_END, 0, 0,
					&ihk_mc_get_mem_user_page, (void *)dump_pase_info);
				}
			}
		}
	}

	return;
}

void ihk_mc_query_mem_free_page(void *dump_pase_info) {
#ifdef IHK_RBTREE_ALLOCATOR
	struct free_chunk *chunk;
	struct rb_node *node;
	struct rb_root *free_chunks;
	unsigned long phy_start, map_start, map_end, free_pages, free_page_cnt, map_size, set_size, k;
	int i, j;
	struct ihk_dump_page_set *dump_page_set;
	struct ihk_dump_page *dump_page;
	struct dump_pase_info *dump_pase_in;
	unsigned long chunk_addr, chunk_size;

	dump_pase_in = (struct dump_pase_info *)dump_pase_info;
	dump_page_set = dump_pase_in->dump_page_set;

	/* Search all NUMA nodes */
	for (i = 0; i < ihk_mc_get_nr_numa_nodes(); i++) {

		free_chunks = &memory_nodes[i].free_chunks;
		free_pages = memory_nodes[i].nr_free_pages;

		/* rb-tree search */
		for (free_page_cnt = 0, node = rb_first_safe(free_chunks); node; free_page_cnt++, node = rb_next_safe(node)) {

			if (free_page_cnt >= free_pages)
				break;

			/* Get chunk information */
			chunk = container_of(node, struct free_chunk, node);

			dump_page = dump_pase_in->dump_pages;
			chunk_addr = chunk->addr;
			chunk_size = chunk->size;

			for (j = 0; j < dump_page_set->count; j++) {

				if (j) {
					dump_page = (struct ihk_dump_page *)((char *)dump_page + ((dump_page->map_count * sizeof(unsigned long)) + sizeof(struct ihk_dump_page)));
				}

				phy_start = dump_page->start;
				map_size = (dump_page->map_count << (PAGE_SHIFT+6));

				if ((chunk_addr >= phy_start)
					&& ((phy_start + map_size) >= chunk_addr)) {

					/* Set free page to page map */
					map_start = (chunk_addr - phy_start) >> PAGE_SHIFT;

					if ((phy_start + map_size) < (chunk_addr + chunk_size)) {
						set_size = map_size - (chunk_addr - phy_start);
						map_end = (map_start + (set_size >> PAGE_SHIFT));
						chunk_addr += set_size;
						chunk_size -= set_size;
					} else {
						map_end = (map_start + (chunk_size >> PAGE_SHIFT));
					}

					for (k = map_start; k < map_end; k++) {

						if (MAP_INDEX(k) >= dump_page->map_count) {
							kprintf("%s:free page is out of range(max:%d): %ld (map_start:0x%lx, map_end:0x%lx) k(0x%lx)\n", __FUNCTION__, dump_page->map_count, MAP_INDEX(k), map_start, map_end, k);
							break;
						}

						dump_page->map[MAP_INDEX(k)] &= ~(1UL << MAP_BIT(k));
					}
				}
			}
		}
	}
#endif
	return;
}

int ihk_mc_chk_page_address(pte_t mem_addr){

	int i, numa_id;;
	unsigned long start, end;

	/* Search all NUMA nodes */
	for (i = 0; i < ihk_mc_get_nr_memory_chunks(); i++) {
		ihk_mc_get_memory_chunk(i, &start, &end, &numa_id);
		if ((mem_addr >= start) && (end >= mem_addr))
			return 0;
	}

	return -1;
}

int ihk_mc_get_mem_user_page(void *arg0, page_table_t pt, pte_t *ptep, void *pgaddr, int pgshift)
{
	struct ihk_dump_page_set *dump_page_set;
	int i;
	unsigned long j, phy_start, phys, map_start, map_end, map_size, set_size;
	struct ihk_dump_page *dump_page;
	struct dump_pase_info *dump_pase_in;
	unsigned long chunk_addr, chunk_size;

	if (((*ptep) & PTATTR_ACTIVE) && ((*ptep) & PTATTR_USER)) {
		phys = pte_get_phys(ptep);
		/* Confirm accessible address */
		if (-1 != ihk_mc_chk_page_address(phys)) {

			dump_pase_in = (struct dump_pase_info *)arg0;
			dump_page_set = dump_pase_in->dump_page_set;
			dump_page = dump_pase_in->dump_pages;

			chunk_addr = phys;
			chunk_size = (1UL << pgshift);

			for (i = 0; i < dump_page_set->count; i++) {

				if (i) {
					dump_page = (struct ihk_dump_page *)((char *)dump_page + ((dump_page->map_count * sizeof(unsigned long)) + sizeof(struct ihk_dump_page)));
				}

				phy_start = dump_page->start;
				map_size = (dump_page->map_count << (PAGE_SHIFT+6));

				if ((chunk_addr >= phy_start)
					&& ((phy_start + map_size) >= chunk_addr)) {

					/* Set user page to page map */
					map_start = (chunk_addr - phy_start) >> PAGE_SHIFT;

					if ((phy_start + map_size) < (chunk_addr + chunk_size)) {
						set_size = map_size - (chunk_addr - phy_start);
						map_end = (map_start + (set_size >> PAGE_SHIFT));
						chunk_addr += set_size;
						chunk_size -= set_size;
					} else {
						map_end = (map_start + (chunk_size >> PAGE_SHIFT));
					}

					for (j = map_start; j < map_end; j++) {

						if (MAP_INDEX(j) >= dump_page->map_count) {
							kprintf("%s:user page is out of range(max:%d): %ld (map_start:0x%lx, map_end:0x%lx) j(0x%lx)\n", __FUNCTION__, dump_page->map_count, MAP_INDEX(j), map_start, map_end, j);
							break;
						}
						dump_page->map[MAP_INDEX(j)] &= ~(1UL << MAP_BIT(j));
					}
				}
			}
		}
	}

	return 0;
}

pte_t *ihk_mc_pt_lookup_fault_pte(struct process_vm *vm, void *virt,
		int pgshift, void **basep, size_t *sizep, int *p2alignp)
{
	int faulted = 0;
	pte_t *ptep;

retry:
	ptep = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
			virt, pgshift, basep, sizep, p2alignp);
	if (!faulted && (!ptep || !pte_is_present(ptep))) {
		page_fault_process_vm(vm, virt, PF_POPULATE | PF_USER);
		faulted = 1;
		goto retry;
	}

	if (faulted && ptep && pte_is_present(ptep)) {
		kprintf("%s: successfully faulted 0x%lx\n", __FUNCTION__, virt);
	}

	return ptep;
}
