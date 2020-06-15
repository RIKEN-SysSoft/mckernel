/* memory.c COPYRIGHT FUJITSU LIMITED 2015-2018 */
#include <ihk/cpu.h>
#include <ihk/mm.h>
#include <types.h>
#include <memory.h>
#include <string.h>
#include <errno.h>
#include <list.h>
#include <process.h>
#include <page.h>
#include <cls.h>
#include <arch/cpu.h>
#include <context.h>
#include <kmalloc.h>
#include <vdso.h>
#include <ihk/debug.h>
#include <rusage_private.h>
#include <cputype.h>

//#define DEBUG

#ifdef DEBUG
#undef DDEBUG_DEFAULT
#define DDEBUG_DEFAULT DDEBUG_PRINT
#endif

#define NOT_IMPLEMENTED()  do { kprintf("%s is not implemented\n", __func__); while(1);} while(0)

static char *last_page;
extern char _head[], _end[];

char empty_zero_page[PAGE_SIZE] = { 0 };

extern unsigned long arm64_kernel_phys_base;
extern unsigned long arm64_st_phys_base;
extern unsigned long arm64_st_phys_size;

int safe_kernel_map;

/* Arch specific early allocation routine */
void *early_alloc_pages(int nr_pages)
{
	void *p;

	if (last_page == NULL) {
		last_page = (void *)MAP_EARLY_ALLOC;
	}
	else if (last_page == (void *)-1) {
		panic("Early allocator is already finalized. Do not use it.\n");
	}
	else if (MAP_EARLY_ALLOC_END <= (unsigned long)last_page) {
		panic("Early allocator is out of memory.\n");
	}
	p = last_page;
	last_page += (nr_pages * PAGE_SIZE);

	return p;
}

void early_alloc_invalidate(void)
{
	last_page = (void *)-1;
}

void *ihk_mc_allocate(int size, int flag)
{
	if (!cpu_local_var(kmalloc_initialized)) {
		kprintf("%s: error, kmalloc not yet initialized\n", __FUNCTION__);
		return NULL;
	}
	return kmalloc(size, IHK_MC_AP_NOWAIT);
}

void ihk_mc_free(void *p)
{
	if (!cpu_local_var(kmalloc_initialized)) {
		kprintf("%s: error, kmalloc not yet initialized\n", __FUNCTION__);
		return;
	}
	kfree(p);
}

void *get_last_early_heap(void)
{
	return last_page;
}

/*
 * flush_tlb(void)
 *   - Flush all EL1 & 0 stage 1 TLB entries if
 *     current VMID have the same entries.
 *     (If VHE=on, EL2 & 0 entries.)
 *
 *   - All cores in the same Inner Shareable domain.
 *
 * flush_tlb_single(unsigned long addr)
 *   - Flush EL1 & 0 stage 1 TLB entries if given VA, current ASID and
 *     current VMID have the same entries.
 *     (If VHE=on, EL2 & 0 entries.)
 *
 *   - All cores in the same Inner Shareable domain.
 *
 * arch_flush_tlb_single(int asid, unsigned long addr)
 *   - Flush EL1 & 0 stage 1 TLB entries if given VA, given ASID and
 *     current VMID have the same entries.
 *     (If VHE=on, EL2 & 0 entries.)
 *
 *   - All cores in the same Inner Shareable domain.
 *
 */
void flush_tlb(void)
{
	dsb(ishst);
	asm("tlbi	vmalle1is");
	dsb(ish);
	isb();
}

static inline void arch_flush_tlb_single(const int asid, const unsigned long addr)
{
	unsigned long flush = 0;
	flush = addr >> 12UL;
	flush |= (unsigned long)asid << 48UL;

	dsb(ishst);
	asm("tlbi	vae1is, %0" : : "r" (flush));
	dsb(ish);
}

void flush_tlb_single(unsigned long addr)
{
	struct thread *thread = cpu_local_var(current);
	struct process_vm* vm = NULL;
	struct address_space *adsp = NULL;
	struct page_table* pt = NULL;
	int asid = 0;

	if (thread) {
		vm = thread->vm;
		if (vm) {
			adsp = vm->address_space;
			if (adsp) {
				pt = adsp->page_table;
				if (pt) {
					asid = get_address_space_id(pt);
				}
			}
		}
	}
	arch_flush_tlb_single(asid, addr);
}

extern struct page_table swapper_page_table;
static struct page_table *init_pt = &swapper_page_table;
static ihk_spinlock_t init_pt_lock;

/* val */
static inline pte_t ptl4_val(const pte_t* l4p)
{
	pte_t pte = 0;
	if (CONFIG_ARM64_PGTABLE_LEVELS > 3) {
		pte = *l4p;
	} else {
		/* ダミー値を返却 */
		void* phys = (void*)0;
		pte = (pte_t)phys & PT_PHYSMASK;
		pte = pte | PMD_SECT_VALID | PMD_TYPE_TABLE;
	}
	return pte;
}
static inline pte_t ptl3_val(const pte_t* l3p)
{
	pte_t pte = 0;
	if (CONFIG_ARM64_PGTABLE_LEVELS > 2) {
		pte = *l3p;
	} else {
		/* ダミー値を返却 */
		void* phys = (void*)0;
		pte = (pte_t)phys & PT_PHYSMASK;
		pte = pte | PMD_SECT_VALID | PMD_TYPE_TABLE;
	}
	return pte;
}
static inline pte_t ptl2_val(const pte_t* l2p)
{
	return *l2p;
}
static inline pte_t ptl1_val(const pte_t* l1p)
{
	return *l1p;
}
static inline pte_t ptl_val(const pte_t* p, int level)
{
	pte_t pte = PTE_NULL;
	switch (level) {
 	case 4:
		pte = ptl4_val(p);
		break;
 	case 3:
		pte = ptl3_val(p);
		break;
 	case 2:
		pte = ptl2_val(p);
		break;
 	case 1:
		pte = ptl1_val(p);
		break;
	default:
		panic("ptl_val failed.\n");
	}
	return pte;
}

/* index */
static inline int ptl4_index(unsigned long addr)
{
	int idx = (addr >> PTL4_SHIFT) & PTL4_INDEX_MASK;
	return idx;
}
static inline int ptl3_index_linux(unsigned long addr)
{
	int idx = (addr >> PTL3_SHIFT) & PTL3_INDEX_MASK_LINUX;
	return idx;
}
static inline int ptl3_index(unsigned long addr)
{
	int idx = (addr >> PTL3_SHIFT) & PTL3_INDEX_MASK;
	return idx;
}
static inline int ptl2_index(unsigned long addr)
{
	int idx = (addr >> PTL2_SHIFT) & PTL2_INDEX_MASK;
	return idx;
}
static inline int ptl1_index(unsigned long addr)
{
	int idx = (addr >> PTL1_SHIFT) & PTL1_INDEX_MASK;
	return idx;
}
static inline int ptl_index(unsigned long addr, int level)
{
	int idx = 0;
	switch (level) {
 	case 4:
		idx = ptl4_index(addr);
		break;
 	case 3:
		idx = ptl3_index(addr);
		break;
 	case 2:
		idx = ptl2_index(addr);
		break;
 	case 1:
		idx = ptl1_index(addr);
		break;
	default:
		panic("ptl_index failed.\n");
	}
	return idx;
}

/* offset */
static inline pte_t* ptl4_offset(const translation_table_t* ptl4, unsigned long addr)
{
	pte_t* ptep = NULL;
	int idx = 0;

	switch (CONFIG_ARM64_PGTABLE_LEVELS)
	{
	case 4:
		idx = ptl4_index(addr);
		ptep = (pte_t*)ptl4 + idx;
		break;
	case 3:
	case 2:
	case 1:
		/* PTL4が無いときにはエントリではなくページテーブルのアドレスを引渡していく */
		ptep = (pte_t*)ptl4;
		break;
	}
	return ptep;
}

static inline pte_t* ptl3_offset_linux(const pte_t* l4p, unsigned long addr)
{
	pte_t* ptep = NULL;
	pte_t pte = 0;
	unsigned long phys = 0;
	translation_table_t* ptl3 = NULL;
	int idx = 0;

	switch (CONFIG_ARM64_PGTABLE_LEVELS)
	{
	case 4:
		pte = ptl4_val(l4p);
		phys = pte & PT_PHYSMASK;
		ptl3 = phys_to_virt(phys);
		idx = ptl3_index_linux(addr);
		ptep = (pte_t*)ptl3 + idx;
		break;
	case 3:
		ptl3 = (translation_table_t*)l4p;
		idx = ptl3_index_linux(addr);
		ptep = (pte_t*)ptl3 + idx;
		break;
	case 2:
	case 1:
		/* PTL3が無いときにはエントリではなくページテーブルのアドレスを引渡していく。*/
		ptep = (pte_t*)l4p;
		break;
	}
	return ptep;
}

static inline pte_t* ptl3_offset(const pte_t* l4p, unsigned long addr)
{
	pte_t* ptep = NULL;
	pte_t pte = 0;
	unsigned long phys = 0;
	translation_table_t* ptl3 = NULL;
	int idx = 0;

	switch (CONFIG_ARM64_PGTABLE_LEVELS)
	{
	case 4:
		pte = ptl4_val(l4p);
		phys = pte & PT_PHYSMASK;
		ptl3 = phys_to_virt(phys);
		idx = ptl3_index(addr);
		ptep = (pte_t*)ptl3 + idx;
		break;
	case 3:
		ptl3 = (translation_table_t*)l4p;
		idx = ptl3_index(addr);
		ptep = (pte_t*)ptl3 + idx;
		break;
	case 2:
	case 1:
		/* PTL3が無いときにはエントリではなくページテーブルのアドレスを引渡していく。*/
		ptep = (pte_t*)l4p;
		break;
	}
	return ptep;
}
static inline pte_t* ptl2_offset(const pte_t* l3p, unsigned long addr)
{
	pte_t* ptep = NULL;
	pte_t pte = 0;
	unsigned long phys = 0;
	translation_table_t* ptl2 = NULL;
	int idx;

	switch (CONFIG_ARM64_PGTABLE_LEVELS)
	{
	case 4:
	case 3:
		pte = ptl3_val(l3p);
		phys = pte & PT_PHYSMASK;
		ptl2 = phys_to_virt(phys);
		break;
	case 2:
	case 1:
		/* PTL2は必ずある*/
		ptl2 = (translation_table_t*)l3p;
		break;
	}
	idx = ptl2_index(addr);
	ptep = (pte_t*)ptl2 + idx;
	return ptep;
}
static inline pte_t* ptl1_offset(const pte_t* l2p, unsigned long addr)
{
	pte_t pte = ptl2_val(l2p);
	unsigned long phys = pte & PT_PHYSMASK;
	translation_table_t* ptl1 = phys_to_virt(phys);
	int idx = ptl1_index(addr);

	return (pte_t*)ptl1 + idx;
}
static inline pte_t* ptl_offset(const void* p, unsigned long addr, int level)
{
	pte_t* ptep = NULL;
	switch (level) {
 	case 4:
		ptep = ptl4_offset((const translation_table_t*)p, addr);
		break;
 	case 3:
		ptep = ptl3_offset((const pte_t*)p, addr);
		break;
 	case 2:
		ptep = ptl2_offset((const pte_t*)p, addr);
		break;
 	case 1:
		ptep = ptl1_offset((const pte_t*)p, addr);
		break;
	default:
		panic("ptl_offset failed.\n");
	}
	return ptep;
}

/* set */
static inline void ptl4_set(pte_t* l4p, pte_t l4)
{
	if (CONFIG_ARM64_PGTABLE_LEVELS > 3) {
		*l4p = l4;
	}
}
static inline void ptl3_set(pte_t* l3p, pte_t l3)
{
	if (CONFIG_ARM64_PGTABLE_LEVELS > 2) {
		*l3p = l3;
	}
}
static inline void ptl2_set(pte_t* l2p, pte_t l2)
{
	*l2p = l2;
}
static inline void ptl1_set(pte_t* l1p, pte_t l1)
{
	*l1p = l1;
}
static inline void ptl_set(pte_t* p, pte_t v, int level)
{
	switch (level) {
 	case 4:
		ptl4_set(p, v);
		break;
 	case 3:
		ptl3_set(p, v);
		break;
 	case 2:
		ptl2_set(p, v);
		break;
 	case 1:
		ptl1_set(p, v);
		break;
	default:
		panic("ptl_set failed.\n");
	}
}

/* clear */
static inline void ptl4_clear(pte_t* l4p)
{
	ptl4_set(l4p, PTE_NULL);
}
static inline void ptl3_clear(pte_t* l3p)
{
	ptl3_set(l3p, PTE_NULL);
}
static inline void ptl2_clear(pte_t* l2p)
{
	ptl2_set(l2p, PTE_NULL);
}
static inline void ptl1_clear(pte_t* l1p)
{
	ptl1_set(l1p, PTE_NULL);
}
static inline void ptl_clear(pte_t* p, int level)
{
	switch (level) {
	case 4:
		ptl4_clear(p);
		break;
	case 3:
		ptl3_clear(p);
		break;
	case 2:
		ptl2_clear(p);
		break;
	case 1:
		ptl1_clear(p);
		break;
	default:
		panic("ptl_clear failed.\n");
	}
}

/* null */
static inline int ptl4_null(const pte_t* l4p)
{
	pte_t pte = ptl4_val(l4p);
	return pte_is_null(&pte);
}
static inline int ptl3_null(const pte_t* l3p)
{
	pte_t pte = ptl3_val(l3p);
	return pte_is_null(&pte);
}
static inline int ptl2_null(const pte_t* l2p)
{
	pte_t pte = ptl2_val(l2p);
	return pte_is_null(&pte);
}
static inline int ptl1_null(const pte_t* l1p)
{
	pte_t pte = ptl1_val(l1p);
	return pte_is_null(&pte);
}
static inline int ptl_null(const pte_t* p, int level)
{
	int ret = 0;
	switch (level) {
 	case 4:
		ret = ptl4_null(p);
		break;
 	case 3:
		ret = ptl3_null(p);
		break;
 	case 2:
		ret = ptl2_null(p);
		break;
 	case 1:
		ret = ptl1_null(p);
		break;
	default:
		panic("ptl_null failed.\n");
	}
	return ret;
}

/* present */
static inline int ptl4_present(const pte_t* l4p)
{
	pte_t pte = ptl4_val(l4p);
	return pte_is_present(&pte);
}
static inline int ptl3_present(const pte_t* l3p)
{
	pte_t pte = ptl3_val(l3p);
	return pte_is_present(&pte);
}
static inline int ptl2_present(const pte_t* l2p)
{
	pte_t pte = ptl2_val(l2p);
	return pte_is_present(&pte);
}
static inline int ptl1_present(const pte_t* l1p)
{
	pte_t pte = ptl1_val(l1p);
	return pte_is_present(&pte);
}
static inline int ptl_present(const pte_t* p, int level)
{
	int ret = 0;
	switch (level) {
 	case 4:
		ret = ptl4_present(p);
		break;
 	case 3:
		ret = ptl3_present(p);
		break;
 	case 2:
		ret = ptl2_present(p);
		break;
 	case 1:
		ret = ptl1_present(p);
		break;
	default:
		panic("ptl_present failed.\n");
	}
	return ret;
}

/* type_block/type_page */
static inline int ptl4_type_block(const pte_t* l4p)
{
	pte_t pte = ptl4_val(l4p);
	int ret = pte_is_type_page(&pte, PTL4_SIZE);
	return ret;
}
static inline int ptl3_type_block(const pte_t* l3p)
{
	pte_t pte = ptl3_val(l3p);
	int ret = pte_is_type_page(&pte, PTL3_SIZE);
	return ret;
}
static inline int ptl2_type_block(const pte_t* l2p)
{
	pte_t pte = ptl2_val(l2p);
	int ret = pte_is_type_page(&pte, PTL2_SIZE);
	return ret;
}
static inline int ptl1_type_page(const pte_t* l1p)
{
	pte_t pte = ptl1_val(l1p);
	int ret = pte_is_type_page(&pte, PTL1_SIZE);
	return ret;
}
static inline int ptl_type_page(const pte_t* p, int level)
{
	int ret = 0;
	switch (level) {
 	case 4:
		ret = ptl4_type_block(p);
		break;
 	case 3:
		ret = ptl3_type_block(p);
		break;
 	case 2:
		ret = ptl2_type_block(p);
		break;
 	case 1:
		ret = ptl1_type_page(p);
		break;
	default:
		panic("ptl_page failed.\n");
	}
	return ret;
}

/* contiguous */
static inline int ptl4_is_contiguous(const pte_t *l4p)
{
	pte_t pte = ptl4_val(l4p);

	return pte_is_contiguous(&pte);
}
static inline int ptl3_is_contiguous(const pte_t *l3p)
{
	pte_t pte = ptl3_val(l3p);

	return pte_is_contiguous(&pte);
}
static inline int ptl2_is_contiguous(const pte_t *l2p)
{
	pte_t pte = ptl2_val(l2p);

	return pte_is_contiguous(&pte);
}
static inline int ptl1_is_contiguous(const pte_t *l1p)
{
	pte_t pte = ptl1_val(l1p);

	return pte_is_contiguous(&pte);
}
static inline int ptl_is_contiguous(const pte_t *p, int level)
{
	int ret = 0;

	switch (level) {
	case 4:
		ret = ptl4_is_contiguous(p);
		break;
	case 3:
		ret = ptl3_is_contiguous(p);
		break;
	case 2:
		ret = ptl2_is_contiguous(p);
		break;
	case 1:
		ret = ptl1_is_contiguous(p);
		break;
	default:
		panic("ptl_is_contiguous failed.\n");
	}
	return ret;
}

/* type_table */
static inline int ptl4_type_table(const pte_t* l4p)
{
	pte_t pte = ptl4_val(l4p);
	return (pte & PMD_TYPE_MASK) == PMD_TYPE_TABLE;
}
static inline int ptl3_type_table(const pte_t* l3p)
{
	pte_t pte = ptl3_val(l3p);
	return (pte & PMD_TYPE_MASK) == PMD_TYPE_TABLE;
}
static inline int ptl2_type_table(const pte_t* l2p)
{
	pte_t pte = ptl2_val(l2p);
	return (pte & PMD_TYPE_MASK) == PMD_TYPE_TABLE;
}
static inline int ptl1_type_table(const pte_t* l1p)
{
	return 0;
}
static inline int ptl_type_table(const pte_t* p, int level)
{
	int ret = 0;
	switch (level) {
 	case 4:
		ret = ptl4_type_table(p);
		break;
 	case 3:
		ret = ptl3_type_table(p);
		break;
 	case 2:
		ret = ptl2_type_table(p);
		break;
 	case 1:
		ret = ptl1_type_table(p);
		break;
	default:
		panic("ptl_table failed.\n");
	}
	return ret;
}

/* phys */
static inline unsigned long ptl4_phys(const pte_t* l4p)
{
	pte_t pte = ptl4_val(l4p);
	return pte_get_phys(&pte);
}
static inline unsigned long ptl3_phys(const pte_t* l3p)
{
	pte_t pte = ptl3_val(l3p);
	return pte_get_phys(&pte);
}
static inline unsigned long ptl2_phys(const pte_t* l2p)
{
	pte_t pte = ptl2_val(l2p);
	return pte_get_phys(&pte);
}
static inline unsigned long ptl1_phys(const pte_t* l1p)
{
	pte_t pte = ptl1_val(l1p);
	return pte_get_phys(&pte);
}
static inline unsigned long ptl_phys(const pte_t* p, int level)
{
	unsigned long ret = 0;
	switch (level) {
 	case 4:
		ret = ptl4_phys(p);
		break;
 	case 3:
		ret = ptl3_phys(p);
		break;
 	case 2:
		ret = ptl2_phys(p);
		break;
 	case 1:
		ret = ptl1_phys(p);
		break;
	default:
		panic("ptl_phys failed.\n");
	}
	return ret;
}

/* dirty */
static inline int ptl4_dirty(const pte_t* l4p)
{
	pte_t pte = ptl4_val(l4p);
	return pte_is_dirty(&pte, PTL4_SIZE);
}
static inline int ptl3_dirty(const pte_t* l3p)
{
	pte_t pte = ptl3_val(l3p);
	return pte_is_dirty(&pte, PTL3_SIZE);
}
static inline int ptl2_dirty(const pte_t* l2p)
{
	pte_t pte = ptl2_val(l2p);
	return pte_is_dirty(&pte, PTL2_SIZE);
}
static inline int ptl1_dirty(const pte_t* l1p)
{
	pte_t pte = ptl1_val(l1p);
	return pte_is_dirty(&pte, PTL1_SIZE);
}
static inline int ptl_dirty(const pte_t* p, int level)
{
	int ret = 0;
	switch (level) {
 	case 4:
		ret = ptl4_dirty(p);
		break;
 	case 3:
		ret = ptl3_dirty(p);
		break;
 	case 2:
		ret = ptl2_dirty(p);
		break;
 	case 1:
		ret = ptl1_dirty(p);
		break;
	default:
		panic("ptl_dirty failed.\n");
	}
	return ret;
}

/* fileoff */
static inline int ptl4_fileoff(const pte_t* l4p)
{
	pte_t pte = ptl4_val(l4p);
	return pte_is_fileoff(&pte, PTL4_SIZE);
}
static inline int ptl3_fileoff(const pte_t* l3p)
{
	pte_t pte = ptl3_val(l3p);
	return pte_is_fileoff(&pte, PTL3_SIZE);
}
static inline int ptl2_fileoff(const pte_t* l2p)
{
	pte_t pte = ptl2_val(l2p);
	return pte_is_fileoff(&pte, PTL2_SIZE);
}
static inline int ptl1_fileoff(const pte_t* l1p)
{
	pte_t pte = ptl1_val(l1p);
	return pte_is_fileoff(&pte, PTL1_SIZE);
}
static inline int ptl_fileoff(const pte_t* p, int level)
{
	int ret = 0;
	switch (level) {
 	case 4:
		ret = ptl4_fileoff(p);
		break;
 	case 3:
		ret = ptl3_fileoff(p);
		break;
 	case 2:
		ret = ptl2_fileoff(p);
		break;
 	case 1:
		ret = ptl1_fileoff(p);
		break;
	default:
		panic("ptl_fileoff failed.\n");
	}
	return ret;
}

typedef void (*setup_normal_area_t)(
	translation_table_t *tt,
	unsigned long base_start,
	unsigned long base_end);

static void setup_l2(translation_table_t *tt,
		     unsigned long base_start, unsigned long base_end)
{
	int i, sidx, eidx;
	unsigned long start, end;
	unsigned long virt_start, virt_end;

	//開始インデックスを算出
	virt_start = (unsigned long)phys_to_virt(base_start);
	sidx = ptl2_index(virt_start);

	//現在のテーブルに登録できるアドレスの限界値を算出
	end = __page_align(base_start, PTL2_SIZE * PTL2_ENTRIES);
	end += PTL2_SIZE * PTL2_ENTRIES;

	//終了インデックスを求める
	if (end <= base_end) {
		//現在のテーブルの最終エントリまでを登録対象とする
		eidx = PTL2_ENTRIES - 1;
	} else {
		//base_endが現在のテーブルの管理内ならインデックスを算出
		virt_end = (unsigned long)phys_to_virt(base_end - 1);
		eidx = ptl2_index(virt_end);
	}

	//エントリを登録する
	start = __page_align(base_start, PTL2_SIZE);
	for (i = sidx; i <= eidx; i++) {
		pte_t* ptr;
		pte_t val;

		// 登録先エントリのアドレスを取得
		ptr = &tt[i];

		val = (start & PHYS_MASK) | PFL_KERN_BLK_ATTR;

		// エントリを登録
		ptl2_set(ptr, val);

		// 次のエントリの情報に更新
		start += PTL2_SIZE;
	}
}

static inline void setup_middle_level(translation_table_t *tt, unsigned long base_start, unsigned long base_end,
				      setup_normal_area_t setup, int shift, unsigned long pgsize, int entries, int level)
{
	int i, sidx, eidx;
	unsigned long start, end;
	unsigned long virt_start, virt_end;

	//開始インデックスを算出
	//start = __page_align(base_start, pgsize);
	virt_start = (unsigned long)phys_to_virt(base_start);
	sidx = ptl_index(virt_start, level);

	//現在のテーブルに登録できるアドレスの限界値を算出
	end = __page_align(base_start, pgsize * entries);
	end += pgsize * entries;

	//終了インデックスを求める
	if (end <= base_end) {
		//現在のテーブルの最終エントリまでを登録対象とする
		eidx = entries - 1;
	} else {
		//base_endが現在のテーブルの管理内ならインデックスを算出
		virt_end = (unsigned long)phys_to_virt(base_end - 1);
		eidx = ptl_index(virt_end, level);
	}

	//エントリを登録する
	start = base_start;
	for (i = sidx; i <= eidx; i++) {
		pte_t* ptr;
		pte_t val;
		unsigned long next;
		translation_table_t* next_tt = NULL;

		// 登録先エントリのアドレスを取得
		ptr = &tt[i];

		// ページテーブルを確保して初期化
		if (ptl_null(ptr, level))  {
			next_tt = ihk_mc_alloc_pages(1, IHK_MC_AP_CRITICAL);
			next = virt_to_phys(next_tt);
			memset(next_tt, 0, PAGE_SIZE);
		} else {
			unsigned long arm64_kernel_phys_end;
			unsigned long arm64_early_alloc_phys_end;
#ifdef CONFIG_ARM64_64K_PAGES
			arm64_kernel_phys_end = arm64_kernel_phys_base + (page_align_up(_end) - (unsigned long)_head);
#else
			arm64_kernel_phys_end = arm64_kernel_phys_base + (large_page_align_up(_end) - (unsigned long)_head);
#endif
			arm64_early_alloc_phys_end = arm64_kernel_phys_end + (MAP_EARLY_ALLOC_END - MAP_EARLY_ALLOC);
			
			next = ptl_phys(ptr, level);
			if (arm64_kernel_phys_base <= next && next < arm64_kernel_phys_end) {
				// phys_to_virt of kernel image area.
				struct page_table* pt = get_init_page_table();
				unsigned long va = (unsigned long)pt->tt;
				unsigned long pa = (unsigned long)pt->tt_pa;
				unsigned long diff = va - pa;
				next_tt = (void*)(next + diff);
			} else if (arm64_kernel_phys_end <= next && next < arm64_early_alloc_phys_end) {
				// phys_to_virt of early alloc area.
				unsigned long early_alloc_phys_base = arm64_kernel_phys_end;
				unsigned long offset = next - early_alloc_phys_base;
				next_tt = (void*)(MAP_EARLY_ALLOC + offset);
			} else {
				kprintf("init normal area: leval=%d, next_phys=%p\n", level, next);
				panic("unexpected physical memory area.");
			}
		}
		setup(next_tt, start, base_end);

		val = (next & PHYS_MASK) | PFL_PDIR_TBL_ATTR;

		// エントリを登録
		ptl_set(ptr, val, level);

		// startをページアラインする
		// (各ページレベルにおいて２枚目以降のsidxを0にさせる)
		start = __page_align(start, pgsize);

		// 次のエントリの情報に更新
		start += pgsize;
	}
}

static void setup_l3(translation_table_t *tt,
                              unsigned long base_start, unsigned long base_end)
{
	setup_middle_level(tt, base_start, base_end,
			   setup_l2, PTL3_SHIFT, PTL3_SIZE, PTL3_ENTRIES, 3);
}

static void setup_l4(translation_table_t *tt,
                              unsigned long base_start, unsigned long base_end)
{
	setup_middle_level(tt, base_start, base_end,
			   setup_l3, PTL4_SHIFT, PTL4_SIZE, PTL4_ENTRIES, 4);
}

/**
 * Map the straight map area.
 * @param pt_va page table address(va of the kernel image area or early_alloc area)
 */
static void init_normal_area(struct page_table *pt)
{
	setup_normal_area_t setup_func_table[] = {setup_l2, setup_l3, setup_l4};
	setup_normal_area_t setup = setup_func_table[CONFIG_ARM64_PGTABLE_LEVELS - 2];
	translation_table_t* tt;
	int i;
	
	tt = get_translation_table(pt);

	setup(tt,
			arm64_st_phys_base,
			arm64_st_phys_base  + (1UL << 40));
	return;

	for (i = 0; i < ihk_mc_get_nr_memory_chunks(); i++) {
		unsigned long map_start, map_end;
		int numa_id;
		ihk_mc_get_memory_chunk(i, &map_start, &map_end, &numa_id);		
		kprintf("[%d] map_start = %lx, map_end = %lx @ NUMA: %d\n",
			i, map_start, map_end, numa_id);
		setup(tt, map_start, map_end);
	}
}

static translation_table_t* __alloc_new_tt(ihk_mc_ap_flag ap_flag)
{
	translation_table_t* newtt = ihk_mc_alloc_pages(1, ap_flag);

	if(newtt)
		memset(newtt, 0, PAGE_SIZE);

	return (void*)virt_to_phys(newtt);
}

/*
 * Conversion of attributes for D_Page and D_Block.
 * D_Table is PFL_PDIR_TBL_ATTR fixed.
 */
enum ihk_mc_pt_attribute attr_mask =
	0
	| PTATTR_ACTIVE
	| PTATTR_WRITABLE
	| PTATTR_USER
	| PTATTR_DIRTY
	| PTATTR_FILEOFF
	| PTATTR_LARGEPAGE
	| PTATTR_NO_EXECUTE
	| ARCH_PTATTR_FLIPPED
	;
#define ATTR_MASK attr_mask

static unsigned long attr_to_blockattr(enum ihk_mc_pt_attribute attr)
{
	unsigned long pte = (attr & ATTR_MASK);
	// append D_Block attributes.
	pte = (pte & ~PMD_TYPE_MASK) | PMD_TYPE_SECT;
	if (attr & PTATTR_UNCACHABLE) {
		pte |= PROT_SECT_DEFAULT | PTE_ATTRINDX(MT_DEVICE_nGnRE);
	} else if (attr & PTATTR_WRITE_COMBINED) {
		pte |= PROT_SECT_DEFAULT | PTE_ATTRINDX(MT_NORMAL_NC);
	} else {
		pte |= PROT_SECT_DEFAULT | PTE_ATTRINDX(MT_NORMAL);
	}
	return pte;
}

static unsigned long attr_to_pageattr(enum ihk_mc_pt_attribute attr)
{
	unsigned long pte = (attr & ATTR_MASK);
	// append D_Page attribute.
	pte = (pte & ~PTE_TYPE_MASK) | PTE_TYPE_PAGE;
 	if (attr & PTATTR_UNCACHABLE) {
		pte |= PROT_DEFAULT | PTE_ATTRINDX(MT_DEVICE_nGnRE);
	} else if (attr & PTATTR_WRITE_COMBINED) {
		switch (read_cpuid_id() & MIDR_CPU_MODEL_MASK) {
		/*
		 * Fix up arm64 braindamage of using NORMAL_NC for write
		 * combining when Device GRE exists specifically for the
		 * purpose. Needed on ThunderX2.
		 */
		case MIDR_CPU_MODEL(ARM_CPU_IMP_BRCM, BRCM_CPU_PART_VULCAN):
		case MIDR_CPU_MODEL(ARM_CPU_IMP_CAVIUM, CAVIUM_CPU_PART_THUNDERX2):
			pte |= PROT_DEFAULT | PTE_ATTRINDX(MT_DEVICE_GRE);
			break;
		default:
			pte |= PROT_DEFAULT | PTE_ATTRINDX(MT_NORMAL_NC);
		}
	} else {
		pte |= PROT_DEFAULT | PTE_ATTRINDX(MT_NORMAL);
	}
	return pte;
}

static unsigned long attr_to_l4attr_not_flip(enum ihk_mc_pt_attribute attr){ return attr_to_blockattr(attr); }
static unsigned long attr_to_l3attr_not_flip(enum ihk_mc_pt_attribute attr){ return attr_to_blockattr(attr); }
static unsigned long attr_to_l2attr_not_flip(enum ihk_mc_pt_attribute attr){ return attr_to_blockattr(attr); }
static unsigned long attr_to_l1attr_not_flip(enum ihk_mc_pt_attribute attr){ return attr_to_pageattr(attr); }
static unsigned long attr_to_lattr_not_flip(enum ihk_mc_pt_attribute attr, int level)
{
	switch (level)
	{
	case 4:	return attr_to_l4attr_not_flip(attr);
	case 3:	return attr_to_l3attr_not_flip(attr);
	case 2:	return attr_to_l2attr_not_flip(attr);
	case 1:	return attr_to_l1attr_not_flip(attr);
	}
	panic("invalid page table level.\n");
	return 0;
}

static unsigned long attr_to_lattr(enum ihk_mc_pt_attribute attr, int level)
{
	if (!(attr & ARCH_PTATTR_FLIPPED)) {
		attr = (attr ^ attr_flip_bits) | ARCH_PTATTR_FLIPPED;
	}
	return attr_to_lattr_not_flip(attr, level);
}
static unsigned long attr_to_l4attr(enum ihk_mc_pt_attribute attr){ return attr_to_lattr(attr, 4); }
static unsigned long attr_to_l3attr(enum ihk_mc_pt_attribute attr){ return attr_to_lattr(attr, 3); }
static unsigned long attr_to_l2attr(enum ihk_mc_pt_attribute attr){ return attr_to_lattr(attr, 2); }
static unsigned long attr_to_l1attr(enum ihk_mc_pt_attribute attr){ return attr_to_lattr(attr, 1); }

static int __set_pt_page(struct page_table *pt, void *virt, unsigned long phys,
                         enum ihk_mc_pt_attribute attr)
{
	unsigned long v = (unsigned long)virt;
	translation_table_t* newtt;
	ihk_mc_ap_flag ap_flag;
	int in_kernel = (v >= USER_END);
	unsigned long init_pt_lock_flags;
	int ret = -ENOMEM;
	pte_t* ptep;
	pte_t pte;
	translation_table_t* tt = NULL;

	init_pt_lock_flags = 0;	/* for avoidance of warning */
	if (in_kernel) {
		init_pt_lock_flags = ihk_mc_spinlock_lock(&init_pt_lock);
	}

	ap_flag = (attr & PTATTR_FOR_USER) ?
	                IHK_MC_AP_NOWAIT: IHK_MC_AP_CRITICAL;

	if (!pt) {
		pt = get_init_page_table();
	}
	tt = get_translation_table(pt);

	if (attr & PTATTR_LARGEPAGE) {
		phys &= LARGE_PAGE_MASK;
	} else {
		phys &= PAGE_MASK;
	}

	/* TODO: more detailed attribute check */
	ptep = ptl4_offset(tt, v);
	if (!ptl4_present(ptep)) {
		if((newtt = __alloc_new_tt(ap_flag)) == NULL)
			goto out;
		pte = (pte_t)newtt | PFL_PDIR_TBL_ATTR;
		ptl4_set(ptep, pte);
	}

	ptep = ptl3_offset(ptep, v);
	if (!ptl3_present(ptep)) {
		if((newtt = __alloc_new_tt(ap_flag)) == NULL)
			goto out;
		pte = (pte_t)newtt | PFL_PDIR_TBL_ATTR;
		ptl3_set(ptep, pte);
	}

	ptep = ptl2_offset(ptep, v);
	if (attr & PTATTR_LARGEPAGE) {
		// D_Block
		if (ptl2_present(ptep)) {
			unsigned long _phys = ptl2_val(ptep) & LARGE_PAGE_MASK;
			if (_phys == phys && ptl2_type_block(ptep)) {
				ret = 0;
			} else {
				ret = -EBUSY;
				kprintf("EBUSY: page table for 0x%lX is already set\n", virt);
			}
		} else {
			ptl2_set(ptep, phys | attr_to_l2attr(attr));
			ret = 0;
		}
		goto out;
	}
	// D_Table
	if (!ptl2_present(ptep)) {
		if((newtt = __alloc_new_tt(ap_flag)) == NULL)
			goto out;
		pte = (pte_t)newtt | PFL_PDIR_TBL_ATTR;
		ptl2_set(ptep, pte);
	}

	//D_Page
	ptep = ptl1_offset(ptep, v);
	if (ptl1_present(ptep)) {
		unsigned long _phys = ptl1_val(ptep) & PAGE_MASK;
		if (_phys == phys && ptl1_type_page(ptep)) {
			ret = 0;
		} else {
			ret = -EBUSY;
			kprintf("EBUSY: page table for 0x%lX is already set\n", virt);
		}
	} else {
		ptl1_set(ptep, phys | attr_to_l1attr(attr));
		ret = 0;
	}
out:
	if (in_kernel) {
		ihk_mc_spinlock_unlock(&init_pt_lock, init_pt_lock_flags);
	}
	return ret;
}

static int __clear_pt_page(struct page_table *pt, void *virt, int largepage)
{
	unsigned long v = (unsigned long)virt;
	pte_t *ptep;
	translation_table_t *tt;

	if (!pt) {
		pt = get_init_page_table();
	}
	tt = get_translation_table(pt);

	if (largepage) {
		v &= LARGE_PAGE_MASK;
	} else {
		v &= PAGE_MASK;
	}

	ptep = ptl4_offset(tt, v);
	if (!ptl4_present(ptep)) {
		return -EINVAL;
	}

	ptep = ptl3_offset(ptep, v);
	if (!ptl3_present(ptep)) {
		return -EINVAL;
	}

	ptep = ptl2_offset(ptep, v);
	if (largepage) {
		// D_Block
		if (!ptl2_present(ptep) || !ptl2_type_block(ptep)) {
			return -EINVAL;
		}
		ptl2_clear(ptep);
		return 0;
	}
	// D_Table
	if (!ptl2_present(ptep) || !ptl2_type_table(ptep)) {
		return -EINVAL;
	}
	// D_Page
	ptep = ptl1_offset(ptep, v);
	ptl1_clear(ptep);
	return 0;
}

uint64_t ihk_mc_pt_virt_to_pagemap(struct page_table *pt, unsigned long virt)
{
	uint64_t ret = PM_PSHIFT(PAGE_SHIFT);
	unsigned long v = (unsigned long)virt;
	pte_t* ptep;
	translation_table_t* tt;

	unsigned long paddr;
	unsigned long size;
	unsigned long mask;
	unsigned long shift;

	if (!pt) {
		pt = get_init_page_table();
	}
	tt = get_translation_table(pt);

	ptep = ptl4_offset(tt, v);
	if (!ptl4_present(ptep)) {
		return ret;
	}

	ptep = ptl3_offset(ptep, v);
	if (!ptl3_present(ptep)) {
		return ret;
	}
	if (ptl3_type_block(ptep)) {
		paddr = ptl3_phys(ptep);
		if (pte_is_contiguous(ptep)) {
			size = PTL3_CONT_SIZE;
			mask = PTL3_CONT_MASK;
			shift = PTL3_CONT_SHIFT;
		} else {
			size = PTL3_SIZE;
			mask = PTL3_MASK;
			shift = PTL3_SHIFT;
		}
		goto out;
	}

	ptep = ptl2_offset(ptep, v);
	if (!ptl2_present(ptep)) {
		return ret;
	}
	if (ptl2_type_block(ptep)) {
		paddr = ptl2_phys(ptep);
		if (pte_is_contiguous(ptep)) {
			size = PTL2_CONT_SIZE;
			mask = PTL2_CONT_MASK;
			shift = PTL2_CONT_SHIFT;
		} else {
			size = PTL2_SIZE;
			mask = PTL2_MASK;
			shift = PTL2_SHIFT;
		}
		goto out;
	}

	ptep = ptl1_offset(ptep, v);
	if (!ptl1_present(ptep)) {
		return ret;
	}
	paddr = ptl1_phys(ptep);
	if (pte_is_contiguous(ptep)) {
		size = PTL1_CONT_SIZE;
		mask = PTL1_CONT_MASK;
		shift = PTL1_CONT_SHIFT;
	} else {
		size = PTL1_SIZE;
		mask = PTL1_MASK;
		shift = PTL1_SHIFT;
	}
out:
	ret = PM_PFRAME(((paddr & mask) + (v & (size - 1))) >> PAGE_SHIFT);
	ret |= PM_PSHIFT(shift) | PM_PRESENT;
	return ret;
}

int ihk_mc_linux_pt_virt_to_phys_size(struct page_table *pt,
                           const void *virt,
						   unsigned long *phys,
						   unsigned long *size)
{
	unsigned long v = (unsigned long)virt;
	pte_t* ptep;
	translation_table_t* tt;

	unsigned long paddr;
	unsigned long lsize;

	tt = get_translation_table(pt);

	ptep = ptl4_offset(tt, v);
	if (!ptl4_present(ptep)) {
		return -EFAULT;
	}

	ptep = ptl3_offset_linux(ptep, v);
	if (!ptl3_present(ptep)) {
		return -EFAULT;
	}
	if (ptl3_type_block(ptep)) {
		paddr = ptl3_phys(ptep);
		lsize = PTL3_SIZE;
		goto out;
	}

	ptep = ptl2_offset(ptep, v);
	if (!ptl2_present(ptep)) {
		return -EFAULT;
	}
	if (ptl2_type_block(ptep)) {
		paddr = ptl2_phys(ptep);
		lsize = PTL2_SIZE;
		goto out;
	}

	ptep = ptl1_offset(ptep, v);
	if (!ptl1_present(ptep)) {
		return -EFAULT;
	}
	paddr = ptl1_phys(ptep);
	lsize = PTL1_SIZE;
out:
	*phys = paddr | (v & (lsize - 1));
	if(size) *size = lsize;
	return 0;
}


int ihk_mc_pt_virt_to_phys_size(struct page_table *pt,
                           const void *virt,
						   unsigned long *phys,
						   unsigned long *size)
{
	unsigned long v = (unsigned long)virt;
	pte_t* ptep;
	translation_table_t* tt;

	unsigned long paddr;
	unsigned long lsize;

	if (!pt) {
		pt = get_init_page_table();
	}
	tt = get_translation_table(pt);

	ptep = ptl4_offset(tt, v);
	if (!ptl4_present(ptep)) {
		return -EFAULT;
	}

	ptep = ptl3_offset(ptep, v);
	if (!ptl3_present(ptep)) {
		return -EFAULT;
	}
	if (ptl3_type_block(ptep)) {
		paddr = ptl3_phys(ptep);
		lsize = PTL3_SIZE;
		goto out;
	}

	ptep = ptl2_offset(ptep, v);
	if (!ptl2_present(ptep)) {
		return -EFAULT;
	}
	if (ptl2_type_block(ptep)) {
		paddr = ptl2_phys(ptep);
		lsize = PTL2_SIZE;
		goto out;
	}

	ptep = ptl1_offset(ptep, v);
	if (!ptl1_present(ptep)) {
		return -EFAULT;
	}
	paddr = ptl1_phys(ptep);
	lsize = PTL1_SIZE;
out:
	*phys = paddr | (v & (lsize - 1));
	if(size) *size = lsize;
	return 0;
}

int ihk_mc_pt_virt_to_phys(struct page_table *pt,
                           const void *virt, unsigned long *phys)
{
	return ihk_mc_pt_virt_to_phys_size(pt, virt, phys, NULL);
}

int ihk_mc_pt_print_pte(struct page_table *pt, void *virt)
{
	const unsigned long v = (unsigned long)virt;
	const pte_t* ptep;
	translation_table_t* tt;

	if (!pt) {
		pt = get_init_page_table();
	}
	tt = get_translation_table(pt);

	__kprintf("%s: 0x%lx, CONFIG_ARM64_PGTABLE_LEVELS: %d, ptl4_index: %ld, ptl3_index: %ld, ptl2_index: %ld, ptl1_index: %ld\n", 
		__func__,
		v,
		CONFIG_ARM64_PGTABLE_LEVELS,
		ptl4_index(v),
		ptl3_index(v),
		ptl2_index(v),
		ptl1_index(v));

	ptep = ptl4_offset(tt, v);
	__kprintf("l4 table: 0x%lX l4idx: %d\n", virt_to_phys(tt), ptl4_index(v));
	if (!(ptl4_present(ptep))) {
		__kprintf("0x%lX l4idx not present! \n", v);
		return -EFAULT;
	}
	__kprintf("l4 entry: 0x%lX\n", ptl4_val(ptep));

	ptep = ptl3_offset(ptep, v);
	__kprintf("l3 table: 0x%lX l3idx: %d\n", ptl3_phys(ptep), ptl3_index(v));
	if (!(ptl3_present(ptep))) {
		__kprintf("0x%lX l3idx not present! \n", v);
		return -EFAULT;
	}
	__kprintf("l3 entry: 0x%lX\n", ptl3_val(ptep));
	if (ptl3_type_block(ptep)) {
		__kprintf("l3 entry size: 0x%lx\n", PTL3_SIZE);
		return 0;
	}
	
	ptep = ptl2_offset(ptep, v);
	__kprintf("l2 table: 0x%lX l2idx: %d\n", ptl2_phys(ptep), ptl2_index(v));
	if (!(ptl2_present(ptep))) {
		__kprintf("0x%lX l2idx not present! \n", v);
		return -EFAULT;
	}
	__kprintf("l2 entry: 0x%lX\n", ptl2_val(ptep));
	if (ptl2_type_block(ptep)) {
		__kprintf("l2 entry size: 0x%lx\n", PTL2_SIZE);
		return 0;
	}

	ptep = ptl1_offset(ptep, v);
	__kprintf("l1 table: 0x%lX l1idx: %d\n", ptl1_phys(ptep), ptl1_index(v));
	if (!(ptl1_present(ptep))) {
		__kprintf("0x%lX l1idx not present! \n", v);
		__kprintf("l1 entry: 0x%lX\n", ptl1_val(ptep));
		return -EFAULT;
	}

	__kprintf("l1 entry: 0x%lX\n", ptl1_val(ptep));
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
	/*
	  vmap 領域の PGD を事前に用意するために使われているが
	  （virtual_allocator_initがIHK_MC_PT_FIRST_LEVELを指定して呼ぶ）
	  最上位のページテーブルがD_Tableになるとは限らない。
	  D_Blockで作成するにも vmap なので対象の PhysAddr は特定できない。
	  他の使われ方がされるまでは、空実装としておく。
	*/
	return 0;
}

struct page_table *ihk_mc_pt_create(ihk_mc_ap_flag ap_flag)
{
	struct page_table *pt;
	translation_table_t* tt;

	// allocate page_table
	pt = (struct page_table*)kmalloc(sizeof(*pt), ap_flag);
	if (pt == NULL) {
		return NULL;
	}
	// allocate translation_table
	tt = ihk_mc_alloc_pages(1, ap_flag);  //call __alloc_new_tt()?
	if (tt == NULL) {
		kfree(pt);
		return NULL;
	}
	// initialize
	memset(pt, 0, sizeof(*pt));
	memset(tt, 0, PAGE_SIZE);
	set_translation_table(pt, tt);
	set_address_space_id(pt, 0);
	return pt;
}

static void destroy_page_table(int level, translation_table_t* tt)
{
	if ((level < 1) || (CONFIG_ARM64_PGTABLE_LEVELS < level)) {
		panic("destroy_page_table: level is out of range");
	}
	if (tt == NULL) {
		panic("destroy_page_table: tt is NULL");
	}

	if (level > 1) {
		const int entries[] = {
			PTL2_ENTRIES,
			PTL3_ENTRIES,
			PTL4_ENTRIES
		};
		const int ents = entries[level-2];
		int ix;
		pte_t pte;
		translation_table_t *lower;

		for (ix = 0; ix < ents; ++ix) {
			pte = tt[ix];
			if (!ptl_present(&pte, level)) {
				/* entry is not valid */
				continue;
			}
			if (!ptl_type_table(&pte, level)) {
				/* not a page table */
				continue;
			}
			lower = (translation_table_t*)ptl_phys(&pte, level);
			lower = phys_to_virt((unsigned long)lower);
			destroy_page_table(level-1, lower);
		}
	}

	ihk_mc_free_pages(tt, 1);
	return;
}

void ihk_mc_pt_destroy(struct page_table *pt)
{
	const int level = CONFIG_ARM64_PGTABLE_LEVELS;
	translation_table_t* tt;

	tt = get_translation_table(pt);
	destroy_page_table(level, tt);
	free_mmu_context(pt);
	kfree(pt);
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

typedef int walk_pte_fn_t(void *args, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end);

typedef int walk_pte_t(translation_table_t *tt, uint64_t base, uint64_t start,
			  uint64_t end, walk_pte_fn_t *funcp, void *args);

static int walk_pte_l1(translation_table_t *tt, uint64_t base, uint64_t start,
		uint64_t end, walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;

	six = (start <= base)? 0: ((start - base) >> PTL1_SHIFT);
	eix = ((end == 0) || ((base + PTL2_SIZE) <= end))? PTL1_ENTRIES
		: (((end - base) + (PTL1_SIZE - 1)) >> PTL1_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		off = i * PTL1_SIZE;
		error = (*funcp)(args, &tt[i], base+off, start, end);
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

static int walk_pte_l2(translation_table_t *tt, uint64_t base, uint64_t start,
		uint64_t end, walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;

	six = (start <= base)? 0: ((start - base) >> PTL2_SHIFT);
	eix = ((end == 0) || ((base + PTL3_SIZE) <= end))? PTL2_ENTRIES
		: (((end - base) + (PTL2_SIZE - 1)) >> PTL2_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		off = i * PTL2_SIZE;
		error = (*funcp)(args, &tt[i], base+off, start, end);
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

static int walk_pte_l3(translation_table_t *tt, uint64_t base, uint64_t start,
		uint64_t end, walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;

	six = (start <= base)? 0: ((start - base) >> PTL3_SHIFT);
	eix = ((end == 0) || ((base + PTL4_SIZE) <= end))? PTL3_ENTRIES
		: (((end - base) + (PTL3_SIZE - 1)) >> PTL3_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		off = i * PTL3_SIZE;
		error = (*funcp)(args, &tt[i], base+off, start, end);
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

static int walk_pte_l4(translation_table_t *tt, uint64_t base, uint64_t start,
		uint64_t end, walk_pte_fn_t *funcp, void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;

	six = (start <= base)? 0: ((start - base) >> PTL4_SHIFT);
	eix = (end == 0)? PTL4_ENTRIES
		:(((end - base) + (PTL4_SIZE - 1)) >> PTL4_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		off = i * PTL4_SIZE;
		error = (*funcp)(args, &tt[i], base+off, start, end);
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

static int split_large_page(pte_t *ptep, size_t pgsize)
{
	translation_table_t *tt, *tt_pa;
	uintptr_t phys_base;
	unsigned int i;
	uintptr_t phys;
	struct page *page;
	pte_t pte;
	pte_t d_table;
	int table_level;
	unsigned int entries;
	unsigned long under_pgsize;

	// ラージページ判定
	if (first_level_block_support && pgsize == PTL3_SIZE) {
		table_level = 3;
		entries = PTL3_ENTRIES;
		under_pgsize = PTL2_SIZE;
	} else if (pgsize == PTL2_SIZE) {
		table_level = 2;
		entries = PTL2_ENTRIES;
		under_pgsize = PTL1_SIZE;
	} else {
		ekprintf("split_large_page:invalid pgsize %#lx\n", pgsize);
		return -EINVAL;
	}

	// D_Tableを作成
	tt_pa = __alloc_new_tt(IHK_MC_AP_NOWAIT);
	if (tt_pa == NULL) {
		ekprintf("split_large_page:__alloc_new_tt failed\n");
		return -ENOMEM;
	}
	tt = phys_to_virt((unsigned long)tt_pa);

	// descriptor typeを変更 (PTL3 は PTL2 の D_Block に分割するので属性変更無し)
	pte = ptl_val(ptep, table_level);
	if (pgsize == PTL2_SIZE) {
		// D_Block -> D_Page
		pte = (pte & ~PMD_TYPE_MASK) | PTE_TYPE_PAGE;
	}

	if (pte_is_fileoff(ptep, pgsize)) {
		// remap_file_pages中など未割当てはこっち
		phys_base = NOPHYS;
	}
	else {
		phys_base = ptl_phys(ptep, table_level);
	}

	for (i = 0; i < entries; ++i) {
		if (phys_base != NOPHYS) {
			phys = phys_base + (i * under_pgsize);
			page = phys_to_page(phys);
			if (page) {
				page_map(page);
			}
		}
		tt[i] = pte;
		if (pgsize == PTL3_SIZE) {
			dkprintf("%lx+,%s: calling memory_stat_rss_add(),size=%ld,pgsize=%ld\n",
				 pte_is_fileoff(ptep, pgsize) ?
				 pte_get_off(&pte, pgsize) :
				 pte_get_phys(&pte),
				 __func__, PTL2_SIZE, PTL2_SIZE);
			memory_stat_rss_add(PTL2_SIZE, PTL2_SIZE);
		}
		else if (pgsize == PTL2_SIZE) {
			dkprintf("%lx+,%s: calling memory_stat_rss_add(),size=%ld,pgsize=%ld\n",
				 pte_is_fileoff(ptep, pgsize) ?
				 pte_get_off(&pte, pgsize) :
				 pte_get_phys(&pte),
				 __func__, PTL1_SIZE, PTL1_SIZE);
			memory_stat_rss_add(PTL1_SIZE, PTL1_SIZE);
		}
		pte += under_pgsize;
	}

	d_table = (pte_t)((unsigned long)tt_pa & PT_PHYSMASK) |
		PFL_PDIR_TBL_ATTR;
	ptl_set(ptep, d_table, table_level);

	dkprintf("%lx-,%s: calling memory_stat_rss_sub(),size=%ld,pgsize=%ld\n",
		 phys_base, __func__, pgsize, pgsize);
	memory_stat_rss_sub(pgsize, pgsize);

	/* Do not do this check for large pages as they don't come from the
	 * zeroobj and are not actually mapped.
	 * TODO: clean up zeroobj as we don't really need it, anonymous
	 * mappings should be allocated for real
	 */
	if (phys_base != NOPHYS) {
		page = phys_to_page(phys_base);
		if (page && page_unmap(page)) {
			ekprintf("%s: error: page_unmap of %p returned true\n",
			       __func__, page);
		}
	}
	return 0;
}

struct visit_pte_args {
	page_table_t pt;
	enum visit_pte_flag flags;
	int pgshift;
	pte_visitor_t *funcp;
	void *arg;
};

static int visit_pte_range_middle(void *arg0, pte_t *ptep, uint64_t base,
				  uint64_t start, uint64_t end, int level);

static int visit_pte_l1(void *arg0, pte_t *ptep, uintptr_t base,
		uintptr_t start, uintptr_t end)
{
	struct visit_pte_args *args = arg0;

	if (ptl1_null(ptep) && (args->flags & VPTEF_SKIP_NULL))
		return 0;

	return (*args->funcp)(args->arg, args->pt, ptep, (void *)base, PTL1_SHIFT);
}

static int visit_pte_l2(void *arg0, pte_t *ptep, uintptr_t base,
		uintptr_t start, uintptr_t end)
{
	return visit_pte_range_middle(arg0, ptep, base, start, end, 2);
}

static int visit_pte_l3(void *arg0, pte_t *ptep, uintptr_t base,
		uintptr_t start, uintptr_t end)
{
	return visit_pte_range_middle(arg0, ptep, base, start, end, 3);
}

static int visit_pte_l4(void *arg0, pte_t *ptep, uintptr_t base,
		uintptr_t start, uintptr_t end)
{
	return visit_pte_range_middle(arg0, ptep, base, start, end, 4);
}

static int visit_pte_range_middle(void *arg0, pte_t *ptep, uint64_t base,
                                  uint64_t start, uint64_t end, int level)
{
	const struct table {
		walk_pte_t* walk;
		walk_pte_fn_t* callback;
		unsigned long pgsize; /* curent level page size */
		unsigned long pgshift; /* curent level page shift */
	} table[] = {
		{ walk_pte_l1, visit_pte_l1, PTL2_SIZE, PTL2_SHIFT }, /*PTL2*/
		{ walk_pte_l2, visit_pte_l2, PTL3_SIZE, PTL3_SHIFT }, /*PTL3*/
		{ walk_pte_l3, visit_pte_l3, PTL4_SIZE, PTL4_SHIFT }, /*PTL4*/
	};
	const struct table tbl = table[level-2];

	int error;
	struct visit_pte_args *args = arg0;
	translation_table_t* tt;

	if (ptl_null(ptep, level) && (args->flags & VPTEF_SKIP_NULL))
		return 0;

	if ((ptl_null(ptep, level) || ptl_type_page(ptep, level))
			&& (start <= base)
			&& (((base + tbl.pgsize) <= end)
				|| (end == 0))
			&& (!args->pgshift || (args->pgshift == tbl.pgshift))) {
		error = (*args->funcp)(args->arg, args->pt, ptep,
				(void *)base, tbl.pgshift);
		if (error != -E2BIG) {
			return error;
		}
	}

	if (ptl_type_page(ptep, level)) {
		ekprintf("visit_pte_range_middle(level=%d):split large page\n", level);
		return -ENOMEM;
	}

	if (ptl_null(ptep, level)) {
		translation_table_t* tt_pa;
		pte_t pte;
		tt_pa = __alloc_new_tt(IHK_MC_AP_NOWAIT);
		if (tt_pa == NULL)
			return -ENOMEM;
		pte = (pte_t)(((unsigned long)tt_pa & PT_PHYSMASK) | PFL_PDIR_TBL_ATTR);
		ptl_set(ptep, pte, level);
		tt = (translation_table_t*)phys_to_virt((unsigned long)tt_pa);
	}
	else {
		tt = (translation_table_t*)phys_to_virt(ptl_phys(ptep, level));
	}

	return tbl.walk(tt, base, start, end, tbl.callback, arg0);
}

int visit_pte_range(page_table_t pt, void *start0, void *end0, int pgshift,
		enum visit_pte_flag flags, pte_visitor_t *funcp, void *arg)
{
	const struct table {
		walk_pte_t* walk;
		walk_pte_fn_t* callback;
	} tables[] = {
		{ walk_pte_l2, visit_pte_l2 }, /*second*/
		{ walk_pte_l3, visit_pte_l3 }, /*first*/
		{ walk_pte_l4, visit_pte_l4 }, /*zero*/
	};
	const struct table initial_lookup = tables[CONFIG_ARM64_PGTABLE_LEVELS - 2];

	const uintptr_t start = (uintptr_t)start0;
	const uintptr_t end = (uintptr_t)end0;
	struct visit_pte_args args;
	translation_table_t* tt;

	args.pt = pt;
	args.flags = flags;
	args.funcp = funcp;
	args.arg = arg;
	args.pgshift = pgshift;

	tt = get_translation_table(pt);
	return initial_lookup.walk(tt, 0, start, end, initial_lookup.callback, &args);
}

static int walk_pte_l1_safe(translation_table_t *tt, uint64_t base,
			    uint64_t start, uint64_t end, walk_pte_fn_t *funcp,
			    void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;
	unsigned long phys;

	if (!tt)
		return 0;

	six = (start <= base) ? 0 : ((start - base) >> PTL1_SHIFT);
	eix = ((end == 0) || ((base + PTL2_SIZE) <= end)) ? PTL1_ENTRIES
		: (((end - base) + (PTL1_SIZE - 1)) >> PTL1_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		phys = ptl_phys(&tt[i], 1);
		if (-1 == ihk_mc_chk_page_address(phys))
			continue;
		off = i * PTL1_SIZE;
		error = (*funcp)(args, &tt[i], base+off, start, end);
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

static int walk_pte_l2_safe(translation_table_t *tt, uint64_t base,
			    uint64_t start, uint64_t end, walk_pte_fn_t *funcp,
			    void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;
	unsigned long phys;

	if (!tt)
		return 0;

	six = (start <= base) ? 0 : ((start - base) >> PTL2_SHIFT);
	eix = ((end == 0) || ((base + PTL3_SIZE) <= end)) ? PTL2_ENTRIES :
		(((end - base) + (PTL2_SIZE - 1)) >> PTL2_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		phys = ptl_phys(&tt[i], 2);
		if (-1 == ihk_mc_chk_page_address(phys))
			continue;
		off = i * PTL2_SIZE;
		error = (*funcp)(args, &tt[i], base+off, start, end);
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

static int walk_pte_l3_safe(translation_table_t *tt, uint64_t base,
			    uint64_t start, uint64_t end, walk_pte_fn_t *funcp,
			    void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;
	unsigned long phys;

	if (!tt)
		return 0;

	six = (start <= base) ? 0 : ((start - base) >> PTL3_SHIFT);
	eix = ((end == 0) || ((base + PTL4_SIZE) <= end)) ? PTL3_ENTRIES :
		(((end - base) + (PTL3_SIZE - 1)) >> PTL3_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		phys = ptl_phys(&tt[i], 3);
		if (-1 == ihk_mc_chk_page_address(phys))
			continue;
		off = i * PTL3_SIZE;
		error = (*funcp)(args, &tt[i], base+off, start, end);
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

static int walk_pte_l4_safe(translation_table_t *tt, uint64_t base,
			    uint64_t start, uint64_t end, walk_pte_fn_t *funcp,
			    void *args)
{
	int six;
	int eix;
	int ret;
	int i;
	int error;
	uint64_t off;
	unsigned long phys;

	if (!tt)
		return 0;

	six = (start <= base) ? 0 : ((start - base) >> PTL4_SHIFT);
	eix = (end == 0) ? PTL4_ENTRIES :
		(((end - base) + (PTL4_SIZE - 1)) >> PTL4_SHIFT);

	ret = -ENOENT;
	for (i = six; i < eix; ++i) {
		phys = ptl_phys(&tt[i], 4);
		if (-1 == ihk_mc_chk_page_address(phys))
			continue;
		off = i * PTL4_SIZE;
		error = (*funcp)(args, &tt[i], base+off, start, end);
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

static int visit_pte_range_middle_safe(void *arg0, pte_t *ptep, uint64_t base,
				       uint64_t start, uint64_t end, int level);

static int visit_pte_l1_safe(void *arg0, pte_t *ptep, uintptr_t base,
			     uintptr_t start, uintptr_t end)
{
	struct visit_pte_args *args = arg0;

	if (ptl1_null(ptep))
		return 0;

	return (*args->funcp)(args->arg, args->pt, ptep, (void *)base,
			      PTL1_SHIFT);
}

static int visit_pte_l2_safe(void *arg0, pte_t *ptep, uintptr_t base,
			     uintptr_t start, uintptr_t end)
{
	return visit_pte_range_middle_safe(arg0, ptep, base, start, end, 2);
}

static int visit_pte_l3_safe(void *arg0, pte_t *ptep, uintptr_t base,
			     uintptr_t start, uintptr_t end)
{
	return visit_pte_range_middle_safe(arg0, ptep, base, start, end, 3);
}

static int visit_pte_l4_safe(void *arg0, pte_t *ptep, uintptr_t base,
			     uintptr_t start, uintptr_t end)
{
	return visit_pte_range_middle_safe(arg0, ptep, base, start, end, 4);
}

static int visit_pte_range_middle_safe(void *arg0, pte_t *ptep, uint64_t base,
				       uint64_t start, uint64_t end, int level)
{
	const struct table {
		walk_pte_t *walk;
		walk_pte_fn_t *callback;
		unsigned long pgsize; /* curent level page size */
		unsigned long pgshift; /* curent level page shift */
	} table[] = {
		{ walk_pte_l1_safe, visit_pte_l1_safe, PTL2_SIZE, PTL2_SHIFT }, /*PTL2*/
		{ walk_pte_l2_safe, visit_pte_l2_safe, PTL3_SIZE, PTL3_SHIFT }, /*PTL3*/
		{ walk_pte_l3_safe, visit_pte_l3_safe, PTL4_SIZE, PTL4_SHIFT }, /*PTL4*/
	};
	const struct table tbl = table[level-2];

	int error;
	struct visit_pte_args *args = arg0;
	translation_table_t *tt;

	if (ptl_null(ptep, level))
		return 0;

	if (ptl_type_page(ptep, level)
			&& (start <= base)
			&& (((base + tbl.pgsize) <= end)
				|| (end == 0))
			&& (!args->pgshift || (args->pgshift == tbl.pgshift))) {
		error = (*args->funcp)(args->arg, args->pt, ptep,
				(void *)base, tbl.pgshift);
		if (error != -E2BIG) {
			return error;
		}
	}

	if (ptl_type_page(ptep, level)) {
		ekprintf("%s(level=%d):split large page\n",
			 __func__, level);
		return -ENOMEM;
	}

	tt = (translation_table_t *)phys_to_virt(ptl_phys(ptep, level));

	return tbl.walk(tt, base, start, end, tbl.callback, arg0);
}

int visit_pte_range_safe(page_table_t pt, void *start0, void *end0,
			 int pgshift, enum visit_pte_flag flags,
			 pte_visitor_t *funcp, void *arg)
{
	const struct table {
		walk_pte_t *walk;
		walk_pte_fn_t *callback;
	} tables[] = {
		{ walk_pte_l2_safe, visit_pte_l2_safe }, /*second*/
		{ walk_pte_l3_safe, visit_pte_l3_safe }, /*first*/
		{ walk_pte_l4_safe, visit_pte_l4_safe }, /*zero*/
	};
	const struct table initial_lookup =
		tables[CONFIG_ARM64_PGTABLE_LEVELS - 2];

	const uintptr_t start = (uintptr_t)start0;
	const uintptr_t end = (uintptr_t)end0;
	struct visit_pte_args args;
	translation_table_t *tt;

	args.pt = pt;
	args.flags = flags;
	args.funcp = funcp;
	args.arg = arg;
	args.pgshift = pgshift;

	tt = get_translation_table(pt);
	return initial_lookup.walk(tt, 0, start, end, initial_lookup.callback,
				   &args);
}

static void unmap_free_stat(struct page *page, unsigned long phys,
			    size_t free_size, const char *func)
{
	if (!page || page_unmap(page)) {
		ihk_mc_free_pages_user(phys_to_virt(phys),
				       free_size >> PAGE_SHIFT);
		dkprintf("%lx-,%s: memory_stat_rss_sub(),phys=%lx,size=%ld,pgsize=%ld\n",
			 phys, func, phys, free_size, free_size);
		memory_stat_rss_sub(free_size, free_size);
	}
}

/*
 * Kernel space page table clearing functions.
 */
struct clear_kernel_range_args {
	int free_physical;
};

static int clear_kernel_range_middle(void *args0, pte_t *ptep, uint64_t base,
			      uint64_t start, uint64_t end, int level);

static int clear_kernel_range_l1(void *args0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	const struct table {
		unsigned long pgsize;
		unsigned long cont_pgsize;
	} tbl = {
		.pgsize = PTL1_SIZE,
		.cont_pgsize = PTL1_CONT_SIZE
	};

	struct clear_kernel_range_args *args = args0;
	uint64_t phys = 0;
	pte_t old;
	size_t clear_size;

	if (ptl1_null(ptep)) {
		return -ENOENT;
	}

	old = xchg(ptep, PTE_NULL);
	if (!pte_is_present(&old))
		return 0;

	arch_flush_tlb_single(0, base);
	clear_size = pte_is_contiguous(&old) ?
		tbl.cont_pgsize : tbl.pgsize;

	dkprintf("%s: 0x%lx:%lu unmapped\n",
		__func__, base, clear_size);

	if (args->free_physical) {
		phys = ptl1_phys(&old);
		ihk_mc_free_pages(phys_to_virt(phys), clear_size >> PAGE_SHIFT);
	}

	return 0;
}

static int clear_kernel_range_l2(void *args0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	return clear_kernel_range_middle(args0, ptep, base, start, end, 2);
}

static int clear_kernel_range_l3(void *args0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	return clear_kernel_range_middle(args0, ptep, base, start, end, 3);
}

static int clear_kernel_range_l4(void *args0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	return clear_kernel_range_middle(args0, ptep, base, start, end, 4);
}

static int clear_kernel_range_middle(void *args0, pte_t *ptep, uint64_t base,
			      uint64_t start, uint64_t end, int level)
{
	const struct table {
		walk_pte_t* walk;
		walk_pte_fn_t* callback;
		unsigned long pgsize;
		unsigned long cont_pgsize;
	} table[] = {
		{walk_pte_l1, clear_kernel_range_l1, PTL2_SIZE, PTL2_CONT_SIZE}, /*PTL2*/
		{walk_pte_l2, clear_kernel_range_l2, PTL3_SIZE, PTL3_CONT_SIZE}, /*PTL3*/
		{walk_pte_l3, clear_kernel_range_l3, PTL4_SIZE, PTL4_CONT_SIZE}, /*PTL4*/
	};
	const struct table tbl = table[level-2];

	struct clear_kernel_range_args *args = args0;
	uint64_t phys = 0;
	translation_table_t *tt;
	int error;
	pte_t old;
	size_t clear_size;

	if (ptl_null(ptep, level)) {
		return -ENOENT;
	}

	dkprintf("%s(level: %d): 0x%lx in 0x%lx-0x%lx\n",
			__func__, level, base, start, end);

	if (ptl_type_page(ptep, level)
			&& ((base < start) || (end < (base + tbl.pgsize)))) {
		error = -EINVAL;
		ekprintf("clear_range_middle(%p,%p,%lx,%lx,%lx,%d):"
			 "split page. %d\n",
			 args0, ptep, base, start, end, level, error);
		return error;
	}

	if (ptl_type_page(ptep, level)) {
		old = xchg(ptep, PTE_NULL);

		if (!ptl_present(&old, level)) {
			return 0;
		}

		arch_flush_tlb_single(0, base);

		clear_size = pte_is_contiguous(&old) ?
			tbl.cont_pgsize : tbl.pgsize;

		dkprintf("%s(level: %d): 0x%lx:%lu unmapped\n",
				__func__, level, base, clear_size);

		if (args->free_physical) {
			phys = ptl_phys(&old, level);
			ihk_mc_free_pages(phys_to_virt(phys), clear_size >> PAGE_SHIFT);
		}

		return 0;
	}

	tt = (translation_table_t*)phys_to_virt(ptl_phys(ptep, level));
	error = tbl.walk(tt, base, start, end, tbl.callback, args0);
	if (error && (error != -ENOENT)) {
		return error;
	}

	if (args->free_physical) {
		if ((start <= base) && ((base + tbl.pgsize) <= end)) {
			ptl_clear(ptep, level);
			arch_flush_tlb_single(0, base);
			ihk_mc_free_pages(tt, 1);
		}
	}

	return 0;
}

static int clear_kernel_range(uintptr_t start, uintptr_t end, int free_physical)
{
	const struct table {
		walk_pte_t* walk;
		walk_pte_fn_t* callback;
	} tables[] = {
		{walk_pte_l2, clear_kernel_range_l2}, /*second*/
		{walk_pte_l3, clear_kernel_range_l3}, /*first*/
		{walk_pte_l4, clear_kernel_range_l4}, /*zero*/
	};
	const struct table initial_lookup = tables[CONFIG_ARM64_PGTABLE_LEVELS - 2];

	int error;
	struct clear_kernel_range_args args;
	translation_table_t* tt;
	unsigned long irqflags;

	dkprintf("%s: start: 0x%lx, end: 0x%lx, free phys: %d\n",
		 __func__, start, end, free_physical);

	if (start <= USER_END)
		return -EINVAL;

	args.free_physical = free_physical;

	irqflags = ihk_mc_spinlock_lock(&init_pt_lock);
	tt = get_translation_table(get_init_page_table());
	error = initial_lookup.walk(tt, 0,
			(start & ~(0xffff000000000000)),
			(end & ~(0xffff000000000000)),
			initial_lookup.callback, &args);
	dkprintf("%s: start: 0x%lx, end: 0x%lx, free phys: %d, ret: %d\n",
		 __func__, start, end, free_physical, error);

	ihk_mc_spinlock_unlock(&init_pt_lock, irqflags);
	return error;
}

int ihk_mc_clear_kernel_range(void *start, void *end)
{
#define	KEEP_PHYSICAL	0
	return clear_kernel_range((uintptr_t)start, (uintptr_t)end, KEEP_PHYSICAL);
}

/*
 * User space page table clearing functions.
 */
struct clear_range_args {
	int free_physical;
	struct memobj *memobj;
	struct process_vm *vm;
};

static int clear_range_middle(void *args0, pte_t *ptep, uint64_t base,
			      uint64_t start, uint64_t end, int level);

static int clear_range_l1(void *args0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	const struct table {
		unsigned long pgsize;
		unsigned long cont_pgsize;
	} tbl = {
		.pgsize = PTL1_SIZE,
		.cont_pgsize = PTL1_CONT_SIZE
	};

	struct clear_range_args *args = args0;
	uint64_t phys = 0;
	struct page *page;
	pte_t old;
	size_t clear_size;

	//dkprintf("%s: %lx,%lx,%lx\n", __FUNCTION__, base, start, end);

	if (ptl1_null(ptep)) {
		return -ENOENT;
	}

	old = xchg(ptep, PTE_NULL);
	arch_flush_tlb_single(get_address_space_id(args->vm->address_space->page_table),
			      base);

	page = NULL;
	if (!ptl1_fileoff(&old)) {
		phys = ptl1_phys(&old);
		page = phys_to_page(phys);
	}

	clear_size = pte_is_contiguous(&old) ?
		tbl.cont_pgsize : tbl.pgsize;

	if (ptl1_dirty(&old) &&
	    is_flushable(page, args->memobj) &&
	    pte_is_head(ptep, &old, tbl.cont_pgsize)) {
		memobj_flush_page(args->memobj, phys, clear_size);
	}

	if (!ptl1_fileoff(&old) && args->free_physical &&
	    is_freeable(args->memobj) &&
	    pte_is_head(ptep, &old, tbl.cont_pgsize)) {
		unmap_free_stat(page, phys, clear_size, __func__);
	}
	
	return 0;
}

static int clear_range_l2(void *args0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	return clear_range_middle(args0, ptep, base, start, end, 2);
}

static int clear_range_l3(void *args0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	return clear_range_middle(args0, ptep, base, start, end, 3);
}

static int clear_range_l4(void *args0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	return clear_range_middle(args0, ptep, base, start, end, 4);
}

static int clear_range_middle(void *args0, pte_t *ptep, uint64_t base,
			      uint64_t start, uint64_t end, int level)
{
	const struct table {
		walk_pte_t* walk;
		walk_pte_fn_t* callback;
		unsigned long pgsize;
		unsigned long cont_pgsize;
	} table[] = {
		{walk_pte_l1, clear_range_l1, PTL2_SIZE, PTL2_CONT_SIZE}, /*PTL2*/
		{walk_pte_l2, clear_range_l2, PTL3_SIZE, PTL3_CONT_SIZE}, /*PTL3*/
		{walk_pte_l3, clear_range_l3, PTL4_SIZE, PTL4_CONT_SIZE}, /*PTL4*/
	};
	const struct table tbl = table[level-2];

	struct clear_range_args *args = args0;
	uint64_t phys = 0;
	translation_table_t *tt;
	int error;
	struct page *page;
	pte_t old;
	size_t clear_size;

	//dkprintf("%s: %lx,%lx,%lx\n", __FUNCTION__, base, start, end);

	if (ptl_null(ptep, level)) {
		return -ENOENT;
	}

	if (ptl_type_page(ptep, level)
			&& ((base < start) || (end < (base + tbl.pgsize)))) {
		error = -EINVAL;
		ekprintf("clear_range_middle(%p,%p,%lx,%lx,%lx,%d):"
			 "split page. %d\n",
			 args0, ptep, base, start, end, level, error);
		return error;
	}

	if (ptl_type_page(ptep, level)) {
		old = xchg(ptep, PTE_NULL);
		arch_flush_tlb_single(get_address_space_id(args->vm->address_space->page_table), base);

		page = NULL;
		if (!ptl_fileoff(&old, level)) {
			phys = ptl_phys(&old, level);
			page = phys_to_page(phys);
		}

		clear_size = pte_is_contiguous(&old) ?
			tbl.cont_pgsize : tbl.pgsize;

		if (ptl_dirty(&old, level) &&
		    is_flushable(page, args->memobj) &&
		    pte_is_head(ptep, &old, tbl.cont_pgsize)) {
			memobj_flush_page(args->memobj, phys, clear_size);
		}

		if (!ptl_fileoff(&old, level) && args->free_physical &&
		    pte_is_head(ptep, &old, tbl.cont_pgsize)) {
			unmap_free_stat(page, phys, clear_size, __func__);
		}

		return 0;
	}

	tt = (translation_table_t*)phys_to_virt(ptl_phys(ptep, level));
	error = tbl.walk(tt, base, start, end, tbl.callback, args0);
	if (error && (error != -ENOENT)) {
		return error;
	}

	if ((start <= base) && ((base + tbl.pgsize) <= end)) {
		ptl_clear(ptep, level);
		arch_flush_tlb_single(get_address_space_id(args->vm->address_space->page_table), base);
		ihk_mc_free_pages(tt, 1);
	}

	return 0;
}

static int clear_range(struct page_table *pt, struct process_vm *vm, 
		uintptr_t start, uintptr_t end, int free_physical, 
		struct memobj *memobj)
{
	const struct table {
		walk_pte_t* walk;
		walk_pte_fn_t* callback;
	} tables[] = {
		{walk_pte_l2, clear_range_l2}, /*second*/
		{walk_pte_l3, clear_range_l3}, /*first*/
		{walk_pte_l4, clear_range_l4}, /*zero*/
	};
	const struct table initial_lookup = tables[CONFIG_ARM64_PGTABLE_LEVELS - 2];

	int error;
	struct clear_range_args args;
	translation_table_t* tt;
	pte_t *ptep;
	size_t pgsize;

	dkprintf("%s: %p,%lx,%lx,%d,%p\n",
		 __func__, pt, start, end, free_physical, memobj);

	if ((start < vm->region.user_start)
			|| (vm->region.user_end < end)
			|| (end <= start)) {
		ekprintf("clear_range(%p,%p,%p,%x):"
				"invalid start and/or end.\n",
				pt, start, end, free_physical);
		return -EINVAL;
	}

	args.free_physical = free_physical;
	if (memobj && (memobj->flags & MF_DEV_FILE)) {
		args.free_physical = 0;
	}
	if (memobj && ((memobj->flags & MF_PREMAP))) {
		args.free_physical = 0;
	}

	if (vm->proc->straight_va &&
			(void *)start == vm->proc->straight_va &&
			(void *)end == (vm->proc->straight_va +
				vm->proc->straight_len)) {
		args.free_physical = 0;
	}

	args.memobj = memobj;
	args.vm = vm;

	ptep = ihk_mc_pt_lookup_pte(pt, (void *)start,
				    0, NULL, &pgsize, NULL);
	if (ptep && pte_is_contiguous(ptep)) {
		if (!page_is_contiguous_head(ptep, pgsize)) {
			// start pte is not contiguous head
			error = split_contiguous_pages(ptep, pgsize);
			if (error) {
				return error;
			}
		}
	}

	ptep = ihk_mc_pt_lookup_pte(pt, (void *)end - 1,
				    0, NULL, &pgsize, NULL);
	if (ptep && pte_is_contiguous(ptep)) {
		if (!page_is_contiguous_tail(ptep, pgsize)) {
			// end pte is not contiguous tail
			error = split_contiguous_pages(ptep, pgsize);
			if (error) {
				return error;
			}
		}
	}

	tt = get_translation_table(pt);
	error = initial_lookup.walk(tt, 0, start, end, initial_lookup.callback, &args);
	return error;
}

int ihk_mc_pt_clear_range(page_table_t pt, struct process_vm *vm, 
		void *start, void *end)
{
#define	KEEP_PHYSICAL	0
	return clear_range(pt, vm, (uintptr_t)start, (uintptr_t)end,
			KEEP_PHYSICAL, NULL);
}

int ihk_mc_pt_free_range(page_table_t pt, struct process_vm *vm, 
		void *start, void *end, struct memobj *memobj)
{
#define	FREE_PHYSICAL	1
	return clear_range(pt, vm, (uintptr_t)start, (uintptr_t)end,
			FREE_PHYSICAL, memobj);
}

struct change_attr_args {
	pte_t clrpte[4];
	pte_t setpte[4];
};
static int change_attr_range_middle(void *arg0, pte_t *ptep, uint64_t base,
				    uint64_t start, uint64_t end, int level);

static int change_attr_range_l1(void *arg0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	pte_t pte;
	struct change_attr_args *args = arg0;

	if (ptl1_null(ptep) || ptl1_fileoff(ptep)) {
		return -ENOENT;
	}
	pte = ptl1_val(ptep);
	pte = (pte & ~args->clrpte[0]) | args->setpte[0];
	ptl1_set(ptep, pte);
	return 0;
}
	
static int change_attr_range_l2(void *arg0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	return change_attr_range_middle(arg0, ptep, base, start, end, 2);
}

static int change_attr_range_l3(void *arg0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	return change_attr_range_middle(arg0, ptep, base, start, end, 3);
}

static int change_attr_range_l4(void *arg0, pte_t *ptep, uint64_t base,
		uint64_t start, uint64_t end)
{
	return change_attr_range_middle(arg0, ptep, base, start, end, 4);
}

static int change_attr_range_middle(void *arg0, pte_t *ptep, uint64_t base,
				    uint64_t start, uint64_t end, int level)
{
	const struct table {
		walk_pte_t* walk;
		walk_pte_fn_t* callback;
		unsigned long pgsize;
	} table[] = {
		{walk_pte_l1, change_attr_range_l1, PTL2_SIZE}, /*PTL2*/
		{walk_pte_l2, change_attr_range_l2, PTL3_SIZE}, /*PTL3*/
		{walk_pte_l3, change_attr_range_l3, PTL4_SIZE}, /*PTL4*/
	};
	const struct table tbl = table[level-2];
	struct change_attr_args *args = arg0;
	int error;
	translation_table_t* tt;

	if (ptl_null(ptep, level) || ptl_fileoff(ptep, level)) {
		return -ENOENT;
	}

	if (ptl_type_page(ptep, level)
	    && ((base < start) || (end < (base + tbl.pgsize)))) {
		error = -EINVAL;
		ekprintf("change_attr_range_middle(%p,%p,%lx,%lx,%lx,%d):"
			 "split failed. %d\n",
			 arg0, ptep, base, start, end, error, level);
		return error;
	}

	if (ptl_type_page(ptep, level)) {
		if (!ptl_fileoff(ptep, level)) {
			pte_t pte = ptl_val(ptep, level);
			pte = (pte & ~args->clrpte[level-1]) | args->setpte[level-1];
			ptl_set(ptep, pte, level);
		}
		return 0;
	}

	tt = (translation_table_t*)phys_to_virt(ptl_phys(ptep, level));
	return tbl.walk(tt, base, start, end, tbl.callback, arg0);
}

int ihk_mc_pt_change_attr_range(page_table_t pt, void *start0, void *end0,
		enum ihk_mc_pt_attribute clrattr,
		enum ihk_mc_pt_attribute setattr)
{
	const struct table {
		walk_pte_t* walk;
		walk_pte_fn_t* callback;
	} tables[] = {
		{walk_pte_l2, change_attr_range_l2}, /*second*/
		{walk_pte_l3, change_attr_range_l3}, /*first*/
		{walk_pte_l4, change_attr_range_l4}, /*zero*/
	};
	const struct table initial_lookup = tables[CONFIG_ARM64_PGTABLE_LEVELS - 2];
	enum ihk_mc_pt_attribute flip_clrattr;
	enum ihk_mc_pt_attribute flip_setattr;

	const intptr_t start = (intptr_t)start0;
	const intptr_t end = (intptr_t)end0;
	struct change_attr_args args;
	translation_table_t* tt;

	// swap the flip bits
	flip_clrattr = (clrattr & ~attr_flip_bits) | (setattr & attr_flip_bits);
	flip_setattr = (setattr & ~attr_flip_bits) | (clrattr & attr_flip_bits);

	// conversion
	switch (CONFIG_ARM64_PGTABLE_LEVELS)
	{
	case 4:	args.clrpte[3] = attr_to_l4attr_not_flip(flip_clrattr); /*PTL4*/
		args.setpte[3] = attr_to_l4attr_not_flip(flip_setattr);
	case 3:	args.clrpte[2] = attr_to_l3attr_not_flip(flip_clrattr); /*PTL3*/
		args.setpte[2] = attr_to_l3attr_not_flip(flip_setattr);
	case 2:	args.clrpte[1] = attr_to_l2attr_not_flip(flip_clrattr); /*PTL2*/
		args.setpte[1] = attr_to_l2attr_not_flip(flip_setattr);
		args.clrpte[0] = attr_to_l1attr_not_flip(flip_clrattr); /*PTL1*/
		args.setpte[0] = attr_to_l1attr_not_flip(flip_setattr);
	}
	tt = get_translation_table(pt);
	return initial_lookup.walk(tt, 0, start, end, initial_lookup.callback, &args);
}

static pte_t *lookup_pte(translation_table_t* tt, uintptr_t virt, int pgshift,
		uintptr_t *basep, size_t *sizep, int *p2alignp)
{
	pte_t *ptep;
	uintptr_t base;
	size_t size;
	int p2align;

	ptep = NULL;
	if (!pgshift) {
		if (first_level_block_support) {
			pgshift = PTL3_CONT_SHIFT;
		} else {
			pgshift = PTL2_CONT_SHIFT;
		}
	}

	ptep = ptl4_offset(tt, virt);
	if (ptl4_null(ptep)) {
		if (pgshift >= PTL3_CONT_SHIFT) {
			pgshift = PTL3_CONT_SHIFT;
		} else if (pgshift > PTL3_SHIFT) {
			pgshift = PTL3_SHIFT;
		} else {
			ptep = NULL;
		}
		goto out;
	}

	ptep = ptl3_offset(ptep, virt);
	if (ptl3_null(ptep)) {
		if (pgshift >= PTL3_CONT_SHIFT) {
			pgshift = PTL3_CONT_SHIFT;
		} else if (pgshift >= PTL3_SHIFT) {
			pgshift = PTL3_SHIFT;
		} else {
			ptep = NULL;
		}
		goto out;
	}
	if (ptl3_type_block(ptep)) {
		if (ptl3_is_contiguous(ptep) &&
		    pgshift >= PTL3_CONT_SHIFT) {
			pgshift = PTL3_CONT_SHIFT;
		} else if (pgshift >= PTL3_SHIFT) {
			pgshift = PTL3_SHIFT;
		} else {
			ptep = NULL;
		}
		goto out;
	}

	ptep = ptl2_offset(ptep, virt);
	if (ptl2_null(ptep)) {
		if (pgshift >= PTL2_CONT_SHIFT) {
			pgshift = PTL2_CONT_SHIFT;
		} else if (pgshift >= PTL2_SHIFT) {
			pgshift = PTL2_SHIFT;
		} else {
			ptep = NULL;
		}
		goto out;
	}
	if (ptl2_type_block(ptep)) {
		if (ptl2_is_contiguous(ptep) &&
		    pgshift >= PTL2_CONT_SHIFT) {
			pgshift = PTL2_CONT_SHIFT;
		} else if (pgshift >= PTL2_SHIFT) {
			pgshift = PTL2_SHIFT;
		} else {
			ptep = NULL;
		}
		goto out;
	}

	ptep = ptl1_offset(ptep, virt);
	if (ptl1_type_page(ptep)) {
		if (ptl1_is_contiguous(ptep) &&
		    pgshift >= PTL1_CONT_SHIFT) {
			pgshift = PTL1_CONT_SHIFT;
		} else {
			pgshift = PTL1_SHIFT;
		}
		goto out;
	}
	if (pgshift >= PTL1_CONT_SHIFT) {
		pgshift = PTL1_CONT_SHIFT;
	} else {
		pgshift = PTL1_SHIFT;
	}

out:
	size = (size_t)1 << pgshift;
	base = virt & ~(size - 1);
	p2align = pgshift - PAGE_SHIFT;
	if (basep) *basep = base;
	if (sizep) *sizep = size;
	if (p2alignp) *p2alignp = p2align;

	return ptep;
}

pte_t *ihk_mc_pt_lookup_pte(page_table_t pt, void *virt, int pgshift,
		void **basep, size_t *sizep, int *p2alignp)
{
	pte_t *ptep;
	uintptr_t base;
	size_t size;
	int p2align;
	translation_table_t* tt;

	dkprintf("ihk_mc_pt_lookup_pte(%p,%p,%d)\n", pt, virt, pgshift);
	tt = get_translation_table(pt);
	ptep = lookup_pte(tt, (uintptr_t)virt, pgshift, &base, &size, &p2align);
	if (basep) *basep = (void *)base;
	if (sizep) *sizep = size;
	if (p2alignp) *p2alignp = p2align;
	dkprintf("ihk_mc_pt_lookup_pte(%p,%p,%d): %p %lx %lx %d\n",
			pt, virt, pgshift, ptep, base, size, p2align);
	return ptep;
}

struct set_range_args {
	page_table_t pt;
	uintptr_t phys;
	pte_t attr[4];
	int pgshift;
	uintptr_t diff;
	struct process_vm *vm;
	struct vm_range *range; /* To find pages we don't need to call memory_stat_rss_add() */
	int overwrite;
};

int set_range_middle(void *args0, pte_t *ptep, uintptr_t base, uintptr_t start,
		     uintptr_t end, int level);

int set_range_l1(void *args0, pte_t *ptep, uintptr_t base, uintptr_t start,
		uintptr_t end)
{
	struct set_range_args *args = args0;
	int error;
	uintptr_t phys;
	pte_t pte;

	dkprintf("set_range_l1(%lx,%lx,%lx)\n", base, start, end);

	if (!args->overwrite && !ptl1_null(ptep)) {
		error = -EBUSY;
		ekprintf("set_range_l1(%lx,%lx,%lx):page exists. %d %lx\n",
				base, start, end, error, *ptep);
		(void)clear_range(args->pt, args->vm, start, base, KEEP_PHYSICAL, NULL);
		goto out;
	}

	phys = args->phys + (base - start);

#if 1
	/* Check if we can begin / end a series of contiguous PTEs */
	if (__page_offset(base, PTL1_CONT_SIZE) == 0) { //check head pte
		uintptr_t next_addr = base + PTL1_CONT_SIZE;

		if (end < next_addr) {
			next_addr = end;
		}

		/* Begin the series if physical address is also aligned and
		 * the range covers the series. Don't start or end it if
		 * physical address is not aligned or the range ends early.
		 */
		if (__page_offset(phys | next_addr, PTL1_CONT_SIZE) == 0) {
			args->attr[0] |= PTE_CONT;
			if (rusage_memory_stat_add(args->range, phys,
						   PTL1_CONT_SIZE,
						   PTL1_CONT_SIZE)) {
				dkprintf("%lx+,%s: calling memory_stat_rss_add(),base=%lx,phys=%lx,size=%ld,pgsize=%ld\n",
					 phys, __func__, base, phys,
					 PTL1_CONT_SIZE, PTL1_CONT_SIZE);
			}
		} else {
			args->attr[0] &= ~PTE_CONT;
		}
	}
#endif
	pte = phys | args->attr[0];
	ptl1_set(ptep, pte);

	error = 0;
	// call memory_stat_rss_add() here because pgshift is resolved here
	if (!(args->attr[0] & PTE_CONT)) {
		if (rusage_memory_stat_add(args->range, phys,
					   PTL1_SIZE, PTL1_SIZE)) {
			dkprintf("%lx+,%s: calling memory_stat_rss_add(),base=%lx,phys=%lx,size=%ld,pgsize=%ld\n",
				phys, __func__, base, phys,
				PTL1_SIZE, PTL1_SIZE);
		}
	}

out:
	dkprintf("set_range_l1(%lx,%lx,%lx): %d %lx\n",
			base, start, end, error, *ptep);
	return error;
}

int set_range_l2(void *args0, pte_t *ptep, uintptr_t base, uintptr_t start,
		uintptr_t end)
{
	return set_range_middle(args0, ptep, base, start, end, 2);
}

int set_range_l3(void *args0, pte_t *ptep, uintptr_t base, uintptr_t start,
		uintptr_t end)
{
	return set_range_middle(args0, ptep, base, start, end, 3);
}

int set_range_l4(void *args0, pte_t *ptep, uintptr_t base, uintptr_t start,
		uintptr_t end)
{
	return set_range_middle(args0, ptep, base, start, end, 4);
}

int set_range_middle(void *args0, pte_t *ptep, uintptr_t base, uintptr_t start,
		     uintptr_t end, int level)
{
	const struct table {
		walk_pte_t* walk;
		walk_pte_fn_t* callback;
		unsigned long pgsize;
		unsigned long pgshift;
		unsigned long cont_pgsize;
		unsigned long cont_pgshift;
	} table[] = {
		{walk_pte_l1, set_range_l1, PTL2_SIZE, PTL2_SHIFT, PTL2_CONT_SIZE, PTL2_CONT_SHIFT}, /*PTL2: second*/
		{walk_pte_l2, set_range_l2, PTL3_SIZE, PTL3_SHIFT, PTL3_CONT_SIZE, PTL2_CONT_SHIFT}, /*PTL3: first*/
		{walk_pte_l3, set_range_l3, PTL4_SIZE, PTL4_SHIFT, PTL4_CONT_SIZE, PTL2_CONT_SHIFT}, /*PTL4: zero*/
	};
	const struct table tbl = table[level-2];

	struct set_range_args *args = args0;
	int error;
	translation_table_t* tt;
	translation_table_t* tt_pa = NULL;

	dkprintf("set_range_middle(%lx,%lx,%lx,%d)\n", base, start, end, level);

retry:
	if (ptl_null(ptep, level) || (args->overwrite && ptl_type_page(ptep, level))) {
		pte_t pte;
		uintptr_t phys;
		if (level == 2 || (level == 3 && first_level_block_support)) {
			if ((start <= base) && ((base + tbl.pgsize) <= end)
			    && ((args->diff & (tbl.pgsize - 1)) == 0)
			    && (!args->pgshift
				|| (args->pgshift == tbl.pgshift ||
				    args->pgshift == tbl.cont_pgshift))) {

				phys = args->phys + (base - start);

#if 1
				/* Check if we can begin / end a series of
				 * contiguous PTEs
				 */
				if (__page_offset(base, tbl.cont_pgsize) == 0) {
					uintptr_t next_addr = base +
						tbl.cont_pgsize;

					if (end < next_addr) {
						next_addr = end;
					}

					/* Begin the series if physical address
					 * is also aligned and the range covers
					 * the series. Don't start or end it if
					 * physical address is not aligned or
					 * the range ends early.
					 */
					if (__page_offset(phys | next_addr, tbl.cont_pgsize) == 0) {
						args->attr[level-1] |= PTE_CONT;
						if (rusage_memory_stat_add(args->range,
									   phys,
									   tbl.cont_pgsize,
									   tbl.cont_pgsize)) {
							dkprintf("%lx+,%s: calling memory_stat_rss_add(),base=%lx,phys=%lx,size=%ld,pgsize=%ld\n",
								 phys, __func__,
								 base, phys,
								 tbl.cont_pgsize,
								 tbl.cont_pgsize);
						}
					} else {
						args->attr[level-1] &= ~PTE_CONT;
					}
				}
#endif

				ptl_set(ptep, phys | args->attr[level-1],
					level);

				error = 0;
				dkprintf("set_range_middle(%lx,%lx,%lx,%d):"
					 "large page. %d %lx\n",
					 base, start, end, level, error, *ptep);
				// Call memory_stat_rss_add() here because pgshift is resolved here
				if (!(args->attr[level-1] & PTE_CONT)) {
					if (rusage_memory_stat_add(args->range,
								   phys,
								   tbl.pgsize,
								   tbl.pgsize)) {
						dkprintf("%lx+,%s: calling memory_stat_rss_add(),base=%lx,phys=%lx,size=%ld,pgsize=%ld\n",
							 phys, __func__, base,
							 phys,
							 tbl.pgsize,
							 tbl.pgsize);
					}
				}
				goto out;
			}
		}

		if (!tt_pa) {
			tt_pa = __alloc_new_tt(IHK_MC_AP_NOWAIT);
			if (tt_pa == NULL) {
				error = -ENOMEM;
				ekprintf("set_range_middle(%lx,%lx,%lx,%d):"
					 "__alloc_new_tt failed. %d %lx\n",
					 base, start, end, level, error, *ptep);
				(void)clear_range(args->pt, args->vm, start, base,
						  KEEP_PHYSICAL, NULL);
				goto out;
			}
		}

		pte = (pte_t)(((unsigned long)(tt_pa) & PT_PHYSMASK) | PFL_PDIR_TBL_ATTR);
		pte = atomic_cmpxchg8(ptep, PTE_NULL, pte);
		if (pte != PTE_NULL) {
			/* failed to set entry */
			goto retry;
		}

		tt = (translation_table_t*)phys_to_virt((unsigned long)tt_pa);
		tt_pa = NULL;
	}
	else if (ptl_type_page(ptep, level)) {
		error = -EBUSY;
		ekprintf("set_range_middle(%lx,%lx,%lx,%d):"
			 "page exists. %d %lx\n",
			 base, start, end, level, error, *ptep);
		(void)clear_range(args->pt, args->vm, start, base, KEEP_PHYSICAL, NULL);
		goto out;
	}
	else {
		tt = (translation_table_t*)phys_to_virt(ptl_phys(ptep, level));
	}

	error = tbl.walk(tt, base, start, end, tbl.callback, args0);
	if (error) {
		ekprintf("set_range_middle(%lx,%lx,%lx,%d):"
			 "walk pte failed. %d %lx\n",
			 base, start, end, level, error, *ptep);
		goto out;
	}

	error = 0;
out:
	if (tt_pa) {
		ihk_mc_free_pages(phys_to_virt((unsigned long)tt_pa), 1);
	}
	dkprintf("set_range_middle(%lx,%lx,%lx,%d): %d %lx\n",
		 base, start, end, level, error, *ptep);
	return error;
}

int ihk_mc_pt_set_range(page_table_t pt, struct process_vm *vm, void *start, 
		void *end, uintptr_t phys, enum ihk_mc_pt_attribute attr,
		int pgshift, struct vm_range *range, int overwrite)
{
	const struct table {
		walk_pte_t* walk;
		walk_pte_fn_t* callback;
	} tables[] = {
		{walk_pte_l2, set_range_l2}, /*second*/
		{walk_pte_l3, set_range_l3}, /*first*/
		{walk_pte_l4, set_range_l4}, /*zero*/
	};
	const struct table initial_lookup = tables[CONFIG_ARM64_PGTABLE_LEVELS - 2];
	int error;
	struct set_range_args args;
	translation_table_t* tt;

	dkprintf("ihk_mc_pt_set_range(%p,%p,%p,%lx,%x,%d,%lx-%lx)\n",
			 pt, start, end, phys, attr, pgshift, range->start, range->end);

	args.pt = pt;
	args.phys = phys;
	args.diff = (uintptr_t)start ^ phys;
	args.vm = vm;
	args.pgshift = pgshift;
	args.range = range;
	args.overwrite = overwrite;

	// conversion
	switch (CONFIG_ARM64_PGTABLE_LEVELS)
	{
	case 4:	args.attr[3] = attr_to_l4attr(attr); /*PTL4*/
	case 3:	args.attr[2] = attr_to_l3attr(attr); /*PTL3*/
	case 2:	args.attr[1] = attr_to_l2attr(attr); /*PTL2*/
		args.attr[0] = attr_to_l1attr(attr); /*PTL1*/
	}


	tt = get_translation_table(pt);
	error = initial_lookup.walk(tt, 0, (uintptr_t)start, (uintptr_t)end,
				    initial_lookup.callback, &args);
	if (error) {
		ekprintf("ihk_mc_pt_set_range(%p,%p,%p,%p,%lx,%x):"
			 "walk_pte failed. %d\n",
			 pt, vm, start, end, phys, attr, error);
		goto out;
	}

	error = 0;
out:
	dkprintf("ihk_mc_pt_set_range(%p,%p,%p,%p,%lx,%x): %d\n",
		 pt, vm, start, end, phys, attr, error);
	return error;
}

int ihk_mc_pt_set_pte(page_table_t pt, pte_t *ptep, size_t pgsize,
		uintptr_t phys, enum ihk_mc_pt_attribute attr)
{
	int error;
	pte_t pte;

	dkprintf("ihk_mc_pt_set_pte(%p,%p,%lx,%lx,%x)\n",
			pt, ptep, pgsize, phys, attr);

	if (pgsize == PTL1_SIZE) {
		pte =  phys | attr_to_l1attr(attr);
		ptl1_set(ptep, pte);
	}
	else if (pgsize == PTL2_SIZE) {
		if (phys & (PTL2_SIZE - 1)) {
			kprintf("%s: error: phys needs to be PTL2_SIZE aligned\n", __FUNCTION__);
			error = -1;
			goto out;
		}
		pte =  phys | attr_to_l2attr(attr | PTATTR_LARGEPAGE);
		ptl2_set(ptep, pte);
	}
	else if (pgsize == PTL3_SIZE && first_level_block_support) {
		if (phys & (PTL3_SIZE - 1)) {
			kprintf("%s: error: phys needs to be PTL3_SIZE aligned\n", __FUNCTION__);
			error = -1;
			goto out;
		}
		pte =  phys | attr_to_l3attr(attr | PTATTR_LARGEPAGE);
		ptl3_set(ptep, pte);
	}
	else {
		error = -EINVAL;
		ekprintf("ihk_mc_pt_set_pte(%p,%p,%lx,%lx,%x):"
				"page size. %d %lx\n",
				pt, ptep, pgsize, phys, attr, error, *ptep);
		panic("ihk_mc_pt_set_pte:page size");
		goto out;
	}

	error = 0;
out:
	dkprintf("ihk_mc_pt_set_pte(%p,%p,%lx,%lx,%x): %d %lx\n",
			pt, ptep, pgsize, phys, attr, error, *ptep);
	return error;
}

int ihk_mc_pt_split(page_table_t pt, struct process_vm *vm, void *addr)
{
	int error;
	pte_t *ptep;
	void *pgaddr;
	size_t pgsize;
	intptr_t phys;
	struct page *page;

	int level;

retry:
	ptep = ihk_mc_pt_lookup_pte(pt, addr, 0, &pgaddr, &pgsize, NULL);
	level = pgsize_to_tbllv(pgsize);
	if (level < 0) {
		ekprintf("ihk_mc_pt_split:invalid pgsize %#lx\n", pgsize);
		return level;
	}

	if (ptep && !ptl_null(ptep, level) && (pgaddr != addr)) {
		page = NULL;
		if (ptl_is_contiguous(ptep, level)) {
			error = split_contiguous_pages(ptep, pgsize);
			if (error) {
				goto out;
			}
			goto retry;
		}

		if (!ptl_fileoff(ptep, level)) {
			phys = ptl_phys(ptep, level);
			page = phys_to_page(phys);
		}
		if (page && (page_is_in_memobj(page)
					|| page_is_multi_mapped(page))) {
			error = -EINVAL;
			kprintf("ihk_mc_pt_split:NYI:page break down\n");
			goto out;
		}

		error = split_large_page(ptep, pgsize);
		if (error) {
			kprintf("ihk_mc_pt_split:split_large_page failed. %d\n", error);
			goto out;
		}
		arch_flush_tlb_single(get_address_space_id(vm->address_space->page_table),
					(uint64_t)pgaddr);
		goto retry;
	}

	error = 0;
out:
	return error;
} /* ihk_mc_pt_split() */

int arch_get_smaller_page_size(void *args, size_t cursize, size_t *newsizep,
		int *p2alignp)
{
	size_t newsize;
	int p2align;
	int error;

	if (0) {
		/* dummy */
		panic("not reached");
	}
	else if (CONFIG_ARM64_PGTABLE_LEVELS > 2 &&
				cursize > PTL3_CONT_SIZE) {
		newsize = PTL3_CONT_SIZE;
		p2align = PTL3_CONT_SHIFT - PTL1_SHIFT;
	}
	else if (CONFIG_ARM64_PGTABLE_LEVELS > 2 &&
				cursize > PTL3_SIZE) {
		newsize = PTL3_SIZE;
		p2align = PTL3_SHIFT - PTL1_SHIFT;
	}
	else if (cursize > PTL2_CONT_SIZE) {
		newsize = PTL2_CONT_SIZE;
		p2align = PTL2_CONT_SHIFT - PTL1_SHIFT;
	}
	else if (cursize > PTL2_SIZE) {
		newsize = PTL2_SIZE;
		p2align = PTL2_SHIFT - PTL1_SHIFT;
	}
	else if (cursize > PTL1_CONT_SIZE) {
		newsize = PTL1_CONT_SIZE;
		p2align = PTL1_CONT_SHIFT - PTL1_SHIFT;
	}
	else if (cursize > PTL1_SIZE) {
		newsize = PTL1_SIZE;
		p2align = PTL1_SHIFT - PTL1_SHIFT;
	}
	else {
		error = -ENOMEM;
		newsize = 0;
		p2align = -1;
		goto out;
	}

	error = 0;
	if (newsizep) *newsizep = newsize;
	if (p2alignp) *p2alignp = p2align;

out:
	dkprintf("arch_get_smaller_page_size(%p,%lx): %d %lx %d\n",
		 args, cursize, error, newsize, p2align);
	return error;
}

enum ihk_mc_pt_attribute arch_vrflag_to_ptattr(unsigned long flag, uint64_t fault, pte_t *ptep)
{
	enum ihk_mc_pt_attribute attr;

	attr = common_vrflag_to_ptattr(flag, fault, ptep);

	if ((fault & PF_PROT)
			|| ((fault & PF_POPULATE) && (flag & VR_PRIVATE))
			|| ((fault & PF_WRITE) && !(flag & VR_PRIVATE))) {
		attr |= PTATTR_DIRTY;
	}
	return attr;
}

struct move_args {
	uintptr_t src;
	uintptr_t dest;
	struct process_vm *vm;
	struct vm_range *range;
};

static int move_one_page(void *arg0, page_table_t pt, pte_t *ptep, 
		void *pgaddr, int pgshift)
{
	int error;
	struct move_args *args = arg0;
	size_t pgsize = (size_t)1 << pgshift;
	uintptr_t dest;
	pte_t apte;
	uintptr_t phys;
	enum ihk_mc_pt_attribute attr;

	dkprintf("move_one_page(%p,%p,%p %#lx,%p,%d)\n",
			arg0, pt, ptep, *ptep, pgaddr, pgshift);
	if (pte_is_fileoff(ptep, pgsize)) {
		error = -ENOTSUPP;
		kprintf("move_one_page(%p,%p,%p %#lx,%p,%d):fileoff. %d\n",
				arg0, pt, ptep, *ptep, pgaddr, pgshift, error);
		goto out;
	}

	dest = args->dest + ((uintptr_t)pgaddr - args->src);

	apte = PTE_NULL;
	pte_xchg(ptep, &apte);

	// check attributes before clearing to PTE_NULL
	if (pte_is_contiguous(&apte)) {
		// check if ptep is an entry of contiguous pte head
		if (page_is_contiguous_head(ptep, pgsize)) {
			int level = pgsize_to_tbllv(pgsize);

			pgsize = tbllv_to_contpgsize(level);
			pgshift = tbllv_to_contpgshift(level);
		} else {
			error = 0;
			goto out;
		}
	}

	phys = apte & PT_PHYSMASK;
	attr = apte & ~PT_PHYSMASK;

	error = ihk_mc_pt_set_range(pt, args->vm, (void *)dest,
				    (void *)(dest + pgsize), phys, attr,
				    pgshift, args->range, 0);
	if (error) {
		kprintf("move_one_page(%p,%p,%p %#lx,%p,%d):"
				"set failed. %d\n",
				arg0, pt, ptep, *ptep, pgaddr, pgshift, error);
		goto out;
	}

	error = 0;
out:
	dkprintf("move_one_page(%p,%p,%p %#lx,%p,%d):%d\n",
			arg0, pt, ptep, *ptep, pgaddr, pgshift, error);
	return error;
}

int move_pte_range(page_table_t pt, struct process_vm *vm, 
		   void *src, void *dest, size_t size, struct vm_range *range)
{
	int error;
	struct move_args args;
	pte_t *ptep;
	size_t pgsize;

	dkprintf("move_pte_range(%p,%p,%p,%#lx)\n", pt, src, dest, size);
	args.src = (uintptr_t)src;
	args.dest = (uintptr_t)dest;
	args.vm = vm;
	args.range = range;

	ptep = ihk_mc_pt_lookup_pte(pt, src, 0, NULL, &pgsize, NULL);
	if (ptep && pte_is_contiguous(ptep)) {
		if (!page_is_contiguous_head(ptep, pgsize)) {
			// start pte is not contiguous head
			error = split_contiguous_pages(ptep, pgsize);
			if (error) {
				goto out;
			}
		}
	}

	ptep = ihk_mc_pt_lookup_pte(pt, src + size - 1, 0, NULL, &pgsize, NULL);
	if (ptep && pte_is_contiguous(ptep)) {
		if (!page_is_contiguous_tail(ptep, pgsize)) {
			// end pte is not contiguous tail
			error = split_contiguous_pages(ptep, pgsize);
			if (error) {
				goto out;
			}
		}
	}

	error = visit_pte_range(pt, src, src+size, 0, VPTEF_SKIP_NULL,
			&move_one_page, &args);
	flush_tlb();	/* XXX: TLB flush */
	if (error) {
		goto out;
	}

	error = 0;
out:
	dkprintf("move_pte_range(%p,%p,%p,%#lx):%d\n",
			pt, src, dest, size, error);
	return error;
}

void load_page_table(struct page_table *pt)
{
	if (pt == NULL) {
		// load page table for idle(EL1) process.
		switch_mm(init_pt);
		return;
	}
	// load page table for user(EL0) thread.
	switch_mm(pt);
	return;
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
	/* head.Sで初期化済み */
	unsigned long __end;
	int nlpages;

	__end = ((unsigned long)_end + LARGE_PAGE_SIZE * 2 - 1)
		& LARGE_PAGE_MASK;
	nlpages = (__end - MAP_KERNEL_START) >> LARGE_PAGE_SHIFT;

	kprintf("TEXT: # of large pages = %d\n", nlpages);
	kprintf("TEXT: Base address = %lx\n", arm64_kernel_phys_base);
}

void *map_fixed_area(unsigned long phys, unsigned long size, int uncachable)
{
	struct page_table* pt;
	unsigned long poffset, paligned;
	int i, npages;
	void *v = (void *)fixed_virt;
	enum ihk_mc_pt_attribute attr;

	poffset = phys & (PAGE_SIZE - 1);
	paligned = phys & PAGE_MASK;
	npages = (poffset + size + PAGE_SIZE - 1) >> PAGE_SHIFT;

	attr = PTATTR_WRITABLE | PTATTR_ACTIVE;
#if 0	/* In the case of LAPIC MMIO, something will happen */
	attr |= PTATTR_NO_EXECUTE;
#endif
	if (uncachable) {
		attr |= PTATTR_UNCACHABLE;
	}

	dkprintf("map_fixed: phys: 0x%lx => 0x%lx (%d pages)\n",
			paligned, v, npages);

	pt = get_init_page_table();
	for (i = 0; i < npages; i++) {
		if(__set_pt_page(pt, (void *)fixed_virt, paligned, attr)){
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
	set_pt_large_page(pt, 0, 0, PTATTR_NO_EXECUTE|PTATTR_WRITABLE);
}

int first_level_block_support;
void init_page_table(void)
{
	uint64_t parange;

	ihk_mc_spinlock_init(&init_pt_lock);

	if (PAGE_SIZE == _SZ4KB) {
		first_level_block_support = 1;
	} else if (PAGE_SIZE == _SZ16KB) {
		first_level_block_support = 0;
	} else {
		parange = read_sysreg(id_aa64mmfr0_el1) & 7;
		first_level_block_support =
			(parange >= ID_AA64MMFR0_PARANGE_52);
	}

	/* Normal memory area */
	init_normal_area(init_pt);
	init_fixed_area(init_pt);
	init_text_area(init_pt);

	/* virt to phys */
	kprintf("Page table is now at %p\n", init_pt);
}

extern void __reserve_arch_pages(unsigned long, unsigned long,
		void (*)(struct ihk_page_allocator_desc *, 
			unsigned long, unsigned long, int));

void ihk_mc_reserve_arch_pages(struct ihk_page_allocator_desc *pa_allocator,
		unsigned long start, unsigned long end,
		void (*cb)(struct ihk_page_allocator_desc *, 
			unsigned long, unsigned long, int))
{
	kprintf("reserve arch pages (%#llx, %#llx, %p)\n", start, end, cb);
	/* Reserve Text + temporal heap */
	cb(pa_allocator, virt_to_phys(_head), virt_to_phys(get_last_early_heap()), 0);
	/* Reserve trampoline area to boot the second ap */
//	cb(pa_allocator, ap_trampoline, ap_trampoline + AP_TRAMPOLINE_SIZE, 0); //TODO:他コア起動時には考慮が必要かも
	/* Reserve the null page */
	cb(pa_allocator, 0, PAGE_SIZE, 0);
	/* 
	 * Micro-arch specific 
	 * TODO: this does nothing in SMP mode, update it for KNC if necessary 
	 */
	__reserve_arch_pages(start, end, cb);
}

unsigned long virt_to_phys(void *v)
{
	unsigned long va = (unsigned long)v;

	if (va >= MAP_ST_START) {
		return va - MAP_ST_START + arm64_st_phys_base;
	}
	return va - MAP_KERNEL_START + arm64_kernel_phys_base;
}

void *phys_to_virt(unsigned long p)
{
	return (void *)((p - arm64_st_phys_base) | MAP_ST_START);
}

int copy_from_user(void *dst, const void *src, size_t siz)
{
	struct process_vm *vm = cpu_local_var(current)->vm;
	return read_process_vm(vm, dst, src, siz);
}

int strlen_user(const char *s)
{
	struct process_vm *vm = cpu_local_var(current)->vm;
	unsigned long pgstart;
	int maxlen;
	int error = 0;
	const uint64_t reason = PF_USER; /* page not present */
	const char *head = s;

	maxlen = PAGE_SIZE - (((unsigned long)s) & (PAGE_SIZE - 1));
	pgstart = ((unsigned long)s) & PAGE_MASK;

	if (!pgstart || pgstart >= MAP_KERNEL_START) {
		return -EFAULT;
	}

	for (;;) {
		error = page_fault_process_vm(vm, (void *)pgstart, reason);
		if (error) {
			return error;
		}

		while (*s && maxlen > 0) {
			s++;
			maxlen--;
		}

		if (!*s) {
			break;
		}
		maxlen = PAGE_SIZE;
		pgstart += PAGE_SIZE;
	}
	return s - head;
}

int strcpy_from_user(char *dst, const char *src)
{
	struct process_vm *vm = cpu_local_var(current)->vm;
	unsigned long pgstart;
	int maxlen;
	int error = 0;
	const uint64_t reason = PF_USER; /* page not present */

	maxlen = PAGE_SIZE - (((unsigned long)src) & (PAGE_SIZE - 1));
	pgstart = ((unsigned long)src) & PAGE_MASK;

	if (!pgstart || pgstart >= MAP_KERNEL_START) {
		return -EFAULT;
	}

	for (;;) {
		error = page_fault_process_vm(vm, (void *)pgstart, reason);
		if (error) {
			return error;
		}

		while (*src && maxlen > 0) {
			*(dst++) = *(src++);
			maxlen--;
		}

		if (!*src) {
			*dst = '\0';
			break;
		}
		maxlen = PAGE_SIZE;
		pgstart += PAGE_SIZE;
	}
	return error;
}

long getlong_user(long *dest, const long *p)
{
	int error;

	error = copy_from_user(dest, p, sizeof(long));
	if (error) {
		return error;
	}

	return 0;
}

int getint_user(int *dest, const int *p)
{
	int error;

	error = copy_from_user(dest, p, sizeof(int));
	if (error) {
		return error;
	}

	return 0;
}

int verify_process_vm(struct process_vm *vm,
		const void *usrc, size_t size)
{
	const uintptr_t ustart = (uintptr_t)usrc;
	const uintptr_t uend = ustart + size;
	uint64_t reason;
	uintptr_t addr;
	int error = 0;

	if ((ustart < vm->region.user_start)
			|| (vm->region.user_end <= ustart)
			|| ((vm->region.user_end - ustart) < size)) {
		kprintf("%s: error: out of user range\n", __FUNCTION__);
		return -EFAULT;
	}

	reason = PF_USER;	/* page not present */
	for (addr = ustart & PAGE_MASK; addr < uend; addr += PAGE_SIZE) {
		if (!addr)
			return -EINVAL;

		error = page_fault_process_vm(vm, (void *)addr, reason);
		if (error) {
			kprintf("%s: error: PF for %p failed\n", __FUNCTION__, addr);
			return error;
		}
	}

	return error;
}

int read_process_vm(struct process_vm *vm, void *kdst, const void *usrc, size_t siz)
{
	const uintptr_t ustart = (uintptr_t)usrc;
	const uintptr_t uend = ustart + siz;
	uint64_t reason;
	uintptr_t addr;
	int error;
	const void *from;
	void *to;
	size_t remain;
	size_t cpsize;
	unsigned long pa;
	void *va;

	if ((ustart < vm->region.user_start)
	    || (vm->region.user_end <= ustart)
	    || ((vm->region.user_end - ustart) < siz)) {
		kprintf("%s: error: out of user range\n", __FUNCTION__);
		return -EFAULT;
	}

	reason = PF_USER;	/* page not present */
	for (addr = ustart & PAGE_MASK; addr < uend; addr += PAGE_SIZE) {
		error = page_fault_process_vm(vm, (void *)addr, reason);
		if (error) {
			kprintf("%s: error: PF for %p failed\n", __FUNCTION__, addr);
			return error;
		}
	}

	from = usrc;
	to = kdst;
	remain = siz;
	while (remain > 0) {
		cpsize = PAGE_SIZE - ((uintptr_t)from & (PAGE_SIZE - 1));
		if (cpsize > remain) {
			cpsize = remain;
		}

		error = ihk_mc_pt_virt_to_phys(vm->address_space->page_table, from, &pa);
		if (error) {
			kprintf("%s: error: resolving physical address or %p\n", __FUNCTION__, from);
			return error;
		}

		if (!is_mckernel_memory(pa, pa + cpsize)) {
			dkprintf("%s: pa is outside of LWK memory, to: %p, pa: %p,"
				"cpsize: %d\n", __FUNCTION__, to, pa, cpsize);
			va = ihk_mc_map_virtual(pa, 1, PTATTR_ACTIVE);
			memcpy(to, va, cpsize);
			ihk_mc_unmap_virtual(va, 1);
		}
		else {
			va = phys_to_virt(pa);
			memcpy(to, va, cpsize);
		}

		from += cpsize;
		to += cpsize;
		remain -= cpsize;
	}

	return 0;
} /* read_process_vm() */

int copy_to_user(void *dst, const void *src, size_t siz)
{
	struct process_vm *vm = cpu_local_var(current)->vm;
	return write_process_vm(vm, dst, src, siz);
}

int setlong_user(long *dst, long data)
{
	return copy_to_user(dst, &data, sizeof(data));
}

int setint_user(int *dst, int data)
{
	return copy_to_user(dst, &data, sizeof(data));
}

int write_process_vm(struct process_vm *vm, void *udst, const void *ksrc, size_t siz)
{
	const uintptr_t ustart = (uintptr_t)udst;
	const uintptr_t uend = ustart + siz;
	uint64_t reason;
	uintptr_t addr;
	int error;
	const void *from;
	void *to;
	size_t remain;
	size_t cpsize;
	unsigned long pa;
	void *va;

	if ((ustart < vm->region.user_start)
			|| (vm->region.user_end <= ustart)
			|| ((vm->region.user_end - ustart) < siz)) {
		return -EFAULT;
	}

	reason = PF_POPULATE | PF_WRITE | PF_USER;
	for (addr = ustart & PAGE_MASK; addr < uend; addr += PAGE_SIZE) {
		error = page_fault_process_vm(vm, (void *)addr, reason);
		if (error) {
			return error;
		}
	}

	from = ksrc;
	to = udst;
	remain = siz;
	while (remain > 0) {
		cpsize = PAGE_SIZE - ((uintptr_t)to & (PAGE_SIZE - 1));
		if (cpsize > remain) {
			cpsize = remain;
		}

		error = ihk_mc_pt_virt_to_phys(vm->address_space->page_table, to, &pa);
		if (error) {
			return error;
		}

		if (!is_mckernel_memory(pa, pa + cpsize)) {
			dkprintf("%s: pa is outside of LWK memory, from: %p,"
				"pa: %p, cpsize: %d\n", __FUNCTION__, from, pa, cpsize);
			va = ihk_mc_map_virtual(pa, 1, PTATTR_WRITABLE|PTATTR_ACTIVE);
			memcpy(va, from, cpsize);
			ihk_mc_unmap_virtual(va, 1);
		}
		else {
			va = phys_to_virt(pa);
			memcpy(va, from, cpsize);
		}

		from += cpsize;
		to += cpsize;
		remain -= cpsize;
	}

	return 0;
} /* write_process_vm() */

int patch_process_vm(struct process_vm *vm, void *udst, const void *ksrc, size_t siz)
{
	const uintptr_t ustart = (uintptr_t)udst;
	const uintptr_t uend = ustart + siz;
	uint64_t reason;
	uintptr_t addr;
	int error;
	const void *from;
	void *to;
	size_t remain;
	size_t cpsize;
	unsigned long pa;
	void *va;

	dkprintf("patch_process_vm(%p,%p,%p,%lx)\n", vm, udst, ksrc, siz);
	if ((ustart < vm->region.user_start)
			|| (vm->region.user_end <= ustart)
			|| ((vm->region.user_end - ustart) < siz)) {
		ekprintf("patch_process_vm(%p,%p,%p,%lx):not in user\n", vm, udst, ksrc, siz);
		return -EFAULT;
	}

	reason = PF_PATCH | PF_POPULATE | PF_WRITE | PF_USER;
	for (addr = ustart & PAGE_MASK; addr < uend; addr += PAGE_SIZE) {
		error = page_fault_process_vm(vm, (void *)addr, reason);
		if (error) {
			ekprintf("patch_process_vm(%p,%p,%p,%lx):pf(%lx):%d\n", vm, udst, ksrc, siz, addr, error);
			return error;
		}
	}

	from = ksrc;
	to = udst;
	remain = siz;
	while (remain > 0) {
		cpsize = PAGE_SIZE - ((uintptr_t)to & (PAGE_SIZE - 1));
		if (cpsize > remain) {
			cpsize = remain;
		}

		error = ihk_mc_pt_virt_to_phys(vm->address_space->page_table, to, &pa);
		if (error) {
			ekprintf("patch_process_vm(%p,%p,%p,%lx):v2p(%p):%d\n", vm, udst, ksrc, siz, to, error);
			return error;
		}

		if (!is_mckernel_memory(pa, pa + cpsize)) {
			dkprintf("%s: pa is outside of LWK memory, from: %p,"
				"pa: %p, cpsize: %d\n", __FUNCTION__, from, pa, cpsize);
			va = ihk_mc_map_virtual(pa, 1, PTATTR_WRITABLE|PTATTR_ACTIVE);
			memcpy(va, from, cpsize);
			ihk_mc_unmap_virtual(va, 1);
		}
		else {
			va = phys_to_virt(pa);
			memcpy(va, from, cpsize);
		}

		from += cpsize;
		to += cpsize;
		remain -= cpsize;
	}

	dkprintf("patch_process_vm(%p,%p,%p,%lx):%d\n", vm, udst, ksrc, siz, 0);
	return 0;
} /* patch_process_vm() */

void set_address_space_id(struct page_table *pt, int asid)
{
	pt->asid = asid;
}

int get_address_space_id(const struct page_table *pt)
{
	return pt->asid;
}

void set_translation_table(struct page_table *pt, translation_table_t* tt)
{
	translation_table_t* tt_pa = (void*)virt_to_phys(tt);
	pt->tt = tt;
	pt->tt_pa = tt_pa;
}

translation_table_t* get_translation_table(const struct page_table *pt)
{
	return pt->tt;
}

translation_table_t* get_translation_table_as_paddr(const struct page_table *pt)
{
	return pt->tt_pa;
}

void arch_adjust_allocate_page_size(struct page_table *pt,
				    uintptr_t fault_addr,
				    pte_t *ptep,
				    void **pgaddrp,
				    size_t *pgsizep)
{
	int level;

	if (!pgsize_is_contiguous(*pgsizep)) {
		return;
	}

	if (ptep == NULL) {
		void *ptr = get_translation_table(pt);
		int i;

		// Check the entries of the upper page table.
		// When PTE_NULL, do not change from the size of ContiguousPTE.
		level = pgsize_to_tbllv(*pgsizep);
		for (i = 4; i > 0; i--) {
			ptr = ptl_offset(ptr, fault_addr, i);
			if (ptl_null(ptr, i)) {
				if (level < i) {
					return;
				}
				ptep = ptr;
				break;
			}
		}
	}

	if (pte_is_null(ptep)) {
		struct memobj *obj;
		uintptr_t zeropage = NOPHYS;
		pte_t *head;
		pte_t *tail;

		if (zeroobj_create(&obj)) {
			panic("zeroobj_create");
		}
		memobj_get_page(obj, 0, PAGE_P2ALIGN, &zeropage, NULL, 0);

		head = get_contiguous_head(ptep, *pgsizep);
		tail = get_contiguous_tail(ptep, *pgsizep);
		for (/*nop*/; head <= tail; head++) {
			uintptr_t phys;

			if (pte_is_null(head)) {
				continue;
			}

			phys = pte_get_phys(head);
			if (phys == zeropage) {
				continue;
			}

			level = pgsize_to_tbllv(*pgsizep);
			*pgsizep = tbllv_to_pgsize(level);
			*pgaddrp = (void *)__page_align(fault_addr, *pgsizep);
			break;
		}
	}
}
