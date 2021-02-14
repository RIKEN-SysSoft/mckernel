#include <types.h>
#include <kmsg.h>
#include <errno.h>
#include <mman.h>
#include <kmalloc.h>
#include <cls.h>
#include <syscall.h>
#include <memory.h>
#include <process.h>
#include <mc_perf_event.h>
#include <bootparam.h>
#include <kref.h>
#include <io.h>

#include <tofu/tof_uapi.h>
#include <tofu/tof_icc.h>

/* DWARF generated headers */
#include <tofu/tofu_generated-tof_core_cq.h>
#include <tofu/tofu_generated-tof_utofu_device.h>
#include <tofu/tofu_generated-tof_utofu_cq.h>


struct kmalloc_cache_header tofu_scatterlist_cache[8];
struct kmalloc_cache_header tofu_mbpt_cache[8];
struct ihk_mc_page_cache_header tofu_mbpt_sg_pages_cache[8];
struct kmalloc_cache_header tofu_stag_range_cache[8];


typedef ihk_spinlock_t spinlock_t;
struct tof_core_irq;
struct tof_core_irq {
	void *reg;  /* base address of interrupt controller registers */
	uint64_t (*handler)(struct tof_core_irq *, uint64_t, void*);
	uint64_t panic_mask;
	uint64_t warn_mask;
	uint64_t task_mask;  /* cleared in tasklets */
	uint64_t all_mask;
	char name[16];
};

typedef void (*tof_core_signal_handler)(int, int, uint64_t, uint64_t);
#include <tofu/tofu_generated-tof_core_bg.h>
#include <tofu/tofu_generated-tof_utofu_bg.h>
#include <tofu/tofu_generated-tof_utofu_mbpt.h>

#include <tofu/tofu_stag_range.h>

/*
 * Tofu STAG regions list keeps track of stags in a given VM range..
 * Per-process tree is protected by process' vm_range_lock.
 */
int tof_utofu_stag_range_insert(struct process_vm *vm,
		struct vm_range *range,
		uintptr_t start, uintptr_t end,
		struct tof_utofu_cq *ucq, int stag)
{
	struct tofu_stag_range *tsr; // = kmalloc(sizeof(*tsr), IHK_MC_AP_NOWAIT);
	tsr = kmalloc_cache_alloc(&tofu_stag_range_cache[ihk_mc_get_numa_id()],
			sizeof(*tsr));

	if (!tsr) {
		kprintf("%s: error: allocating tofu_stag_range\n", __func__);
		return -ENOMEM;
	}

	tsr->start = start;
	tsr->end = end;
	tsr->ucq = ucq;
	tsr->stag = stag;

	ihk_mc_spinlock_lock_noirq(&vm->tofu_stag_lock);
	list_add_tail(&tsr->list, &range->tofu_stag_list);
	list_add_tail(&tsr->hash, &vm->tofu_stag_hash[stag % TOFU_STAG_HASH_SIZE]);
	ihk_mc_spinlock_unlock_noirq(&vm->tofu_stag_lock);

	dkprintf("%s: stag: %d for TNI %d CQ %d @ %p:%lu\n",
			__func__,
			tsr->stag,
			tsr->ucq->tni,
			tsr->ucq->cqid,
			tsr->start,
			(unsigned long)(tsr->end - tsr->start));

	return 0;
}

struct tofu_stag_range *tofu_stag_range_lookup_by_stag(struct process_vm *vm,
	int stag)
{
	struct tofu_stag_range *tsr;
	struct tofu_stag_range *match = NULL;

	ihk_mc_spinlock_lock_noirq(&vm->tofu_stag_lock);
	list_for_each_entry(tsr,
			&vm->tofu_stag_hash[stag % TOFU_STAG_HASH_SIZE], hash) {
		if (tsr->stag == stag) {
			match = tsr;
			break;
		}
	}
	ihk_mc_spinlock_unlock_noirq(&vm->tofu_stag_lock);

	return match;
}

/* XXX: vm->tofu_stag_lock must be held */
void __tofu_stag_range_remove(struct process_vm *vm, struct tofu_stag_range *tsr)
{
	dkprintf("%s: stag: %d for TNI %d CQ %d @ %p:%lu\n",
			__func__,
			tsr->stag,
			tsr->ucq->tni,
			tsr->ucq->cqid,
			tsr->start,
			(unsigned long)(tsr->end - tsr->start));

	list_del(&tsr->list);
	list_del(&tsr->hash);
	//kfree(tsr);
	kmalloc_cache_free(tsr);
}

void tofu_stag_range_remove(struct process_vm *vm, struct tofu_stag_range *tsr)
{
	ihk_mc_spinlock_lock_noirq(&vm->tofu_stag_lock);
	__tofu_stag_range_remove(vm, tsr);
	ihk_mc_spinlock_unlock_noirq(&vm->tofu_stag_lock);
}

static int tof_utofu_free_stag(struct tof_utofu_cq *ucq, int stag);

int tofu_stag_range_remove_overlapping(struct process_vm *vm,
		struct vm_range *range)
{
	struct tofu_stag_range *tsr, *next;
	int entries = 0;

	ihk_mc_spinlock_lock_noirq(&vm->tofu_stag_lock);

	list_for_each_entry_safe(tsr, next,
			&range->tofu_stag_list, list) {

		dkprintf("%s: stag: %d @ %p:%lu\n",
				__func__,
				tsr->stag,
				tsr->start,
				(unsigned long)(tsr->end - tsr->start));

		linux_spin_lock(&tsr->ucq->trans.mru_lock);
		tof_utofu_free_stag(tsr->ucq, tsr->stag);
		linux_spin_unlock(&tsr->ucq->trans.mru_lock);

		__tofu_stag_range_remove(vm, tsr);
		++entries;
	}

	ihk_mc_spinlock_unlock_noirq(&vm->tofu_stag_lock);

	return entries;
}

void tofu_stag_range_remove_by_addr(struct process_vm *vm,
	uintptr_t addr, size_t len)
{
	struct tofu_stag_range *tsr, *next;
	int hash;

	ihk_mc_spinlock_lock_noirq(&vm->tofu_stag_lock);
	for (hash = 0; hash < TOFU_STAG_HASH_SIZE; ++hash) {
		list_for_each_entry_safe(tsr, next,
				&vm->tofu_stag_hash[hash], hash) {

			if (tsr->start >= addr && tsr->end <= (addr + len)) {
				linux_spin_lock(&tsr->ucq->trans.mru_lock);
				tof_utofu_free_stag(tsr->ucq, tsr->stag);
				linux_spin_unlock(&tsr->ucq->trans.mru_lock);

				kprintf("%s: removed stag %d in %p:%lu\n",
						__func__, tsr->stag, addr, len);
				__tofu_stag_range_remove(vm, tsr);
			}

			{
				uintptr_t max_start, min_end;

				max_start = addr > tsr->start ? addr : tsr->start;
				min_end = (addr + len) < tsr->end ? (addr + len) : tsr->end;

				if ((tsr->start != 0 || vm->proc->status == PS_EXITED) &&
						(max_start < min_end)) {
					linux_spin_lock(&tsr->ucq->trans.mru_lock);
					tof_utofu_free_stag(tsr->ucq, tsr->stag);
					linux_spin_unlock(&tsr->ucq->trans.mru_lock);

					kprintf("%s: removed stag %p:%lu (overlaps with range %p:%lu)\n",
						__func__, tsr->start, (tsr->end - tsr->start), addr, len);
					__tofu_stag_range_remove(vm, tsr);
				}
			}
		}
	}
	ihk_mc_spinlock_unlock_noirq(&vm->tofu_stag_lock);
}

int tofu_stag_split_vm_range_on_addr(struct process_vm *vm,
		struct vm_range *range_low, struct vm_range *range_high,
		uintptr_t addr)
{
	struct tofu_stag_range *tsr, *next;
	int moved = 0;

	ihk_mc_spinlock_lock_noirq(&vm->tofu_stag_lock);

	list_for_each_entry_safe(tsr, next,
			&range_low->tofu_stag_list, list) {

		if (tsr->start >= addr) {
			list_del(&tsr->list);
			list_add_tail(&tsr->list, &range_high->tofu_stag_list);
			++moved;

			kprintf("%s: stag: %d @ %p:%lu moved to high range..\n",
					__func__,
					tsr->stag,
					tsr->start,
					(unsigned long)(tsr->end - tsr->start));
		}

		if (tsr->start < addr && tsr->end > addr) {
			kprintf("%s: WARNING: VM range split in middle of stag range..\n", __func__);
		}
	}

	ihk_mc_spinlock_unlock_noirq(&vm->tofu_stag_lock);

	return moved;
}



#define TOF_UTOFU_VERSION TOF_UAPI_VERSION
#define TOF_UTOFU_NUM_STAG_NTYPES 3
#define TOF_UTOFU_NUM_STAG_BITS(size) ((size) + 13)
#define TOF_UTOFU_NUM_STAG(size) ((uint64_t)1 << TOF_UTOFU_NUM_STAG_BITS(size))
#define TOF_UTOFU_STAG_TRANS_BITS 3
#define TOF_UTOFU_STAG_TRANS_SIZE ((uint64_t)1 << TOF_UTOFU_STAG_TRANS_BITS)
#define TOF_UTOFU_STAG_TRANS_TABLE_LEN(size) (TOF_UTOFU_NUM_STAG(size) * TOF_UTOFU_STAG_TRANS_SIZE)
#define TOF_UTOFU_STEERING_TABLE_LEN(size) (TOF_UTOFU_NUM_STAG(size) * TOF_ICC_STEERING_SIZE)
#define TOF_UTOFU_MB_TABLE_LEN(size) (TOF_UTOFU_NUM_STAG(size) * TOF_ICC_MB_SIZE)
#define TOF_UTOFU_STAG_MEM_LEN(size) (TOF_UTOFU_STEERING_TABLE_LEN(size) * 4)
#define TOF_UTOFU_SPECIAL_STAG 4096

#define TOF_UTOFU_ICC_COMMON_REGISTER (tof_icc_reg_pa + 0x0B000000)
#define TOF_UTOFU_REG_START tof_icc_reg_pa
#define TOF_UTOFU_REG_END (TOF_UTOFU_ICC_COMMON_REGISTER + 0x000FFFFF)

#define TOF_UTOFU_SET_SUBNET_TNI	0	/* This number is kernel TNIs number in setting subnet */
#define TOF_UTOFU_KCQ			11
#define TOF_UTOFU_LINKDOWN_PORT_MASK	0x000003FF

#define TOF_UTOFU_ALLOC_STAG_LPG	0x2
#define TOF_UTOFU_BLANK_MBVA (-1)

#define TOF_UTOFU_MRU_EMPTY (-1)

/* The `const' in roundup() prevents gcc-3.3 from calling __divdi3 */
#define roundup(x, y) (					\
{							\
	const typeof(y) __y = y;			\
	(((x) + (__y - 1)) / __y) * __y;		\
}							\
)
#define rounddown(x, y) (				\
{							\
	typeof(x) __x = (x);				\
	__x - (__x % (y));				\
}							\
)

ihk_spinlock_t tofu_tni_cq_lock[6][12];

struct tof_utofu_trans_list {
	int16_t prev;
	int16_t next;
	uint8_t pgszbits;
	struct tof_utofu_mbpt *mbpt;
};

static inline uintptr_t tof_utofu_get_stag_start(struct tof_utofu_cq *ucq, int stag)
{
	return ((uintptr_t)ucq->trans.table[stag].steering.bits.start) << PAGE_SHIFT;
}
static inline size_t tof_utofu_get_stag_len(struct tof_utofu_cq *ucq, int stag)
{
	return ((size_t)ucq->trans.table[stag].steering.bits.len) << PAGE_SHIFT;
}
static inline uintptr_t tof_utofu_get_mbpt_start(struct tof_utofu_cq *ucq, int stag)
{
	return ((uintptr_t)ucq->trans.table[stag].mbpt.bits.start) << PAGE_SHIFT;
}
static inline size_t tof_utofu_get_mbpt_len(struct tof_utofu_cq *ucq, int stag)
{
	return ((size_t)ucq->trans.table[stag].mbpt.bits.len) << PAGE_SHIFT;
}

#define raw_rc_output(fmt, args...) kprintf("%s: ", fmt, __func__, ##args)
static int tof_utofu_raw_rc_output_supress = 1;
static int tof_utofu_mbpt_address_match = 1;

static int tof_utofu_get_pagesize_locked(uintptr_t addr, size_t len,
		uint8_t *_pgszbits, bool readonly) {
	uint8_t cur_shift;
	uint8_t min_shift = U8_MAX;
	uintptr_t start, end, va;
	struct process *proc = cpu_local_var(current)->proc;
	struct process_vm *vm = cpu_local_var(current)->vm;
	int p2align;
	size_t psize;
	pte_t *ptep;
	//struct vm_range *range;

	if(addr < PAGE_SIZE){
		*_pgszbits = PAGE_SHIFT;
		return 0;
	}

	start = round_down(addr, PAGE_SIZE);
	end = round_up(addr + len, PAGE_SIZE);

	//range = lookup_process_memory_range(vm, start, end);
	//if (!range) {
	//	return -EFAULT;
	//}

	/* Special case for straight mapping */
	if (proc->straight_va && (void *)start >= proc->straight_va &&
		(void *)end < proc->straight_va + proc->straight_len) {

		if (end - start < PTL2_SIZE) {
			*_pgszbits = PTL1_SHIFT;
		}
		else {
			*_pgszbits = PTL2_SHIFT;
			*_pgszbits = PTL1_CONT_SHIFT;
		}
		return 0;
	}

	for (va = start; va < end; va += ((size_t)1 << cur_shift)) {
		ptep = ihk_mc_pt_lookup_fault_pte(vm, (void *)va,
				0, NULL, &psize, &p2align);

		if (unlikely(!ptep || !pte_is_present(ptep))) {
			kprintf("%s: ERROR: no valid PTE for 0x%lx\n",
					__func__, va);
			return -EFAULT;
		}

		cur_shift = p2align + PAGE_SHIFT;

		if (cur_shift < min_shift) {
			min_shift = cur_shift;
		}

		if (min_shift <= PAGE_SHIFT) {
			break;
		}
	}

#if 1
	/* Tofu only support 64kB and 2MB pages */
	if (min_shift > PTL1_CONT_SHIFT)
		min_shift = PTL1_CONT_SHIFT;
#endif

	*_pgszbits = min_shift;
	return 0;
}

static int tof_utofu_trans_search(struct tof_utofu_cq *ucq, uintptr_t start, uintptr_t end, uint8_t pgszbits, bool readonly){
	struct tof_utofu_trans_list *mru = ucq->trans.mru;
	uintptr_t stagstart, stagend;
	int stag;

	stag = ucq->trans.mruhead;
	if(stag == TOF_UTOFU_MRU_EMPTY){
		if(unlikely(!tof_utofu_raw_rc_output_supress)){
			raw_rc_output(-ENOENT);
		}
		return -ENOENT;
	}
	do {
		stagstart = tof_utofu_get_stag_start(ucq, stag);
		stagend = stagstart + tof_utofu_get_stag_len(ucq, stag);
		if(stag >= TOF_UTOFU_SPECIAL_STAG && ((stag & 0x1) == readonly) && (mru[stag].pgszbits == pgszbits)) {
			if ((tof_utofu_mbpt_address_match & 0x1)) {
				if ((stagstart == start) && (stagend == end)) {
				kprintf("%s: found stag: %d\n", __func__, stag);
					return stag;
				}
			}
			else {
				if ((stagstart <= start) && (end <= stagend)) {
					return stag;
				}
			}
		}
		stag = ucq->trans.mru[stag].next;
	} while(stag != ucq->trans.mruhead);
	if(unlikely(!tof_utofu_raw_rc_output_supress)){
		raw_rc_output(-ENOENT);
	}
	dkprintf("%s: -ENOENT\n", __func__);
	return -ENOENT;
}

static int tof_utofu_reserve_stag(struct tof_utofu_cq *ucq, bool readonly){
	int stag;
	for(stag = TOF_UTOFU_SPECIAL_STAG + readonly; stag < TOF_UTOFU_NUM_STAG(ucq->num_stag); stag += 2){
		if(!ucq->steering[stag].enable){
			dkprintf("%s: could use: %d\n", __func__, stag);
			return stag;
		}
	}
	return -1;
}

static int tof_utofu_calc_mbptstart(int64_t start, int64_t end, size_t mbpt_npages, uint8_t pgszbits,
	uintptr_t *mbptstart)
{
#if 0
	struct vm_area_struct *vma;
	int64_t len = mbpt_npages << pgszbits;
	size_t pgsz = (size_t)1 << pgszbits;

	vma = find_vma(current->mm, start);
	if(vma == NULL || vma->vm_start > start || vma->vm_end < end){
		return -ENOENT;
	}

	if(vma->vm_flags & VM_GROWSDOWN){
		/* stack */
		/* we cannot extend MBPTs to lower address.
		 * therefore, we allocate rather large MBPT. */
		int64_t upperbound;
		uintptr_t mbpttail;
		upperbound = round_up(vma->vm_end, pgsz);
		if ((start + len) < 0) {
			mbpttail = upperbound;
		}
		else {
			mbpttail = min(upperbound, start + len);
		}
		*mbptstart = mbpttail - len;
	}else{
		int64_t lowerbound;
		lowerbound = round_down(vma->vm_start, pgsz);
		*mbptstart = max(lowerbound, end - len);
	}
#else
	*mbptstart = start;
#endif

	return 0;
}

int16_t *tof_ib_stag_list;
ihk_spinlock_t *tof_ib_stag_lock;
int *tof_ib_stag_list_Rp_addr;
#define tof_ib_stag_list_Rp (*tof_ib_stag_list_Rp_addr)
int *tof_ib_stag_list_Wp_addr;
#define tof_ib_stag_list_Wp (*tof_ib_stag_list_Wp_addr)
#define TOF_IB_MAX_STAG 0x4000

static int16_t tof_ib_stag_alloc(void){
	int16_t ret;
	unsigned long flags;

	linux_spin_lock_irqsave(tof_ib_stag_lock, flags);

	if(tof_ib_stag_list_Rp != tof_ib_stag_list_Wp){
		ret = tof_ib_stag_list[tof_ib_stag_list_Rp];
		tof_ib_stag_list_Rp = (tof_ib_stag_list_Rp + 1) % TOF_IB_MAX_STAG;
	}
	else{
		/* empty */
		ret =  -ENOENT;
	}
	linux_spin_unlock_irqrestore(tof_ib_stag_lock, flags);

	dkprintf("%s: stag: %d allocated\n", __func__, ret);
	return ret;
}

static void tof_ib_stag_free(int16_t stag){
	int16_t next;
	unsigned long flags;

	linux_spin_lock_irqsave(tof_ib_stag_lock, flags);

	next = (tof_ib_stag_list_Wp + 1) % TOF_IB_MAX_STAG;
	if(next != tof_ib_stag_list_Rp){ /* next == tof_ib_stag_list_Rp is full. */
		tof_ib_stag_list[tof_ib_stag_list_Wp] = stag;
		tof_ib_stag_list_Wp = next;
	}
	linux_spin_unlock_irqrestore(tof_ib_stag_lock, flags);

	dkprintf("%s: stag: %d freed\n", __func__, stag);
}

struct tof_util_aligned_mem {
	void *mem;
	int nr_pages;
	uint32_t offset;  /* should be less than PAGE_SIZE */
};
static struct tof_util_aligned_mem *tof_ib_mbpt_mem = NULL;
static struct tof_icc_steering_entry *tof_ib_steering = NULL;
static struct tof_icc_mb_entry *tof_ib_mb = NULL;

static int tof_ib_steering_enable(int stag, uint64_t mbpt_ipa, size_t npages, size_t length, uint64_t mbva){
	struct tof_icc_steering_entry *steering = &tof_ib_steering[stag];
	struct tof_icc_mb_entry *mb = &tof_ib_mb[stag];
	if(steering->enable != 0 || mb->enable != 0){
		return -EBUSY;
	}
	mb->ps = TOF_ICC_MB_PS_ENCODE(PAGE_SHIFT);  /* will be 0 */
	mb->enable = 1;
	mb->ipa = mbpt_ipa >> 8;
	mb->npage = npages;
	steering->readonly = 0;
	steering->mbid = stag;
	steering->mbva = mbva >> 8;
	steering->length = length;
	dma_wmb();
	steering->enable = 1;
	return 0;
}

int tof_core_cq_cacheflush(int tni, int cqid);

#define TOF_IB_TNI_OFFSET 3
#define TOF_IB_KCQ (TOF_ICC_NCQS - 1)
#define TOF_IB_ROUTE_CHECK_STAG 0
#define TOF_IB_ROUTE_CHECK_DMAADDR 0

#define TOF_IB_SEND_MTU (7 * 256 - sizeof(struct tof_ib_send_header))
#define TOF_IB_SEND_MAXLEN (32 * TOF_IB_SEND_MTU)

#define TOF_IB_TIMER_DELAY 1

#define TOF_IB_MAX_STAG 0x4000

#define TOF_IB_MAX_QPNO 800000
#define TOF_IB_MAX_QPID 4

static void tof_ib_steering_disable(int stag){
	struct tof_icc_steering_entry *steering = &tof_ib_steering[stag];
	struct tof_icc_mb_entry *mb = &tof_ib_mb[stag];
	steering->enable = 0;
	dma_wmb();
	mb->enable = 0;
	dma_wmb();
	tof_core_cq_cacheflush(TOF_IB_TNI_OFFSET, TOF_IB_KCQ);
	tof_core_cq_cacheflush(TOF_IB_TNI_OFFSET + 1, TOF_IB_KCQ);
}

static inline uint64_t tof_ib_dmaaddr_pack(uint32_t stag, uint32_t offset){
	return (uint64_t)stag << 32 | offset;
}

static inline uint32_t tof_ib_dmaaddr_stag(uint64_t dmaaddr){
	return dmaaddr >> 32;
}

/*
 * McKernel scatterlist is simply a contiguous buffer
 * This greatly simplifes dealing with it.
 */
struct scatterlist {
	void *pages;
	unsigned int	offset;
	unsigned int	length;
	unsigned long	dma_address;
	unsigned int	dma_length;
};

#if 0
static int tof_ib_map_sg(struct scatterlist *sg, int nents){
	struct tof_icc_mbpt_entry *mbpt;
	int stag;
	int ret;
	int i;
	int nr_pages;

	//if(!tof_ib_sg_is_contiguous(sg, nents)){
	//	tof_info(7002, "SG is not contiguous\n");
	//	return 0;
	//}

	for(i = 0; ; i++){
		stag = tof_ib_stag_alloc();
		if(stag >= 0){
			break;
		}
		if(i % 10000 == 0){
			//tof_warn(6013, "Cannot allocate STag\n");
			kprintf("%s: WARNING: cannot allocate STag\n", __func__);
		}
		//schedule();
	}

	//ret = tof_util_aligned_alloc(&tof_ib_mbpt_mem[stag], nents * TOF_ICC_MBPT_SIZE, TOF_ICC_MBPT_ALIGN);
	//if(ret < 0){
	//	tof_ib_stag_free(stag);
	//	return 0;
	//}

	nr_pages = (nents * TOF_ICC_MBPT_SIZE + (PAGE_SIZE - 1)) / PAGE_SIZE;
	tof_ib_mbpt_mem[stag].mem = ihk_mc_alloc_pages(nr_pages, IHK_MC_AP_NOWAIT);
	if (!tof_ib_mbpt_mem[stag].mem) {
		tof_ib_stag_free(stag);
		return 0;
	}
	tof_ib_mbpt_mem[stag].nr_pages = nr_pages;
	tof_ib_mbpt_mem[stag].offset = 0;

	mbpt = tof_ib_mbpt_mem[stag].mem;
	for(i = 0; i < nents; i++){
		//uint64_t paddr = sg_phys(&sg[i]) - sg[i].offset;
		uint64_t paddr = virt_to_phys(sg->pages) + i * PAGE_SIZE;
		mbpt[i].ipa = paddr >> 12;
		mbpt[i].enable = 1;
		//sg[i].dma_address = tof_ib_dmaaddr_pack(stag, i * PAGE_SIZE + sg[i].offset);
		//sg[i].dma_length = sg[i].length;
	}
	sg->dma_address = tof_ib_dmaaddr_pack(stag, 0);
	sg->dma_length = sg->length;

	//ret = tof_ib_steering_enable(stag, tof_util_get_pa(mbpt), nents, (size_t)nents << PAGE_SHIFT, 0);
	ret = tof_ib_steering_enable(stag, virt_to_phys(mbpt), nents, (size_t)nents << PAGE_SHIFT, 0);
	if(ret < 0){
		/* something going wrong */
		tof_ib_stag_free(stag);
		//tof_util_aligned_free(&tof_ib_mbpt_mem[stag]);
		ihk_mc_free_pages(tof_ib_mbpt_mem[stag].mem, nr_pages);
		return 0;
	}
	return nents;
}
#endif

static void tof_ib_unmap_sg(struct scatterlist *sg, int nents){
	int stag;
	//if(!tof_ib_sg_is_contiguous(sg, nents)){
	//	tof_info(7002, "SG is not contiguous\n");
	//	return;
	//}
	stag = tof_ib_dmaaddr_stag(sg->dma_address);
	tof_ib_steering_disable(stag);
	tof_ib_stag_free(stag);
	//tof_util_aligned_free(&tof_ib_mbpt_mem[stag]);
	ihk_mc_free_pages(tof_ib_mbpt_mem[stag].mem,
		tof_ib_mbpt_mem[stag].nr_pages);
	tof_ib_mbpt_mem[stag].mem = NULL;
	tof_ib_mbpt_mem[stag].nr_pages = 0;
}


static int tof_utofu_alloc_mbpt(struct tof_utofu_cq *ucq, uint32_t npages, struct tof_utofu_mbpt **pmbpt, int stag){
	size_t nsgents = npages / (PAGE_SIZE >> TOF_ICC_MBPT_SIZE_BITS);
	//int i;
	int ret;
	struct scatterlist *sg;
	struct tof_utofu_mbpt *mbpt;

	//sg = tof_util_alloc(nsgents * sizeof(*sg), GFP_ATOMIC);
	//sg = kmalloc(sizeof(*sg), IHK_MC_AP_NOWAIT);
	sg = kmalloc_cache_alloc(&tofu_scatterlist_cache[ihk_mc_get_numa_id()],
			sizeof(*sg));
	if(sg == NULL){
		raw_rc_output(-ENOMEM);
		return -ENOMEM;
	}
	memset(sg, 0, sizeof(*sg));

	//sg_init_table(sg, nsgents);
	//for(i = 0; i < nsgents; i++){
	//	void *buf;
	//	buf = (void *)tof_util_get_free_pages(GFP_ATOMIC, 0);
	//	if(buf == NULL){
	//		ret = -ENOMEM;
	//		raw_rc_output(ret);
	//		goto free_ent;
	//	}
	//	memset(buf, 0, PAGE_SIZE);
	//	sg_set_buf(&sg[i], buf, PAGE_SIZE);
	//}
	if (0 && nsgents == 1) {
		sg->pages = ihk_mc_page_cache_alloc(
				&tofu_mbpt_sg_pages_cache[ihk_mc_get_numa_id()], 1);
	}
	else {
		sg->pages = ihk_mc_alloc_pages(nsgents, IHK_MC_AP_NOWAIT);
	}
	if (!sg->pages) {
		raw_rc_output(-ENOMEM);
		ret = -ENOMEM;
		goto free_sg;
	}

	if (!zero_at_free)
		memset(sg->pages, 0, PAGE_SIZE * nsgents);

	//mbpt = tof_util_alloc(sizeof(*mbpt), GFP_ATOMIC);
	//mbpt = kmalloc(sizeof(*mbpt), IHK_MC_AP_NOWAIT);
	mbpt = kmalloc_cache_alloc(&tofu_mbpt_cache[ihk_mc_get_numa_id()],
		sizeof(*mbpt));
	if(mbpt == NULL){
		raw_rc_output(-ENOMEM);
		ret = -ENOMEM;
		goto free_sg_pages;
	}

	//ret = tof_smmu_iova_map_sg(ucq->tni, ucq->cqid, sg, nsgents);
	//if(ret == 0){
	//	ret = -EINVAL;
	//	goto free_ent;
	//}

	sg->dma_address = -1;
	{
		unsigned long phys = virt_to_phys(sg->pages);
		int i;

		for (i = 0; i < ihk_mc_get_nr_memory_chunks(); ++i) {
			unsigned long start, end;

			ihk_mc_get_memory_chunk(i, &start, &end, NULL);

			// Since chunks are contiguous, if end falls in,
			// the whole region is covered..
			if (phys < start || phys > end) {
				continue;
			}

			ihk_mc_get_memory_chunk_dma_addr(i, ucq->tni, ucq->cqid,
					(uintptr_t *)&sg->dma_address);
			sg->dma_address += (phys - start);
			break;
		}
	}

	if (sg->dma_address == -1) {
		kprintf("%s: error: obtaining sg DMA address\n", __func__);
		ret = -EINVAL;
		goto free_ent;
	}

	//atomic64_inc((atomic64_t *)&kref_init_count);
	kref_init(&mbpt->kref);
	mbpt->ucq = ucq;
	//mbpt->iova = sg_dma_address(sg);
	mbpt->iova = sg->dma_address;
	mbpt->sg = sg;
	mbpt->nsgents = nsgents;
	*pmbpt = mbpt;
	dkprintf("%s: mbpt iova: 0x%lx\n", __func__, mbpt->iova);

	return 0;
free_ent:
	//for(i = i - 1; i >= 0; i--){
	//	tof_util_free_pages((unsigned long)sg_virt(&sg[i]), 0);
	//}
	//kfree(mbpt);
	kmalloc_cache_free(mbpt);
free_sg_pages:
	if (0 && nsgents == 1) {
		ihk_mc_page_cache_free(
				&tofu_mbpt_sg_pages_cache[ihk_mc_get_numa_id()], sg->pages);
	}
	else {
		ihk_mc_free_pages(sg->pages, nsgents);
	}
free_sg:
	//kfree(sg);
	kmalloc_cache_free(sg);

	return ret;
}

static uintptr_t tof_utofu_disable_mbpt(struct tof_utofu_mbpt *mbpt, int idx){
	int i0, i1;
	struct tof_icc_mbpt_entry *ent;
	uintptr_t ipa;
	i0 = idx / (PAGE_SIZE / TOF_ICC_MBPT_SIZE);
	i1 = idx - i0 * (PAGE_SIZE / TOF_ICC_MBPT_SIZE);
	//ent = sg_virt(&mbpt->sg[i0]);
	ent = mbpt->sg->pages + (i0 * PAGE_SIZE);
	if(!ent[i1].enable){
		return 0;
	}
	ent[i1].enable = 0;
	ipa = (uint64_t)ent[i1].ipa << 12;
	ent[i1].ipa = 0;
	return ipa;
}

static void tof_utofu_enable_mbpt(struct tof_utofu_mbpt *mbpt, int idx, uintptr_t iova){
	int i0, i1;
	struct tof_icc_mbpt_entry *ent;
	i0 = idx / (PAGE_SIZE / TOF_ICC_MBPT_SIZE);
	i1 = idx - i0 * (PAGE_SIZE / TOF_ICC_MBPT_SIZE);
	//ent = sg_virt(&mbpt->sg[i0]);
	ent = mbpt->sg->pages + (i0 * PAGE_SIZE);
	ent[i1].ipa = iova>>12;
	dma_wmb();
	ent[i1].enable = 1;
}

static struct tof_icc_mbpt_entry *tof_utofu_get_mbpt_entry(struct tof_utofu_mbpt *mbpt, int idx){
	int i0, i1;
	struct tof_icc_mbpt_entry *ent;
	i0 = idx / (PAGE_SIZE / TOF_ICC_MBPT_SIZE);
	i1 = idx - i0 * (PAGE_SIZE / TOF_ICC_MBPT_SIZE);
	//ent = sg_virt(&mbpt->sg[i0]);
	ent = mbpt->sg->pages + (i0 * PAGE_SIZE);
	return &(ent[i1]);
}

static bool tof_utofu_mbpt_is_enabled(struct tof_utofu_mbpt *mbpt, int idx) {
	struct tof_icc_mbpt_entry *ent = tof_utofu_get_mbpt_entry(mbpt, idx);
	return (ent->enable == 1);
}

static int tof_utofu_update_mbpt_entries(struct tof_utofu_cq *ucq,
		struct tof_utofu_mbpt *mbpt,
		uintptr_t start,
		uintptr_t end,
		uint32_t ix,
		size_t pgsz,
		bool readonly)
{
	//struct page *page;
	struct process *proc = cpu_local_var(current)->proc;
	uintptr_t iova = 0, va;
	unsigned long phys = 0;

	/* Special case for straight mapping */
	if (proc->straight_va && (void *)start >= proc->straight_va &&
			(void *)end < proc->straight_va + proc->straight_len) {

		for (va = start; va < end; va += pgsz, ix++) {
			if (tof_utofu_mbpt_is_enabled(mbpt, ix)) {
				/* this page is already mapped to mbpt */
				kprintf("%s: 0x%lx already mapped...\n", __func__, va);
				continue;
			}

			/* Not yet resolved? */
			if (!iova) {
				int i;

				phys = proc->straight_pa +
					((void *)va - proc->straight_va);

				iova = -1;
				for (i = 0; i < ihk_mc_get_nr_memory_chunks(); ++i) {
					unsigned long start, end;

					ihk_mc_get_memory_chunk(i, &start, &end, NULL);

					if (phys < start || phys > end) {
						continue;
					}

					ihk_mc_get_memory_chunk_dma_addr(i, ucq->tni, ucq->cqid,
							(uintptr_t *)&iova);
					iova += (phys - start);
					break;
				}

				if (iova == -1) {
					return -EINVAL;
				}
			}

			tof_utofu_enable_mbpt(mbpt, ix, iova);
			iova += pgsz;
		}

		return 0;
	}

	for(va = start; va < end; va += pgsz, ix++){
		size_t psize;
		pte_t *ptep;

		if (tof_utofu_mbpt_is_enabled(mbpt, ix)) {
			/* this page is already mapped to mbpt */
			continue;
		}

		//ret = get_user_pages(va, 1, readonly ? 0 : FOLL_WRITE, &page, NULL);
		//if(ret < 1){
		//	raw_rc_output(ret);
		//	if(tof_utofu_stag_debug & 0x4){
		//		tof_info(9999, "[%s] get_user_pages: ret=%d va=0x%lx readonly=%d\n", current->comm, ret, va, readonly);
		//	}
		//	if(ret == -EFAULT && !readonly){
		//		return -EPERM;
		//	}
		//	return -ENOMEM;
		//}

		ptep = ihk_mc_pt_lookup_fault_pte(cpu_local_var(current)->vm,
				(void *)va, 0, NULL, &psize, NULL);

		if (unlikely(!ptep || !pte_is_present(ptep))) {
			kprintf("%s: ERROR: no valid PTE for 0x%lx\n",
					__func__, va);
			return -ENOMEM;
		}

		phys = (pte_get_phys(ptep) & ~(psize - 1)) +
			(va & (psize - 1));

		//iova = tof_smmu_get_ipa_cq(ucq->tni, ucq->cqid,
		//			   pfn_to_kaddr(page_to_pfn(page)), pgsz);
		//if (iova == 0) {
		//	put_page(page);
		//	raw_rc_output(ret);
		//	return -ENOMEM;
		//}

		iova = -1;
		{
			int i;
			for (i = 0; i < ihk_mc_get_nr_memory_chunks(); ++i) {
				unsigned long start, end;

				ihk_mc_get_memory_chunk(i, &start, &end, NULL);

				if (phys < start || phys > end) {
					continue;
				}

				ihk_mc_get_memory_chunk_dma_addr(i, ucq->tni, ucq->cqid,
						(uintptr_t *)&iova);
				iova += (phys - start);
				break;
			}
		}

		if (iova == -1) {
			return -EINVAL;
		}

		dkprintf("%s: VA: 0x%lx -> iova (phys): 0x%lx\n",
				__func__, va, phys);

		/* Check ovalap MBPT IOVA */
		//ret = tof_utofu_check_overlap_mbpt_iova(iova, ucq, mbpt, ix);
		//if(unlikely(ret)){
		//	put_page(page);
		//	return ret;
		//}

		tof_utofu_enable_mbpt(mbpt, ix, iova);
		//put_page(page);
	}
	return 0;
}

static void tof_utofu_free_mbpt(struct tof_utofu_cq *ucq, struct tof_utofu_mbpt *mbpt){
	int i;
	int disabled = 0;
#ifdef PROFILE_ENABLE
	unsigned long ts;
#endif // PROFILE_ENABLE

	/*
	 * Once we hit an empty entry after disabling some,
	 * we know the rest are not used because all stag
	 * registrations are contiguous.
	 */
	for(i = 0; i < mbpt->nsgents * PAGE_SIZE / sizeof(struct tof_icc_mbpt_entry); i++){
		uintptr_t iova = tof_utofu_disable_mbpt(mbpt, i);
		if (iova) {
			++disabled;
		}

		if (disabled > 0 && !iova) {
			break;
		}
		//uintptr_t iova;
		//iova = tof_utofu_disable_mbpt(mbpt, i);
		//if(iova){
			/* This appears to be doing nothing, see tof_ib_dma_ops->unmap_page */
			//tof_smmu_release_ipa_cq(ucq->tni, ucq->cqid, iova, mbpt->pgsz);
		//}
	}

	//tof_smmu_iova_unmap_sg(ucq->tni, ucq->cqid, mbpt->sg, mbpt->nsgents);
	// Do nothing in McKernel..

	//for(i = 0; i < mbpt->nsgents; i++){
	//	tof_util_free_pages((unsigned long)sg_virt(&mbpt->sg[i]), 0);
	//}
#ifdef PROFILE_ENABLE
	ts = rdtsc();
#endif // PROFILE_ENABLE
	if (0 && mbpt->nsgents == 1) {
		ihk_mc_page_cache_free(
				&tofu_mbpt_sg_pages_cache[ihk_mc_get_numa_id()],
				mbpt->sg->pages);
	}
	else {
		ihk_mc_free_pages(mbpt->sg->pages, mbpt->nsgents);
	}
#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_tofu_stag_free_stag_dealloc_free_pages, rdtsc() - ts);
#endif // PROFILE_ENABLE

	//tof_util_free(mbpt->sg);
	//kfree(mbpt->sg);
	kmalloc_cache_free(mbpt->sg);

	//tof_util_free(mbpt);
	//kfree(mbpt);
	kmalloc_cache_free(mbpt);
	dkprintf("%s: mbpt %p freed\n", __func__, mbpt);
}

static void tof_utofu_enable_steering(struct tof_utofu_cq *ucq, int stag, uintptr_t mbva, size_t length, bool readonly){
	struct tof_icc_steering_entry *steering = &ucq->steering[stag];

	steering->length = length;
	steering->readonly = readonly;
	steering->mbva = mbva>>8;
	steering->mbid = stag;
	dma_wmb();
	steering->enable = 1;
}

static void tof_utofu_enable_mb(struct tof_utofu_cq *ucq, int stag, uintptr_t iova, uint8_t pgszbits, size_t npages){
	struct tof_icc_mb_entry *mb = &ucq->mb[stag];

	mb->npage = npages;
	mb->ps = TOF_ICC_MB_PS_ENCODE(pgszbits);
	mb->ipa = iova>>8;
	dma_wmb();
	mb->enable = 1;
}

static void tof_utofu_trans_mru_delete(struct tof_utofu_cq *ucq, int stag){
	struct tof_utofu_trans_list *mru = ucq->trans.mru;
	int prev = mru[stag].prev;
	int next = mru[stag].next;
	if(prev == TOF_UTOFU_MRU_EMPTY || next == TOF_UTOFU_MRU_EMPTY){ /* already deleted */
		return;
	}
	if(prev == stag){  /* a single entry */
		ucq->trans.mruhead = TOF_UTOFU_MRU_EMPTY;
	}else{
		if(ucq->trans.mruhead == stag){
			ucq->trans.mruhead = next;
		}
		mru[prev].next = next;
		mru[next].prev = prev;
	}
	mru[stag].prev = TOF_UTOFU_MRU_EMPTY;
	mru[stag].next = TOF_UTOFU_MRU_EMPTY;
}

static void tof_utofu_trans_mru_insert(struct tof_utofu_cq *ucq, int stag, uint8_t pgszbits, struct tof_utofu_mbpt *mbpt){
	struct tof_utofu_trans_list *mru = ucq->trans.mru;
	mru[stag].pgszbits = pgszbits;
	mru[stag].mbpt = mbpt;
	if(ucq->trans.mruhead == TOF_UTOFU_MRU_EMPTY){
		mru[stag].prev = stag;
		mru[stag].next = stag;
	}else{
		int next = ucq->trans.mruhead;
		int prev = mru[next].prev;
		mru[stag].prev = prev;
		mru[stag].next = next;
		mru[prev].next = stag;
		mru[next].prev = stag;
	}
	ucq->trans.mruhead = stag;
}

static void tof_utofu_trans_update(struct tof_utofu_cq *ucq, int stag, uintptr_t start, size_t len, uint8_t pgszbits, struct tof_utofu_mbpt *mbpt){
	struct tof_trans_table *table = ucq->trans.table;
	union {
		struct tof_trans_table ent;
		uint64_t atomic;
	} tmp;
	unsigned long flags;

	tmp.ent.steering.bits.start = start >> PAGE_SHIFT;
	tmp.ent.steering.bits.len = len >> PAGE_SHIFT;
	tmp.ent.steering.bits.ps_code = (pgszbits == PAGE_SHIFT)? TOF_STAG_TRANS_PS_CODE_64KB:TOF_STAG_TRANS_PS_CODE_2MB;
	//atomic64_set((atomic64_t *)&table[stag], tmp.atomic);
	ihk_atomic64_set((ihk_atomic64_t *)&table[stag], tmp.atomic);

	linux_spin_lock_irqsave(&ucq->trans.mru_lock, flags);
	tof_utofu_trans_mru_delete(ucq, stag);
	tof_utofu_trans_mru_insert(ucq, stag, pgszbits, mbpt);
	linux_spin_unlock_irqrestore(&ucq->trans.mru_lock, flags);
}



static void tof_utofu_trans_disable(struct tof_utofu_cq *ucq, int stag){
	struct tof_trans_table *table = ucq->trans.table;
	//atomic64_set((atomic64_t *)&table[stag], 0);
	ihk_atomic64_set((ihk_atomic64_t *)&table[stag], 0);
	tof_utofu_trans_mru_delete(ucq, stag);
}

static void tof_utofu_trans_enable(struct tof_utofu_cq *ucq, int stag, uintptr_t start, size_t len, uintptr_t mbptstart, size_t mbptlen, uint8_t pgszbits, struct tof_utofu_mbpt *mbpt){
	struct tof_trans_table *table = ucq->trans.table;
	table[stag].mbpt.bits.start = mbptstart >> PAGE_SHIFT;
	table[stag].mbpt.bits.len = mbptlen >> PAGE_SHIFT;
	table[stag].mbpt.bits.ps_code = (pgszbits == PAGE_SHIFT)? TOF_STAG_TRANS_PS_CODE_64KB:TOF_STAG_TRANS_PS_CODE_2MB;
	wmb();
	tof_utofu_trans_update(ucq, stag, start, len, pgszbits, mbpt);
}

static int tof_utofu_alloc_new_steering(struct tof_utofu_cq *ucq, int stag, uintptr_t start, uintptr_t end, uint8_t pgszbits, uintptr_t plus_mbva, bool readonly){
	uintptr_t mbptstart;
	size_t pgsz = (size_t)1 << pgszbits;
	size_t npages, mbpt_npages;
	uint32_t ix;
	int ret;
	struct tof_utofu_mbpt *mbpt;
	uintptr_t mbva;
#ifdef PROFILE_ENABLE
	unsigned long ts = rdtsc();
	unsigned long ts_rolling = ts;
#endif // PROFILE_ENABLE

	npages = (end - start) >> pgszbits;
	mbpt_npages = roundup(npages, PAGE_SIZE / TOF_ICC_MBPT_SIZE);
	ret = tof_utofu_calc_mbptstart((int64_t)start, (int64_t)end, mbpt_npages, pgszbits, &mbptstart);
	if (ret < 0) {
		raw_rc_output(ret);
		return ret;
	}

	ret = tof_utofu_alloc_mbpt(ucq, mbpt_npages, &mbpt, stag);
	if(ret < 0){
		raw_rc_output(ret);
		return ret;
	}
	mbpt->mbptstart = mbptstart;
	mbpt->pgsz = pgsz;
#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_tofu_stag_alloc_new_steering_alloc_mbpt,
			rdtsc() - ts_rolling);
	ts_rolling = rdtsc();
#endif // PROFILE_ENABLE

	ix = (start - mbptstart) >> pgszbits;
	ret = tof_utofu_update_mbpt_entries(ucq, mbpt, start, end, ix, pgsz, readonly);
	if (ret < 0) {
		raw_rc_output(ret);
		//if(ret == -EFAULT){
		//	tof_warn(9999, "Founds the overlap MBPT iova. abnormal end. Target TNI=%d CQ=%d Stag[%d] comm=%s pid=%d\n"
		//		,ucq->tni, ucq->cqid, stag, current->comm, current->pid);
		//}
		tof_utofu_free_mbpt(ucq, mbpt);
		return ret;
	}

	if(plus_mbva == TOF_UTOFU_BLANK_MBVA) {
		mbva = 0;
	} else {
		mbva = start - mbptstart + plus_mbva;
	}
	//if(tof_utofu_stag_debug & 0x1){
	//	tof_info(9999, "[%s] tni=%d cq=%d stag=%d mbva=%ld start=0x%lx end=0x%lx mbptstart=0x%lx npages=%ld mbpt_npages=%ld plus_mbva=%ld pgszbits=%d\n", current->comm, ucq->tni, ucq->cqid, stag, mbva, start, end, mbptstart, npages, mbpt_npages, plus_mbva, pgszbits);
	//}
	tof_utofu_enable_mb(ucq, stag, mbpt->iova, pgszbits, mbpt_npages);
	tof_utofu_enable_steering(ucq, stag, mbva, end - mbptstart - mbva, readonly);
	tof_utofu_trans_enable(ucq, stag, start, end - start, mbptstart, mbpt_npages * TOF_ICC_MBPT_SIZE, pgszbits, mbpt);

#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_tofu_stag_alloc_new_steering_update_mbpt,
			rdtsc() - ts_rolling);
	profile_event_add(PROFILE_tofu_stag_alloc_new_steering,
			rdtsc() - ts);
#endif // PROFILE_ENABLE
	return 0;
}

static void tof_utofu_release_stag(struct tof_utofu_cq *ucq, int stag){
	/* nothing to do */
	/* tof_utofu_reserve_stag() and tof_utofu_release_stag() are in a same ucq_lock region */
	return;
}

static int tof_utofu_ioctl_alloc_stag(struct tof_utofu_device *dev, unsigned long arg) {
	struct tof_utofu_cq *ucq;
	struct tof_alloc_stag req;
	struct process_vm *vm = cpu_local_var(current)->vm;
	bool readonly;
	uintptr_t start;
	uintptr_t end;
	uint8_t pgszbits;
	size_t pgsz;
	int ret = -ENOTSUPP;
	unsigned long irqflags;
	struct vm_range *range = NULL;

	ucq = container_of(dev, struct tof_utofu_cq, common);
	if(!ucq->common.enabled){
		return -EPERM;
	}
	if(copy_from_user(&req, (void *)arg, sizeof(req)) != 0){
		return -EFAULT;
	}
	dkprintf("%s: [IN] tni=%d cqid=%d flags=%u stag=%d va=%p len=%llx\n",
		__func__, ucq->tni, ucq->cqid, req.flags, req.stag, req.va, req.len);

	if(req.stag < -1 || req.stag >= TOF_UTOFU_SPECIAL_STAG ||
	   req.va == NULL || req.len == 0){
		return -EINVAL;
	}
	dkprintf("%s: ucq->steering: 0x%lx\n", __func__, ucq->steering);
	if(req.stag >= 0 && ucq->steering[req.stag].enable){
		return -EBUSY;
	}

	readonly = (req.flags & 1) != 0;

retry:
	ihk_rwspinlock_read_lock_noirq(&vm->memory_range_lock);

	/* Assume smallest page size at first */
	start = round_down((uintptr_t)req.va, PAGE_SIZE);
	end = round_up((uintptr_t)req.va + req.len, PAGE_SIZE);

	/* Find range, straight mapping special lookup */
	if (vm->proc->straight_va &&
			start >= (unsigned long)vm->proc->straight_va &&
			end <= ((unsigned long)vm->proc->straight_va +
				vm->proc->straight_len) &&
			!(start == (unsigned long)vm->proc->straight_va &&
				end == ((unsigned long)vm->proc->straight_va +
					vm->proc->straight_len))) {
		struct vm_range *range_iter;

		range_iter = lookup_process_memory_range(vm, 0, -1);

		while (range_iter) {
			if (range_iter->straight_start &&
					start >= range_iter->straight_start &&
					start < (range_iter->straight_start +
						(range_iter->end - range_iter->start))) {
				range = range_iter;
				break;
			}

			range_iter = next_process_memory_range(vm, range_iter);
		}
	}
	else {
		range = lookup_process_memory_range(vm, start, end);
	}

	if (!range) {
		if (vm->region.stack_start <= start &&
				vm->region.stack_end > end) {

			ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);

			if (page_fault_process_vm(vm, (void *)start,
						PF_POPULATE | PF_WRITE | PF_USER) < 0) {
				ret = -EINVAL;
				goto out;
			}

			goto retry;
		}

		ret = -EINVAL;
		goto unlock_out;
	}

	pgszbits = PAGE_SHIFT;
	if (req.flags & TOF_UTOFU_ALLOC_STAG_LPG) {
		ret = tof_utofu_get_pagesize_locked((uintptr_t)req.va,
				req.len, &pgszbits, readonly);
		if(ret < 0){
			kprintf("%s: ret: %d\n", __func__, ret);
			ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);
			return ret;
		}
	}
	pgsz = (size_t)1 << pgszbits;
	start = round_down((uintptr_t)req.va, pgsz);
	end = round_up((uintptr_t)req.va + req.len, pgsz);
	dkprintf("%s: 0x%lx:%llu, start: 0x%lx, end: 0x%lx, pgsz: %d\n",
		__func__, req.va, req.len, start, end, pgsz);

	//down(&ucq->ucq_sem);
	ihk_mc_spinlock_lock_noirq(&tofu_tni_cq_lock[ucq->tni][ucq->cqid]);

	if(req.stag < 0){
#if 1
		/* normal stag */
		int stag;
		linux_spin_lock_irqsave(&ucq->trans.mru_lock, irqflags);
		stag = tof_utofu_trans_search(ucq, start, end, pgszbits, readonly);
		linux_spin_unlock_irqrestore(&ucq->trans.mru_lock, irqflags);
		if(stag < 0){
			struct tof_utofu_mbpt *mbpt = NULL;
			stag = tof_utofu_reserve_stag(ucq, readonly);
			if(stag < 0){
				//up(&ucq->ucq_sem);
				ihk_mc_spinlock_unlock_noirq(&tofu_tni_cq_lock[ucq->tni][ucq->cqid]);
				ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);
				return -ENOSPC;
			}

			/* With tof_utofu_disable_extend, this call does nothing */
			//spin_lock(&ucq->trans.mru_lock);
			//mbpt = tof_utofu_mbpt_search(ucq, start, end, readonly, pgszbits);
			//spin_unlock(&ucq->trans.mru_lock);
			if (mbpt == NULL) {
				ret = tof_utofu_alloc_new_steering(ucq, stag, start, end, pgszbits,
					TOF_UTOFU_BLANK_MBVA, readonly);
			}
			//else {
			//	ret = tof_utofu_extend_steering(ucq, stag, mbpt, start, end, pgszbits, readonly);
			//}
			if(ret < 0){
				tof_utofu_release_stag(ucq, stag);
			}
		}
		else{
			ret = 0;
		}
		req.stag = stag;
		req.offset = (uintptr_t)req.va - tof_utofu_get_mbpt_start(ucq, stag);
#endif
	}
	else{
		/* special stag */
		uintptr_t plus_mbva;
		if(ucq->steering[req.stag].enable){
			kprintf("%s: ret: %d\n", __func__, -EBUSY);
			//up(&ucq->ucq_sem);
			ihk_mc_spinlock_unlock_noirq(&tofu_tni_cq_lock[ucq->tni][ucq->cqid]);
			ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);
			return -EBUSY;
		}
		plus_mbva = round_down((uintptr_t)req.va, 256) - start;
		ret = tof_utofu_alloc_new_steering(ucq, req.stag, start, end, pgszbits, plus_mbva, readonly);
		req.offset = (uintptr_t)req.va & 0xff;
	}

	//up(&ucq->ucq_sem);
	ihk_mc_spinlock_unlock_noirq(&tofu_tni_cq_lock[ucq->tni][ucq->cqid]);

	if (ret == 0) {
		tof_utofu_stag_range_insert(vm, range, start, end, ucq, req.stag);
	}

unlock_out:
	ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);

out:
	if(ret == 0){
		if(copy_to_user((void *)arg, &req, sizeof(req)) != 0){
			kprintf("%s: ret: %d\n", __func__, -EFAULT);
			ret = -EFAULT;
		}
	}

	//if(unlikely(tof_utofu_stag_debug & 0x100)){
	//	tof_info(9999, "[%s] ucq=%d:%d stag=%d offset=%llu va=%p len=%llu flags=%d\n",
	//		current->comm, ucq->tni, ucq->cqid, req.stag, req.offset, req.va, req.len, req.flags);
	//}

	dkprintf("%s: [OUT] tni=%d cqid=%d stag=%d offset=0x%llx ret=%d\n",
		__func__, ucq->tni, ucq->cqid, req.stag, req.offset, ret);
	return ret;
}

static void tof_utofu_mbpt_release(struct kref *kref)
{
	struct tof_utofu_mbpt *mbpt = container_of(kref, struct tof_utofu_mbpt, kref);
	//atomic64_inc((atomic64_t *)&kref_free_count);
	tof_utofu_free_mbpt(mbpt->ucq, mbpt);
}

//static struct tof_core_cq tof_core_cq[TOF_ICC_NTNIS][TOF_ICC_NCQS];
static struct tof_core_cq *tof_core_cq;

struct tof_core_cq *tof_core_cq_get(int tni, int cqid){
	if((unsigned int)tni >= TOF_ICC_NTNIS ||
	   (unsigned int)cqid >= TOF_ICC_NCQS){
		return NULL;
	}
	//return tof_core_cq[tni][cqid];

	// Convert [][] notion into pointer aritmethic
	return tof_core_cq + (tni * TOF_ICC_NCQS) + cqid;
}

static inline void tof_writeq_relaxed(uint64_t val, void *reg, off_t offset){
	writeq_relaxed(val, (char *)reg + offset);
}

static inline uint64_t tof_readq(void *reg, off_t offset){
	return readq((char *)reg + offset);
}

static inline void tof_writeq(uint64_t val, void *reg, off_t offset){
	writeq(val, (char *)reg + offset);
}

static inline bool tof_core_readq_spin(void *reg, off_t offset, uint64_t mask,
				uint64_t expect, unsigned long timeout){
	uint64_t val;
	unsigned long cyc;
	cyc = rdtsc();
	do{
		val = tof_readq(reg, offset);
		if(rdtsc() - cyc > timeout){
			return false;
		}
	}while((val & mask) != expect);
	return true;
}

static int tof_core_cq_cache_flush_timeout_panic_disabled = 1;
static int tof_core_cq_cacheflush_is_cqs_steering_table_bit_disabled = 1;

#define TOF_CORE_KCQID (TOF_ICC_NCQS - 1)

static int tof_core_cacheflush_timeout(struct tof_core_cq *timeout_cq){
	int tni, cqid;

	for(tni = 0; tni < TOF_ICC_NTNIS; tni++){
		for(cqid = 0; cqid < TOF_ICC_NCQS; cqid++){
			struct tof_core_cq *cq  = tof_core_cq_get(tni, cqid);

			if(cqid == TOF_CORE_KCQID){
				continue;
			}
			/* write 0 to steering table enable bit of CQS reg -> MRQ RCODE 10h issued */
			if(tof_core_cq_cacheflush_is_cqs_steering_table_bit_disabled){
				tof_writeq_relaxed(0, cq->reg.cqs, TOF_ICC_REG_CQS_STEERING_TABLE_ENABLE);
				wmb();
			}
			/* send signal */
			//if(tof_core_cq_cacheflush_is_send_signal_enabled){
			//	tof_core_irq_handler_cq_user(&cq->irq, TOF_ICC_DUMMY_IRQ_CQS_CACHEFLUSH_TIMEOUT, timeout_cq);
			//}
			kprintf("%s WARNING: no signal sent.. \n", __func__);
		}
	}
	return 0;
}

static int   tof_core_cq_cache_flush_timeout_sec = 3;
static int   tof_core_cq_cache_flush_2nd_timeout_sec = 3600;
int tof_core_cq_cacheflush_timeout_dbg_msg_disabled = 1;

// Assuming 1 GHz..
#define TOF_CORE_TIMEOUT_SEC(n) ((1UL) * (n) * 1000000000)

int tof_core_cq_cacheflush(int tni, int cqid){
	struct tof_core_cq *cq;
	cq = tof_core_cq_get(tni, cqid);
	tof_writeq_relaxed(1, cq->reg.cqs, TOF_ICC_REG_CQS_CACHE_FLUSH);
	if(!tof_core_readq_spin(cq->reg.cqs, TOF_ICC_REG_CQS_STATUS,
				TOF_ICC_REG_CQS_STATUS_CACHE_FLUSH_BUSY,
				0, TOF_CORE_TIMEOUT_SEC(tof_core_cq_cache_flush_timeout_sec))){
 		if(likely(tof_core_cq_cache_flush_timeout_panic_disabled)){

			//tof_warn(2018, "cache flush timeout: tni=%d cqid=%d", tni, cqid);
			kprintf("%s: cache flush timeout: tni=%d cqid=%d", __func__, tni, cqid);

			/* cacheflush timeout processing for user CQ in TNI */
			tof_core_cacheflush_timeout(cq);

			/* Check cacheflush status change */
			if(!tof_core_readq_spin(cq->reg.cqs, TOF_ICC_REG_CQS_STATUS,
					TOF_ICC_REG_CQS_STATUS_CACHE_FLUSH_BUSY,
					0, TOF_CORE_TIMEOUT_SEC(tof_core_cq_cache_flush_2nd_timeout_sec))){
				//tof_info(9999, "been exceeded cacheflush timeout status check time=%d : tni=%d cqid=%d",tof_core_cq_cache_flush_2nd_timeout_sec,tni,cqid);
				//tof_panic(8, "cache flush timeout: tni=%d cqid=%d", tni, cqid);
				kprintf("%s: cache flush timeout: tni=%d cqid=%d", __func__, tni, cqid);
				panic("cache flush timeout");
			}
			else{
				//if(!tof_core_cq_cacheflush_timeout_dbg_msg_disabled){
				//	tof_info(9999, "been changed within cacheflush timeout status check time=%d : tni=%d cqid=%d",tof_core_cq_cache_flush_2nd_timeout_sec,tni,cqid);
				//}
			}
		}else{
			//tof_panic(8, "cache flush timeout: tni=%d cqid=%d", tni, cqid);
			kprintf("%s: cache flush timeout: tni=%d cqid=%d", __func__, tni, cqid);
			panic("cache flush timeout");
		}
	}
	return 0;
}

static int tof_utofu_cq_cacheflush(struct tof_utofu_cq *ucq){
	return tof_core_cq_cacheflush(ucq->tni, ucq->cqid);
}


static int tof_utofu_free_stag(struct tof_utofu_cq *ucq, int stag){
#ifdef PROFILE_ENABLE
	unsigned long ts = 0;
	unsigned long ts_rolling = 0;
	if (cpu_local_var(current)->profile) {
		ts = rdtsc();
		ts_rolling = ts;
	}
#endif // PROFILE_ENABLE
	if(stag < 0 || stag >= TOF_UTOFU_NUM_STAG(ucq->num_stag) ||
	   ucq->steering == NULL){
		return -EINVAL;
	}
	if(!(ucq->steering[stag].enable)){
		return -ENOENT;
	}
	if (!kref_is_mckernel(&ucq->trans.mru[stag].mbpt->kref)) {
		kprintf("%s: stag: %d is not an McKernel kref\n", __func__, stag);
		return -EINVAL;
	}
	//if(unlikely(tof_utofu_stag_debug & 0x20)){
	//	tof_info(9999, "[%s] ucq=%d:%d stag=%d\n", current->comm, ucq->tni, ucq->cqid, stag);
	//}
	ucq->steering[stag].enable = 0;
	ucq->mb[stag].enable = 0;
	tof_utofu_trans_disable(ucq, stag);
	dma_wmb();
#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_tofu_stag_free_stag_pre, rdtsc() - ts_rolling);
	ts_rolling = rdtsc();
#endif // PROFILE_ENABLE
	tof_utofu_cq_cacheflush(ucq);
#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_tofu_stag_free_stag_cqflush, rdtsc() - ts_rolling);
	ts_rolling = rdtsc();
#endif // PROFILE_ENABLE
	kref_put(&ucq->trans.mru[stag].mbpt->kref, tof_utofu_mbpt_release);
	ucq->trans.mru[stag].mbpt = NULL;
	dkprintf("%s: TNI: %d, CQ: %d, STAG: %d deallocated\n",
			__func__, ucq->tni, ucq->cqid, stag);
#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_tofu_stag_free_stag_dealloc, rdtsc() - ts_rolling);
	profile_event_add(PROFILE_tofu_stag_free_stag, rdtsc() - ts);
#endif // PROFILE_ENABLE
	return 0;
}


static int tof_utofu_ioctl_free_stags(struct tof_utofu_device *dev, unsigned long arg){
	struct tof_utofu_cq *ucq;
	struct tof_free_stags req;
	int i, no_free_cnt = 0, ret;
	int stags[1024];
	unsigned long irqflags;

	ucq = container_of(dev, struct tof_utofu_cq, common);

	if(copy_from_user(&req, (void *)arg, sizeof(req)) != 0){
		raw_rc_output(-EFAULT);
		return -EFAULT;
	}
	//tof_log_if("[IN] tni=%d cqid=%d num=%u stags=%p\n", ucq->tni, ucq->cqid, req.num, req.stags);
	dkprintf("%s: [IN] tni=%d cqid=%d num=%u stags=%p\n",
			__func__, ucq->tni, ucq->cqid, req.num, req.stags);

	if(req.num > 1024 || req.stags == NULL){
		return -EINVAL;
	}

	if(copy_from_user(stags, req.stags, sizeof(int) * req.num) != 0){
		raw_rc_output(-EFAULT);
		return -EFAULT;
	}

	for(i = 0; i < req.num; i++){
		linux_spin_lock_irqsave(&ucq->trans.mru_lock, irqflags);
		ret = tof_utofu_free_stag(ucq, stags[i]);
		linux_spin_unlock_irqrestore(&ucq->trans.mru_lock, irqflags);

		{
			struct tofu_stag_range *tsr;

			tsr = tofu_stag_range_lookup_by_stag(
					cpu_local_var(current)->vm, stags[i]);

			if (tsr) {
				tofu_stag_range_remove(cpu_local_var(current)->vm, tsr);
			}
			else {
				kprintf("%s: no stag range object for %d??\n", __func__, stags[i]);
			}
		}

		if(ret == 0){
			stags[i] = -1;
		}
		else if(ret == -ENOENT){
			no_free_cnt++;
			continue; /* continue free tag process */
		}
		else{
			req.num = i - no_free_cnt;

			if(copy_to_user(req.stags, stags, sizeof(int) * req.num) != 0){
				raw_rc_output(-EFAULT);
				return -EFAULT;
			}

			if(copy_to_user((void *)arg, &req, sizeof(req)) != 0){
				return -EFAULT;
			}
			//tof_log_if("[OUT] tni=%d cqid=%d num=%u stags=%p ret=%d no_free_cnt=%d\n", ucq->tni, ucq->cqid, req.num, req.stags, ret, no_free_cnt);
			return ret;
		}
	}

	req.num = i - no_free_cnt;
	if(copy_to_user(req.stags, stags, sizeof(int) * req.num) != 0){
		raw_rc_output(-EFAULT);
		return -EFAULT;
	}

	if(copy_to_user((void *)arg, &req, sizeof(req)) != 0){
		return -EFAULT;
	}
	//tof_log_if("[OUT] tni=%d cqid=%d num=%u stags=%p no_free_cnt=%d\n", ucq->tni, ucq->cqid, req.num, req.stags, no_free_cnt);
	dkprintf("%s: [OUT] tni=%d cqid=%d num=%u stags=%p no_free_cnt=%d\n",
		__func__, ucq->tni, ucq->cqid, req.num, req.stags, no_free_cnt);

	return no_free_cnt > 0 ? -ENOENT : 0;
}

void tof_utofu_release_cq(void *pde_data)
{
	struct tof_utofu_cq *ucq;
	struct tof_utofu_device *dev;
	unsigned long irqflags;
	int do_free = 1;

	dev = (struct tof_utofu_device *)pde_data;
	ucq = container_of(dev, struct tof_utofu_cq, common);

	if (!ucq->common.enabled) {
		kprintf("%s: UCQ TNI %d, CQ %d is disabled\n",
			__func__, ucq->tni, ucq->cqid);
		do_free = 0;
	}

	{
		int i;
		struct tofu_stag_range *tsr, *next;
		struct process_vm *vm = cpu_local_var(current)->vm;

		ihk_mc_spinlock_lock_noirq(&vm->tofu_stag_lock);
		for (i = 0; i < TOFU_STAG_HASH_SIZE; ++i) {
			list_for_each_entry_safe(tsr, next,
					&vm->tofu_stag_hash[i], hash) {
				if (tsr->ucq != ucq)
					continue;

				if (do_free) {
					dkprintf("%s: removing stag %d for TNI %d CQ %d\n",
							__func__, tsr->stag, ucq->tni, ucq->cqid);

					linux_spin_lock_irqsave(&ucq->trans.mru_lock, irqflags);
					tof_utofu_free_stag(tsr->ucq, tsr->stag);
					linux_spin_unlock_irqrestore(&ucq->trans.mru_lock, irqflags);
				}
				else {
					kprintf("%s: WARNING: could not free stag %d for TNI %d CQ %d (UCQ is disabled)\n",
							__func__, tsr->stag, ucq->tni, ucq->cqid);
				}

				__tofu_stag_range_remove(vm, tsr);
			}
		}
		ihk_mc_spinlock_unlock_noirq(&vm->tofu_stag_lock);
	}

	/* Loop through as well just to make sure everything is cleaned up */
	if (do_free) {
		int stag;

		for (stag = 0; stag < TOF_UTOFU_NUM_STAG(ucq->num_stag); stag++) {
			linux_spin_lock_irqsave(&ucq->trans.mru_lock, irqflags);
			tof_utofu_free_stag(ucq, stag);
			linux_spin_unlock_irqrestore(&ucq->trans.mru_lock, irqflags);
		}
	}

	dkprintf("%s: UCQ (pde: %p) TNI %d, CQ %d\n",
		__func__, pde_data, ucq->tni, ucq->cqid);
}

/*
 *
 * Tofu barrier gate related functions.
 *
 */

#define TOF_CORE_TIMEOUT_BG_ENABLE TOF_CORE_TIMEOUT_SEC(3)
#define TOF_CORE_TIMEOUT_BG_DISABLE TOF_CORE_TIMEOUT_SEC(3)
#define TOF_CORE_TIMEOUT_BCH_ENABLE TOF_CORE_TIMEOUT_SEC(3)
#define TOF_CORE_TIMEOUT_BCH_DISABLE TOF_CORE_TIMEOUT_SEC(3)

//struct tof_core_bg tof_core_bg[TOF_ICC_NTNIS][TOF_ICC_NBGS];
static struct tof_core_bg *tof_core_bg;

struct tof_core_bg *tof_core_bg_get(int tni, int bgid){
	if((unsigned int)tni >= TOF_ICC_NTNIS ||
	   (unsigned int)bgid >= TOF_ICC_NBGS){
		return NULL;
	}
	//return &tof_core_bg[tni][bgid];

	// Convert [][] notion into pointer aritmethic
	return tof_core_bg + (tni * TOF_ICC_NBGS) + bgid;
}


//static struct tof_utofu_bg tof_utofu_bg[TOF_ICC_NTNIS][TOF_ICC_NBGS];
static struct tof_utofu_bg *tof_utofu_bg;

static struct tof_utofu_bg *tof_utofu_bg_get(int tni, int bgid){
	if((unsigned int)tni >= TOF_ICC_NTNIS ||
	   (unsigned int)bgid >= TOF_ICC_NBGS){
		return NULL;
	}
	//return &tof_utofu_bg[tni][bgid];

	// Convert [][] notion into pointer aritmethic
	return tof_utofu_bg + (tni * TOF_ICC_NBGS) + bgid;
}


int tof_core_enable_bch(int tni, int bgid, uint64_t dma_ipa){
	struct tof_core_bg *bg;
	bg = tof_core_bg_get(tni, bgid);
	if(bg == NULL || bg->reg.bch == NULL ||  /* this BG is not associated with a BCH */
	   (dma_ipa & (TOF_ICC_BCH_DMA_ALIGN - 1)) != 0){
		return -EINVAL;
	}

	/* no need to lock, since they are permanent after initialization */
	tof_writeq(dma_ipa, bg->reg.bgs, TOF_ICC_REG_BGS_BCH_NOTICE_IPA);
	tof_writeq(0, bg->reg.bgs, TOF_ICC_REG_BGS_BCH_MASK);
	if(!tof_core_readq_spin(bg->reg.bgs, TOF_ICC_REG_BGS_BCH_MASK_STATUS,
				TOF_ICC_REG_BGS_BCH_MASK_STATUS_RUN,
				0,
				TOF_CORE_TIMEOUT_BCH_ENABLE)){
		return -ETIMEDOUT;
	}
	return 0;
}

static inline bool tof_utofu_subnet_includes(struct tof_set_subnet *subnet, uint8_t px, uint8_t py, uint8_t pz){
	return (subnet->lx == 0 ? px < subnet->nx : (px < subnet->sx ? px + subnet->nx : px) < subnet->sx + subnet->lx) &&
	       (subnet->ly == 0 ? py < subnet->ny : (py < subnet->sy ? py + subnet->ny : py) < subnet->sy + subnet->ly) &&
	       (subnet->lz == 0 ? pz < subnet->nz : (pz < subnet->sz ? pz + subnet->nz : pz) < subnet->sz + subnet->lz);
}

static inline uint64_t tof_utofu_pack_subnet(const struct tof_set_subnet *subnet){
	union {
		struct tof_icc_reg_subnet subnet;
		uint64_t val;
	} u;
	u.subnet.nx = subnet->nx;
	u.subnet.sx = subnet->sx;
	u.subnet.lx = subnet->lx;
	u.subnet.ny = subnet->ny;
	u.subnet.sy = subnet->sy;
	u.subnet.ly = subnet->ly;
	u.subnet.nz = subnet->nz;
	u.subnet.sz = subnet->sz;
	u.subnet.lz = subnet->lz;
	return u.val;
}

static inline void tof_utofu_unpack_subnet(uint64_t val, struct tof_set_subnet *subnet)
{
	union {
		struct tof_icc_reg_subnet subnet;
		uint64_t val;
	} u;
	u.val = val;
	subnet->nx = u.subnet.nx;
	subnet->sx = u.subnet.sx;
	subnet->lx = u.subnet.lx;
	subnet->ny = u.subnet.ny;
	subnet->sy = u.subnet.sy;
	subnet->ly = u.subnet.ly;
	subnet->nz = u.subnet.nz;
	subnet->sz = u.subnet.sz;
	subnet->lz = u.subnet.lz;
}

static inline void tof_core_reset_irqmask_imc(struct tof_core_irq *dev){
	tof_writeq_relaxed(dev->all_mask, dev->reg, TOF_ICC_IRQREG_IMC);
}
static inline void tof_core_reset_irqmask(struct tof_core_irq *dev){
	tof_writeq_relaxed(GENMASK(63, 0), dev->reg, TOF_ICC_IRQREG_IMR);
	tof_writeq_relaxed(GENMASK(63, 0), dev->reg, TOF_ICC_IRQREG_IRC);
	wmb();
}

static __always_inline uint64_t tof_util_mask_set(uint64_t val, uint64_t mask){
	uint64_t shift = mask & (~mask + 1);
	return val * shift & mask;
}

static inline uint64_t tof_core_pack_remote_bg(const struct tof_addr *taddr,
					       uint64_t tni, int64_t gate){
	union {
		struct tof_icc_reg_bg_address bgaddr;
		uint32_t val;
	} u;
	u.bgaddr.pa = taddr->pa;
	u.bgaddr.pb = taddr->pb;
	u.bgaddr.pc = taddr->pc;
	u.bgaddr.x = taddr->x;
	u.bgaddr.y = taddr->y;
	u.bgaddr.z = taddr->z;
	u.bgaddr.a = taddr->a;
	u.bgaddr.b = taddr->b;
	u.bgaddr.c = taddr->c;
	u.bgaddr.tni = tni;
	u.bgaddr.bgid = gate;
	return u.val;
}

int tof_core_set_bg(const struct tof_set_bg *setbg,
		    uint64_t subnet,
		    uint32_t bseq, uint32_t gpid){
	int64_t slgate = setbg->source_lgate;
	const struct tof_addr *sraddr = &setbg->source_raddr;
	uint64_t srtni = setbg->source_rtni;
	int64_t srgate = setbg->source_rgate;
	int64_t dlgate = setbg->dest_lgate;
	const struct tof_addr *draddr = &setbg->dest_raddr;
	uint64_t drtni = setbg->dest_rtni;
	int64_t drgate = setbg->dest_rgate;
	struct tof_core_bg *bg;
	uint64_t sigmask = 0;
	uint64_t locallink = 0;
	uint64_t remotelink = 0;
	int ret = 0;
	unsigned long flags;

	bg = tof_core_bg_get(setbg->tni, setbg->gate);
	if(bg == NULL){
		return -EINVAL;
	}
	//spin_lock_irqsave(&bg->lock, flags);
	linux_spin_lock_irqsave(&bg->lock, flags);

	bg->subnet = subnet;
	bg->gpid = gpid;
	tof_core_reset_irqmask(&bg->irq);
	tof_core_reset_irqmask_imc(&bg->irq);

	if(slgate >= 0){
		locallink |= tof_util_mask_set(slgate, TOF_ICC_REG_BGS_LOCAL_LINK_BGID_RECV);
	}else{
		sigmask |= TOF_ICC_REG_BGS_SIGNAL_MASK_SIG_RECV;
	}
	if(srgate >= 0){
		uint64_t bgaddr;
		bgaddr = tof_core_pack_remote_bg(sraddr, srtni, srgate);
		remotelink |= tof_util_mask_set(bgaddr, TOF_ICC_REG_BGS_REMOTE_LINK_BG_ADDRESS_RECV);
	}else{
		sigmask |= TOF_ICC_REG_BGS_SIGNAL_MASK_TLP_RECV;
	}
	if(dlgate >= 0){
		locallink |= tof_util_mask_set(dlgate, TOF_ICC_REG_BGS_LOCAL_LINK_BGID_SEND);
	}else{
		sigmask |= TOF_ICC_REG_BGS_SIGNAL_MASK_SIG_SEND;
	}
	if(drgate >= 0){
		uint64_t bgaddr;
		bgaddr = tof_core_pack_remote_bg(draddr, drtni, drgate);
		remotelink |= tof_util_mask_set(bgaddr, TOF_ICC_REG_BGS_REMOTE_LINK_BG_ADDRESS_SEND);
	}else{
		sigmask |= TOF_ICC_REG_BGS_SIGNAL_MASK_TLP_SEND;
	}
	tof_writeq(sigmask, bg->reg.bgs, TOF_ICC_REG_BGS_SIGNAL_MASK);
	tof_writeq(locallink, bg->reg.bgs, TOF_ICC_REG_BGS_LOCAL_LINK);
	tof_writeq(remotelink, bg->reg.bgs, TOF_ICC_REG_BGS_REMOTE_LINK);
	tof_writeq(subnet, bg->reg.bgs, TOF_ICC_REG_BGS_SUBNET_SIZE);
	tof_writeq((uint64_t)gpid << 24 | bseq, bg->reg.bgs, TOF_ICC_REG_BGS_GPID_BSEQ);
	wmb();
	tof_writeq(1, bg->reg.bgs, TOF_ICC_REG_BGS_ENABLE);
	if(!tof_core_readq_spin(bg->reg.bgs, TOF_ICC_REG_BGS_STATE,
				TOF_ICC_REG_BGS_STATE_ENABLE,
				TOF_ICC_REG_BGS_STATE_ENABLE,
				TOF_CORE_TIMEOUT_BG_ENABLE)){
		ret = -ETIMEDOUT;
	}
	//spin_unlock_irqrestore(&bg->lock, flags);
	linux_spin_unlock_irqrestore(&bg->lock, flags);
	return ret;
}

void tof_core_register_signal_bg(int tni, int bgid, tof_core_signal_handler handler)
{
	struct tof_core_bg *bg = tof_core_bg_get(tni, bgid);
	unsigned long flags;
	linux_spin_lock_irqsave(&bg->lock, flags);
	bg->sighandler = handler;
	linux_spin_unlock_irqrestore(&bg->lock, flags);
}

typedef void (tof_utofu_handler_bg_signal_t)(int tni, int bgid, uint64_t irr, uint64_t data);
static tof_utofu_handler_bg_signal_t *tof_utofu_handler_bg_signal;

typedef int kuid_t;
static int tof_utofu_set_bg(struct tof_utofu_bg *ubch, struct tof_set_bg __user *bgs, kuid_t kuid, uint32_t bseq){
	struct tof_set_bg req;
	struct tof_utofu_bg *ubg;
	struct tof_set_subnet subnet;
	int ret;

	if(copy_from_user(&req, bgs, sizeof(req)) != 0){
		return -EFAULT;
	}
	//tof_log_if("ubch->tni=%d ubch->bgid=%d tni=%d gate=%d source_lgate=%d source_raddr=%x source_rtni=%d source_rgate=%d dest_lgate=%d dest_raddr=%x dest_rtni=%d dest_rgate=%d\n",
	dkprintf("%s: ubch->tni=%d ubch->bgid=%d tni=%d gate=%d source_lgate=%d source_raddr=%x source_rtni=%d source_rgate=%d dest_lgate=%d dest_raddr=%x dest_rtni=%d dest_rgate=%d\n",
			__func__, ubch->tni, ubch->bgid, req.tni, req.gate, req.source_lgate, req.source_raddr, req.source_rtni, req.source_rgate, req.dest_lgate, req.dest_raddr, req.dest_rtni, req.dest_rgate);

	ubg = tof_utofu_bg_get(req.tni, req.gate);
	if(ubg == NULL){
		raw_rc_output(-EINVAL);
		return -EINVAL;
	}
	tof_utofu_unpack_subnet(ubg->common.subnet, &subnet);
	if(req.source_lgate >= TOF_ICC_NBGS ||
	   (req.source_rgate >= 0 &&
	    (!tof_utofu_subnet_includes(&subnet, req.source_raddr.x, req.source_raddr.y, req.source_raddr.z) ||
	     (unsigned int)req.source_rtni >= TOF_ICC_NTNIS ||
	     req.source_rgate >= TOF_ICC_NBGS)) ||
	   req.dest_lgate >= TOF_ICC_NBGS ||
	   (req.dest_rgate >= 0 &&
	    (!tof_utofu_subnet_includes(&subnet, req.dest_raddr.x, req.dest_raddr.y, req.dest_raddr.z) ||
	     (unsigned int)req.dest_rtni >= TOF_ICC_NTNIS ||
	     req.dest_rgate >= TOF_ICC_NBGS))){
		raw_rc_output(-EINVAL);
		ret = -EINVAL;
		goto end;
	}
	if(ubg->common.enabled){
		ret = -EBUSY;
		goto end;
	}

	// TODO: fix this
	//if(!uid_eq(kuid, GLOBAL_ROOT_UID) &&
	//   !uid_eq(kuid, ubg->common.kuid)){
	//	ret = -EACCES;
	//	goto end;
	//}

	ret = tof_core_set_bg(&req, ubg->common.subnet, bseq, ubg->common.gpid);
	if(ret < 0){
		raw_rc_output(ret);
		goto end;
	}

	ubg->common.enabled = true;
	/* something else? */

	/* TODO: wrapping function */
	ubch->bch.bgmask[req.tni] |= (uint64_t)1 << req.gate;

	tof_core_register_signal_bg(req.tni, req.gate, tof_utofu_handler_bg_signal);
end:
	/* unlock? */
	return ret;
}

/**
 * tof_core_disable_bch - disable a BCH
 *
 * tries to disable the BCH gracefully, however, what if
 * some remote nodes have hung up?  therefore, it does not
 * wait for the BCH becoming ready.
 */
static int tof_core_bch_disable_locked(struct tof_core_bg *bg){
	if(bg->reg.bch == NULL){  /* this BG is not associated with a BCH */
		return -EINVAL;
	}
	tof_writeq(TOF_ICC_REG_BGS_BCH_MASK_MASK, bg->reg.bgs, TOF_ICC_REG_BGS_BCH_MASK);

	/* XXX: tof_core_bch_skip_mask_check is 1 */
	//if(tof_core_bch_skip_mask_check){
		return 0;
	//}

#if 0
	if(!tof_core_readq_spin(bg->reg.bgs, TOF_ICC_REG_BGS_BCH_MASK_STATUS,
				TOF_ICC_REG_BGS_BCH_MASK_STATUS_RUN,
				0,
				TOF_CORE_TIMEOUT_BCH_DISABLE)){
		tof_warn_limit(2012, "BCH disable timeout\n");
	}
	if(!tof_core_readq_spin(bg->reg.bch, TOF_ICC_REG_BCH_READY,
				TOF_ICC_REG_BCH_READY_STATE,
				TOF_ICC_REG_BCH_READY_STATE,
				TOF_CORE_TIMEOUT_BCH_DISABLE)){
		/* don't panic */
		tof_warn_limit(2013, "BCH ready timeout\n");
	}
	return 0;
#endif
}

int tof_core_disable_bch(int tni, int bgid){
	struct tof_core_bg *bg;
	int ret;
	bg = tof_core_bg_get(tni, bgid);
	if(bg == NULL || bg->reg.bch == NULL){
		return -EINVAL;
	}
	ret = tof_core_bch_disable_locked(bg);
	return ret;
}

static int tof_core_bg_disable(struct tof_core_bg *bg){
	/* BCH->... should be masked */
	tof_writeq(0, bg->reg.bgs, TOF_ICC_REG_BGS_ENABLE);

	/* XXX: tof_core_bg_disable_timeout_check_enable is 0 */
#if 0
	if(unlikely(tof_core_bg_disable_timeout_check_enable)){
		if(!tof_core_readq_spin(bg->reg.bgs, TOF_ICC_REG_BGS_STATE,
					TOF_ICC_REG_BGS_STATE_ENABLE,
					0,
					TOF_CORE_TIMEOUT_SEC(tof_core_bg_disable_timeout_limit_sec))){
			tof_warn_limit(2011, "BG disable timeout\n");
			return -ETIMEDOUT;
		}
	}
#endif
	return 0;
}

int tof_core_unset_bg(int tni, int bgid){
	struct tof_core_bg *bg;
	bg = tof_core_bg_get(tni, bgid);
	if(bg == NULL){
		return -EINVAL;
	}
	return tof_core_bg_disable(bg);
}

static inline void tof_core_unregister_signal_bg(int tni, int bgid)
{
	return tof_core_register_signal_bg(tni, bgid, NULL);
}

static int __tof_utofu_unset_bg(struct tof_utofu_bg *ubg){
	if(ubg->common.enabled){
		tof_core_unset_bg(ubg->tni, ubg->bgid);
		ubg->common.enabled = false;
		tof_core_unregister_signal_bg(ubg->tni, ubg->bgid);
	}
	return 0;
}

static int tof_utofu_unset_bg(struct tof_set_bg __user *bgs){
	struct tof_set_bg req;
	struct tof_utofu_bg *ubg;
	if(copy_from_user(&req, bgs, sizeof(req)) != 0){
		return -EFAULT;
	}
	ubg = tof_utofu_bg_get(req.tni, req.gate);
	return __tof_utofu_unset_bg(ubg);
}

static int tof_utofu_ioctl_enable_bch(struct tof_utofu_device *dev, unsigned long arg){
	struct tof_utofu_bg *ubg;
	struct tof_enable_bch req;
	uintptr_t ipa;
	kuid_t kuid;
	unsigned long phys = 0;
	struct process *proc = cpu_local_var(current)->proc;
	struct process_vm *vm = cpu_local_var(current)->vm;
	int ret;
	int i = 0;

	ubg = container_of(dev, struct tof_utofu_bg, common);
	if(ubg->bgid >= TOF_ICC_NBCHS){
		return -ENOTTY;
	}

	if(ubg->bch.enabled){
		return -EBUSY;
	}

	if(copy_from_user(&req, (void *)arg, sizeof(req)) != 0){
		return -EFAULT;
	}
	dkprintf("%s: tni=%d bgid=%d addr=%p bseq=%d num=%d bgs=%p\n",
		__func__, ubg->tni, ubg->bgid, req.addr, req.bseq, req.num, req.bgs);

	if(req.num < 0 || req.bgs == NULL || req.addr == NULL ||
	   ((uintptr_t)req.addr & (TOF_ICC_BCH_DMA_ALIGN - 1)) != 0 ||
	   (uint32_t)req.bseq >= TOF_ICC_BG_BSEQ_SIZE){
		return -EINVAL;
	}

	//ret = get_user_pages_fast((uintptr_t)req.addr, 1, 0, &page);
	//if(ret < 1){
	//	raw_rc_output(ret);
	//	return -ENOMEM;
	//}

	ihk_rwspinlock_read_lock_noirq(&vm->memory_range_lock);

	/* Special case for straight mapping */
	if (proc->straight_va && (void *)req.addr >= proc->straight_va &&
			(void *)req.addr < proc->straight_va + proc->straight_len) {

		phys = proc->straight_pa +
			((void *)req.addr - proc->straight_va);
	}

	if (!phys) {
		size_t psize;
		pte_t *ptep;

		ptep = ihk_mc_pt_lookup_fault_pte(cpu_local_var(current)->vm,
				(void *)req.addr, 0, NULL, &psize, NULL);

		if (unlikely(!ptep || !pte_is_present(ptep))) {
			kprintf("%s: ERROR: no valid PTE for 0x%lx\n",
					__func__, req.addr);
			raw_rc_output(-ENOMEM);
			ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);
			return -ENOMEM;
		}

		phys = (pte_get_phys(ptep) & ~(psize - 1)) +
			((uint64_t)req.addr & (psize - 1));
	}

	ihk_rwspinlock_read_unlock_noirq(&vm->memory_range_lock);

	//ipa = tof_smmu_get_ipa_bg(ubg->tni, ubg->bgid,
	//			  pfn_to_kaddr(page_to_pfn(page)) + ((uintptr_t)req.addr & (~PAGE_MASK)),
	//			  TOF_ICC_BCH_DMA_ALIGN);
	//if(ipa == 0){
	//	raw_rc_output(-ENOMEM);
	//	put_page(page);
	//	return -ENOMEM;
	//}
	ipa = (uintptr_t)phys;

	memset(ubg->bch.bgmask, 0, sizeof(ubg->bch.bgmask));

	//kuid = current_euid();  /* real? effective? */
	kuid = cpu_local_var(current)->proc->euid;

	ret = tof_core_enable_bch(ubg->tni, ubg->bgid, ipa);
	if(ret < 0){
		raw_rc_output(ret);
		goto revert;
	}

	for(i = 0; i < req.num; i++){
		ret = tof_utofu_set_bg(ubg, &req.bgs[i], kuid, req.bseq);
		if(ret < 0){
			raw_rc_output(ret);
			goto revert;
		}
	}

	ubg->bch.enabled = true;
	ubg->bch.iova = ipa;
	//ubg->bch.page = page;
end:
	return ret;

revert:
	tof_core_disable_bch(ubg->tni, ubg->bgid);
	for( ; i--; ){
		tof_utofu_unset_bg(&req.bgs[i]);
	}
	//tof_smmu_release_ipa_bg(ubg->tni, ubg->bgid, ipa, TOF_ICC_BCH_DMA_ALIGN);
	//put_page(page);
	goto end;
}

static int tof_utofu_disable_bch(struct tof_utofu_bg *ubg){
	int ret;
	int tni, bgid;

	if(!ubg->bch.enabled){
		return -EPERM;
	}

	ret = tof_core_disable_bch(ubg->tni, ubg->bgid);
	if(ret < 0){
		raw_rc_output(ret);
		return ret;
	}

	for(tni = 0; tni < TOF_ICC_NTNIS; tni++){
		uint64_t mask = ubg->bch.bgmask[tni];
		for(bgid = 0; bgid < TOF_ICC_NBGS; bgid++){
			if((mask >> bgid) & 1){
				ret = __tof_utofu_unset_bg(tof_utofu_bg_get(tni, bgid));
				if(ret < 0){
					/* OK? */
					//BUG();
					return ret;
				}
			}
		}
	}
	//tof_smmu_release_ipa_bg(ubg->tni, ubg->bgid, ubg->bch.iova, TOF_ICC_BCH_DMA_ALIGN);
	//put_page(ubg->bch.page);
	ubg->bch.enabled = false;
	smp_mb();
	dkprintf("%s: tni=%d bgid=%d\n", __func__, ubg->tni, ubg->bgid);
	return 0;
}


static int tof_utofu_ioctl_disable_bch(struct tof_utofu_device *dev, unsigned long arg){
	struct tof_utofu_bg *ubg;

	ubg = container_of(dev, struct tof_utofu_bg, common);
	//tof_log_if("tni=%d bgid=%d\n", ubg->tni, ubg->bgid);
	dkprintf("%s: tni=%d bgid=%d\n", __func__, ubg->tni, ubg->bgid);
	return tof_utofu_disable_bch(ubg);
}

static int tof_utofu_release_bch(void *pde_data){
	struct tof_utofu_bg *ubg;
	struct tof_utofu_device *dev = (struct tof_utofu_device *)pde_data;

	ubg = container_of(dev, struct tof_utofu_bg, common);
	//tof_log_if("tni=%d bgid=%d\n", ubg->tni, ubg->bgid);
	dkprintf("%s: tni=%d bgid=%d\n", __func__, ubg->tni, ubg->bgid);
	return tof_utofu_disable_bch(ubg);
}


/*
 * Main unified ioctl() call.
 */
long tof_utofu_unlocked_ioctl(int fd,
		unsigned int cmd, unsigned long arg) {
	int ret = -ENOTSUPP;
	struct thread *thread = cpu_local_var(current);
	struct tof_utofu_device *dev;
#ifdef PROFILE_ENABLE
	unsigned long ts = 0;
	if (cpu_local_var(current)->profile) {
		ts = rdtsc();
	}
#endif // PROFILE_ENABLE

	/* ENOTSUPP inidicates proceed with offload */
	if (fd >= MAX_FD_PDE || !thread->proc->fd_pde_data[fd]) {
		return -ENOTSUPP;
	}

	dev = (struct tof_utofu_device *)thread->proc->fd_pde_data[fd];

	switch (cmd) {
		case TOF_IOCTL_ALLOC_STAG:
			ret = tof_utofu_ioctl_alloc_stag(dev, arg);
#ifdef PROFILE_ENABLE
			profile_event_add(PROFILE_tofu_stag_alloc, rdtsc() - ts);
#endif // PROFILE_ENABLE
			break;

		case TOF_IOCTL_FREE_STAGS:
			ret = tof_utofu_ioctl_free_stags(dev, arg);
#ifdef PROFILE_ENABLE
			profile_event_add(PROFILE_tofu_stag_free_stags, rdtsc() - ts);
#endif // PROFILE_ENABLE
			break;

		case TOF_IOCTL_ENABLE_BCH:
			ret = tof_utofu_ioctl_enable_bch(dev, arg);
			break;

		case TOF_IOCTL_DISABLE_BCH:
			ret = tof_utofu_ioctl_disable_bch(dev, arg);
			break;

#if 0
		case TOF_IOCTL_INIT_CQ:
			kprintf("%s: TOF_IOCTL_INIT_CQ @ %d\n", __func__, fd);
			break;

		case TOF_IOCTL_SET_RT_SIGNAL:
			kprintf("%s: TOF_IOCTL_SET_RT_SIGNAL @ %d\n", __func__, fd);
			break;

		case TOF_IOCTL_GET_PORT_STAT:
			kprintf("%s: TOF_IOCTL_GET_PORT_STAT @ %d\n", __func__, fd);
			break;

		case TOF_IOCTL_GET_CQ_STAT:
			kprintf("%s: TOF_IOCTL_GET_CQ_STAT @ %d\n", __func__, fd);
			break;

		case TOF_IOCTL_SET_SUBNET:
			kprintf("%s: TOF_IOCTL_SET_SUBNET @ %d\n", __func__, fd);
			break;

		case TOF_IOCTL_REG_USER:
			kprintf("%s: TOF_IOCTL_REG_USER @ %d\n", __func__, fd);
			break;

		case TOF_IOCTL_NOTIFY_LINKDOWN:
			kprintf("%s: TOF_IOCTL_NOTIFY_LINKDOWN @ %d\n", __func__, fd);
			break;

		case TOF_IOCTL_LOAD_REGISTER:
			kprintf("%s: TOF_IOCTL_LOAD_REGISTER @ %d\n", __func__, fd);
			break;

		case TOF_IOCTL_LOAD_RESOURCE:
			kprintf("%s: TOF_IOCTL_LOAD_RESOURCE @ %d\n", __func__, fd);
			break;
#endif
		default:
			dkprintf("%s: unknown @ %d\n", __func__, fd);
			ret = -ENOTSUPP;
			break;
	}

	return ret;
}

extern struct tofu_globals *ihk_mc_get_tofu_globals(void);
void tof_utofu_init_globals(void)
{
	struct tofu_globals *tg = ihk_mc_get_tofu_globals();

	tof_ib_stag_list = (int16_t *)tg->tof_ib_stag_list_addr;
	tof_ib_stag_lock = (ihk_spinlock_t *)tg->tof_ib_stag_lock_addr;
	tof_ib_stag_list_Rp_addr = (int *)tg->tof_ib_stag_list_Rp_addr;
	tof_ib_stag_list_Wp_addr = (int *)tg->tof_ib_stag_list_Wp_addr;
	tof_ib_mbpt_mem =
		(struct tof_util_aligned_mem *)tg->tof_ib_mbpt_mem_addr;
	tof_ib_steering =
		(struct tof_icc_steering_entry *)tg->tof_ib_steering_addr;
	tof_ib_mb =
		(struct tof_icc_mb_entry *)tg->tof_ib_mb_addr;
	tof_core_cq =
		(struct tof_core_cq *)tg->tof_core_cq_addr;
	tof_core_bg =
		(struct tof_core_bg *)tg->tof_core_bg_addr;
	tof_utofu_bg =
		(struct tof_utofu_bg *)tg->tof_utofu_bg_addr;
	tof_utofu_handler_bg_signal =
		(tof_utofu_handler_bg_signal_t *)tg->tof_utofu_handler_bg_signal_addr;

	dkprintf("%s: tof_ib_stag_lock: 0x%lx\n",
		__func__, tg->tof_ib_stag_lock_addr);
	dkprintf("%s: tof_ib_stag_list_Wp_addr: 0x%lx\n",
			__func__, tg->tof_ib_stag_list_Wp_addr);
	dkprintf("%s: tof_ib_stag_list_Wp: %d\n",
			__func__, *((int *)tg->tof_ib_stag_list_Wp_addr));
	kprintf("%s: linux_vmalloc_start: %p\n", __func__, tg->linux_vmalloc_start);

	memset(tofu_scatterlist_cache, 0, sizeof(tofu_scatterlist_cache));
	memset(tofu_mbpt_cache, 0, sizeof(tofu_mbpt_cache));
	memset(tofu_mbpt_sg_pages_cache, 0, sizeof(tofu_mbpt_sg_pages_cache));
	memset(tofu_stag_range_cache, 0, sizeof(tofu_stag_range_cache));

	{
		int tni, cq;

		for (tni = 0; tni < 6; ++tni) {
			for (cq = 0; cq < 12; ++cq) {
				ihk_mc_spinlock_init(&tofu_tni_cq_lock[tni][cq]);
			}
		}
	}

	kprintf("Tofu globals initialized.\n");
}

void tof_utofu_release_fd(struct process *proc, int fd)
{
	if (!proc->enable_tofu)
		return;

	if (!proc->fd_pde_data[fd] || !proc->fd_path[fd]) {
		return;
	}

	if (strstr((const char *)proc->fd_path[fd], "cq")) {
		dkprintf("%s: PID: %d, fd: %d -> release CQ\n",
			__func__, proc->pid, fd);
		tof_utofu_release_cq(proc->fd_pde_data[fd]);
	}

	else if (strstr((const char *)proc->fd_path[fd], "bch")) {
		dkprintf("%s: PID: %d, fd: %d -> release BCH\n",
			__func__, proc->pid, fd);
		tof_utofu_release_bch(proc->fd_pde_data[fd]);
	}
}

void tof_utofu_release_fds(struct process *proc)
{
	int fd;

	if (!proc->enable_tofu)
		return;

	for (fd = 0; fd < MAX_FD_PDE; ++fd) {
		tof_utofu_release_fd(proc, fd);
	}
}

void tof_utofu_finalize(void)
{
	struct tofu_globals *tg = ihk_mc_get_tofu_globals();

	/* Could be called from idle.. */
	if (cpu_local_var(current)->proc->enable_tofu) {
		int i;
		struct process_vm *vm = cpu_local_var(current)->vm;
		struct tofu_stag_range *tsr, *next;

		for (i = 0; i < TOFU_STAG_HASH_SIZE; ++i) {
			list_for_each_entry_safe(tsr, next,
					&vm->tofu_stag_hash[i], hash) {

				dkprintf("%s: WARNING: stray stag %d (%p:%lu) for TNI %d CQ %d?\n",
						__func__, tsr->stag,
						tsr->start, tsr->end - tsr->start,
						tsr->ucq->tni, tsr->ucq->cqid);
			}
		}
		kprintf("%s: STAG processing done\n", __func__);
	}

	ihk_mc_clear_kernel_range((void *)tg->linux_vmalloc_start,
			(void *)tg->linux_vmalloc_end);
}

