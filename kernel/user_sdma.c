#include <hfi1/hfi.h>
#include <hfi1/sdma.h>
#include <hfi1/user_sdma.h>
#include <hfi1/user_exp_rcv.h>
#include <hfi1/common.h> 

//#define DEBUG_PRINT_HFI1_SDMA

#ifdef DEBUG_PRINT_HFI1_SDMA
#define dkprintf(...) kprintf(__VA_ARGS__)
#else
#define dkprintf(...) do { if(0) kprintf(__VA_ARGS__); } while (0)
#endif

static uint hfi1_sdma_comp_ring_size = 128;

/* The maximum number of Data io vectors per message/request */
#define MAX_VECTORS_PER_REQ 8
/*
 * Maximum number of packet to send from each message/request
 * before moving to the next one.
 */
#define MAX_PKTS_PER_QUEUE 16

#define num_pages(x) (1 + ((((x) - 1) & PAGE_MASK) >> PAGE_SHIFT))

#define req_opcode(x) \
	(((x) >> HFI1_SDMA_REQ_OPCODE_SHIFT) & HFI1_SDMA_REQ_OPCODE_MASK)
#define req_version(x) \
	(((x) >> HFI1_SDMA_REQ_VERSION_SHIFT) & HFI1_SDMA_REQ_OPCODE_MASK)
#define req_iovcnt(x) \
	(((x) >> HFI1_SDMA_REQ_IOVCNT_SHIFT) & HFI1_SDMA_REQ_IOVCNT_MASK)

#define PBC2LRH(x) ((((x) & 0xfff) << 2) - 4)
#define LRH2PBC(x) ((((x) >> 2) + 1) & 0xfff)

#define AHG_HEADER_SET(arr, idx, dw, bit, width, value)			\
	do {								\
		if ((idx) < ARRAY_SIZE((arr)))				\
			(arr)[(idx++)] = sdma_build_ahg_descriptor(	\
				(__force u16)(value), (dw), (bit),	\
							(width));	\
		else							\
			return -ERANGE;					\
	} while (0)

/* KDETH OM multipliers and switch over point */
#define KDETH_OM_SMALL     4
#define KDETH_OM_LARGE     64
#define KDETH_OM_MAX_SIZE  (1 << ((KDETH_OM_LARGE / KDETH_OM_SMALL) + 1))

/* Tx request flag bits */
#define TXREQ_FLAGS_REQ_ACK   BIT(0)      /* Set the ACK bit in the header */
#define TXREQ_FLAGS_REQ_DISABLE_SH BIT(1) /* Disable header suppression */

/* SDMA request flag bits */
#define SDMA_REQ_FOR_THREAD 1
#define SDMA_REQ_SEND_DONE  2
#define SDMA_REQ_HAVE_AHG   3
#define SDMA_REQ_HAS_ERROR  4
#define SDMA_REQ_DONE_ERROR 5


/*
 * Maximum retry attempts to submit a TX request
 * before putting the process to sleep.
 */
#define MAX_DEFER_RETRY_COUNT 1

static unsigned initial_pkt_count = 8;

#define SDMA_IOWAIT_TIMEOUT 1000 /* in milliseconds */

struct user_sdma_iovec {
	struct list_head list;
	struct iovec iov;
#ifdef __HFI1_ORIG__
	/* number of pages in this vector */
	unsigned npages;
	/* array of pinned pages for this vector */
	struct page **pages;
#else
	/*
	 * Physical address corresponding to the page that contains
	 * iov.iov_base and the corresponding page size.
	 */
	unsigned int base_pgsize;
	unsigned long base_phys;
#endif
	/*
	 * offset into the virtual address space of the vector at
	 * which we last left off.
	 */
	u64 offset;
#ifdef __HFI1_ORIG__
	struct sdma_mmu_node *node;
#else
	/*
	 * Virtual address corresponding to base_phys
	 * (i.e., the beginning of the underlying page).
	 */
	void *base_virt;
#endif
};


#include <hfi1/hfi1_generated_user_sdma_request.h>

/*
 * A single txreq could span up to 3 physical pages when the MTU
 * is sufficiently large (> 4K). Each of the IOV pointers also
 * needs it's own set of flags so the vector has been handled
 * independently of each other.
 */

#include <hfi1/hfi1_generated_user_sdma_txreq.h>


static int user_sdma_send_pkts(struct user_sdma_request *req,
		unsigned maxpkts,
		struct kmalloc_cache_header *txreq_cache);
static inline void pq_update(struct hfi1_user_sdma_pkt_q *);
static int check_header_template(struct user_sdma_request *,
				 struct hfi1_pkt_header *, u32, u32);
static int set_txreq_header(struct user_sdma_request *,
			    struct user_sdma_txreq *, u32);
static int set_txreq_header_ahg(struct user_sdma_request *,
				struct user_sdma_txreq *, u32);
static void user_sdma_free_request(struct user_sdma_request *, bool);
static inline void set_comp_state(struct hfi1_user_sdma_pkt_q *,
				  struct hfi1_user_sdma_comp_q *,
				  u16, enum hfi1_sdma_comp_state, int);
static void user_sdma_txreq_cb(struct sdma_txreq *, int);

static u8 dlid_to_selector(u16 dlid)
{
	static u8 mapping[256];
	static int initialized;
	static u8 next;
	int hash;

	if (!initialized) {
		memset(mapping, 0xFF, 256);
		initialized = 1;
	}

	hash = ((dlid >> 8) ^ dlid) & 0xFF;
	if (mapping[hash] == 0xFF) {
		mapping[hash] = next;
		next = (next + 1) & 0x7F;
	}

	return mapping[hash];
}

/* hfi1/chip_registers.h */
#define CORE		0x000000000000
#define TXE			(CORE + 0x000001800000)
#define RXE			(CORE + 0x000001000000)
#define RCV_ARRAY (RXE + 0x000000200000)
/* hfi1/chip.h */
#define TXE_PIO_SEND (TXE + TXE_PIO_SEND_OFFSET)
#define TXE_PIO_SEND_OFFSET 0x0800000
#define TXE_PIO_SIZE (32 * 0x100000)	/* 32 MB */

int hfi1_map_device_addresses(struct hfi1_filedata *fd)
{
	pte_t *lptep;
	pte_t *ptep;
	enum ihk_mc_pt_attribute attr;
	void *virt;
	unsigned long phys;
	unsigned long len;
	unsigned long irqstate;
	int ret = 0;

	struct process *proc = cpu_local_var(current)->proc;
	struct process_vm *vm = cpu_local_var(current)->vm;
	struct hfi1_user_sdma_comp_q *cq = fd->cq;
	struct hfi1_devdata *dd = fd->dd;

	irqstate = ihk_mc_spinlock_lock(&proc->hfi1_lock);

	/*
	 * Map device addresses if not mapped or mapping changed.
	 */
	if (proc->hfi1_kregbase != dd->kregbase1) {
		void *hfi1_kregbase = dd->kregbase1;

		phys = dd->physaddr;
		attr = PTATTR_UNCACHABLE | PTATTR_WRITABLE;
		/*
		 * No race condition here as ihk_mc_pt_set_page() holds
		 * the lock to kernel space mapping manipulation
		 *
		 * XXX: use large pages?
		 * XXX: where are we going to unmap this?
		 */

		for (virt = hfi1_kregbase; virt < (hfi1_kregbase + TXE_PIO_SEND);
				virt += PAGE_SIZE, phys += PAGE_SIZE) {
			if (ihk_mc_pt_set_page(vm->address_space->page_table,
						virt, phys, attr) < 0) {
				kprintf("%s: ERROR: failed to map kregbase: 0x%lx -> 0x%lx\n",
						__FUNCTION__, virt, phys);
				ret = -1;
				goto unlock_out;
			}

			ptep = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
					virt, 0, 0, 0, 0);
			if (!ptep && !pte_is_present(ptep)) {
				kprintf("%s: ERROR: no mapping in McKernel for kregbase: 0x%lx?\n",
						__FUNCTION__, virt);
				ret = -1;
				goto unlock_out;
			}

			lptep = ihk_mc_pt_lookup_pte(ihk_mc_get_linux_kernel_pgt(),
					virt, 0, 0, 0, 0);
			if (!lptep && !pte_is_present(lptep)) {
				kprintf("%s: ERROR: no mapping in Linux for kregbase: 0x%lx?\n",
						__FUNCTION__, virt);
				ret = -1;
				goto unlock_out;
			}

			*ptep = *lptep;
		}

		dkprintf("%s: hfi1_kregbase: 0x%lx - 0x%lx -> 0x%lx:%lu\n",
				__FUNCTION__,
				hfi1_kregbase,
				hfi1_kregbase + TXE_PIO_SEND,
				(phys - TXE_PIO_SEND), TXE_PIO_SEND);
		//ihk_mc_pt_print_pte(vm->address_space->page_table, hfi1_kregbase);

		proc->hfi1_kregbase = hfi1_kregbase;

		/* Initialize registration tree */
		proc->hfi1_reg_tree = RB_ROOT;
		proc->hfi1_inv_tree = RB_ROOT;
	}

	if (proc->hfi1_piobase != dd->piobase) {
		void *hfi1_piobase = dd->piobase;

		phys = dd->physaddr + TXE_PIO_SEND;
		attr = PTATTR_WRITE_COMBINED | PTATTR_WRITABLE;

		for (virt = hfi1_piobase; virt < (hfi1_piobase + TXE_PIO_SIZE);
				virt += PAGE_SIZE, phys += PAGE_SIZE) {
			if (ihk_mc_pt_set_page(vm->address_space->page_table,
						virt, phys, attr) < 0) {
				kprintf("%s: ERROR: failed to map piobase: 0x%lx -> 0x%lx\n",
					__FUNCTION__, virt, phys);
				ret = -1;
				goto unlock_out;
			}

			ptep = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
					virt, 0, 0, 0, 0);
			if (!ptep && !pte_is_present(ptep)) {
				kprintf("%s: ERROR: no mapping in McKernel for piobase: 0x%lx?\n",
						__FUNCTION__, virt);
				ret = -1;
				goto unlock_out;
			}

			lptep = ihk_mc_pt_lookup_pte(ihk_mc_get_linux_kernel_pgt(),
					virt, 0, 0, 0, 0);
			if (!lptep && !pte_is_present(lptep)) {
				kprintf("%s: ERROR: no mapping in Linux for piobase: 0x%lx?\n",
						__FUNCTION__, virt);
				ret = -1;
				goto unlock_out;
			}

			*ptep = *lptep;
		}

		dkprintf("%s: hfi1_piobase: 0x%lx - 0x%lx -> 0x%lx:%lu\n",
				__FUNCTION__,
				hfi1_piobase,
				hfi1_piobase + TXE_PIO_SIZE,
				(phys - TXE_PIO_SIZE), TXE_PIO_SIZE);

		proc->hfi1_piobase = hfi1_piobase;
	}

	if (proc->hfi1_rcvarray_wc != dd->rcvarray_wc) {
		void *hfi1_rcvarray_wc = dd->rcvarray_wc;

		phys = dd->physaddr + RCV_ARRAY;
		attr = PTATTR_WRITE_COMBINED | PTATTR_WRITABLE;

		for (virt = hfi1_rcvarray_wc;
				virt < (hfi1_rcvarray_wc + dd->chip_rcv_array_count * 8);
				virt += PAGE_SIZE, phys += PAGE_SIZE) {
			if (ihk_mc_pt_set_page(vm->address_space->page_table,
						virt, phys, attr) < 0) {
				kprintf("%s: ERROR: failed to map rcvarray_wc: 0x%lx -> 0x%lx\n",
						__FUNCTION__, virt, phys);
				ret = -1;
				goto unlock_out;
			}

			ptep = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
					virt, 0, 0, 0, 0);
			if (!ptep && !pte_is_present(ptep)) {
				kprintf("%s: ERROR: no mapping in McKernel for rcvarray: 0x%lx?\n",
						__FUNCTION__, virt);
				ret = -1;
				goto unlock_out;
			}

			lptep = ihk_mc_pt_lookup_pte(ihk_mc_get_linux_kernel_pgt(),
					virt, 0, 0, 0, 0);
			if (!lptep && !pte_is_present(lptep)) {
				kprintf("%s: ERROR: no mapping in Linux for rcvarray: 0x%lx?\n",
						__FUNCTION__, virt);
				ret = -1;
				goto unlock_out;
			}

			*ptep = *lptep;
		}

		dkprintf("%s: hfi1_rcvarray_wc: 0x%lx - 0x%lx -> 0x%lx:%lu\n",
				__FUNCTION__,
				hfi1_rcvarray_wc,
				hfi1_rcvarray_wc + dd->chip_rcv_array_count * 8,
				(phys - dd->chip_rcv_array_count * 8),
				dd->chip_rcv_array_count * 8);

		proc->hfi1_rcvarray_wc = hfi1_rcvarray_wc;
		proc->hfi1_rcvarray_wc_len = dd->chip_rcv_array_count * 8;
	}

	/*
	 * Map in cq->comps, allocated by vmalloc_user() in Linux.
	 */
	if (proc->hfi1_cq_comps != cq->comps) {
		len = ((sizeof(*cq->comps) * cq->nentries)
				+ PAGE_SIZE - 1) & PAGE_MASK;
		attr = PTATTR_WRITABLE;

		for (virt = (void *)cq->comps; virt < (((void *)cq->comps) + len);
				virt += PAGE_SIZE) {

			lptep = ihk_mc_pt_lookup_pte(ihk_mc_get_linux_kernel_pgt(),
					virt, 0, 0, 0, 0);
			if (!lptep && !pte_is_present(lptep)) {
				kprintf("%s: ERROR: no mapping in Linux for cq: 0x%lx?\n",
						__FUNCTION__, virt);
				ret = -1;
				goto unlock_out;
			}

			phys = pte_get_phys(lptep);

			ptep = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
					virt, 0, 0, 0, 0);
			if (ptep && pte_is_present(ptep) && pte_get_phys(ptep) == phys) {
				continue;
			}

			if (ihk_mc_pt_set_page(vm->address_space->page_table,
						virt, phys, attr) < 0) {
				/* Not necessarily an error.. */
				kprintf("%s: WARNING: mapping cq: 0x%lx -> 0x%lx\n",
						__FUNCTION__, virt, phys);
			}

			ptep = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
					virt, 0, 0, 0, 0);
			if (!ptep) {
				kprintf("%s: ERROR: no PTE in McKernel for cq: 0x%lx?\n",
						__FUNCTION__, virt);
				ret = -1;
				goto unlock_out;
			}

			*ptep = *lptep;
		}

		dkprintf("%s: hfi1_cq_comps: 0x%lx - 0x%lx mapped\n",
				__FUNCTION__,
				cq->comps, len);

		proc->hfi1_cq_comps = cq->comps;
		proc->hfi1_cq_comps_len = len;
	}

	if (proc->hfi1_events != dd->events) {
		void *hfi1_events = dd->events;
		len = (dd->chip_rcv_contexts * HFI1_MAX_SHARED_CTXTS *
				sizeof(*dd->events) + PAGE_SIZE - 1) & PAGE_MASK;

		/*
		 * Events are in Linux vmalloc area, we need to
		 * resolve physical addresses by looking at Linux
		 * page tables.
		 */
		for (virt = hfi1_events; virt < hfi1_events + len;
				virt += PAGE_SIZE) {

			lptep = ihk_mc_pt_lookup_pte(ihk_mc_get_linux_kernel_pgt(),
					virt, 0, 0, 0, 0);
			if (!lptep && !pte_is_present(lptep)) {
				kprintf("%s: ERROR: no mapping in Linux for events: 0x%lx?\n",
						__FUNCTION__, virt);
				ret = -1;
				goto unlock_out;
			}

			phys = pte_get_phys(lptep);
			if (ihk_mc_pt_set_page(vm->address_space->page_table,
						virt, phys, attr) < 0) {
				kprintf("%s: ERROR: failed to map events: 0x%lx -> 0x%lx\n",
						__FUNCTION__, virt, phys);
				ret = -1;
				goto unlock_out;
			}

			ptep = ihk_mc_pt_lookup_pte(vm->address_space->page_table,
					virt, 0, 0, 0, 0);
			if (!ptep && !pte_is_present(ptep)) {
				kprintf("%s: ERROR: no mapping in McKernel for events: 0x%lx?\n",
						__FUNCTION__, virt);
				ret = -1;
				goto unlock_out;
			}

			*ptep = *lptep;
		}

		dkprintf("%s: hfi1_events: 0x%lx - 0x%lx\n",
				__FUNCTION__,
				hfi1_events,
				hfi1_events + len);
		//ihk_mc_pt_print_pte(vm->address_space->page_table, hfi1_events);

		proc->hfi1_events = hfi1_events;
	}

	flush_tlb();

unlock_out:
	ihk_mc_spinlock_unlock(&proc->hfi1_lock, irqstate);

	return ret;
}


int hfi1_unmap_device_addresses(struct process *proc)
{
	unsigned long irqstate;
	int ret = 0;

	struct process_vm *vm = proc->vm;
	extern void ihk_mc_pt_destroy_pgd_subtree(struct page_table *pt,
			void *virt);

	irqstate = ihk_mc_spinlock_lock(&proc->hfi1_lock);

	/*
	 * Unmap device addresses if mapped.
	 */
	if (proc->hfi1_kregbase) {

		ihk_mc_pt_destroy_pgd_subtree(vm->address_space->page_table,
			proc->hfi1_kregbase);
/*
		ihk_mc_pt_clear_kernel_range(vm->address_space->page_table, vm,
				proc->hfi1_kregbase, proc->hfi1_kregbase + TXE_PIO_SEND);

		kprintf("%s: hfi1_kregbase unmapped\n",
				__FUNCTION__);
*/
		proc->hfi1_kregbase = 0;
	}

	if (proc->hfi1_piobase) {

		ihk_mc_pt_destroy_pgd_subtree(vm->address_space->page_table,
			proc->hfi1_piobase);
/*
		ihk_mc_pt_clear_kernel_range(vm->address_space->page_table, vm,
				proc->hfi1_piobase, proc->hfi1_piobase + TXE_PIO_SIZE);

		kprintf("%s: hfi1_piobase unmapped\n",
				__FUNCTION__);
*/
		proc->hfi1_piobase = 0;
	}

	if (proc->hfi1_rcvarray_wc) {

		ihk_mc_pt_destroy_pgd_subtree(vm->address_space->page_table,
			proc->hfi1_rcvarray_wc);
/*
		ihk_mc_pt_clear_kernel_range(vm->address_space->page_table, vm,
				proc->hfi1_rcvarray_wc,
				proc->hfi1_rcvarray_wc + proc->hfi1_rcvarray_wc_len);

		kprintf("%s: hfi1_rcvarray_wc unmapped\n",
				__FUNCTION__);
*/
		proc->hfi1_rcvarray_wc = 0;
	}

	if (proc->hfi1_cq_comps) {

		ihk_mc_pt_destroy_pgd_subtree(vm->address_space->page_table,
			proc->hfi1_cq_comps);
/*
		ihk_mc_pt_clear_kernel_range(vm->address_space->page_table, vm,
				proc->hfi1_cq_comps,
				proc->hfi1_cq_comps + proc->hfi1_cq_comps_len);

		kprintf("%s: hfi1_cq_comps unmapped\n",
				__FUNCTION__);
*/
		proc->hfi1_cq_comps = 0;
	}

	ihk_mc_spinlock_unlock(&proc->hfi1_lock, irqstate);

	return ret;
}

#undef PROFILE_ENABLE

int hfi1_user_sdma_process_request(void *private_data, struct iovec *iovec,
				   unsigned long dim, unsigned long *count)
{
	int ret = 0, i;
	struct hfi1_filedata *fd = private_data;
	struct hfi1_ctxtdata *uctxt = fd->uctxt;
	struct hfi1_user_sdma_pkt_q *pq = fd->pq;
	struct hfi1_user_sdma_comp_q *cq = fd->cq;
	struct hfi1_devdata *dd = pq->dd;
	unsigned long idx = 0;
	u8 pcount = initial_pkt_count;
	struct sdma_req_info info;
	struct user_sdma_request *req;
	u8 opcode, sc, vl;
	u16 dlid;
	u32 selector;
	unsigned long size_info = sizeof(info);
	struct kmalloc_cache_header *txreq_cache =
		&cpu_local_var(txreq_cache);

	hfi1_cdbg(AIOWRITE, "+");
	if (iovec[idx].iov_len < sizeof(info) + sizeof(req->hdr)) {
		hfi1_cdbg(
		   SDMA,
		   "[%u:%u:%u] First vector not big enough for header %lu/%lu",
		   dd->unit, uctxt->ctxt, fd->subctxt,
		   iovec[idx].iov_len, size_info + sizeof(req->hdr));
		return -EINVAL;
	}
	ret = copy_from_user(&info, iovec[idx].iov_base, size_info);
	if (ret) {
		hfi1_cdbg(SDMA, "[%u:%u:%u] Failed to copy info QW (%d)",
			  dd->unit, uctxt->ctxt, fd->subctxt, ret);
		return -EFAULT;
	}

	// trace_hfi1_sdma_user_reqinfo(dd, uctxt->ctxt, fd->subctxt,
	// 			     (u16 *)&info);

	if (info.comp_idx >= hfi1_sdma_comp_ring_size) {
		hfi1_cdbg(SDMA,
			  "[%u:%u:%u:%u] Invalid comp index",
			  dd->unit, uctxt->ctxt, fd->subctxt, info.comp_idx);
		return -EINVAL;
	}

	/*
	 * Sanity check the header io vector count.  Need at least 1 vector
	 * (header) and cannot be larger than the actual io vector count.
	 */
	if (req_iovcnt(info.ctrl) < 1 || req_iovcnt(info.ctrl) > dim) {
		hfi1_cdbg(SDMA,
			  "[%u:%u:%u:%u] Invalid iov count %d, dim %ld",
			  dd->unit, uctxt->ctxt, fd->subctxt, info.comp_idx,
			  req_iovcnt(info.ctrl), dim);
		return -EINVAL;
	}

	if (!info.fragsize) {
		hfi1_cdbg(SDMA,
			  "[%u:%u:%u:%u] Request does not specify fragsize",
			  dd->unit, uctxt->ctxt, fd->subctxt, info.comp_idx);
		return -EINVAL;
	}


	/* Try to claim the request. */
	if (test_and_set_bit(info.comp_idx, pq->req_in_use)) {
		hfi1_cdbg(SDMA, "[%u:%u:%u] Entry %u is in use",
			  dd->unit, uctxt->ctxt, fd->subctxt,
			  info.comp_idx);
		return -EBADSLT;
	}

	/*
	 * All safety checks have been done and this request has been claimed.
	 */
	//trace_hfi1_sdma_user_process_request(dd, uctxt->ctxt, fd->subctxt,
	//				     info.comp_idx);
	req = pq->reqs + info.comp_idx;
	req->data_iovs = req_iovcnt(info.ctrl) - 1; /* subtract header vector */
	req->data_len  = 0;
	req->pq = pq;
	req->cq = cq;
	req->ahg_idx = -1;
	req->iov_idx = 0;
	req->sent = 0;
	req->seqnum = 0;
	req->seqcomp = 0;
	req->seqsubmitted = 0;
	req->tids = NULL;
	req->has_error = 0;
	INIT_LIST_HEAD(&req->txps);


	fast_memcpy(&req->info, &info, size_info);

	/* The request is initialized, count it */
	ihk_atomic_inc(&pq->n_reqs);

	if (req_opcode(info.ctrl) == EXPECTED) {
		/* expected must have a TID info and at least one data vector */
		if (req->data_iovs < 2) {
			SDMA_DBG(req,
				 "Not enough vectors for expected request");
			ret = -EINVAL;
			goto free_req;
		}
		req->data_iovs--;
	}

	if (!info.npkts || req->data_iovs > MAX_VECTORS_PER_REQ) {
		SDMA_DBG(req, "Too many vectors (%u/%u)", req->data_iovs,
			 MAX_VECTORS_PER_REQ);
		ret = -EINVAL;
		goto free_req;
	}
	/* Copy the header from the user buffer */
	ret = copy_from_user(&req->hdr, iovec[idx].iov_base + size_info,
			     sizeof(req->hdr));
	if (ret) {
		SDMA_DBG(req, "Failed to copy header template (%d)", ret);
		ret = -EFAULT;
		goto free_req;
	}

	/* If Static rate control is not enabled, sanitize the header. */
	if (!HFI1_CAP_IS_USET(STATIC_RATE_CTRL))
		req->hdr.pbc[2] = 0;

	/* Validate the opcode. Do not trust packets from user space blindly. */
	opcode = (be32_to_cpu(req->hdr.bth[0]) >> 24) & 0xff;
	if ((opcode & USER_OPCODE_CHECK_MASK) !=
	     USER_OPCODE_CHECK_VAL) {
		SDMA_DBG(req, "Invalid opcode (%d)", opcode);
		ret = -EINVAL;
		goto free_req;
	}
	/*
	 * Validate the vl. Do not trust packets from user space blindly.
	 * VL comes from PBC, SC comes from LRH, and the VL needs to
	 * match the SC look up.
	 */
	vl = (le16_to_cpu(req->hdr.pbc[0]) >> 12) & 0xF;
	sc = (((be16_to_cpu(req->hdr.lrh[0]) >> 12) & 0xF) |
	      (((le16_to_cpu(req->hdr.pbc[1]) >> 14) & 0x1) << 4));
	if (vl >= dd->pport->vls_operational ||
	    vl != sc_to_vlt(dd, sc)) {
		SDMA_DBG(req, "Invalid SC(%u)/VL(%u)", sc, vl);
		ret = -EINVAL;
		goto free_req;
	}
// TODO: Enable this validation and checking
#ifdef __HFI1_ORIG__
	/* Checking P_KEY for requests from user-space */
	if (egress_pkey_check(dd->pport, req->hdr.lrh, req->hdr.bth, sc,
			      PKEY_CHECK_INVALID)) {
		ret = -EINVAL;
		goto free_req;
	}
#endif /* __HFI1_ORIG__ */

	/*
	 * Also should check the BTH.lnh. If it says the next header is GRH then
	 * the RXE parsing will be off and will land in the middle of the KDETH
	 * or miss it entirely.
	 */
	if ((be16_to_cpu(req->hdr.lrh[0]) & 0x3) == HFI1_LRH_GRH) {
		SDMA_DBG(req, "User tried to pass in a GRH");
		ret = -EINVAL;
		goto free_req;
	}

	req->koffset = le32_to_cpu(req->hdr.kdeth.swdata[6]);
	/*
	 * Calculate the initial TID offset based on the values of
	 * KDETH.OFFSET and KDETH.OM that are passed in.
	 */
	req->tidoffset = KDETH_GET(req->hdr.kdeth.ver_tid_offset, OFFSET) *
		(KDETH_GET(req->hdr.kdeth.ver_tid_offset, OM) ?
		 KDETH_OM_LARGE : KDETH_OM_SMALL);
	//trace_hfi1_sdma_user_initial_tidoffset(dd, uctxt->ctxt, fd->subctxt,
	//				       info.comp_idx, req->tidoffset);
	idx++;

	/* Save all the IO vector structures */
	for (i = 0; i < req->data_iovs; i++) {
		pte_t *ptep;
		size_t base_pgsize;
		struct user_sdma_iovec *usi;
		void *virt;

		req->iovs[i].offset = 0;
		INIT_LIST_HEAD(&req->iovs[i].list);

		/*
		 * req->iovs[] contain only the data.
		 */
		fast_memcpy(&req->iovs[i].iov, iovec + idx++, sizeof(struct iovec));

		usi = &req->iovs[i];
		virt = usi->iov.iov_base;

		/*
		 * Look up the PTE for the start of this iovec.
		 * Store the physical address of the first page and
		 * the page size in iovec.
		 */
		ptep = ihk_mc_pt_lookup_fault_pte(
				cpu_local_var(current)->vm,
				virt,
				0,
				0,
				&base_pgsize,
				0);
		if (unlikely(!ptep || !pte_is_present(ptep))) {
			kprintf("%s: ERROR: no valid PTE for 0x%lx\n",
					__FUNCTION__, virt);
			return -EFAULT;
		}

		usi->base_pgsize = (unsigned)base_pgsize;
		usi->base_phys = pte_get_phys(ptep);
		usi->base_virt = (void *)((unsigned long)virt &
				~((unsigned long)usi->base_pgsize - 1));
		SDMA_DBG("%s: iovec: %d, base_virt: 0x%lx, base_phys: 0x%lx, "
				"base_pgsize: %lu\n",
				__FUNCTION__,
				i,
				usi->base_virt,
				usi->base_phys,
				usi->base_pgsize);
		req->data_len += req->iovs[i].iov.iov_len;
	}
	//trace_hfi1_sdma_user_data_length(dd, uctxt->ctxt, fd->subctxt,
	//				 info.comp_idx, req->data_len);
	if (pcount > req->info.npkts)
		pcount = req->info.npkts;
	/*
	 * Copy any TID info
	 * User space will provide the TID info only when the
	 * request type is EXPECTED. This is true even if there is
	 * only one packet in the request and the header is already
	 * setup. The reason for the singular TID case is that the
	 * driver needs to perform safety checks.
	 */
	if (req_opcode(req->info.ctrl) == EXPECTED) {
		u16 ntids = iovec[idx].iov_len / sizeof(*req->tids);

		if (!ntids || ntids > MAX_TID_PAIR_ENTRIES) {
			ret = -EINVAL;
			goto free_req;
		}
		req->tids = kmalloc_cache_alloc(
				&cpu_local_var(tids_cache),
				sizeof(*req->tids) * MAX_TID_PAIR_ENTRIES);
		if (!req->tids) {
			ret = -ENOMEM;
			goto free_req;
		}
		/*
		 * We have to copy all of the tids because they may vary
		 * in size and, therefore, the TID count might not be
		 * equal to the pkt count. However, there is no way to
		 * tell at this point.
		 */
		ret = copy_from_user(req->tids, iovec[idx].iov_base,
				     ntids * sizeof(*req->tids));
		if (ret) {
			SDMA_DBG(req, "Failed to copy %d TIDs (%d)",
				 ntids, ret);
			ret = -EFAULT;
			goto free_req;
		}
		req->n_tids = ntids;
		req->tididx = 0;
		idx++;
	}

	dlid = be16_to_cpu(req->hdr.lrh[1]);
	selector = dlid_to_selector(dlid);
	selector += uctxt->ctxt + fd->subctxt;
	req->sde = sdma_select_user_engine(dd, selector, vl);

	if (!req->sde) {
		kprintf("%s: !req->sde", __FUNCTION__);
		ret = -ECOMM;
		goto free_req;
	}

	if (!sdma_running(req->sde)) {
		kprintf("%s: !sdma_running(req->sde)", __FUNCTION__);
		ret = -ECOMM;
		goto free_req;
	}

	/* We don't need an AHG entry if the request contains only one packet */
	if (req->info.npkts > 1 && HFI1_CAP_IS_USET(SDMA_AHG)) {
		int ahg = sdma_ahg_alloc(req->sde);

		if (likely(ahg >= 0)) {
			req->ahg_idx = (u8)ahg;
		}
	}

	set_comp_state(pq, cq, info.comp_idx, QUEUED, 0);
	pq->state = SDMA_PKT_Q_ACTIVE;

	/* Send the first N packets in the request to buy us some time */
	ret = user_sdma_send_pkts(req, pcount, txreq_cache);
	if (unlikely(ret < 0 && ret != -EBUSY)) {
		goto free_req;
	}

	/*
	 * This is a somewhat blocking send implementation.
	 * The driver will block the caller until all packets of the
	 * request have been submitted to the SDMA engine. However, it
	 * will not wait for send completions.
	 */
	while (req->seqsubmitted != req->info.npkts) {
		ret = user_sdma_send_pkts(req, pcount, txreq_cache);
		if (ret < 0) {
			if (ret != -EBUSY) {
				goto free_req;
			}
			{
				unsigned long ts = rdtsc();
				while (ihk_atomic_read(&pq->n_reqs) > 0 &&
						pq->state != SDMA_PKT_Q_ACTIVE) {
					cpu_pause();
				}
				kprintf("%s: waited %lu cycles for SDMA_PKT_Q_ACTIVE\n",
						__FUNCTION__, rdtsc() - ts);
			}
		}
	}
	*count += idx;
	return 0;
free_req:
	user_sdma_free_request(req, true);
	/*
	 * If the submitted seqsubmitted == npkts, the completion routine
	 * controls the final state.  If sequbmitted < npkts, wait for any
	 * outstanding packets to finish before cleaning up.
	 */
	if (req->seqsubmitted < req->info.npkts) {
		if (req->seqsubmitted) {
			{
				unsigned long ts = rdtsc();
				while (req->seqcomp != req->seqsubmitted - 1) {
					cpu_pause();
				}
				kprintf("%s: waited %lu cycles for req->seqcomp\n",
						__FUNCTION__, rdtsc() - ts);
			}
		}
		user_sdma_free_request(req, true);
		pq_update(pq);
		set_comp_state(pq, cq, info.comp_idx, ERROR, ret);
	}
	return ret;
}

static inline u32 compute_data_length(struct user_sdma_request *req,
				      struct user_sdma_txreq *tx)
{
	/*
	 * Determine the proper size of the packet data.
	 * The size of the data of the first packet is in the header
	 * template. However, it includes the header and ICRC, which need
	 * to be subtracted.
	 * The minimum representable packet data length in a header is 4 bytes,
	 * therefore, when the data length request is less than 4 bytes, there's
	 * only one packet, and the packet data length is equal to that of the
	 * request data length.
	 * The size of the remaining packets is the minimum of the frag
	 * size (MTU) or remaining data in the request.
	 */
	u32 len;

	if (!req->seqnum) {
		if (req->data_len < sizeof(u32))
			len = req->data_len;
		else
			len = ((be16_to_cpu(req->hdr.lrh[2]) << 2) -
			       (sizeof(tx->hdr) - 4));
	} else if (req_opcode(req->info.ctrl) == EXPECTED) {
		u32 tidlen = EXP_TID_GET(req->tids[req->tididx], LEN) *
			PAGE_SIZE;
		/*
		 * Get the data length based on the remaining space in the
		 * TID pair.
		 */
		len = min(tidlen - req->tidoffset, (u32)req->info.fragsize);
		/* If we've filled up the TID pair, move to the next one. */
		if (unlikely(!len) && ++req->tididx < req->n_tids &&
		    req->tids[req->tididx]) {
			tidlen = EXP_TID_GET(req->tids[req->tididx],
					     LEN) * PAGE_SIZE;
			req->tidoffset = 0;
			len = min_t(u32, tidlen, req->info.fragsize);
		}
		/*
		 * Since the TID pairs map entire pages, make sure that we
		 * are not going to try to send more data that we have
		 * remaining.
		 */
		len = min(len, req->data_len - req->sent);
	} else {
		len = min(req->data_len - req->sent, (u32)req->info.fragsize);
	}
	return len;
}

static inline u32 pad_len(u32 len)
{
	if (len & (sizeof(u32) - 1))
		len += sizeof(u32) - (len & (sizeof(u32) - 1));
	return len;
}

static inline u32 get_lrh_len(struct hfi1_pkt_header hdr, u32 len)
{
	/* (Size of complete header - size of PBC) + 4B ICRC + data length */
	return ((sizeof(hdr) - sizeof(hdr.pbc)) + 4 + len);
}

void hfi1_kmalloc_cache_prealloc(void)
{
	/*
	 * TODO: nr_elems have been determined based on profiling
	 * HACC and UMT2013, would be interesting to do some clever
	 * dynamic releasing/expanding.
	 */
	kmalloc_cache_prealloc(&cpu_local_var(txreq_cache),
			sizeof(struct user_sdma_txreq), 2048);
	kmalloc_cache_prealloc(&cpu_local_var(tids_cache),
			sizeof(*(((struct user_sdma_request *)0)->tids)) *
				MAX_TID_PAIR_ENTRIES, 256);
	kmalloc_cache_prealloc(&cpu_local_var(tidlist_cache),
			sizeof(u32) * 2048, 128);
	kmalloc_cache_prealloc(&cpu_local_var(tid_node_cache),
			sizeof(struct tid_rb_node), 512);
}

static int user_sdma_send_pkts(struct user_sdma_request *req,
		unsigned maxpkts,
		struct kmalloc_cache_header *txreq_cache)
{
	int ret = 0;
	u32 count;
	unsigned npkts = 0;
	struct user_sdma_txreq *tx = NULL;
	struct hfi1_user_sdma_pkt_q *pq = NULL;
	struct user_sdma_iovec *iovec = NULL;

	if (!req->pq)
		return -EINVAL;

	pq = req->pq;

	/* If tx completion has reported an error, we are done. */
	if (READ_ONCE(req->has_error))
		return -EFAULT;

	/*
	 * Check if we might have sent the entire request already
	 */
	if (unlikely(req->seqnum == req->info.npkts)) {
		if (!list_empty(&req->txps))
			goto dosend;
		return ret;
	}

	if (!maxpkts || maxpkts > req->info.npkts - req->seqnum)
		maxpkts = req->info.npkts - req->seqnum;

	while (npkts < maxpkts) {
		u32 datalen = 0, queued = 0, data_sent = 0;
		u64 iov_offset = 0;

#ifdef PROFILE_ENABLE
	unsigned long prof_ts = rdtsc();
#endif

//TODO: enable test_bit
#ifdef __HFI1_ORIG__
		/*
		 * Check whether any of the completions have come back
		 * with errors. If so, we are not going to process any
		 * more packets from this request.
		 */
		if (READ_ONCE(req->has_error))
			return -EFAULT;
#endif /* __HFI1_ORIG__ */

		tx = kmalloc_cache_alloc(txreq_cache, sizeof(*tx));
		if (!tx)
			return -ENOMEM;
		tx->flags = 0;
		tx->req = req;
		tx->busycount = 0;
		INIT_LIST_HEAD(&tx->list);

		/*
		 * For the last packet set the ACK request
		 * and disable header suppression.
		 */
		if (req->seqnum == req->info.npkts - 1)
			tx->flags |= (TXREQ_FLAGS_REQ_ACK |
				      TXREQ_FLAGS_REQ_DISABLE_SH);

#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_sdma_0,
			(rdtsc() - prof_ts));
	prof_ts = rdtsc();
#endif // PROFILE_ENABLE
		/*
		 * Calculate the payload size - this is min of the fragment
		 * (MTU) size or the remaining bytes in the request but only
		 * if we have payload data.
		 */
		if (req->data_len) {
			iovec = &req->iovs[req->iov_idx];
			if (ACCESS_ONCE(iovec->offset) == iovec->iov.iov_len) {
				if (++req->iov_idx == req->data_iovs) {
					ret = -EFAULT;
					goto free_txreq;
				}
				iovec = &req->iovs[req->iov_idx];
				WARN_ON(iovec->offset);
			}

			datalen = compute_data_length(req, tx);

			/*
			 * Disable header suppression for the payload <= 8DWS.
			 * If there is an uncorrectable error in the receive
			 * data FIFO when the received payload size is less than
			 * or equal to 8DWS then the RxDmaDataFifoRdUncErr is
			 * not reported.There is set RHF.EccErr if the header
			 * is not suppressed.
			 */
			if (!datalen) {
				SDMA_DBG(req,
					 "Request has data but pkt len is 0");
				ret = -EFAULT;
				goto free_tx;
			} else if (datalen <= 32) {
				tx->flags |= TXREQ_FLAGS_REQ_DISABLE_SH;
			}
		}

#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_sdma_1,
			(rdtsc() - prof_ts));
	prof_ts = rdtsc();
#endif // PROFILE_ENABLE
		if (req->ahg_idx >= 0) {
			if (!req->seqnum) {
				TP("+ if !req->seqnum");
				u16 pbclen = le16_to_cpu(req->hdr.pbc[0]);
				u32 lrhlen = get_lrh_len(req->hdr,
							 pad_len(datalen));
				/*
				 * Copy the request header into the tx header
				 * because the HW needs a cacheline-aligned
				 * address.
				 * This copy can be optimized out if the hdr
				 * member of user_sdma_request were also
				 * cacheline aligned.
				 */
				fast_memcpy(&tx->hdr, &req->hdr, sizeof(tx->hdr));
				if (PBC2LRH(pbclen) != lrhlen) {
					pbclen = (pbclen & 0xf000) |
						LRH2PBC(lrhlen);
					tx->hdr.pbc[0] = cpu_to_le16(pbclen);
				}
				ret = check_header_template(req, &tx->hdr,
							    lrhlen, datalen);
				if (ret)
					goto free_tx;
				ret = sdma_txinit_ahg(&tx->txreq,
						      SDMA_TXREQ_F_AHG_COPY,
						      sizeof(tx->hdr) + datalen,
						      req->ahg_idx, 0, NULL, 0,
						      user_sdma_txreq_cb);
				if (ret)
					goto free_tx;
				ret = sdma_txadd_kvaddr(pq->dd, &tx->txreq,
							&tx->hdr,
							sizeof(tx->hdr));
				if (ret)
					goto free_txreq;
			} else {
				int changes;

				changes = set_txreq_header_ahg(req, tx,
							       datalen);
				if (changes < 0)
					goto free_tx;
			}
		} else {
			ret = sdma_txinit(&tx->txreq, 0, sizeof(req->hdr) +
					  datalen, user_sdma_txreq_cb);
			if (ret)
				goto free_tx;
			/*
			 * Modify the header for this packet. This only needs
			 * to be done if we are not going to use AHG. Otherwise,
			 * the HW will do it based on the changes we gave it
			 * during sdma_txinit_ahg().
			 */
			ret = set_txreq_header(req, tx, datalen);
			if (ret)
				goto free_txreq;
		}
		
#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_sdma_2,
			(rdtsc() - prof_ts));
	prof_ts = rdtsc();
#endif // PROFILE_ENABLE
		/*
		 * If the request contains any data vectors, add up to
		 * fragsize bytes to the descriptor.
		 */
		 TP("+ If the request contains any data vectors, add up to fragsize bytes to the descriptor.");
		 while (queued < datalen &&
		       (req->sent + data_sent) < req->data_len) {
			unsigned len;
			uintptr_t base;
			void *virt;

			base = (uintptr_t)iovec->iov.iov_base;
			virt = (void*)(base + iovec->offset + iov_offset);

			/*
			 * Resolve iovec->base_phys if virt is out of last page.
			 */
			if (unlikely(virt >= (iovec->base_virt + iovec->base_pgsize))) {
				pte_t *ptep;
				size_t base_pgsize;

				ptep = ihk_mc_pt_lookup_fault_pte(
						cpu_local_var(current)->vm,
						virt, 0, 0, &base_pgsize, 0);
				if (unlikely(!ptep || !pte_is_present(ptep))) {
					kprintf("%s: ERROR: no valid PTE for 0x%lx\n",
							__FUNCTION__, virt);
					return -EFAULT;
				}

				iovec->base_pgsize = (unsigned)base_pgsize;
				iovec->base_phys = pte_get_phys(ptep);
				iovec->base_virt = (void *)((unsigned long)virt &
						~((unsigned long)iovec->base_pgsize - 1));
				SDMA_DBG("%s: base_virt: 0x%lx, base_phys: 0x%lx, "
						"base_pgsize: %lu\n",
						__FUNCTION__,
						iovec->base_virt,
						iovec->base_phys,
						iovec->base_pgsize);
			}

			len = (iovec->base_virt + iovec->base_pgsize - virt) >
				 req->info.fragsize ? req->info.fragsize :
				(iovec->base_virt + iovec->base_pgsize - virt);
			len = min((datalen - queued), len);
			SDMA_DBG("%s: dl: %d, qd: %d, len: %d\n",
					__FUNCTION__, datalen, queued, len);

			ret = sdma_txadd_page(pq->dd, &tx->txreq,
					iovec->base_phys + (virt - iovec->base_virt),
					len);
			if (ret) {
				SDMA_DBG(req, "SDMA txreq add page failed %d\n",
					 ret);
				goto free_txreq;
			}
			iov_offset += len;
			queued += len;
			data_sent += len;
			if (unlikely(queued < datalen &&
					iov_offset == iovec->iov.iov_len &&
				     req->iov_idx < req->data_iovs - 1)) {
				iovec->offset += iov_offset;
				iovec = &req->iovs[++req->iov_idx];
				iov_offset = 0;
			}
		}

#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_sdma_3,
			(rdtsc() - prof_ts));
	prof_ts = rdtsc();
#endif // PROFILE_ENABLE
		TP("- If the request contains any data vectors, add up to fragsize bytes to the descriptor.");
		/*
		 * The txreq was submitted successfully so we can update
		 * the counters.
		 */
		req->koffset += datalen;
		if (req_opcode(req->info.ctrl) == EXPECTED)
			req->tidoffset += datalen;
		req->sent += data_sent;
		if (req->data_len)
			iovec->offset += iov_offset;
		list_add_tail(&tx->txreq.list, &req->txps);
		/*
		 * It is important to increment this here as it is used to
		 * generate the BTH.PSN and, therefore, can't be bulk-updated
		 * outside of the loop.
		 */
		tx->seqnum = req->seqnum++;
		npkts++;
#ifdef PROFILE_ENABLE
	profile_event_add(PROFILE_sdma_4,
			(rdtsc() - prof_ts));
	prof_ts = rdtsc();
#endif // PROFILE_ENABLE
	}
dosend:

	ret = sdma_send_txlist(req->sde,
			NULL,
			&req->txps, &count);
	req->seqsubmitted += count;
	if (req->seqsubmitted == req->info.npkts) {
		/*
		 * The txreq has already been submitted to the HW queue
		 * so we can free the AHG entry now. Corruption will not
		 * happen due to the sequential manner in which
		 * descriptors are processed.
		 */
		if (req->ahg_idx >= 0)
			sdma_ahg_free(req->sde, req->ahg_idx);
	}
	return ret;

free_txreq:
	sdma_txclean(pq->dd, &tx->txreq);
free_tx:
	kmalloc_cache_free(tx);
	return ret;
}

static int check_header_template(struct user_sdma_request *req,
				 struct hfi1_pkt_header *hdr, u32 lrhlen,
				 u32 datalen)
{
	/*
	 * Perform safety checks for any type of packet:
	 *    - transfer size is multiple of 64bytes
	 *    - packet length is multiple of 4 bytes
	 *    - packet length is not larger than MTU size
	 *
	 * These checks are only done for the first packet of the
	 * transfer since the header is "given" to us by user space.
	 * For the remainder of the packets we compute the values.
	 */
	if (req->info.fragsize % PIO_BLOCK_SIZE || lrhlen & 0x3 ||
	    lrhlen > get_lrh_len(*hdr, req->info.fragsize))
		return -EINVAL;

	if (req_opcode(req->info.ctrl) == EXPECTED) {
		/*
		 * The header is checked only on the first packet. Furthermore,
		 * we ensure that at least one TID entry is copied when the
		 * request is submitted. Therefore, we don't have to verify that
		 * tididx points to something sane.
		 */
		u32 tidval = req->tids[req->tididx],
			tidlen = EXP_TID_GET(tidval, LEN) * PAGE_SIZE,
			tididx = EXP_TID_GET(tidval, IDX),
			tidctrl = EXP_TID_GET(tidval, CTRL),
			tidoff;
		__le32 kval = hdr->kdeth.ver_tid_offset;

		tidoff = KDETH_GET(kval, OFFSET) *
			  (KDETH_GET(req->hdr.kdeth.ver_tid_offset, OM) ?
			   KDETH_OM_LARGE : KDETH_OM_SMALL);
		/*
		 * Expected receive packets have the following
		 * additional checks:
		 *     - offset is not larger than the TID size
		 *     - TIDCtrl values match between header and TID array
		 *     - TID indexes match between header and TID array
		 */
		if ((tidoff + datalen > tidlen) ||
		    KDETH_GET(kval, TIDCTRL) != tidctrl ||
		    KDETH_GET(kval, TID) != tididx)
			return -EINVAL;
	}
	return 0;
}

/*
 * Correctly set the BTH.PSN field based on type of
 * transfer - eager packets can just increment the PSN but
 * expected packets encode generation and sequence in the
 * BTH.PSN field so just incrementing will result in errors.
 */
static inline u32 set_pkt_bth_psn(__be32 bthpsn, u8 expct, u32 frags)
{
	u32 val = be32_to_cpu(bthpsn),
		mask = (HFI1_CAP_IS_KSET(EXTENDED_PSN) ? 0x7fffffffull :
			0xffffffull),
		psn = val & mask;
	if (expct)
		psn = (psn & ~HFI1_KDETH_BTH_SEQ_MASK) |
			((psn + frags) & HFI1_KDETH_BTH_SEQ_MASK);
	else
		psn = psn + frags;
	return psn & mask;
}

static int set_txreq_header(struct user_sdma_request *req,
			    struct user_sdma_txreq *tx, u32 datalen)
{
	struct hfi1_user_sdma_pkt_q *pq = req->pq;
	struct hfi1_pkt_header *hdr = &tx->hdr;
	u8 omfactor; /* KDETH.OM */
	u16 pbclen;
	int ret;
	u32 tidval = 0, lrhlen = get_lrh_len(*hdr, pad_len(datalen));

	/* Copy the header template to the request before modification */
	fast_memcpy(hdr, &req->hdr, sizeof(*hdr));

	/*
	 * Check if the PBC and LRH length are mismatched. If so
	 * adjust both in the header.
	 */
	pbclen = le16_to_cpu(hdr->pbc[0]);
	if (PBC2LRH(pbclen) != lrhlen) {
		pbclen = (pbclen & 0xf000) | LRH2PBC(lrhlen);
		hdr->pbc[0] = cpu_to_le16(pbclen);
		hdr->lrh[2] = cpu_to_be16(lrhlen >> 2);
		/*
		 * Third packet
		 * This is the first packet in the sequence that has
		 * a "static" size that can be used for the rest of
		 * the packets (besides the last one).
		 */
		if (unlikely(req->seqnum == 2)) {
			/*
			 * From this point on the lengths in both the
			 * PBC and LRH are the same until the last
			 * packet.
			 * Adjust the template so we don't have to update
			 * every packet
			 */
			req->hdr.pbc[0] = hdr->pbc[0];
			req->hdr.lrh[2] = hdr->lrh[2];
		}
	}
	/*
	 * We only have to modify the header if this is not the
	 * first packet in the request. Otherwise, we use the
	 * header given to us.
	 */
	if (unlikely(!req->seqnum)) {
		ret = check_header_template(req, hdr, lrhlen, datalen);
		if (ret)
			return ret;
		goto done;
	}

	hdr->bth[2] = cpu_to_be32(
		set_pkt_bth_psn(hdr->bth[2],
				(req_opcode(req->info.ctrl) == EXPECTED),
				req->seqnum));

	/* Set ACK request on last packet */
	if (unlikely(tx->flags & TXREQ_FLAGS_REQ_ACK))
		hdr->bth[2] |= cpu_to_be32(1UL << 31);

	/* Set the new offset */
	hdr->kdeth.swdata[6] = cpu_to_le32(req->koffset);
	/* Expected packets have to fill in the new TID information */
	if (req_opcode(req->info.ctrl) == EXPECTED) {
		tidval = req->tids[req->tididx];
		/*
		 * If the offset puts us at the end of the current TID,
		 * advance everything.
		 */
		if ((req->tidoffset) == (EXP_TID_GET(tidval, LEN) *
					 PAGE_SIZE)) {
			req->tidoffset = 0;
			/*
			 * Since we don't copy all the TIDs, all at once,
			 * we have to check again.
			 */
			if (++req->tididx > req->n_tids - 1 ||
			    !req->tids[req->tididx]) {
				return -EINVAL;
			}
			tidval = req->tids[req->tididx];
		}
		omfactor = EXP_TID_GET(tidval, LEN) * PAGE_SIZE >=
			KDETH_OM_MAX_SIZE ? KDETH_OM_LARGE_SHIFT :
			KDETH_OM_SMALL_SHIFT;
		/* Set KDETH.TIDCtrl based on value for this TID. */
		KDETH_SET(hdr->kdeth.ver_tid_offset, TIDCTRL,
			  EXP_TID_GET(tidval, CTRL));
		/* Set KDETH.TID based on value for this TID */
		KDETH_SET(hdr->kdeth.ver_tid_offset, TID,
			  EXP_TID_GET(tidval, IDX));
		/* Clear KDETH.SH when DISABLE_SH flag is set */
		if (unlikely(tx->flags & TXREQ_FLAGS_REQ_DISABLE_SH))
			KDETH_SET(hdr->kdeth.ver_tid_offset, SH, 0);
		/*
		 * Set the KDETH.OFFSET and KDETH.OM based on size of
		 * transfer.
		 */
		//trace_hfi1_sdma_user_tid_info(
		//	pq->dd, pq->ctxt, pq->subctxt, req->info.comp_idx,
		//	req->tidoffset, req->tidoffset >> omfactor,
		//	omfactor != KDETH_OM_SMALL_SHIFT);
		KDETH_SET(hdr->kdeth.ver_tid_offset, OFFSET,
			  req->tidoffset >> omfactor);
		KDETH_SET(hdr->kdeth.ver_tid_offset, OM,
			  omfactor != KDETH_OM_SMALL_SHIFT);
	}
done:
	// trace_hfi1_sdma_user_header(pq->dd, pq->ctxt, pq->subctxt,
				    // req->info.comp_idx, hdr, tidval);
	return sdma_txadd_kvaddr(pq->dd, &tx->txreq, hdr, sizeof(*hdr));
}

static int set_txreq_header_ahg(struct user_sdma_request *req,
				struct user_sdma_txreq *tx, u32 datalen)
{
	u32 ahg[AHG_KDETH_ARRAY_SIZE];
	int diff = 0;
	u8 omfactor; /* KDETH.OM */
	struct hfi1_pkt_header *hdr = &req->hdr;
	u16 pbclen = le16_to_cpu(hdr->pbc[0]);
	u32 val32, tidval = 0, lrhlen = get_lrh_len(*hdr, pad_len(datalen));

	if (PBC2LRH(pbclen) != lrhlen) {
		/* PBC.PbcLengthDWs */
		AHG_HEADER_SET(ahg, diff, 0, 0, 12,
			       cpu_to_le16(LRH2PBC(lrhlen)));
		/* LRH.PktLen (we need the full 16 bits due to byte swap) */
		AHG_HEADER_SET(ahg, diff, 3, 0, 16,
			       cpu_to_be16(lrhlen >> 2));
	}

	/*
	 * Do the common updates
	 */
	/* BTH.PSN and BTH.A */
	val32 = (be32_to_cpu(hdr->bth[2]) + req->seqnum) &
		(HFI1_CAP_IS_KSET(EXTENDED_PSN) ? 0x7fffffff : 0xffffff);
	if (unlikely(tx->flags & TXREQ_FLAGS_REQ_ACK))
		val32 |= 1UL << 31;
	AHG_HEADER_SET(ahg, diff, 6, 0, 16, cpu_to_be16(val32 >> 16));
	AHG_HEADER_SET(ahg, diff, 6, 16, 16, cpu_to_be16(val32 & 0xffff));
	/* KDETH.Offset */
	AHG_HEADER_SET(ahg, diff, 15, 0, 16,
		       cpu_to_le16(req->koffset & 0xffff));
	AHG_HEADER_SET(ahg, diff, 15, 16, 16, cpu_to_le16(req->koffset >> 16));
	if (req_opcode(req->info.ctrl) == EXPECTED) {
		__le16 val;

		tidval = req->tids[req->tididx];

		/*
		 * If the offset puts us at the end of the current TID,
		 * advance everything.
		 */
		if ((req->tidoffset) == (EXP_TID_GET(tidval, LEN) *
					 PAGE_SIZE)) {
			req->tidoffset = 0;
			/*
			 * Since we don't copy all the TIDs, all at once,
			 * we have to check again.
			 */
			if (++req->tididx > req->n_tids - 1 ||
			    !req->tids[req->tididx])
				return -EINVAL;
			tidval = req->tids[req->tididx];
		}
		omfactor = ((EXP_TID_GET(tidval, LEN) *
				  PAGE_SIZE) >=
				 KDETH_OM_MAX_SIZE) ? KDETH_OM_LARGE_SHIFT :
				 KDETH_OM_SMALL_SHIFT;
		/* KDETH.OM and KDETH.OFFSET (TID) */
		AHG_HEADER_SET(ahg, diff, 7, 0, 16,
			       ((!!(omfactor - KDETH_OM_SMALL_SHIFT)) << 15 |
				((req->tidoffset >> omfactor)
				 & 0x7fff)));
		/* KDETH.TIDCtrl, KDETH.TID, KDETH.Intr, KDETH.SH */
		val = cpu_to_le16(((EXP_TID_GET(tidval, CTRL) & 0x3) << 10) |
				   (EXP_TID_GET(tidval, IDX) & 0x3ff));

		if (unlikely(tx->flags & TXREQ_FLAGS_REQ_DISABLE_SH)) {
			val |= cpu_to_le16((KDETH_GET(hdr->kdeth.ver_tid_offset,
						      INTR) <<
					    AHG_KDETH_INTR_SHIFT));
		} else {
			val |= KDETH_GET(hdr->kdeth.ver_tid_offset, SH) ?
			       cpu_to_le16(0x1 << AHG_KDETH_SH_SHIFT) :
			       cpu_to_le16((KDETH_GET(hdr->kdeth.ver_tid_offset,
						      INTR) <<
					     AHG_KDETH_INTR_SHIFT));
		}

		AHG_HEADER_SET(ahg, diff, 7, 16, 14, val);
	}
	if (diff < 0)
		return diff;

	sdma_txinit_ahg(&tx->txreq,
			SDMA_TXREQ_F_USE_AHG,
			datalen, req->ahg_idx, diff,
			ahg, sizeof(req->hdr),
			user_sdma_txreq_cb);

	return diff;
}

/*
 * SDMA tx request completion callback. Called when the SDMA progress
 * state machine gets notification that the SDMA descriptors for this
 * tx request have been processed by the DMA engine. Called in
 * interrupt context.
 */
static void user_sdma_txreq_cb(struct sdma_txreq *txreq, int status)
{
	struct user_sdma_txreq *tx =
		container_of(txreq, struct user_sdma_txreq, txreq);
	struct user_sdma_request *req;
	struct hfi1_user_sdma_pkt_q *pq;
	struct hfi1_user_sdma_comp_q *cq;
	enum hfi1_sdma_comp_state state = COMPLETE;

	if (!tx->req)
		return;

	req = tx->req;
	pq = req->pq;
	cq = req->cq;

	if (status != SDMA_TXREQ_S_OK) {
		SDMA_DBG(req, "SDMA completion with error %d",
			 status);
		WRITE_ONCE(req->has_error, 1);
		state = ERROR;
	}

	req->seqcomp = tx->seqnum;
	kmalloc_cache_free(tx);

	/* sequence isn't complete?  We are done */
	if (req->seqcomp != req->info.npkts - 1)
		return;

	user_sdma_free_request(req, false);
	set_comp_state(pq, cq, req->info.comp_idx, state, status);
	pq_update(pq);
}

static inline void pq_update(struct hfi1_user_sdma_pkt_q *pq)
{
	if (atomic_dec_and_test(&pq->n_reqs)) {
		//TODO: pq_update wake_up
		//wake_up(&pq->wait);
	}
}

static void user_sdma_free_request(struct user_sdma_request *req, bool unpin)
{
	if (!list_empty(&req->txps)) {
		struct sdma_txreq *t, *p;

		list_for_each_entry_safe(t, p, &req->txps, list) {
			struct user_sdma_txreq *tx =
				container_of(t, struct user_sdma_txreq, txreq);
			list_del_init(&t->list);
			sdma_txclean(req->pq->dd, t);
			kmalloc_cache_free(tx);
		}
	}

	kmalloc_cache_free(req->tids);
	clear_bit(req->info.comp_idx, req->pq->req_in_use);
}
static inline void set_comp_state(struct hfi1_user_sdma_pkt_q *pq,
				  struct hfi1_user_sdma_comp_q *cq,
				  u16 idx, enum hfi1_sdma_comp_state state,
				  int ret)
{
	if (state == ERROR)
		cq->comps[idx].errcode = -ret;
	barrier();
	cq->comps[idx].status = state;
}
