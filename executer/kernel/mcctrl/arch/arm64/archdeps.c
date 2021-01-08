/* archdeps.c COPYRIGHT FUJITSU LIMITED 2016-2019 */
#include <linux/version.h>
#include <linux/mm_types.h>
#include <linux/kallsyms.h>
#include <linux/delay.h>
#if KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE
#include <linux/sched/task_stack.h>
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) */
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/mmu_notifier.h>
#include <linux/kref.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <asm/vdso.h>
#include "config.h"
#include "../../mcctrl.h"

//#define SC_DEBUG

#ifdef SC_DEBUG
#define	dprintk(...)	printk(__VA_ARGS__)
#else
#define	dprintk(...)
#endif

#define D(fmt, ...) printk("%s(%d) " fmt, __func__, __LINE__, ##__VA_ARGS__)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
void *vdso_start;
void *vdso_end;
static struct vm_special_mapping (*vdso_spec)[2];
#endif

#ifdef ENABLE_TOFU
/* Tofu CQ and barrier gate release functions */
struct file_operations *mcctrl_tof_utofu_procfs_ops_cq;
int (*mcctrl_tof_utofu_release_cq)(struct inode *inode,
		struct file *filp);
struct file_operations *mcctrl_tof_utofu_procfs_ops_bch;
int (*mcctrl_tof_utofu_release_bch)(struct inode *inode,
		struct file *filp);
int (*mcctrl_tof_core_cq_cacheflush)(int tni, int cqid);
int (*mcctrl_tof_core_disable_bch)(int tni, int bgid);
int (*mcctrl_tof_core_unset_bg)(int tni, int bgid);
typedef void (*tof_core_signal_handler)(int, int, uint64_t, uint64_t);
void (*mcctrl_tof_core_register_signal_bg)(int tni, int bgid,
			tof_core_signal_handler handler);
struct tof_utofu_bg;
struct tof_utofu_bg *mcctrl_tof_utofu_bg;


/* Tofu MMU notifier */
struct mmu_notifier_ops *mcctrl_tof_utofu_mn_ops;
struct mmu_notifier_ops __mcctrl_tof_utofu_mn_ops;
static void (*mcctrl_tof_utofu_mn_invalidate_range_end)(
	struct mmu_notifier *mn,
	struct mm_struct *mm,
	unsigned long start,
	unsigned long end);
void __mcctrl_tof_utofu_mn_invalidate_range_end(
	struct mmu_notifier *mn,
	struct mm_struct *mm,
	unsigned long start,
	unsigned long end);
#endif

int arch_symbols_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
	vdso_start = (void *) kallsyms_lookup_name("vdso_start");
	if (WARN_ON(!vdso_start))
		return -EFAULT;

	vdso_end = (void *) kallsyms_lookup_name("vdso_end");
	if (WARN_ON(!vdso_end))
		return -EFAULT;

	vdso_spec = (void *) kallsyms_lookup_name("vdso_spec");
	if (WARN_ON(!vdso_spec))
		return -EFAULT;
#endif

#ifdef ENABLE_TOFU
	mcctrl_tof_utofu_procfs_ops_cq =
		(void *)kallsyms_lookup_name("tof_utofu_procfs_ops_cq");
	if (WARN_ON(!mcctrl_tof_utofu_procfs_ops_cq))
		return -EFAULT;

	mcctrl_tof_utofu_procfs_ops_bch =
		(void *)kallsyms_lookup_name("tof_utofu_procfs_ops_bch");
	if (WARN_ON(!mcctrl_tof_utofu_procfs_ops_bch))
		return -EFAULT;

	mcctrl_tof_utofu_release_cq =
		(void *)kallsyms_lookup_name("tof_utofu_release_cq");
	if (WARN_ON(!mcctrl_tof_utofu_release_cq))
		return -EFAULT;

	mcctrl_tof_utofu_release_bch =
		(void *)kallsyms_lookup_name("tof_utofu_release_bch");
	if (WARN_ON(!mcctrl_tof_utofu_release_bch))
		return -EFAULT;
#endif

	mcctrl_tof_core_cq_cacheflush =
		(void *)kallsyms_lookup_name("tof_core_cq_cacheflush");
	if (WARN_ON(!mcctrl_tof_core_cq_cacheflush))
		return -EFAULT;

	mcctrl_tof_core_disable_bch =
		(void *)kallsyms_lookup_name("tof_core_disable_bch");
	if (WARN_ON(!mcctrl_tof_core_disable_bch))
		return -EFAULT;

	mcctrl_tof_core_unset_bg =
		(void *)kallsyms_lookup_name("tof_core_unset_bg");
	if (WARN_ON(!mcctrl_tof_core_unset_bg))
		return -EFAULT;

	mcctrl_tof_core_register_signal_bg =
		(void *)kallsyms_lookup_name("tof_core_register_signal_bg");
	if (WARN_ON(!mcctrl_tof_core_register_signal_bg))
		return -EFAULT;

	mcctrl_tof_utofu_bg =
		(void *)kallsyms_lookup_name("tof_utofu_bg");
	if (WARN_ON(!mcctrl_tof_utofu_bg))
		return -EFAULT;

	mcctrl_tof_utofu_mn_ops =
		(void *)kallsyms_lookup_name("tof_utofu_mn_ops");
	if (WARN_ON(!mcctrl_tof_utofu_mn_ops))
		return -EFAULT;
	/*
	 * Copy original content and update redirected function,
	 * CQ will be pointed to this structure after init ioctl()
	 */
	memcpy(&__mcctrl_tof_utofu_mn_ops, mcctrl_tof_utofu_mn_ops,
			sizeof(*mcctrl_tof_utofu_mn_ops));
	__mcctrl_tof_utofu_mn_ops.invalidate_range =
		__mcctrl_tof_utofu_mn_invalidate_range_end;

	mcctrl_tof_utofu_mn_invalidate_range_end =
		(void *)kallsyms_lookup_name("tof_utofu_mn_invalidate_range_end");
	if (WARN_ON(!mcctrl_tof_utofu_mn_invalidate_range_end))
		return -EFAULT;

	return 0;
}


#define VDSO_MAXPAGES 1
struct vdso {
	long busy;
	int vdso_npages;
	int padding;
	long vdso_physlist[VDSO_MAXPAGES];
	long vvar_phys;
	long lbase;
	long offset_sigtramp;
};

unsigned long
reserve_user_space_common(struct mcctrl_usrdata *usrdata, unsigned long start, unsigned long end);

int
reserve_user_space(struct mcctrl_usrdata *usrdata, unsigned long *startp, unsigned long *endp)
{
	struct vm_area_struct *vma;
	unsigned long start = 0L;
	unsigned long end;

	if (mutex_lock_killable(&usrdata->reserve_lock) < 0) {
		return -1;
	}

#define DESIRED_USER_END	TASK_UNMAPPED_BASE
	end = DESIRED_USER_END;
	down_write(&current->mm->mmap_sem);
	vma = find_vma(current->mm, 0);
	if (vma->vm_start < end) {
		printk("mcctrl:user space overlap.\n");
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	up_write(&current->mm->mmap_sem);
#endif
	start = reserve_user_space_common(usrdata, start, end);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,5,0)
	up_write(&current->mm->mmap_sem);
#endif

	mutex_unlock(&usrdata->reserve_lock);

	if (IS_ERR_VALUE(start)) {
		return start;
	}
	*startp = start;
	*endp = end;
	return 0;
}

#if KERNEL_VERSION(4, 0, 0) <= LINUX_VERSION_CODE
static long elf_search_vdso_sigtramp(void)
{
	int i = 0;
	long ans = -1;
	char *shstr = NULL, *dynstr = NULL;
	Elf64_Ehdr *eh = NULL;
	Elf64_Shdr *tmp_sh = NULL, *sym_sh = NULL;
	Elf64_Sym *sym = NULL;

	/* ELF header */
	eh = (Elf64_Ehdr *)vdso_start;
	if (eh == NULL) {
		D("vdso_start is NULL.\n");
		goto out;
	}

	/* ELF magic check */
	if (eh->e_ident[EI_MAG0] != ELFMAG0 &&
	    eh->e_ident[EI_MAG1] != ELFMAG1 &&
	    eh->e_ident[EI_MAG2] != ELFMAG2 &&
	    eh->e_ident[EI_MAG3] != ELFMAG3) {
		D("vdso_start ELF MAGIC Mismatch.\n"
		  "e_ident[EI_MAG0 - EI_MAG3]: %02x %02x %02x %02x\n",
		  eh->e_ident[EI_MAG0], eh->e_ident[EI_MAG1],
		  eh->e_ident[EI_MAG2], eh->e_ident[EI_MAG3]);
		goto out;
	}

	/* Search dynsym-table and dynstr-table offset
	 * from section header table
	 */
	tmp_sh = (Elf64_Shdr *)(vdso_start + eh->e_shoff);
	shstr = vdso_start + (tmp_sh + eh->e_shstrndx)->sh_offset;
	for (i = 0; i < eh->e_shnum; i++, tmp_sh++) {
		if (tmp_sh->sh_type == SHT_DYNSYM) {
			sym_sh = tmp_sh;
		}

		if (tmp_sh->sh_type == SHT_STRTAB &&
		    !strcmp(&shstr[tmp_sh->sh_name], ".dynstr")) {
			dynstr = vdso_start + tmp_sh->sh_offset;
		}
	}

	if (sym_sh == NULL) {
		D("dynsym-table not found.\n");
		goto out;
	}

	if (dynstr == 0) {
		D("dynstr-table not found.\n");
		goto out;
	}

	/* Search __kernel_rt_sigreturn offset from dynsym-table */
	sym = (Elf64_Sym *)(vdso_start + sym_sh->sh_offset);
	for (i = 0; (i * sym_sh->sh_entsize) < sym_sh->sh_size; i++, sym++) {
		if (!strcmp(dynstr + sym->st_name, "__kernel_rt_sigreturn")) {
			ans = sym->st_value;
		}
	}

out:
	return ans;
}
#endif /*LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)*/

void get_vdso_info(ihk_os_t os, long vdso_rpa)
{
	ihk_device_t dev = ihk_os_to_dev(os);
	struct vm_special_mapping* vvar_map;
	struct vm_special_mapping* vdso_map;
	int nr_vdso_page;
	long vdso_pa;
	struct vdso *vdso;

	vdso_pa = ihk_device_map_memory(dev, vdso_rpa, sizeof(*vdso));
	vdso = ihk_device_map_virtual(dev, vdso_pa, sizeof(*vdso), NULL, 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	vvar_map = &(*vdso_spec)[0];
	vdso_map = &(*vdso_spec)[1];
	nr_vdso_page = ((vdso_end - vdso_start) + PAGE_SIZE - 1) >> PAGE_SHIFT;

	/* VDSO pages */
	//D("nr_vdso_page:%d\n", nr_vdso_page);
	vdso->vdso_npages = 1; //vdso page is supposed to be one
	if (vdso->vdso_npages != nr_vdso_page) {
		vdso->vdso_npages = 0;
		goto out;
	}
	//D("vdso->vdso_physlist[0]:0x#lx\n", vdso->vdso_physlist[0]);
	vdso->vdso_physlist[0] = page_to_phys(*vdso_map->pages);

	/* VVAR page */
	//D("vdso->vvar_phys:0x#lx\n", vdso->vvar_phys);
	vdso->vvar_phys = page_to_phys(*vvar_map->pages);

	/* offsets */
	vdso->lbase = VDSO_LBASE;
	vdso->offset_sigtramp = elf_search_vdso_sigtramp();

	if (unlikely(vdso->offset_sigtramp == -1)) {
		D("Use vdso_offset_sigtramp in header-file.\n");
		vdso->offset_sigtramp = vdso_offset_sigtramp;
	}
#endif /*LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)*/
out:
	wmb();
	vdso->busy = 0;

	ihk_device_unmap_virtual(dev, vdso, sizeof(*vdso));
	ihk_device_unmap_memory(dev, vdso_pa, sizeof(*vdso));
	return;
} /* get_vdso_info() */

void *
get_user_sp(void)
{
	return (void *)current_pt_regs()->sp;
}

void
set_user_sp(void *usp)
{
	current_pt_regs()->sp = (unsigned long)usp;
}

struct trans_uctx {
	volatile int cond;
	int fregsize;
	struct user_pt_regs regs;
	unsigned long tls_baseaddr;
};

void
restore_tls(unsigned long addr)
{
	const unsigned long tpidrro = 0;

	asm volatile(
	"	msr	tpidr_el0, %0\n"
	"	msr	tpidrro_el0, %1"
	: : "r" (addr), "r" (tpidrro));
}

void
save_tls_ctx(void __user *ctx)
{
	struct trans_uctx __user *tctx = ctx;
	unsigned long baseaddr;

	asm volatile(
	"	mrs	%0, tpidr_el0"
	: "=r" (baseaddr));

	if (copy_to_user(&tctx->tls_baseaddr, &baseaddr,
			 sizeof(tctx->tls_baseaddr))) {
		pr_err("%s: copy_to_user failed.\n", __func__);
		return;
	}
}

unsigned long
get_tls_ctx(void __user *ctx)
{
	struct trans_uctx __user *tctx = ctx;
	struct trans_uctx kctx;

	if (copy_from_user(&kctx, tctx, sizeof(struct trans_uctx))) {
		pr_err("%s: copy_from_user failed.\n", __func__);
		return 0;
	}
	return kctx.tls_baseaddr;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
# define IHK_MC_PGTABLE_LEVELS CONFIG_ARM64_PGTABLE_LEVELS
#else
# define IHK_MC_PGTABLE_LEVELS CONFIG_PGTABLE_LEVELS
#endif

typedef unsigned long translation_table_t;
struct page_table {
	translation_table_t* tt;
	translation_table_t* tt_pa;
	int asid;
};

int translate_rva_to_rpa(ihk_os_t os, unsigned long rpt, unsigned long rva,
		unsigned long *rpap, unsigned long *pgsizep)
{
	unsigned long rpa;
	int i;
	int ix;
	unsigned long phys;
	unsigned long *pt;
	int error;
	unsigned long pgsize;
	struct page_table* tbl;

	struct property {
		int idx_bits;
		int block;    /*block support flag*/
		int pgshift;
	} properties[3][4] = {
		{	/* 4KB */
			{.idx_bits = 47 - 39 + 1, .block = 0, .pgshift = 39},  /*zero*/
			{.idx_bits = 38 - 30 + 1, .block = 1, .pgshift = 30},  /*first*/
			{.idx_bits = 29 - 21 + 1, .block = 1, .pgshift = 21},  /*second*/
			{.idx_bits = 20 - 12 + 1, .block = 0, .pgshift = 12},  /*third*/
		},
		{	/* 16KB */
			{.idx_bits = 47 - 47 + 1, .block = 0, .pgshift = 47},  /*zero*/
			{.idx_bits = 46 - 36 + 1, .block = 0, .pgshift = 36},  /*first*/
			{.idx_bits = 35 - 25 + 1, .block = 1, .pgshift = 25},  /*second*/
			{.idx_bits = 24 - 14 + 1, .block = 0, .pgshift = 14},  /*third*/
		},
		{	/* 64KB */
			{0},  /*zero*/
			{.idx_bits = 47 - 42 + 1, .block = 0, .pgshift = 42},  /*first*/
			{.idx_bits = 41 - 29 + 1, .block = 1, .pgshift = 29},  /*second*/
			{.idx_bits = 28 - 16 + 1, .block = 0, .pgshift = 16},  /*third*/
		},
	};
	const struct property* prop =
		(PAGE_SIZE == (1UL << 12)) ? &(properties[0][0]) :
		(PAGE_SIZE == (1UL << 14)) ? &(properties[1][0]) :
		(PAGE_SIZE == (1UL << 16)) ? &(properties[2][0]) : NULL;

	// page table to translation_table.
	phys = ihk_device_map_memory(ihk_os_to_dev(os), rpt, PAGE_SIZE);
#ifdef ENABLE_FUGAKU_HACKS
	if (!phys) {
		pr_err("%s(): ERROR: VA: 0x%lx, rpt is NULL for PID %d\n",
			__func__, rva, task_tgid_vnr(current));
		error = -EFAULT;
		goto out;
	}
#endif

	tbl = ihk_device_map_virtual(ihk_os_to_dev(os), phys, PAGE_SIZE, NULL, 0);
	rpa = (unsigned long)tbl->tt_pa;

	/* i = 0:zero, 1:first, 2:second, 3:third */
	for (i = 4 - IHK_MC_PGTABLE_LEVELS; i < 4; ++i) {
		ix = (rva >> prop[i].pgshift) & ((1 << prop[i].idx_bits) - 1);
		phys = ihk_device_map_memory(ihk_os_to_dev(os), rpa, PAGE_SIZE);
		pt = ihk_device_map_virtual(ihk_os_to_dev(os), phys, PAGE_SIZE, NULL, 0);
		dprintk("rpa %#lx offsh %d ix %#x phys %#lx pt %p pt[ix] %#lx\n",
				rpa, prop[i].pgshift, ix, phys, pt, pt[ix]);

#define	PG_DESC_VALID	0x1
		if (!(pt[ix] & PG_DESC_VALID)) {
			ihk_device_unmap_virtual(ihk_os_to_dev(os), pt, PAGE_SIZE);
			ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);
			error = -EFAULT;
			dprintk("Remote PTE is not present for 0x%lx (rpt: %lx) ?\n", rva, rpt);
			goto out;
		}

#define	PG_DESC_TYEP_MASK	0x3
#define	PG_DESC_BLOCK		0x1
		if (prop[i].block && (pt[ix]&PG_DESC_TYEP_MASK) == PG_DESC_BLOCK) {
			/* D_Block */
			pgsize = 1UL << prop[i].pgshift;
			rpa = (pt[ix] & ((1UL << 47) - 1)) & ~(pgsize - 1);
			rpa |= rva & (pgsize - 1);
			ihk_device_unmap_virtual(ihk_os_to_dev(os), pt, PAGE_SIZE);
			ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);
			error = 0;
			goto found;
		}
		/* D_Table */
		rpa = (pt[ix] & ((1UL << 47) - 1)) & ~(PAGE_SIZE - 1);
		ihk_device_unmap_virtual(ihk_os_to_dev(os), pt, PAGE_SIZE);
		ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);
	}
	/* D_Page */
	pgsize = PAGE_SIZE;
	rpa |= rva & (pgsize - 1);

found:
	error = 0;
	*rpap = rpa;
	*pgsizep = pgsize;

out:
	dprintk("translate_rva_to_rpa: %d rva %#lx --> rpa %#lx (%lx)\n",
			error, rva, rpa, pgsize);
	return error;
}

/*
 * Assembler switch_ctx executes only ioctl.
 * Context register save/load is done on Linux (get from current_pt_regs).
 * Do TLS save/load and register host_thread with ioctl.
 */
long arch_switch_ctx(struct uti_switch_ctx_desc *desc)
{
	int rc = 0;
	struct trans_uctx *__user rctx = NULL;
	struct trans_uctx *__user lctx = NULL;
	struct trans_uctx klctx = {
		.regs = current_pt_regs()->user_regs,
	};

	rctx = desc->rctx;
	lctx = desc->lctx;

	if (copy_to_user(lctx, &klctx, sizeof(klctx))) {
		pr_err("%s: Error: copy_to_user failed\n", __func__);
		rc = -EFAULT;
		goto out;
	}

	if (copy_from_user(&current_pt_regs()->user_regs,
			   &rctx->regs, sizeof(rctx->regs))) {
		pr_err("%s: Error: copy_from_user failed\n", __func__);
		rc = -EFAULT;
		goto out;
	}
	restore_tls(get_tls_ctx(rctx));

out:
	return rc;
}


#ifdef ENABLE_TOFU
/*
 * Tofu CQ and BCH release handlers
 */
int __mcctrl_tof_utofu_release_cq(struct inode *inode, struct file *filp);
int __mcctrl_tof_utofu_release_bch(struct inode *inode, struct file *filp);

void mcctrl_tofu_hijack_release_handlers(void)
{
	mcctrl_tof_utofu_procfs_ops_cq->release =
		__mcctrl_tof_utofu_release_cq;
	mcctrl_tof_utofu_procfs_ops_bch->release =
		__mcctrl_tof_utofu_release_bch;
	wmb();
}

void mcctrl_tofu_restore_release_handlers(void)
{
	mcctrl_tof_utofu_procfs_ops_cq->release =
		mcctrl_tof_utofu_release_cq;
	mcctrl_tof_utofu_procfs_ops_bch->release =
		mcctrl_tof_utofu_release_bch;
	wmb();
}

/*
 * Tofu cleanup functions
 */
#include <tofu/tof_uapi.h>
#include <tofu/tof_icc.h>
#include <tofu/tofu_generated-tof_core_cq.h>
#include <tofu/tofu_generated-tof_utofu_device.h>
#include <tofu/tofu_generated-tof_utofu_cq.h>
#include <tofu/tofu_generated-tof_utofu_mbpt.h>
#include <tofu/tofu_generated-tof_utofu_bg.h>

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

struct tof_utofu_trans_list {
	int16_t prev;
	int16_t next;
	uint8_t pgszbits;
	struct tof_utofu_mbpt *mbpt;
};


/*
 * Bit 30 marks a kref as McKernel internal.
 * This can be used to distinguish krefs from Linux and
 * it also ensures that a non deallocated kref will not
 * crash the Linux allocator.
 */
#define MCKERNEL_KREF_MARK	(1U << 30)
static inline unsigned int mcctrl_kref_is_mckernel(const struct kref *kref)
{
	return (refcount_read(&kref->refcount) & (MCKERNEL_KREF_MARK));
}

/**
 * kref_put - decrement refcount for object.
 * @kref: object.
 * @release: pointer to the function that will clean up the object when the
 *	     last reference to the object is released.
 *	     This pointer is required, and it is not acceptable to pass kfree
 *	     in as this function.  If the caller does pass kfree to this
 *	     function, you will be publicly mocked mercilessly by the kref
 *	     maintainer, and anyone else who happens to notice it.  You have
 *	     been warned.
 *
 * Decrement the refcount, and if 0, call release().
 * Return 1 if the object was removed, otherwise return 0.  Beware, if this
 * function returns 0, you still can not count on the kref from remaining in
 * memory.  Only use the return value if you want to see if the kref is now
 * gone, not present.
 */
static inline int mcctrl_kref_put(struct kref *kref, void (*release)(struct kref *kref))
{
	if (atomic_dec_return(&kref->refcount.refs) == MCKERNEL_KREF_MARK) {
		release(kref);
		return 1;
	}
	return 0;
}

static int tof_utofu_cq_cacheflush(struct tof_utofu_cq *ucq){
	return mcctrl_tof_core_cq_cacheflush(ucq->tni, ucq->cqid);
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

static void tof_utofu_trans_disable(struct tof_utofu_cq *ucq, int stag){
	struct tof_trans_table *table = ucq->trans.table;
	atomic64_set((atomic64_t *)&table[stag], 0);
	tof_utofu_trans_mru_delete(ucq, stag);
}

/* McKernel scatterlist is simply a contiguous buffer. */
struct scatterlist {
	void *pages;
	unsigned int	offset;
	unsigned int	length;
	unsigned long	dma_address;
	unsigned int	dma_length;
};

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

static void tof_utofu_free_mbpt(struct tof_utofu_cq *ucq, struct tof_utofu_mbpt *mbpt){
	int i;

	for(i = 0; i < mbpt->nsgents * PAGE_SIZE / sizeof(struct tof_icc_mbpt_entry); i++){
		uintptr_t iova;
		iova = tof_utofu_disable_mbpt(mbpt, i);
#if 0
		/*
		 * NOTE: Not performed for McKernel managed stags.
		 */
		if(iova){
			tof_smmu_release_ipa_cq(ucq->tni, ucq->cqid, iova, mbpt->pgsz);
		}
#endif
	}

#if 0
	/*
	 * NOTE: Everyhing below has been allocated in McKernel, do nothing here!!
	 * This leaks memory in McKernel, but it doesn't crash Linux.
	 * Memory will be released once McKernel is unbooted.
	 */
	tof_smmu_iova_unmap_sg(ucq->tni, ucq->cqid, mbpt->sg, mbpt->nsgents);

	for(i = 0; i < mbpt->nsgents; i++){
		tof_util_free_pages((unsigned long)sg_virt(&mbpt->sg[i]), 0);
	}
	tof_util_free(mbpt->sg);
	tof_util_free(mbpt);
#endif
}

static void tof_utofu_mbpt_release(struct kref *kref)
{
	struct tof_utofu_mbpt *mbpt = container_of(kref, struct tof_utofu_mbpt, kref);
	//atomic64_inc((atomic64_t *)&kref_free_count);
	tof_utofu_free_mbpt(mbpt->ucq, mbpt);
}

static int tof_utofu_free_stag(struct tof_utofu_cq *ucq, int stag){
	if(stag < 0 || stag >= TOF_UTOFU_NUM_STAG(ucq->num_stag) ||
	   ucq->steering == NULL){
		return -EINVAL;
	}
	if(!(ucq->steering[stag].enable)){
		return -ENOENT;
	}
	if (!mcctrl_kref_is_mckernel(&ucq->trans.mru[stag].mbpt->kref)) {
		printk("%s: stag: %d is not an McKernel kref\n", __func__, stag);
		return -EINVAL;
	}
	ucq->steering[stag].enable = 0;
	ucq->mb[stag].enable = 0;
	tof_utofu_trans_disable(ucq, stag);
	dma_wmb();
	tof_utofu_cq_cacheflush(ucq);
	mcctrl_kref_put(&ucq->trans.mru[stag].mbpt->kref, tof_utofu_mbpt_release);
	ucq->trans.mru[stag].mbpt = NULL;
	dprintk("%s: TNI: %d, CQ: %d: stag %d deallocated\n",
			__func__, ucq->tni, ucq->cqid, stag);
	return 0;
}

void mcctrl_mckernel_tof_utofu_release_cq(void *pde_data)
{
	struct tof_utofu_cq *ucq;
	struct tof_utofu_device *dev;
	unsigned long irqflags;
	int stag;

	dev = (struct tof_utofu_device *)pde_data;
	ucq = container_of(dev, struct tof_utofu_cq, common);

	if (!ucq->common.enabled) {
		return;
	}

	dprintk("%s: UCQ (PDE: 0x%lx) TNI %d CQ %d\n",
		__func__, (unsigned long)pde_data, ucq->tni, ucq->cqid);

	/*
	 * Only release stags here, actual cleanup is still performed
	 * in the Tofu driver
	 */
	for (stag = 0; stag < TOF_UTOFU_NUM_STAG(ucq->num_stag); stag++) {
		spin_lock_irqsave(&ucq->trans.mru_lock, irqflags);
		tof_utofu_free_stag(ucq, stag);
		spin_unlock_irqrestore(&ucq->trans.mru_lock, irqflags);
	}
}

static inline void tof_core_unregister_signal_bg(int tni, int bgid)
{
	return mcctrl_tof_core_register_signal_bg(tni, bgid, NULL);
}

static struct tof_utofu_bg *tof_utofu_bg_get(int tni, int bgid){
	if((unsigned int)tni >= TOF_ICC_NTNIS ||
	   (unsigned int)bgid >= TOF_ICC_NBGS){
		return NULL;
	}
	//return &tof_utofu_bg[tni][bgid];

	// Convert [][] notion into pointer aritmethic
	return mcctrl_tof_utofu_bg + (tni * TOF_ICC_NBGS) + bgid;
}

static int __tof_utofu_unset_bg(struct tof_utofu_bg *ubg){
	if(ubg->common.enabled){
		mcctrl_tof_core_unset_bg(ubg->tni, ubg->bgid);
		ubg->common.enabled = false;
		tof_core_unregister_signal_bg(ubg->tni, ubg->bgid);
	}
	return 0;
}

static int mcctrl_tof_utofu_disable_bch(struct tof_utofu_bg *ubg){
	int ret;
	int tni, bgid;

	if(!ubg->bch.enabled){
		return -EPERM;
	}

	ret = mcctrl_tof_core_disable_bch(ubg->tni, ubg->bgid);
	if(ret < 0){
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

	/* Not performed in McKernel handler */
	//tof_smmu_release_ipa_bg(ubg->tni, ubg->bgid, ubg->bch.iova, TOF_ICC_BCH_DMA_ALIGN);
	//put_page(ubg->bch.page);
	ubg->bch.enabled = false;
	smp_mb();
	dprintk("%s: tni=%d bgid=%d\n", __func__, ubg->tni, ubg->bgid);
	return 0;
}

void mcctrl_mckernel_tof_utofu_release_bch(void *pde_data)
{
	struct tof_utofu_bg *ubg;
	struct tof_utofu_device *dev = (struct tof_utofu_device *)pde_data;

	ubg = container_of(dev, struct tof_utofu_bg, common);
	//tof_log_if("tni=%d bgid=%d\n", ubg->tni, ubg->bgid);
	dprintk("%s: tni=%d bgid=%d\n", __func__, ubg->tni, ubg->bgid);
	mcctrl_tof_utofu_disable_bch(ubg);
}

void mcctrl_tofu_cleanup_file(struct mcctrl_file_to_pidfd *f2pfd)
{
	/* Figure out whether CQ or BCH */
	if (strstr(f2pfd->tofu_dev_path, "cq")) {
		dprintk("%s: PID: %d, fd: %d (%s) -> release CQ\n",
			__func__, f2pfd->pid, f2pfd->fd, f2pfd->tofu_dev_path);
		mcctrl_mckernel_tof_utofu_release_cq(f2pfd->pde_data);
	}

	else if (strstr(f2pfd->tofu_dev_path, "bch")) {
		dprintk("%s: PID: %d, fd: %d (%s) -> release BCH\n",
			__func__, f2pfd->pid, f2pfd->fd, f2pfd->tofu_dev_path);
		mcctrl_mckernel_tof_utofu_release_bch(f2pfd->pde_data);
	}
}


int __mcctrl_tof_utofu_release_handler(struct inode *inode, struct file *filp,
		int (*__release_func)(struct inode *inode, struct file *filp))
{
	struct mcctrl_usrdata *usrdata;
	struct mcctrl_file_to_pidfd *f2pfd;
	struct mcctrl_per_proc_data *ppd;
	struct ikc_scd_packet isp;
	int ret;

	dprintk("%s: current PID: %d, comm: %s \n",
			__func__, task_tgid_vnr(current), current->comm);

	f2pfd = mcctrl_file_to_pidfd_hash_lookup(filp, current->group_leader);
	if (!f2pfd) {
		goto out;
	}

	dprintk("%s: current PID: %d, PID: %d, fd: %d ...\n",
			__func__, task_tgid_vnr(current), f2pfd->pid, f2pfd->fd);
	usrdata = ihk_host_os_get_usrdata(f2pfd->os);

	/* Look up per-process structure */
	ppd = mcctrl_get_per_proc_data(usrdata, f2pfd->pid);
	if (!ppd) {
		pr_err("%s: PID: %d, fd: %d no PPD\n",
				__func__, f2pfd->pid, f2pfd->fd);
		goto out;
	}

	dprintk("%s: PID: %d, fd: %d PPD OK\n",
			__func__, f2pfd->pid, f2pfd->fd);

	/*
	 * We are in release() due to the process being killed,
	 * or because the application didn't close the file properly.
	 * Ask McKernel to clean up this fd.
	 */
	isp.msg = SCD_MSG_CLEANUP_FD;
	isp.pid = f2pfd->pid;
	isp.arg = f2pfd->fd;

	ret = mcctrl_ikc_send_wait(f2pfd->os, ppd->ikc_target_cpu,
			&isp, -20, NULL, NULL, 0);
	if (ret != 0) {
		pr_err("%s: WARNING: IKC req for PID: %d, fd: %d failed\n",
				__func__, f2pfd->pid, f2pfd->fd);
	}

	/* Disable any remaining STAGs/BCH in mcctrl anyway */
	mcctrl_tofu_cleanup_file(f2pfd);

	mcctrl_file_to_pidfd_hash_remove(filp, f2pfd->os,
			current->group_leader, f2pfd->fd);

	mcctrl_put_per_proc_data(ppd);

out:
	dprintk("%s: current PID: %d, comm: %s -> calling release\n",
			__func__, task_tgid_vnr(current), current->comm);
	return __release_func(inode, filp);
}

int __mcctrl_tof_utofu_release_cq(struct inode *inode, struct file *filp)
{
	return __mcctrl_tof_utofu_release_handler(inode, filp,
			mcctrl_tof_utofu_release_cq);
}

int __mcctrl_tof_utofu_release_bch(struct inode *inode, struct file *filp)
{
	return __mcctrl_tof_utofu_release_handler(inode, filp,
			mcctrl_tof_utofu_release_bch);
}

/*
 * Tofu MMU notifier functions
 */
void __mcctrl_tof_utofu_mn_invalidate_range_end(
	struct mmu_notifier *mn,
	struct mm_struct *mm,
	unsigned long start,
	unsigned long end)
{
	char tmpname[TASK_COMM_LEN];

	/* Not an offloaded syscall? */
	if (current->mm != mm) {
		goto out_call_real;
	}

	/* Not mcexec? Just in case.. */
	get_task_comm(tmpname, current);
	if (strncmp(tmpname, "mcexec", TASK_COMM_LEN)) {
		goto out_call_real;
	}

	/* This is only called for Tofu enabled mcexec processes */
	dprintk("%s: skipping tof_utofu_mn_invalidate_range_end() "
			"for mcexec PID %d\n",
			__func__, task_tgid_vnr(current));
	return;

out_call_real:
	return mcctrl_tof_utofu_mn_invalidate_range_end(mn, mm, start, end);
}

int __mcctrl_tof_utofu_ioctl_init_cq(struct tof_utofu_device *dev,
		unsigned long arg) {
	struct tof_utofu_cq *ucq;

	ucq = container_of(dev, struct tof_utofu_cq, common);
	if (!ucq->common.enabled) {
		return -EINVAL;
	}

	dprintk("%s: Tofu TNI %d CQ %d (PDE: 0x%lx) MMU notifier to be hijacked\n",
		__func__, ucq->tni, ucq->cqid, (unsigned long)dev);
	/* Override the MMU notifier */
	ucq->mn.ops = &__mcctrl_tof_utofu_mn_ops;

	return 0;
}

long __mcctrl_tof_utofu_unlocked_ioctl_cq(void *pde_data, unsigned int cmd,
					unsigned long arg) {
	struct tof_utofu_device *dev = (struct tof_utofu_device *)pde_data;
	int ret;

	switch (cmd) {
		/* We only care about init, where we hijack the MMU notifier */
		case TOF_IOCTL_INIT_CQ:
			ret = __mcctrl_tof_utofu_ioctl_init_cq(dev, arg);
			break;
		default:
			ret = 0;
	}

	return ret;
}
#endif
