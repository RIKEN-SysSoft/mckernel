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
}

void mcctrl_tofu_restore_release_handlers(void)
{
	mcctrl_tof_utofu_procfs_ops_cq->release =
		mcctrl_tof_utofu_release_cq;
	mcctrl_tof_utofu_procfs_ops_bch->release =
		mcctrl_tof_utofu_release_bch;
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
		dprintk("%s: WARNING: failed to send IKC msg: %d\n",
				__func__, ret);
	}

	mcctrl_file_to_pidfd_hash_remove(filp, f2pfd->os,
			current->group_leader, f2pfd->fd);

	mcctrl_put_per_proc_data(ppd);

	/* Do not call into Linux driver if timed out in SIGKILL.. */
	if (ret == -ETIME && __fatal_signal_pending(current)) {
		pr_err("%s: WARNING: failed to send IKC msg in SIGKILL: %d\n",
				__func__, ret);
		goto out_no_release;
	}
out:
	dprintk("%s: current PID: %d, comm: %s -> calling release\n",
			__func__, task_tgid_vnr(current), current->comm);
	return __release_func(inode, filp);

out_no_release:
	return ret;
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
#endif
