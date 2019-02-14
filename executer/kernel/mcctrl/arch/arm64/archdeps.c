/* archdeps.c COPYRIGHT FUJITSU LIMITED 2016 */
#include <linux/version.h>
#include <linux/mm_types.h>
#include <linux/kallsyms.h>
#include <asm/vdso.h>
#include "../../../config.h"
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
	vdso->offset_sigtramp = vdso_offset_sigtramp;
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
	/* TODO; skeleton for UTI */
	return NULL;
}

void
set_user_sp(void *usp)
{
	/* TODO; skeleton for UTI */
}

/* TODO; skeleton for UTI */
struct trans_uctx {
	volatile int cond;
	int fregsize;

	unsigned long rax;
	unsigned long rbx;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long rbp;
	unsigned long r8;
	unsigned long r9;
	unsigned long r10;
	unsigned long r11;
	unsigned long r12;
	unsigned long r13;
	unsigned long r14;
	unsigned long r15;
	unsigned long rflags;
	unsigned long rip;
	unsigned long rsp;
	unsigned long fs;
};

void
restore_fs(unsigned long fs)
{
	/* TODO; skeleton for UTI */
}

void
save_fs_ctx(void *ctx)
{
	/* TODO; skeleton for UTI */
}

unsigned long
get_fs_ctx(void *ctx)
{
	/* TODO; skeleton for UTI */
	return 0;
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
