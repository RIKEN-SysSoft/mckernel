/* archdeps.c COPYRIGHT FUJITSU LIMITED 2016 */
#include <linux/version.h>
#include <linux/mm_types.h>
#include <asm/vdso.h>
#include "../../../config.h"
#include "../../mcctrl.h"

#define D(fmt, ...) printk("%s(%d) " fmt, __func__, __LINE__, ##__VA_ARGS__)

#ifdef MCCTRL_KSYM_vdso_start
# if MCCTRL_KSYM_vdso_start
void *vdso_start = (void *)MCCTRL_KSYM_vdso_start;
# endif
#else
# error missing address of vdso_start.
#endif

#ifdef MCCTRL_KSYM_vdso_end
# if MCCTRL_KSYM_vdso_end
void *vdso_end = (void *)MCCTRL_KSYM_vdso_end;
# endif
#else
# error missing address of vdso_end.
#endif

#ifdef MCCTRL_KSYM_vdso_spec
# if MCCTRL_KSYM_vdso_spec
static struct vm_special_mapping (*vdso_spec)[2] = (void*)MCCTRL_KSYM_vdso_spec;
# endif
#else
# error missing address of vdso_spec.
#endif

#ifdef POSTK_DEBUG_ARCH_DEP_52
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
#endif /*POSTK_DEBUG_ARCH_DEP_52*/

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
