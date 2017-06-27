#include <linux/version.h>
#include "../../../config.h"
#include "../../mcctrl.h"

#ifdef MCCTRL_KSYM_vdso_image_64
#if MCCTRL_KSYM_vdso_image_64
struct vdso_image *vdso_image = (void *)MCCTRL_KSYM_vdso_image_64;
#endif
#endif

#ifdef MCCTRL_KSYM_vdso_start
#if MCCTRL_KSYM_vdso_start
void *vdso_start = (void *)MCCTRL_KSYM_vdso_start;
#endif
#endif

#ifdef MCCTRL_KSYM_vdso_end
#if MCCTRL_KSYM_vdso_end
void *vdso_end = (void *)MCCTRL_KSYM_vdso_end;
#endif
#endif

#ifdef MCCTRL_KSYM_vdso_pages
#if MCCTRL_KSYM_vdso_pages
struct page **vdso_pages = (void *)MCCTRL_KSYM_vdso_pages;
#endif
#endif

#ifdef MCCTRL_KSYM___vvar_page
#if MCCTRL_KSYM___vvar_page
void *__vvar_page = (void *)MCCTRL_KSYM___vvar_page;
#endif
#endif

long *hpet_addressp
#ifdef MCCTRL_KSYM_hpet_address
#if MCCTRL_KSYM_hpet_address
	= (void *)MCCTRL_KSYM_hpet_address;
#else
	= &hpet_address;
#endif
#else
	= NULL;
#endif

void **hv_clockp
#ifdef MCCTRL_KSYM_hv_clock
#if MCCTRL_KSYM_hv_clock
	= (void *)MCCTRL_KSYM_hv_clock;
#else
	= &hv_clock;
#endif
#else
	= NULL;
#endif

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

#define	DESIRED_USER_END	0x800000000000
#define	GAP_FOR_MCEXEC		0x008000000000UL
	end = DESIRED_USER_END;
	down_write(&current->mm->mmap_sem);
	vma = find_vma(current->mm, 0);
	if (vma) {
		end = (vma->vm_start - GAP_FOR_MCEXEC) & ~(GAP_FOR_MCEXEC - 1);
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
	long vdso_pa;
	struct vdso *vdso;
	size_t size;
	int i;

	vdso_pa = ihk_device_map_memory(dev, vdso_rpa, sizeof(*vdso));
	vdso = ihk_device_map_virtual(dev, vdso_pa, sizeof(*vdso), NULL, 0);

	/* VDSO pages */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
	size = vdso_image->size;
	vdso->vdso_npages = size >> PAGE_SHIFT;

	if (vdso->vdso_npages > VDSO_MAXPAGES) {
		vdso->vdso_npages = 0;
		goto out;
	}

	for (i = 0; i < vdso->vdso_npages; ++i) {
		vdso->vdso_physlist[i] = virt_to_phys(
				vdso_image->data + (i * PAGE_SIZE));
	}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
	size = vdso_end - vdso_start;
	size = (size + PAGE_SIZE - 1) & PAGE_MASK;

	vdso->vdso_npages = size >> PAGE_SHIFT;
	if (vdso->vdso_npages > VDSO_MAXPAGES) {
		vdso->vdso_npages = 0;
		goto out;
	}

	for (i = 0; i < vdso->vdso_npages; ++i) {
		vdso->vdso_physlist[i] = page_to_phys(vdso_pages[i]);
	}
#endif

	/* VVAR page */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
	vdso->vvar_is_global = 0;
	vdso->vvar_virt = (void *)(-3 * PAGE_SIZE);
	vdso->vvar_phys = virt_to_phys(__vvar_page);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
	vdso->vvar_is_global = 0;
	vdso->vvar_virt = (void *)(-2 * PAGE_SIZE);
	vdso->vvar_phys = virt_to_phys(__vvar_page);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
	vdso->vvar_is_global = 0;
	vdso->vvar_virt = (void *)(vdso->vdso_npages * PAGE_SIZE);
	vdso->vvar_phys = virt_to_phys(__vvar_page);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
	vdso->vvar_is_global = 1;
	vdso->vvar_virt = (void *)fix_to_virt(VVAR_PAGE);
	vdso->vvar_phys = virt_to_phys(__vvar_page);
#endif

	/* HPET page */
	if (hpet_addressp && *hpet_addressp) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
		vdso->hpet_is_global = 0;
		vdso->hpet_virt = (void *)(-2 * PAGE_SIZE);
		vdso->hpet_phys = *hpet_addressp;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
		vdso->hpet_is_global = 0;
		vdso->hpet_virt = (void *)(-1 * PAGE_SIZE);
		vdso->hpet_phys = *hpet_addressp;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
		vdso->hpet_is_global = 0;
		vdso->hpet_virt = (void *)((vdso->vdso_npages + 1) * PAGE_SIZE);
		vdso->hpet_phys = *hpet_addressp;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
		vdso->hpet_is_global = 1;
		vdso->hpet_virt = (void *)fix_to_virt(VSYSCALL_HPET);
		vdso->hpet_phys = *hpet_addressp;
#endif
	}

	/* struct pvlock_vcpu_time_info table */
	if (hv_clockp && *hv_clockp) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
		vdso->pvti_is_global = 0;
		vdso->pvti_virt = (void *)(-1 * PAGE_SIZE);
		vdso->pvti_phys = virt_to_phys(*hv_clockp);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
		vdso->pvti_is_global = 1;
		vdso->pvti_virt = (void *)fix_to_virt(PVCLOCK_FIXMAP_BEGIN);
		vdso->pvti_phys = virt_to_phys(*hv_clockp);
#endif
	}

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
	unsigned long usp;

	asm volatile("movq %%gs:0xaf80, %0" : "=r" (usp));
	return (void *)usp;
}

void
set_user_sp(void *usp)
{
	asm volatile("movq %0, %%gs:0xaf80" :: "r" (usp));
}

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
	wrmsrl(MSR_FS_BASE, fs);
}

void
save_fs_ctx(void *ctx)
{
	struct trans_uctx *tctx = ctx;

	rdmsrl(MSR_FS_BASE, tctx->fs);
}

unsigned long
get_fs_ctx(void *ctx)
{
	struct trans_uctx *tctx = ctx;

	return tctx->fs;
}
