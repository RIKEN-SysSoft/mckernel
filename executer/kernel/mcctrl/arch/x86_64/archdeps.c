/* archdeps.c COPYRIGHT FUJITSU LIMITED 2016-2018 */
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/rwlock_types.h>
#include "../../../config.h"
#include "../../mcctrl.h"

//#define SC_DEBUG

#ifdef SC_DEBUG
#define	dprintk(...)	printk(__VA_ARGS__)
#else
#define	dprintk(...)
#endif

//#define DEBUG_PPD
#ifdef DEBUG_PPD
#define pr_ppd(msg, tid, ppd) do { \
		pr_info("%s: " msg ",tid=%d,refc=%d\n", \
			__func__, tid, atomic_read(&ppd->refcount)); \
	} while (0)
#else
#define pr_ppd(msg, tid, ppd) do { } while (0)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
static struct vdso_image *_vdso_image_64;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23)
static void *vdso_start;
static void *vdso_end;
static struct page **vdso_pages;
#endif
static void *__vvar_page;
static long *hpet_address;
static void **hv_clock;

int arch_symbols_init(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
	_vdso_image_64 = (void *) kallsyms_lookup_name("vdso_image_64");
	if (WARN_ON(!_vdso_image_64))
		return -EFAULT;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 23)
	vdso_start = (void *) kallsyms_lookup_name("vdso_start");
	if (WARN_ON(!vdso_start))
		return -EFAULT;

	vdso_end = (void *) kallsyms_lookup_name("vdso_end");
	if (WARN_ON(!vdso_end))
		return -EFAULT;

	vdso_pages = (void *) kallsyms_lookup_name("vdso_pages");
	if (WARN_ON(!vdso_pages))
		return -EFAULT;
#endif

	__vvar_page = (void *) kallsyms_lookup_name("__vvar_page");
	if (WARN_ON(!__vvar_page))
		return -EFAULT;

	hpet_address = (void *) kallsyms_lookup_name("hpet_address");
	hv_clock = (void *) kallsyms_lookup_name("hv_clock");
	return 0;
}


#ifdef POSTK_DEBUG_ARCH_DEP_52
#define VDSO_MAXPAGES 2
struct vdso {
	long busy;
	int vdso_npages;
	char vvar_is_global;
	char hpet_is_global;
	char pvti_is_global;
	char padding;
	long vdso_physlist[VDSO_MAXPAGES];
	void *vvar_virt;
	long vvar_phys;
	void *hpet_virt;
	long hpet_phys;
	void *pvti_virt;
	long pvti_phys;
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
	size = _vdso_image_64->size;
	vdso->vdso_npages = size >> PAGE_SHIFT;

	if (vdso->vdso_npages > VDSO_MAXPAGES) {
		vdso->vdso_npages = 0;
		goto out;
	}

	for (i = 0; i < vdso->vdso_npages; ++i) {
		vdso->vdso_physlist[i] = virt_to_phys(
				_vdso_image_64->data + (i * PAGE_SIZE));
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
	if (hpet_address && *hpet_address) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
		vdso->hpet_is_global = 0;
		vdso->hpet_virt = (void *)(-2 * PAGE_SIZE);
		vdso->hpet_phys = *hpet_address;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
		vdso->hpet_is_global = 0;
		vdso->hpet_virt = (void *)(-1 * PAGE_SIZE);
		vdso->hpet_phys = *hpet_address;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
		vdso->hpet_is_global = 0;
		vdso->hpet_virt = (void *)((vdso->vdso_npages + 1) * PAGE_SIZE);
		vdso->hpet_phys = *hpet_address;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
		vdso->hpet_is_global = 1;
		vdso->hpet_virt = (void *)fix_to_virt(VSYSCALL_HPET);
		vdso->hpet_phys = *hpet_address;
#endif
	}

	/* struct pvlock_vcpu_time_info table */
	if (hv_clock && *hv_clock) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,5,0)
		vdso->pvti_is_global = 0;
		vdso->pvti_virt = (void *)(-1 * PAGE_SIZE);
		vdso->pvti_phys = virt_to_phys(*hv_clock);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0)
		vdso->pvti_is_global = 1;
		vdso->pvti_virt = (void *)fix_to_virt(PVCLOCK_FIXMAP_BEGIN);
		vdso->pvti_phys = virt_to_phys(*hv_clock);
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
restore_tls(unsigned long addr)
{
	wrmsrl(MSR_FS_BASE, addr);
}

void
save_tls_ctx(void __user *ctx)
{
	struct trans_uctx __user *tctx = ctx;
	struct trans_uctx kctx;

	if (copy_from_user(&kctx, tctx, sizeof(struct trans_uctx))) {
		pr_err("%s: copy_from_user failed.\n", __func__);
		return;
	}
	rdmsrl(MSR_FS_BASE, kctx.fs);
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
	return kctx.fs;
}

unsigned long
get_rsp_ctx(void *ctx)
{
	struct trans_uctx *tctx = ctx;

	return tctx->rsp;
}

int translate_rva_to_rpa(ihk_os_t os, unsigned long rpt, unsigned long rva,
		unsigned long *rpap, unsigned long *pgsizep)
{
	unsigned long rpa;
	int offsh;
	int i;
	int ix;
	unsigned long phys;
	unsigned long *pt;
	int error;
	unsigned long pgsize;

	rpa = rpt;
	offsh = 39;
	pgsize = 0;
	/* i = 0: PML4, 1: PDPT, 2: PDT, 3: PT */
	for (i = 0; i < 4; ++i) {
		ix = (rva >> offsh) & 0x1FF;
		phys = ihk_device_map_memory(ihk_os_to_dev(os), rpa, PAGE_SIZE);
		pt = ihk_device_map_virtual(ihk_os_to_dev(os), phys, PAGE_SIZE, NULL, 0);
		dprintk("rpa %#lx offsh %d ix %#x phys %#lx pt %p pt[ix] %#lx\n",
				rpa, offsh, ix, phys, pt, pt[ix]);

#define	PTE_P	0x001
		if (!(pt[ix] & PTE_P)) {
			ihk_device_unmap_virtual(ihk_os_to_dev(os), pt, PAGE_SIZE);
			ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);
			error = -EFAULT;
			dprintk("Remote PTE is not present for 0x%lx (rpt: %lx) ?\n", rva, rpt);
			goto out;
		}

#define	PTE_PS	0x080
		if (pt[ix] & PTE_PS) {
			pgsize = 1UL << offsh;
			rpa = pt[ix] & ((1UL << 52) - 1) & ~(pgsize - 1);
			rpa |= rva & (pgsize - 1);

			/* For GB pages, just report regular 2MB page */
			if (offsh == 30) {
				pgsize = 1UL << 21;
				dprintk("%s: GB page translated 0x%lx -> 0x%lx, pgsize: %lu\n",
						__FUNCTION__, rva, rpa, pgsize);
			}

			ihk_device_unmap_virtual(ihk_os_to_dev(os), pt, PAGE_SIZE);
			ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);
			error = 0;
			goto found;
		}

		rpa = pt[ix] & ((1UL << 52) - 1) & ~((1UL << 12) - 1);
		offsh -= 9;
		ihk_device_unmap_virtual(ihk_os_to_dev(os), pt, PAGE_SIZE);
		ihk_device_unmap_memory(ihk_os_to_dev(os), phys, PAGE_SIZE);
	}
	pgsize = 1UL << 12;
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

#ifdef POSTK_DEBUG_ARCH_DEP_12
#define PFN_WRITE_COMBINED _PAGE_PWT
static inline bool pte_is_write_combined(pte_t pte)
{
	return ((pte_flags(pte) & _PAGE_PWT) && !(pte_flags(pte) & _PAGE_PCD));
}
#endif /* POSTK_DEBUG_ARCH_DEP_12 */

long mcexec_uti_save_fs(ihk_os_t os, struct uti_save_fs_desc __user *udesc,
			struct file *file)
{
	extern struct list_head host_threads;
	extern rwlock_t host_thread_lock;
	int rc = 0;
	void *usp = get_user_sp();
	struct mcos_handler_info *info;
	struct host_thread *thread;
	unsigned long flags;
	struct uti_save_fs_desc desc;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);
	struct mcctrl_per_proc_data *ppd;

	if (copy_from_user(&desc, udesc, sizeof(struct uti_save_fs_desc))) {
		pr_err("%s: Error: copy_from_user failed\n", __func__);
		rc = -EFAULT;
		goto out;
	}

	save_tls_ctx(desc.lctx);
	info = ihk_os_get_mcos_private_data(file);
	thread = kmalloc(sizeof(struct host_thread), GFP_KERNEL);
	memset(thread, '\0', sizeof(struct host_thread));
	thread->pid = task_tgid_vnr(current);
	thread->tid = task_pid_vnr(current);
	thread->usp = (unsigned long)usp;
	thread->ltls = get_tls_ctx(desc.lctx);
	thread->rtls = get_tls_ctx(desc.lctx);
	thread->handler = info;

	write_lock_irqsave(&host_thread_lock, flags);
	list_add_tail(&thread->list, &host_threads);
	write_unlock_irqrestore(&host_thread_lock, flags);

	/* How ppd refcount reaches zero depends on how utility-thread exits:
	 *  (1) MCEXEC_UP_CREATE_PPD sets to 1
	 *  (2) mcexec_util_thread2() increments to 2
	 *  (3) syscall hook detects exit/exit_group call
	 *	and decrements to 1 via mcexec_terminate_thread()
	 *  (4) mcexec calls exit_fd(), it calls release_handler(),
	 *	it decrements to 0
	 *
	 *  KNOWN ISSUE:
	 *	mcexec_terminate_thread() isn't called when mcexec is
	 *	killed by signal so the refcount remains 1 when
	 *	calling release_handler()
	 */
	ppd = mcctrl_get_per_proc_data(usrdata, task_tgid_vnr(current));
	pr_ppd("get", task_pid_vnr(current), ppd);
 out:
	return rc;
}
