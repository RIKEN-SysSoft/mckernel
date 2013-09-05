#include <linux/sched.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/anon_inodes.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <asm/uaccess.h>
#include <asm/delay.h>
#include <asm/io.h>
#include "mcctrl.h"

#define ALIGN_WAIT_BUF(z)   (((z + 63) >> 6) << 6)

//#define SC_DEBUG

#ifdef SC_DEBUG
#define	dprintk(...)	printk(__VA_ARGS__)
#else
#define	dprintk(...)
#endif

#ifdef SC_DEBUG
//static struct ihk_dma_request last_request;

static void print_dma_lastreq(void)
{
	printk("SRC OS : %p | %lx\nDESTOS : %p | %lx\n", last_request.src_os,
	       last_request.src_phys, last_request.dest_os,
	       last_request.dest_phys);
	printk("SIZE   : %lx | NOTIFY : %p | PRIV : %p\n",
	       last_request.size, last_request.notify, last_request.priv);
}
#endif

int init_peer_channel_registry(struct mcctrl_usrdata *ud)
{
	ud->keys = kzalloc(sizeof(void *) * ud->num_channels, GFP_KERNEL);
	if (!ud->keys) {
		printk("Error: cannot allocate usrdata.keys[].\n");
		return -ENOMEM;
	}

	return 0;
}

int register_peer_channel(struct mcctrl_usrdata *ud, void *key, struct mcctrl_channel *ch)
{
	int cpu;

	cpu = ch - ud->channels;
	if ((cpu < 0) || (ud->num_channels <= cpu)) {
		printk("register_peer_channel(%p,%p,%p):"
				"not a syscall channel. cpu=%d\n",
				ud, key, ch, cpu);
		return -EINVAL;
	}

	if (ud->keys[cpu] != NULL) {
		printk("register_peer_channel(%p,%p,%p):"
				"already registered. cpu=%d\n",
				ud, key, ch, cpu);
		/*
		 * When mcexec receives a signal,
		 * it may be finished without doing deregister_peer_channel().
		 * Therefore a substitute registration is necessary.
		 */
#if 0
		return -EBUSY;
#endif
	}

	ud->keys[cpu] = key;
	return 0;
}

int deregister_peer_channel(struct mcctrl_usrdata *ud, void *key, struct mcctrl_channel *ch)
{
	int cpu;

	cpu = ch - ud->channels;
	if ((cpu < 0) || (ud->num_channels <= cpu)) {
		printk("deregister_peer_channel(%p,%p,%p):"
				"not a syscall channel. cpu=%d\n",
				ud, key, ch, cpu);
		return -EINVAL;
	}

	if (ud->keys[cpu] && (ud->keys[cpu] != key)) {
		printk("deregister_peer_channel(%p,%p,%p):"
				"not registered. cpu=%d\n",
				ud, key, ch, cpu);
		return -EBUSY;
	}

	ud->keys[cpu] = NULL;
	return 0;
}

struct mcctrl_channel *get_peer_channel(struct mcctrl_usrdata *ud, void *key)
{
	int cpu;

	for (cpu = 0; cpu < ud->num_channels; ++cpu) {
		if (ud->keys[cpu] == key) {
			return &ud->channels[cpu];
		}
	}

	return NULL;
}

#if 1	/* x86 depend, host OS side */
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
			goto out;
		}

#define	PTE_PS	0x080
		if (pt[ix] & PTE_PS) {
			pgsize = 1UL << offsh;
			rpa = pt[ix] & ((1UL << 52) - 1) & ~(pgsize - 1);
			rpa |= rva & (pgsize - 1);
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
#endif

static int remote_page_fault(struct mcctrl_usrdata *usrdata, void *fault_addr, uint64_t reason)
{
	struct mcctrl_channel *channel;
	struct syscall_request *req;
	struct syscall_response *resp;
	int error;

	dprintk("remote_page_fault(%p,%p,%llx)\n", usrdata, fault_addr, reason);

	channel = get_peer_channel(usrdata, current);
	if (!channel) {
		error = -ENOENT;
		printk("remote_page_fault(%p,%p,%llx):channel not found. %d\n",
				usrdata, fault_addr, reason, error);
		goto out;
	}

	req = channel->param.request_va;
	resp = channel->param.response_va;

	/* request page fault */
	resp->ret = -EFAULT;
	resp->fault_address = (unsigned long)fault_addr;
	resp->fault_reason = reason;

#define	STATUS_PAGE_FAULT	3
	req->valid = 0;
	mb();
	resp->status = STATUS_PAGE_FAULT;

	/* wait for response */
	error = wait_event_interruptible(channel->wq_syscall, channel->req);
	if (error) {
		printk("remote_page_fault:interrupted. %d\n", error);
		goto out;
	}
	channel->req = 0;
	if (!req->valid) {
		printk("remote_page_fault:not valid\n");
	}
	req->valid = 0;

	/* check result */
	if (req->number != __NR_mmap) {
		printk("remote_page_fault:unexpected response. %lx %lx\n",
				req->number, req->args[0]);
		error = -EIO;
		goto out;
	}
	else if (req->args[0] != 0x0101) {
		printk("remote_page_fault:unexpected response. %lx %lx\n",
				req->number, req->args[0]);
		error = -EIO;
		goto out;
	}
	else if (req->args[1] != 0) {
		error = req->args[1];
		printk("remote_page_fault:response %d\n", error);
		goto out;
	}

	error = 0;
out:
	dprintk("remote_page_fault(%p,%p,%llx): %d\n", usrdata, fault_addr, reason, error);
	return error;
}

static int rus_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct mcctrl_usrdata *	usrdata	= vma->vm_file->private_data;
	ihk_device_t		dev = ihk_os_to_dev(usrdata->os);
	unsigned long		rpa;
	unsigned long		phys;
	int			error;
	int			try;
	uint64_t		reason;
	unsigned long		pgsize;
	unsigned long		rva;
	unsigned long		pfn;

	dprintk("mcctrl:page fault:flags %#x pgoff %#lx va %p page %p\n",
			vmf->flags, vmf->pgoff, vmf->virtual_address, vmf->page);

	for (try = 1; ; ++try) {
		error = translate_rva_to_rpa(usrdata->os, usrdata->rpgtable,
				(unsigned long)vmf->virtual_address,
				&rpa, &pgsize);
#define	NTRIES 2
		if (!error || (try >= NTRIES)) {
			break;
		}

		reason = 0;
		if (vmf->flags & FAULT_FLAG_WRITE) {
#define	PF_WRITE	0x02
			reason |= PF_WRITE;
		}
		error = remote_page_fault(usrdata, vmf->virtual_address, reason);
		if (error) {
			printk("forward_page_fault failed. %d\n", error);
			break;
		}
	}
	if (error) {
		printk("mcctrl:page fault:flags %#x pgoff %#lx va %p page %p\n",
				vmf->flags, vmf->pgoff, vmf->virtual_address, vmf->page);
		return VM_FAULT_SIGBUS;
	}

	rva = (unsigned long)vmf->virtual_address & ~(pgsize - 1);
	rpa = rpa & ~(pgsize - 1);

	phys = ihk_device_map_memory(dev, rpa, pgsize);
	pfn = phys >> PAGE_SHIFT;
	error = remap_pfn_range(vma, rva, pfn, pgsize, PAGE_SHARED);
	ihk_device_unmap_memory(dev, phys, pgsize);
	if (error) {
		printk("mcctrl:page fault:flags %#x pgoff %#lx va %p page %p\n",
				vmf->flags, vmf->pgoff, vmf->virtual_address, vmf->page);
		return VM_FAULT_SIGBUS;
	}

	return VM_FAULT_NOPAGE;
}

static struct vm_operations_struct rus_vmops = {
	.fault = &rus_vm_fault,
};

static int rus_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_flags |= VM_IO | VM_RESERVED | VM_DONTEXPAND | VM_PFNMAP;
	vma->vm_ops = &rus_vmops;
	return 0;
}

static struct file_operations rus_fops = {
	.mmap = &rus_mmap,
};

int reserve_user_space(struct mcctrl_usrdata *usrdata, unsigned long *startp, unsigned long *endp)
{
	struct file *file;
	struct vm_area_struct *vma;
	unsigned long start;
	unsigned long end;
	struct cred *promoted;
	const struct cred *original;

	file = anon_inode_getfile("[mckernel]", &rus_fops, usrdata, O_RDWR);
	if (IS_ERR(file)) {
		return PTR_ERR(file);
	}

	promoted = prepare_creds();
	if (!promoted) {
		printk("mcctrl:user space reservation failed. ENOMEM\n");
		fput(file);
		return -ENOMEM;
	}
	/*
	 * CAP_SYS_RAWIO for mmap_min_addr check avoidance
	 */
	cap_raise(promoted->cap_effective, CAP_SYS_RAWIO);
	original = override_creds(promoted);

#define	DESIRED_USER_END	0x800000000000
#define	GAP_FOR_MCEXEC		0x008000000000UL
	end = DESIRED_USER_END;
	down_write(&current->mm->mmap_sem);
	vma = find_vma(current->mm, 0);
	if (vma) {
		end = (vma->vm_start - GAP_FOR_MCEXEC) & ~(GAP_FOR_MCEXEC - 1);
	}
	start = do_mmap_pgoff(file, 0, end,
			PROT_READ|PROT_WRITE, MAP_FIXED|MAP_SHARED, 0);
	up_write(&current->mm->mmap_sem);

	revert_creds(original);
	put_cred(promoted);
	fput(file);
	if (IS_ERR_VALUE(start)) {
		printk("mcctrl:user space reservation failed.\n");
		return start;
	}

	*startp = start;
	*endp = end;
	return 0;
}

//unsigned long last_thread_exec = 0;

#ifndef DO_USER_MODE
static struct {
	long (*do_sys_open)(int, const char __user *, int, int);
	long (*sys_lseek)(unsigned int, off_t, unsigned int);
	long (*sys_read)(unsigned int, char __user *, size_t);
	long (*sys_write)(unsigned int, const char __user *, size_t);
} syscalls;

void
mcctrl_syscall_init(void)
{
	printk("mcctrl_syscall_init\n");
	syscalls.do_sys_open = (void *)kallsyms_lookup_name("do_sys_open");
	syscalls.sys_lseek = (void *)kallsyms_lookup_name("sys_lseek");
	syscalls.sys_read = (void *)kallsyms_lookup_name("sys_read");
	syscalls.sys_write = (void *)kallsyms_lookup_name("sys_write");
	printk("syscalls.do_sys_open=%lx\n", (long)syscalls.do_sys_open);
	printk("syscalls.sys_lseek=%lx\n", (long)syscalls.sys_lseek);
	printk("syscalls.sys_read=%lx\n", (long)syscalls.sys_read);
	printk("syscalls.sys_write=%lx\n", (long)syscalls.sys_write);
}

static int do_async_copy(ihk_os_t os, unsigned long dest, unsigned long src,
                         unsigned long size, unsigned int inbound)
{
	struct ihk_dma_request request;
	ihk_dma_channel_t channel;
	unsigned long asize = ALIGN_WAIT_BUF(size);

	channel = ihk_device_get_dma_channel(ihk_os_to_dev(os), 0);
	if (!channel) {
		return -EINVAL;
	}

	memset(&request, 0, sizeof(request));
	request.src_os = inbound ? os : NULL;
	request.src_phys = src;
	request.dest_os = inbound ? NULL : os;
	request.dest_phys = dest;
	request.size = size;
	request.notify = (void *)(inbound ? dest + asize : src + asize);
	request.priv = (void *)1;

	*(unsigned long *)phys_to_virt((unsigned long)request.notify) = 0;
#ifdef SC_DEBUG
	last_request = request;
#endif

	ihk_dma_request(channel, &request);

	return 0;
}

//int mcctrl_dma_abort;

static void async_wait(ihk_os_t os, unsigned char *p, int size)
{
	int asize = ALIGN_WAIT_BUF(size);
	unsigned long long s, w;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	rdtscll(s);
	while (!p[asize]) {
		mb();
		cpu_relax();
		rdtscll(w);
		if (w > s + 1024UL * 1024 * 1024 * 10) {
			printk("DMA Timed out : %p (%p + %d) => %d\n",
			       p + asize, p, size, p[asize]);
#ifdef SC_DEBUG
			print_dma_lastreq();
#endif
			usrdata->mcctrl_dma_abort = 1;
			return;
		}
	}
}

static void clear_wait(unsigned char *p, int size)
{
	//int asize = ALIGN_WAIT_BUF(size);
	p[size] = 0;
}

static unsigned long translate_remote_va(struct mcctrl_channel *c,
                                         unsigned long rva)
{
	int i, n;
	struct syscall_post *p;

	p = c->param.post_va;

	n = (int)p->v[0];
	if (n < 0 || n >= PAGE_SIZE / sizeof(struct syscall_post)) {
		return -EINVAL;
	}
	for (i = 0; i < n; i++) {
		if (p[i + 1].v[0] != 1) {
			continue;
		}
		if (rva >= p[i + 1].v[1] && rva < p[i + 1].v[2]) {
			return p[i + 1].v[3] + (rva - p[i + 1].v[1]);
		}
	}

	return -EFAULT;
}

//extern struct mcctrl_channel *channels;

#if 0
int __do_in_kernel_syscall(ihk_os_t os, struct mcctrl_channel *c,
                           struct syscall_request *sc)
{
	int ret;
	mm_segment_t fs;
	unsigned long pa;
	struct mcctrl_usrdata *usrdata = ihk_host_os_get_usrdata(os);

	switch (sc->number) {
	case 0: /* read */
	case 1024:
		if (sc->number & 1024) {
			sc->args[1] = translate_remote_va(c, sc->args[1]);
			if ((long)sc->args[1] < 0) {
				__return_syscall(c, -EFAULT);
				return 0;
			}
		}

		clear_wait(c->dma_buf, sc->args[2]);
		fs = get_fs();
		set_fs(KERNEL_DS);
		ret = syscalls.sys_read(sc->args[0], c->dma_buf, sc->args[2]);
		if (ret > 0) {
			do_async_copy(os, sc->args[1], virt_to_phys(c->dma_buf),
			              sc->args[2], 0);
			set_fs(fs);
			
			async_wait(os, c->dma_buf, sc->args[2]);
		}
		__return_syscall(c, ret);
		return 0;

	case 1: /* write */
	case 1025:
		if (sc->number & 1024) {
			sc->args[1] = translate_remote_va(c, sc->args[1]);
			if ((long)sc->args[1] < 0) {
				__return_syscall(c, -EFAULT);
				return 0;
			}
		}

		clear_wait(c->dma_buf, sc->args[2]);
		do_async_copy(os, virt_to_phys(c->dma_buf), sc->args[1],
		              sc->args[2], 1);
		fs = get_fs();
		set_fs(KERNEL_DS);
		async_wait(os, c->dma_buf, sc->args[2]);

		ret = syscalls.sys_write(sc->args[0], c->dma_buf, sc->args[2]);
		set_fs(fs);

		__return_syscall(c, ret);
		return 0;
		
	case 2: /* open */
	case 1026:
		if (sc->number & 1024) {
			sc->args[0] = translate_remote_va(c, sc->args[0]);
			if ((long)sc->args[0] < 0) {
				__return_syscall(c, -EFAULT);
				return 0;
			}
		}

		clear_wait(c->dma_buf, 256);
		do_async_copy(os, virt_to_phys(c->dma_buf), sc->args[0], 
		              256, 1);
		fs = get_fs();
		set_fs(KERNEL_DS);
		async_wait(os, c->dma_buf, 256);

		ret = syscalls.do_sys_open(AT_FDCWD, c->dma_buf, sc->args[1],
		                  sc->args[2]);
		set_fs(fs);

		__return_syscall(c, ret);
		return 0;

	case 3: /* Close */
		ret = sys_close(sc->args[0]);
		__return_syscall(c, ret);
		return 0;

	case 8: /* lseek */
		ret = syscalls.sys_lseek(sc->args[0], sc->args[1], sc->args[2]);
		__return_syscall(c, ret);
		return 0;

	case 56: /* Clone */
		usrdata->last_thread_exec++;
		if (mcctrl_ikc_is_valid_thread(usrdata->last_thread_exec)) {
			printk("Clone notification: %lx\n", sc->args[0]);
			if (channels[usrdata->last_thread_exec].param.post_va) {
				memcpy(usrdata->channels[usrdata->last_thread_exec].param.post_va,
				       c->param.post_va, PAGE_SIZE);
			}
			mcctrl_ikc_send_msg(usrdata->last_thread_exec,
			                    SCD_MSG_SCHEDULE_PROCESS,
			                    usrdata->last_thread_exec, sc->args[0]);
		}

		__return_syscall(c, 0);
		return 0;
		
	default:
		if (sc->number & 1024) {
			__return_syscall(c, -EFAULT);
			return 0;
		} else {
			return -ENOSYS;
		}
	}
}
#endif
#endif /* !DO_USER_MODE */

static void __return_syscall(struct mcctrl_channel *c, int ret)
{
	c->param.response_va->ret = ret;
	mb();
	c->param.response_va->status = 1;
}

static void clear_pte_range(uintptr_t addr, uintptr_t len)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	uintptr_t start;
	uintptr_t end;

	down_read(&mm->mmap_sem);
	vma = find_vma(mm, 0);
	if (!vma) {
		printk("clear_pte_range(%lx,%lx):find_vma(0) failed\n",
				addr, len);
		up_read(&mm->mmap_sem);
		return;
	}

	start = addr;
	end = addr + len;
	if (start < vma->vm_start) {
		start = vma->vm_start;
	}
	if (vma->vm_end < end) {
		end = vma->vm_end;
	}
	if (start < end) {
		zap_vma_ptes(vma, start, end-start);
	}

	up_read(&mm->mmap_sem);
	return;
}

int __do_in_kernel_syscall(ihk_os_t os, struct mcctrl_channel *c, struct syscall_request *sc)
{
	int error;
	long ret;

	dprintk("__do_in_kernel_syscall(%p,%p,%p %ld)\n", os, c, sc, sc->number);
	switch (sc->number) {
	case __NR_munmap:
		clear_pte_range(sc->args[0], sc->args[1]);
		ret = 0;
		break;

	default:
		error = -ENOSYS;
		goto out;
		break;
	}

	__return_syscall(c, ret);

	error = 0;
out:
	dprintk("__do_in_kernel_syscall(%p,%p,%p %ld): %d\n", os, c, sc, sc->number, error);
	return error;
}
