#include <linux/sched.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <asm/uaccess.h>
#include <asm/delay.h>
#include <asm/io.h>
#include "mcctrl.h"

#define ALIGN_WAIT_BUF(z)   (((z + 63) >> 6) << 6)

//#define SC_DEBUG
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

static void __return_syscall(struct mcctrl_channel *c, int ret)
{
	c->param.response_va->ret = ret;
	c->param.response_va->status = 1;
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
#endif /* !DO_USER_MODE */
