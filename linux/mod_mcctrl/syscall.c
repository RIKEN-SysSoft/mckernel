#include <linux/sched.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <asm/uaccess.h>
#include <asm/delay.h>
#include "mcctrl.h"

static int do_async_copy(aal_os_t os, unsigned long dest, unsigned long src,
                         unsigned long size, unsigned int inbound)
{
	struct aal_dma_request request;
	aal_dma_channel_t channel;

	channel = aal_device_get_dma_channel(aal_os_to_dev(os), 0);
	if (!channel) {
		return -EINVAL;
	}

	memset(&request, 0, sizeof(request));
	request.src_os = os;
	request.src_phys = src;
	request.dest_os = NULL;
	request.dest_phys = dest;
	request.size = size;
	request.notify = (void *)(inbound ? dest + size : src + size);
	request.priv = (void *)1;

	aal_dma_request(channel, &request);

	return 0;
}

static void async_wait(unsigned char *p, int size)
{
	while (!p[size]) {
		mb();
		cpu_relax();
	}
}
static void clear_wait(unsigned char *p, int size)
{
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

unsigned long last_thread_exec = 0;

extern struct mcctrl_channel *channels;

int __do_in_kernel_syscall(aal_os_t os, struct mcctrl_channel *c,
                           struct syscall_request *sc)
{
	int ret;
	mm_segment_t fs;
	unsigned long pa;

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
		ret = sys_read(sc->args[0], c->dma_buf, sc->args[2]);
		if (ret > 0) {
			do_async_copy(os, sc->args[1], virt_to_phys(c->dma_buf),
			              sc->args[2], 0);
			set_fs(fs);
			
			async_wait(c->dma_buf, sc->args[2]);
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
		async_wait(c->dma_buf, sc->args[2]);

		ret = sys_write(sc->args[0], c->dma_buf, sc->args[2]);
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
		async_wait(c->dma_buf, 256);

		ret = do_sys_open(AT_FDCWD, c->dma_buf, sc->args[1],
		                  sc->args[2]);
		set_fs(fs);

		__return_syscall(c, ret);
		return 0;

	case 3: /* Close */
		ret = sys_close(sc->args[0]);
		__return_syscall(c, ret);
		return 0;

	case 56: /* Clone */
		last_thread_exec++;
		if (mcctrl_ikc_is_valid_thread(last_thread_exec)) {
			printk("Clone notification: %lx\n", sc->args[0]);
			if (channels[last_thread_exec].param.post_va) {
				memcpy(channels[last_thread_exec].param.post_va,
				       c->param.post_va, PAGE_SIZE);
			}
			mcctrl_ikc_send_msg(last_thread_exec,
			                    SCD_MSG_SCHEDULE_PROCESS,
			                    last_thread_exec, sc->args[0]);
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
