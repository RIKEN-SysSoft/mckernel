#include <types.h>
#include <kmsg.h>
#include <aal/cpu.h>
#include <aal/mm.h>
#include <aal/debug.h>
#include <aal/ikc.h>
#include <errno.h>
#include <cls.h>
#include <syscall.h>
#include <page.h>
#include <amemcpy.h>

int memcpy_async(unsigned long dest, unsigned long src,
                 unsigned long len, int wait, unsigned long *notify);

static void send_syscall(struct syscall_request *req)
{
	struct ikc_scd_packet packet;
	struct syscall_response *res = cpu_local_var(scp).response_va;
	unsigned long fin;

	res->status = 0;

	memcpy_async(cpu_local_var(scp).request_pa,
	             virt_to_phys(req), sizeof(*req), 0, &fin);

	memcpy_async_wait(&cpu_local_var(scp).post_fin);
	cpu_local_var(scp).post_va->v[0] = cpu_local_var(scp).post_idx;

	memcpy_async_wait(&fin);

	*(unsigned int *)cpu_local_var(scp).doorbell_va = 1;

#ifdef SYSCALL_BY_IKC
	packet.msg = SCD_MSG_SYSCALL_ONESIDE;
	packet.ref = aal_mc_get_processor_id();
	packet.arg = cpu_local_var(scp).request_rpa;
	
	aal_ikc_send(cpu_local_var(syscall_channel), &packet, 0); 
#endif
}

static int do_syscall(struct syscall_request *req)
{
	struct syscall_response *res = cpu_local_var(scp).response_va;

	send_syscall(req);

	while (!res->status) {
		cpu_pause();
	}

	return res->ret;
}

long sys_brk(int n, aal_mc_user_context_t *ctx)
{
	unsigned long address = aal_mc_syscall_arg0(ctx);
	struct vm_regions *region = &cpu_local_var(current)->region;

	region->brk_end = 
		extend_process_region(cpu_local_var(current),
		                      region->brk_start, region->brk_end,
		                      address);
	return region->brk_end;

}

#define SYSCALL_DECLARE(name) long sys_##name(int n, aal_mc_user_context_t *ctx)
#define SYSCALL_HEADER struct syscall_request request; \
	request.number = n
#define SYSCALL_ARG_D(n)    request.args[n] = aal_mc_syscall_arg##n(ctx)
#define SYSCALL_ARG_MO(n) \
	do { \
	unsigned long __phys; \
	if (aal_mc_pt_virt_to_phys(cpu_local_var(current)->page_table, \
	                           (void *)aal_mc_syscall_arg##n(ctx),\
	                           &__phys)) { \
		return -EFAULT; \
	}\
	request.args[n] = __phys; \
	} while(0)
#define SYSCALL_ARG_MI(n) \
	do { \
	unsigned long __phys; \
	if (aal_mc_pt_virt_to_phys(cpu_local_var(current)->page_table, \
	                           (void *)aal_mc_syscall_arg##n(ctx),\
	                           &__phys)) { \
		return -EFAULT; \
	}\
	request.args[n] = __phys; \
	} while(0)


#define SYSCALL_ARGS_1(a0)          SYSCALL_ARG_##a0(0)
#define SYSCALL_ARGS_2(a0, a1)      SYSCALL_ARG_##a0(0); SYSCALL_ARG_##a1(1)
#define SYSCALL_ARGS_3(a0, a1, a2)  SYSCALL_ARG_##a0(0); SYSCALL_ARG_##a1(1); \
	                            SYSCALL_ARG_##a2(2)
#define SYSCALL_ARGS_4(a0, a1, a2, a3) \
	SYSCALL_ARG_##a0(0); SYSCALL_ARG_##a1(1); \
	SYSCALL_ARG_##a2(2); SYSCALL_ARG_##a3(3)

#define SYSCALL_FOOTER return do_syscall(&request)

SYSCALL_DECLARE(fstat)
{
	SYSCALL_HEADER;
	SYSCALL_ARGS_2(D, MO);
	SYSCALL_FOOTER;
}

static int stop(void)
{
	while(1);
	return 0;
}

SYSCALL_DECLARE(open)
{
	SYSCALL_HEADER;
	SYSCALL_ARGS_3(MI, D, D);
	SYSCALL_FOOTER;
}

SYSCALL_DECLARE(ioctl)
{
	SYSCALL_HEADER;

	/* Very ad-hoc for termios */
	switch(aal_mc_syscall_arg1(ctx)) {
	case 0x5401:
		SYSCALL_ARGS_3(D, D, MO);
		SYSCALL_FOOTER;
	}

	return -EINVAL;
}

SYSCALL_DECLARE(read)
{
	SYSCALL_HEADER;
	SYSCALL_ARGS_3(D, MO, D);
	SYSCALL_FOOTER;
}

SYSCALL_DECLARE(pread)
{
	SYSCALL_HEADER;
	SYSCALL_ARGS_4(D, MO, D, D);
	SYSCALL_FOOTER;
}

SYSCALL_DECLARE(write)
{
	SYSCALL_HEADER;
	SYSCALL_ARGS_3(D, MI, D);
	SYSCALL_FOOTER;
}

SYSCALL_DECLARE(pwrite)
{
	SYSCALL_HEADER;
	SYSCALL_ARGS_4(D, MI, D, D);
	SYSCALL_FOOTER;
}

SYSCALL_DECLARE(close)
{
	SYSCALL_HEADER;
	SYSCALL_ARGS_1(D);
	SYSCALL_FOOTER;
}

SYSCALL_DECLARE(lseek)
{
	SYSCALL_HEADER;
	SYSCALL_ARGS_3(D, D, D);
	SYSCALL_FOOTER;
}


SYSCALL_DECLARE(exit_group)
{
	SYSCALL_HEADER;
	do_syscall(&request);

	free_process_memory(cpu_local_var(current));
	cpu_local_var(next) = &cpu_local_var(idle);
	
	schedule();

	return 0;
}

SYSCALL_DECLARE(mmap)
{
	unsigned long address, ret;
	struct vm_regions *region = &cpu_local_var(current)->region;
		
	/* anonymous */
	if (aal_mc_syscall_arg3(ctx) & 0x22) {
		ret = region->map_end;
		address = region->map_end + aal_mc_syscall_arg1(ctx);

		region->map_end = 
			extend_process_region(cpu_local_var(current),
			                      region->map_start,
			                      region->map_end,
			                      address);
		if (region->map_end == address) {
			return ret;
		} else {
			return -EINVAL;
		}
	}
	kprintf("Non-anonymous mmap: fd = %lx, %lx\n",
	        aal_mc_syscall_arg4(ctx), aal_mc_syscall_arg5(ctx));
	while(1);
}

SYSCALL_DECLARE(munmap)
{
	unsigned long address, len;

	address = aal_mc_syscall_arg0(ctx);
	len = aal_mc_syscall_arg1(ctx);

	return remove_process_region(cpu_local_var(current), address, 
	                             address + len);
}

SYSCALL_DECLARE(getpid)
{
	return cpu_local_var(current)->pid;
}

long sys_uname(int n, aal_mc_user_context_t *ctx)
{
	struct syscall_request request;
	unsigned long phys;

	if (aal_mc_pt_virt_to_phys(cpu_local_var(current)->page_table, 
	                           (void *)aal_mc_syscall_arg0(ctx), &phys)) {
		return -EFAULT;
	}

	request.number = n;
	request.args[0] = phys;

	return do_syscall(&request);
}

long sys_getxid(int n, aal_mc_user_context_t *ctx)
{
	struct syscall_request request;

	request.number = n;

	return do_syscall(&request);
}

long sys_arch_prctl(int n, aal_mc_user_context_t *ctx)
{
	unsigned long code = aal_mc_syscall_arg0(ctx);
	unsigned long address = aal_mc_syscall_arg1(ctx);

	switch (code) {
	case 0x1002:
		return aal_mc_arch_set_special_register(AAL_ASR_X86_FS,
		                                        address);

	case 0x1003:
		return aal_mc_arch_get_special_register(AAL_ASR_X86_FS,
		                                        (unsigned long *)
		                                        address);
	}

	return -EINVAL;
}

static long (*syscall_table[])(int, aal_mc_user_context_t *) = {
	[0] = sys_read,
	[1] = sys_write,
	[2] = sys_open,
	[3] = sys_close,
	[5] = sys_fstat,
	[8] = sys_lseek,
	[9] = sys_mmap,
	[11] = sys_munmap,
	[12] = sys_brk,
	[16] = sys_ioctl,
	[17] = sys_pread,
	[18] = sys_pwrite,
	[39] = sys_getpid,
	[63] = sys_uname,
	[102] = sys_getxid,
	[104] = sys_getxid,
	[107] = sys_getxid,
	[108] = sys_getxid,
	[110] = sys_getxid,
	[111] = sys_getxid,
	[158] = sys_arch_prctl,
	[231] = sys_exit_group,
};

long syscall(int num, aal_mc_user_context_t *ctx)
{
	long l;

	cpu_enable_interrupt();

	if (syscall_table[num]) {
		l = syscall_table[num](num, ctx);
		return l;
	} else {
		kprintf("USC[%3d](%lx, %lx, %lx, %lx, %lx) @ %lx | %lx\n", num,
		        aal_mc_syscall_arg0(ctx), aal_mc_syscall_arg1(ctx),
		        aal_mc_syscall_arg2(ctx), aal_mc_syscall_arg3(ctx),
		        aal_mc_syscall_arg4(ctx), aal_mc_syscall_pc(ctx),
		        aal_mc_syscall_sp(ctx));
		while(1);
		return -ENOSYS;
	}
}

void __host_update_process_range(struct process *process, 
                                 struct vm_range *range)
{
	struct syscall_post *post;
	int idx;

	memcpy_async_wait(&cpu_local_var(scp).post_fin);

	post = &cpu_local_var(scp).post_buf;

	post->v[0] = 1;
	post->v[1] = range->start;
	post->v[2] = range->end;
	post->v[3] = range->phys;

	cpu_disable_interrupt();
	if (cpu_local_var(scp).post_idx >= 
	    PAGE_SIZE / sizeof(struct syscall_post)) {
		/* XXX: Wait until it is consumed */
	} else {
		idx = ++(cpu_local_var(scp).post_idx);

		cpu_local_var(scp).post_fin = 0;
		memcpy_async(cpu_local_var(scp).post_pa + 
		             idx * sizeof(*post),
		             virt_to_phys(post), sizeof(*post), 0,
		             &cpu_local_var(scp).post_fin);
	}
	cpu_enable_interrupt();
}
