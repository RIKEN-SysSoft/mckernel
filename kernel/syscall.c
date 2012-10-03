#include <types.h>
#include <kmsg.h>
#include <aal/cpu.h>
#include <cpulocal.h>
#include <aal/mm.h>
#include <aal/debug.h>
#include <aal/ikc.h>
#include <errno.h>
#include <cls.h>
#include <syscall.h>
#include <page.h>
#include <amemcpy.h>
#include <uio.h>
#include <aal/lock.h>
#include <ctype.h>
#include <waitq.h>
#include <rlimit.h>
#include <affinity.h>
#include <time.h>

/* Headers taken from kitten LWK */
#include <lwk/stddef.h>
#include <futex.h>

#define SYSCALL_BY_IKC

#define DEBUG_PRINT_SC

#ifdef DEBUG_PRINT_SC
#define dkprintf kprintf
#else
#define dkprintf(...)
#endif

static aal_atomic_t pid_cnt = AAL_ATOMIC_INIT(1024);

int memcpy_async(unsigned long dest, unsigned long src,
                 unsigned long len, int wait, unsigned long *notify);

static void send_syscall(struct syscall_request *req)
{
	struct ikc_scd_packet packet;
	struct syscall_response *res = cpu_local_var(scp).response_va;
	unsigned long fin;
	int w;

	res->status = 0;
	req->valid = 0;

	memcpy_async(cpu_local_var(scp).request_pa,
	             virt_to_phys(req), sizeof(*req), 0, &fin);

	memcpy_async_wait(&cpu_local_var(scp).post_fin);
	cpu_local_var(scp).post_va->v[0] = cpu_local_var(scp).post_idx;

	w = aal_mc_get_processor_id() + 1;

	memcpy_async_wait(&fin);

	cpu_local_var(scp).request_va->valid = 1;
	*(unsigned int *)cpu_local_var(scp).doorbell_va = w;

#ifdef SYSCALL_BY_IKC
	packet.msg = SCD_MSG_SYSCALL_ONESIDE;
	packet.ref = aal_mc_get_processor_id();
	packet.arg = cpu_local_var(scp).request_rpa;
	
	aal_ikc_send(cpu_local_var(syscall_channel), &packet, 0); 
	//aal_ikc_send(get_cpu_local_var(0)->syscall_channel, &packet, 0); 
#endif
}

static int do_syscall(struct syscall_request *req, aal_mc_user_context_t *ctx)
{
	struct syscall_response *res = cpu_local_var(scp).response_va;

	dkprintf("SC(%d)[%3d] sending syscall\n",
	        aal_mc_get_processor_id(),
	        req->number);

	send_syscall(req);

	dkprintf("SC(%d)[%3d] waiting for host.. \n", 
	        aal_mc_get_processor_id(),
	        req->number);
	
	while (!res->status) {
		cpu_pause();
	}
	
	dkprintf("SC(%d)[%3d] got host reply: %d \n", 
	        aal_mc_get_processor_id(),
	        req->number, res->ret);

	return res->ret;
}

long sys_brk(int n, aal_mc_user_context_t *ctx)
{
	unsigned long address = aal_mc_syscall_arg0(ctx);
	struct vm_regions *region = &cpu_local_var(current)->vm->region;

	region->brk_end = 
		extend_process_region(cpu_local_var(current),
		                      region->brk_start, region->brk_end,
		                      address);
	
	return region->brk_end;

}

#define SYSCALL_DECLARE(name) long sys_##name(int n, aal_mc_user_context_t *ctx)
#define SYSCALL_HEADER struct syscall_request request AAL_DMA_ALIGN; \
	request.number = n
#define SYSCALL_ARG_D(n)    request.args[n] = aal_mc_syscall_arg##n(ctx)
#define SYSCALL_ARG_MO(n) \
	do { \
	unsigned long __phys; \
	if (aal_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, \
	                           (void *)aal_mc_syscall_arg##n(ctx),\
	                           &__phys)) { \
		return -EFAULT; \
	}\
	request.args[n] = __phys; \
	} while(0)
#define SYSCALL_ARG_MI(n) \
	do { \
	unsigned long __phys; \
	if (aal_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, \
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
#define SYSCALL_ARGS_6(a0, a1, a2, a3, a4, a5) \
	SYSCALL_ARG_##a0(0); SYSCALL_ARG_##a1(1); \
	SYSCALL_ARG_##a2(2); SYSCALL_ARG_##a3(3); \
	SYSCALL_ARG_##a4(4); SYSCALL_ARG_##a5(5);

#define SYSCALL_FOOTER return do_syscall(&request, ctx)

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
	dkprintf("open: %s\n", (char*)aal_mc_syscall_arg0(ctx));
	SYSCALL_ARGS_3(MI, D, D);
	SYSCALL_FOOTER;
}

SYSCALL_DECLARE(stat)
{
	SYSCALL_HEADER;
	dkprintf("stat(\"%s\");\n", (char*)aal_mc_syscall_arg0(ctx));
	SYSCALL_ARGS_2(MO, MO);
	SYSCALL_FOOTER;
}


SYSCALL_DECLARE(gettimeofday)
{
	SYSCALL_HEADER;
	dkprintf("gettimeofday() \n");
	SYSCALL_ARGS_1(MO);
	SYSCALL_FOOTER;
}


static DECLARE_WAITQ(my_waitq);

SYSCALL_DECLARE(ioctl)
{

	switch (aal_mc_syscall_arg0(ctx)) {

	case 0: {
		struct waitq_entry my_wait;
		waitq_init_entry(&my_wait, cpu_local_var(current));

		dkprintf("CPU[%d] pid[%d] going to sleep...\n",
		        cpu_local_var(current)->cpu_id, 
				cpu_local_var(current)->pid);

		waitq_prepare_to_wait(&my_waitq, &my_wait, PS_INTERRUPTIBLE);
		schedule();
		
		waitq_finish_wait(&my_waitq, &my_wait);
		
		dkprintf("CPU[%d] pid[%d] woke up!\n",
		        cpu_local_var(current)->cpu_id, 
				cpu_local_var(current)->pid);

		break;
	}

	case 1:
	
		dkprintf("CPU[%d] pid[%d] waking up everyone..\n",
		        cpu_local_var(current)->cpu_id, 
				cpu_local_var(current)->pid);
		
		waitq_wakeup(&my_waitq);
		
		break;
	
	case 2:
	
		dkprintf("[%d] pid %d made an ioctl\n", 
		        cpu_local_var(current)->cpu_id, 
				cpu_local_var(current)->pid);

		break;
	
	default:
		dkprintf("ioctl() unimplemented\n");
		
	}

	return 0;

#if 0
	SYSCALL_HEADER;

	/* Very ad-hoc for termios */
	switch(aal_mc_syscall_arg1(ctx)) {
	case 0x5401:
		SYSCALL_ARGS_3(D, D, MO);
		SYSCALL_FOOTER;
	}

	return -EINVAL;
#endif
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
#if 0
	dkprintf("[%d] close() \n", aal_mc_get_processor_id());
	return -EBADF;
#endif
/*
	SYSCALL_HEADER;
	SYSCALL_ARGS_1(D);
	SYSCALL_FOOTER;
*/
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
	do_syscall(&request, ctx);

	runq_del_proc(cpu_local_var(current), aal_mc_get_processor_id());
	free_process_memory(cpu_local_var(current));

	//cpu_local_var(next) = &cpu_local_var(idle);
	
	cpu_local_var(current) = NULL; 
	schedule();

	return 0;
}

// MIC:9 linux:90
SYSCALL_DECLARE(mmap)
{
	struct vm_regions *region = &cpu_local_var(current)->vm->region;
    unsigned long lockr;

    kprintf("syscall.c,mmap,addr=%lx,len=%lx,prot=%lx,flags=%x,fd=%x,offset=%lx\n",
            aal_mc_syscall_arg0(ctx), aal_mc_syscall_arg1(ctx),
            aal_mc_syscall_arg2(ctx), aal_mc_syscall_arg3(ctx),
            aal_mc_syscall_arg4(ctx), aal_mc_syscall_arg5(ctx)
            );
    //kprintf("syscall.c,mmap,dumping kmsg...\n");
    //    send_kmsg(ctx);
    //    return -EINVAL; // debug
		
    if((aal_mc_syscall_arg3(ctx) & 0x10) == 0x10) {
        // libc/sysdeps/unix/sysv/linux/x86_64/bits/mman.h
        // #define MAP_FIXED  0x10
        // use the given vaddr as is
        struct syscall_request request AAL_DMA_ALIGN;
        request.number = n;
        
        // do a job similar to mcos/kernel/host.c:process_msg_prepare_process
        unsigned long s = (aal_mc_syscall_arg0(ctx)) & PAGE_MASK;
        unsigned long e = (s + aal_mc_syscall_arg1(ctx)
                           + PAGE_SIZE - 1) & PAGE_MASK;
		int range_npages = (e - s) >> PAGE_SHIFT;

        unsigned long pa;
        int r = aal_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, (void *)s, &pa);
        // va range is not overwrapped with existing mmap
        if(r != 0) {
            pa = virt_to_phys(aal_mc_alloc_pages(range_npages, 0)); // allocate pa
            //            lockr = aal_mc_spinlock_lock(&cpu_status_lock);
            add_process_memory_range(cpu_local_var(current), s, e, pa, 0); // register to page_table
            //            aal_mc_spinlock_unlock(&cpu_status_lock, lockr);
            kprintf("syscall.c,pa allocated=%lx\n", pa);
        } else {
            kprintf("syscall.c,pa found=%lx\n", pa);
            // we need to clear to avoid BSS contamination, even when reusing physical memory range
            // because ld.so performs mmap (va:0, size:va of second section including BSS, FIXED, prot:RX, offset:0)
	    // this causes contamination of BSS section when libc.so is large enough to reach BSS section
	    // then performs mmap (va:second section including BSS, FIXED, prot:RW, offset:second section in file)
            kprintf("syscall.c,clearing from %lx to %lx\n", s, e);
            memset((void*)phys_to_virt(pa), 0, e - s);
        }
        if ((aal_mc_syscall_arg3(ctx) & 0x20) == 0x20) {
            // #define MAP_ANONYMOUS  0x20
            kprintf("syscall.c,MAP_FIXED,MAP_ANONYMOUS\n");
            return aal_mc_syscall_arg0(ctx); // maybe we should return zero
        } else {
            kprintf("syscall.c,MAP_FIXED,!MAP_ANONYMOUS\n");
            // lseek(mmap_fd, mmap_off, SEEK_SET);
            // read(mmap_fd, mmap_addr, mmap_len);
            SYSCALL_ARGS_6(MO, D, D, D, D, D); 
            int r = do_syscall(&request, ctx);
            if(r == 0) { return aal_mc_syscall_arg0(ctx); } else { return -EINVAL; }
        }
    } else if ((aal_mc_syscall_arg3(ctx) & 0x20) == 0x20) {
        // #define MAP_ANONYMOUS  0x20
        kprintf("syscall.c,!MAP_FIXED,MAP_ANONYMOUS\n");
        unsigned long s = (region->map_end + PAGE_SIZE - 1) & PAGE_MASK;
		unsigned long len = (aal_mc_syscall_arg1(ctx) + PAGE_SIZE - 1) & PAGE_MASK;
        //        lockr = aal_mc_spinlock_lock(&cpu_status_lock);
		region->map_end = 
			extend_process_region(cpu_local_var(current),
			                      region->map_start,
			                      region->map_end,
			                      s + len);
        //        aal_mc_spinlock_unlock(&cpu_status_lock, lockr);
		kprintf("syscall.c,returning to caller...\n");
		if (region->map_end == s + len) { return s; } else { return -EINVAL; }

	} else if ((aal_mc_syscall_arg3(ctx) & 0x02) == 0x02) {
        // #define MAP_PRIVATE    0x02

        unsigned long s = (region->map_end + PAGE_SIZE - 1) & PAGE_MASK;
		unsigned long len = (aal_mc_syscall_arg1(ctx) + PAGE_SIZE - 1) & PAGE_MASK;
        //        lockr = aal_mc_spinlock_lock(&cpu_status_lock);
		region->map_end = 
			extend_process_region(cpu_local_var(current),
			                      region->map_start,
			                      region->map_end,
			                      s + len);
        //        aal_mc_spinlock_unlock(&cpu_status_lock, lockr);
		if (region->map_end != s + len) { return -EINVAL; }

        struct syscall_request request AAL_DMA_ALIGN;
        request.number = n;

        kprintf("syscall.c,!MAP_FIXED,!MAP_ANONYMOUS,MAP_PRIVATE\n");
        // lseek(mmap_fd, mmap_off, SEEK_SET);
        // read(mmap_fd, mmap_addr, mmap_len);
        SYSCALL_ARGS_6(MO, D, D, D, D, D); 
        // overwriting request.args[0]
        unsigned long __phys;                                      
        if (aal_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, (void *)s, &__phys)) {
            return -EFAULT; 
        }                 
        request.args[0] = __phys;
        
        int r = do_syscall(&request, ctx);
        if(r == 0) { return s; } else { return -EINVAL; }
    }
	dkprintf("mmap flags not supported: fd = %lx, %lx\n",
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

SYSCALL_DECLARE(mprotect)
{
	dkprintf("mprotect returns 0\n");
	return 0;
}


SYSCALL_DECLARE(getpid)
{
	return cpu_local_var(current)->pid;
}

SYSCALL_DECLARE(uname)
{
	SYSCALL_HEADER;
	unsigned long phys;
	int ret;

	if (aal_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, 
	                           (void *)aal_mc_syscall_arg0(ctx), &phys)) {
		return -EFAULT;
	}

	request.number = n;
	request.args[0] = phys;

	ret = do_syscall(&request, ctx);

	return ret;
}

long sys_getxid(int n, aal_mc_user_context_t *ctx)
{
	struct syscall_request request AAL_DMA_ALIGN;

	request.number = n;

	return do_syscall(&request, ctx);
}

long do_arch_prctl(unsigned long code, unsigned long address)
{
	int err = 0;
	enum aal_asr_type type;

	switch (code) {
		case ARCH_SET_FS:
		case ARCH_GET_FS:
			type = AAL_ASR_X86_FS;
			break;
		case ARCH_GET_GS:
			type = AAL_ASR_X86_GS;
			break;
		case ARCH_SET_GS:
			return -ENOTSUPP;
		default:
			return -EINVAL;
	}

	switch (code) {
		case ARCH_SET_FS:
			kprintf("[%d] arch_prctl: ARCH_SET_FS: 0x%lX\n",
			        aal_mc_get_processor_id(), address);
			cpu_local_var(current)->thread.tlsblock_base = address;
			err = aal_mc_arch_set_special_register(type, address);
			break;
		case ARCH_SET_GS:
			err = aal_mc_arch_set_special_register(type, address);
			break;
		case ARCH_GET_FS:
		case ARCH_GET_GS:
			err = aal_mc_arch_get_special_register(type,
												   (unsigned long*)address);
			break;
		default:
			break;
	}

	return err;
}


SYSCALL_DECLARE(arch_prctl)
{
	return do_arch_prctl(aal_mc_syscall_arg0(ctx), 
	                     aal_mc_syscall_arg1(ctx));
}


SYSCALL_DECLARE(clone)
{
	int i;
	int cpuid = -1;
	int clone_flags = aal_mc_syscall_arg0(ctx);
	//unsigned long	flags;	/* spinlock */
	struct aal_mc_cpu_info *cpu_info = aal_mc_get_cpu_info();
	struct process *new;
	
	dkprintf("[%d] clone(): stack_pointr: 0x%lX\n",
	         aal_mc_get_processor_id(), 
			 (unsigned long)aal_mc_syscall_arg1(ctx));

	//flags = aal_mc_spinlock_lock(&cpu_status_lock);
	for (i = 0; i < cpu_info->ncpus; i++) {
		if (get_cpu_local_var(i)->status == CPU_STATUS_IDLE) {
			cpuid = i;
			break;
		}
	}

	if (cpuid < 0) 
		return -EAGAIN;
	
	new = clone_process(cpu_local_var(current), aal_mc_syscall_pc(ctx),
	                    aal_mc_syscall_arg1(ctx));
	
	if (!new) {
		return -ENOMEM;
	}

	/* Allocate new pid */
	new->pid = aal_atomic_inc_return(&pid_cnt);
	
	if (clone_flags & CLONE_PARENT_SETTID) {
		dkprintf("clone_flags & CLONE_PARENT_SETTID: 0x%lX\n",
		         (unsigned long)aal_mc_syscall_arg2(ctx));
		
		*(int*)aal_mc_syscall_arg2(ctx) = new->pid;
	}
	
	if (clone_flags & CLONE_CHILD_CLEARTID) {
		dkprintf("clone_flags & CLONE_CHILD_CLEARTID: 0x%lX\n", 
			     (unsigned long)aal_mc_syscall_arg3(ctx));

		new->thread.clear_child_tid = (int*)aal_mc_syscall_arg3(ctx);
	}
	
	if (clone_flags & CLONE_SETTLS) {
		dkprintf("clone_flags & CLONE_SETTLS: 0x%lX\n", 
			     (unsigned long)aal_mc_syscall_arg4(ctx));
		
		new->thread.tlsblock_base = 
			(unsigned long)aal_mc_syscall_arg4(ctx);
	}
	else { 
		new->thread.tlsblock_base = 
			cpu_local_var(current)->thread.tlsblock_base;
	}

	aal_mc_syscall_ret(new->uctx) = 0;
	
	dkprintf("clone: kicking scheduler!\n");
	runq_add_proc(new, cpuid);

	//while (1) { cpu_halt(); }
#if 0
	aal_mc_syscall_ret(new->uctx) = 0;

	/* Hope it is scheduled after... :) */
	request.number = n;
	request.args[0] = (unsigned long)new;
	/* Sync */
	do_syscall(&request, ctx);
	dkprintf("Clone ret.\n");
#endif

	return new->pid;
}

SYSCALL_DECLARE(set_tid_address)
{
	cpu_local_var(current)->thread.clear_child_tid = 
	                        (int*)aal_mc_syscall_arg2(ctx);

	return cpu_local_var(current)->pid;
}


SYSCALL_DECLARE(set_robust_list)
{
	return -ENOSYS;
}

SYSCALL_DECLARE(writev)
{
	/* Adhoc implementation of writev calling write sequentially */
	struct syscall_request request AAL_DMA_ALIGN;
	unsigned long seg;
	size_t seg_ret, ret = 0;
	
	int fd = aal_mc_syscall_arg0(ctx);
	struct iovec *iov = (struct iovec*)aal_mc_syscall_arg1(ctx);
	unsigned long nr_segs = aal_mc_syscall_arg2(ctx);

	for (seg = 0; seg < nr_segs; ++seg) {
		unsigned long __phys; 
		
		if (aal_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, 
	                           (void *)iov[seg].iov_base, &__phys)) {
			return -EFAULT;
		}
		
		request.number = 1; /* write */
		request.args[0] = fd;
		request.args[1] = __phys;
		request.args[2] = iov[seg].iov_len;

		seg_ret = do_syscall(&request, ctx);
		
		if (seg_ret < 0) {
			ret = -EFAULT;
			break;
		}
		
		ret += seg_ret;
	}

	return ret;
}

SYSCALL_DECLARE(futex)
{
	// TODO: timespec support!
	//struct timespec _utime;
	uint64_t timeout = 1000; // MAX_SCHEDULE_TIMEOUT;
	uint32_t val2 = 0;

	uint32_t *uaddr = (uint32_t *)aal_mc_syscall_arg0(ctx);
	int op = (int)aal_mc_syscall_arg1(ctx);
	uint32_t val = (uint32_t)aal_mc_syscall_arg2(ctx);
	//struct timespec __user *utime = aal_mc_syscall_arg3(ctx);
	uint32_t *uaddr2 = (uint32_t *)aal_mc_syscall_arg4(ctx);
	uint32_t val3 = (uint32_t)aal_mc_syscall_arg5(ctx);

	/* Mask off the FUTEX_PRIVATE_FLAG,
	 * assume all futexes are address space private */
	op = (op & FUTEX_CMD_MASK);

#if 0 
	if (utime && (op == FUTEX_WAIT)) {
		if (copy_from_user(&_utime, utime, sizeof(_utime)) != 0)
			return -EFAULT;
		if (!timespec_valid(&_utime))
			return -EINVAL;
		timeout = timespec_to_ns(_utime);
	}
#endif

	/* Requeue parameter in 'utime' if op == FUTEX_CMP_REQUEUE.
	 * number of waiters to wake in 'utime' if op == FUTEX_WAKE_OP. */
	if (op == FUTEX_CMP_REQUEUE || op == FUTEX_WAKE_OP)
		val2 = (uint32_t) (unsigned long) aal_mc_syscall_arg3(ctx);

	return futex(uaddr, op, val, timeout, uaddr2, val2, val3);
}

SYSCALL_DECLARE(exit)
{
	/* If there is a clear_child_tid address set, clear it and wake it.
	 * This unblocks any pthread_join() waiters. */
	if (cpu_local_var(current)->thread.clear_child_tid) {
		
		kprintf("exit clear_child!\n");

		*cpu_local_var(current)->thread.clear_child_tid = 0;
		barrier();
		futex((uint32_t *)cpu_local_var(current)->thread.clear_child_tid, 
		      FUTEX_WAKE, 1, 0, NULL, 0, 0);
	}
	
	runq_del_proc(cpu_local_var(current), cpu_local_var(current)->cpu_id);
	free_process_memory(cpu_local_var(current));

	cpu_local_var(current) = NULL; 
	schedule();
	
	return 0;
}

SYSCALL_DECLARE(getrlimit)
{
	int ret;
	int resource = aal_mc_syscall_arg0(ctx);
	struct rlimit *rlm = (struct rlimit *)aal_mc_syscall_arg1(ctx);

	switch (resource) {

	case RLIMIT_STACK:

		dkprintf("[%d] getrlimit() RLIMIT_STACK\n", aal_mc_get_processor_id());
		rlm->rlim_cur = (512*4096);  /* Linux provides 8MB */
		rlm->rlim_max = (1024*1024*1024);
		ret = 0;
		break;

	default:

		return -ENOSYS;
	}

	return ret;
}

SYSCALL_DECLARE(sched_getaffinity)
{
	//int pid = (int)aal_mc_syscall_arg0(ctx);
	//int size = (int)aal_mc_syscall_arg1(ctx);
	int cpu_id;
	cpu_set_t *mask = (cpu_set_t *)aal_mc_syscall_arg2(ctx);

	CPU_ZERO(mask);
	for (cpu_id = 0; cpu_id < 120; ++cpu_id)
		CPU_SET(cpu_id, mask);

	dkprintf("sched_getaffinity returns full mask\n");

	return 0;
}


SYSCALL_DECLARE(noop)
{
	kprintf("noop() \n");
	return -EFAULT;
}

static long (*syscall_table[])(int, aal_mc_user_context_t *) = {
	[0] = sys_read,
	[1] = sys_write,
	[2] = sys_open,
	[3] = sys_close,
	[4] = sys_stat,
	[5] = sys_fstat,
	[8] = sys_lseek,
	[9] = sys_mmap,
	[10] = sys_mprotect,
	[11] = sys_munmap,
	[12] = sys_brk,
	[14] = sys_noop,
	[16] = sys_ioctl,
	[17] = sys_pread,
	[18] = sys_pwrite,
	[20] = sys_writev,
	[28] = sys_noop,
	[39] = sys_getpid,
	[56] = sys_clone,
	[60] = sys_exit,
	[63] = sys_uname,
	[96] = sys_gettimeofday,
	[97]  = sys_getrlimit,
	[102] = sys_getxid,
	[104] = sys_getxid,
	[107] = sys_getxid,
	[108] = sys_getxid,
	[110] = sys_getxid,
	[111] = sys_getxid,
	[158] = sys_arch_prctl,
	[202] = sys_futex,
	[204] = sys_sched_getaffinity,
	[218] = sys_set_tid_address,
	[231] = sys_exit_group,
	[273] = sys_set_robust_list,
	[288] = NULL,
};

#if 0

aal_spinlock_t cpu_status_lock;

static int clone_init(void)
{
	unsigned long flags;

	aal_mc_spinlock_init(&cpu_status_lock);
	
	return 0;
}

#endif

long syscall(int num, aal_mc_user_context_t *ctx)
{
	long l;

	cpu_enable_interrupt();

	dkprintf("SC(%d)[%3d](%lx, %lx) @ %lx | %lx = ", 
	        aal_mc_get_processor_id(),
	        num,
	        aal_mc_syscall_arg0(ctx), aal_mc_syscall_arg1(ctx),
	        aal_mc_syscall_pc(ctx), aal_mc_syscall_sp(ctx));

	if (syscall_table[num]) {
		l = syscall_table[num](num, ctx);
		
		dkprintf("SC(%d)[%3d] ret: %d\n", 
				aal_mc_get_processor_id(), num, l);
	} else {
		dkprintf("USC[%3d](%lx, %lx, %lx, %lx, %lx) @ %lx | %lx\n", num,
		        aal_mc_syscall_arg0(ctx), aal_mc_syscall_arg1(ctx),
		        aal_mc_syscall_arg2(ctx), aal_mc_syscall_arg3(ctx),
		        aal_mc_syscall_arg4(ctx), aal_mc_syscall_pc(ctx),
		        aal_mc_syscall_sp(ctx));
		//while(1);
		l = -ENOSYS;
	}
	
	return l;
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

