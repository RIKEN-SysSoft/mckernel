#include <types.h>
#include <kmsg.h>
#include <ihk/cpu.h>
#include <cpulocal.h>
#include <ihk/mm.h>
#include <ihk/debug.h>
#include <ihk/ikc.h>
#include <errno.h>
#include <cls.h>
#include <syscall.h>
#include <page.h>
#include <amemcpy.h>
#include <uio.h>
#include <ihk/lock.h>
#include <ctype.h>
#include <waitq.h>
#include <rlimit.h>
#include <affinity.h>
#include <time.h>
#include <ihk/perfctr.h>
#include <mman.h>

/* Headers taken from kitten LWK */
#include <lwk/stddef.h>
#include <futex.h>

#define SYSCALL_BY_IKC

//#define DEBUG_PRINT_SC

#ifdef DEBUG_PRINT_SC
#define dkprintf kprintf
#else
#define dkprintf(...)
#endif

static ihk_atomic_t pid_cnt = IHK_ATOMIC_INIT(1024);

/* generate system call handler's prototypes */
#define	SYSCALL_HANDLED(number,name)	extern long sys_##name(int n, ihk_mc_user_context_t *ctx);
#define	SYSCALL_DELEGATED(number,name)
#include <syscall_list.h>
#undef	SYSCALL_HANDLED
#undef	SYSCALL_DELEGATED

/* generate syscall_table[] */
static long (*syscall_table[])(int, ihk_mc_user_context_t *) = {
#define	SYSCALL_HANDLED(number,name)	[number] = &sys_##name,
#define	SYSCALL_DELEGATED(number,name)
#include <syscall_list.h>
#undef	SYSCALL_HANDLED
#undef	SYSCALL_DELEGATED
};

/* generate syscall_name[] */
#define	MCKERNEL_UNUSED	__attribute__ ((unused))
static char *syscall_name[] MCKERNEL_UNUSED = {
#define	DECLARATOR(number,name)		[number] = #name,
#define	SYSCALL_HANDLED(number,name)	DECLARATOR(number,sys_##name)
#define	SYSCALL_DELEGATED(number,name)	DECLARATOR(number,sys_##name)
#include <syscall_list.h>
#undef	DECLARATOR
#undef	SYSCALL_HANDLED
#undef	SYSCALL_DELEGATED
};

#ifdef DCFA_KMOD
static void do_mod_exit(int status);
#endif

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

	w = ihk_mc_get_processor_id() + 1;

	memcpy_async_wait(&fin);

	cpu_local_var(scp).request_va->valid = 1;
	*(unsigned int *)cpu_local_var(scp).doorbell_va = w;

#ifdef SYSCALL_BY_IKC
	packet.msg = SCD_MSG_SYSCALL_ONESIDE;
	packet.ref = ihk_mc_get_processor_id();
	packet.arg = cpu_local_var(scp).request_rpa;
	
	ihk_ikc_send(cpu_local_var(syscall_channel), &packet, 0); 
#endif
}


int do_syscall(struct syscall_request *req, ihk_mc_user_context_t *ctx)
{
	struct syscall_response *res = cpu_local_var(scp).response_va;

	dkprintf("SC(%d)[%3d] sending syscall\n",
	        ihk_mc_get_processor_id(),
	        req->number);

	send_syscall(req);

	dkprintf("SC(%d)[%3d] waiting for host.. \n", 
	        ihk_mc_get_processor_id(),
	        req->number);
	
	while (!res->status) {
		cpu_pause();
	}
	
	dkprintf("SC(%d)[%3d] got host reply: %d \n", 
	        ihk_mc_get_processor_id(),
	        req->number, res->ret);

	return res->ret;
}

long syscall_generic_forwarding(int n, ihk_mc_user_context_t *ctx)
{
	SYSCALL_HEADER;
	dkprintf("syscall_generic_forwarding(%d)\n", n);
	SYSCALL_ARGS_6(D,D,D,D,D,D);
	SYSCALL_FOOTER;
}

SYSCALL_DECLARE(open)
{

	SYSCALL_HEADER;
	dkprintf("open: %s\n", (char*)ihk_mc_syscall_arg0(ctx));
	SYSCALL_ARGS_3(MI, D, D);
	SYSCALL_FOOTER;
}

SYSCALL_DECLARE(exit_group)
{
	SYSCALL_HEADER;
	struct process *proc = cpu_local_var(current);

#ifdef DCFA_KMOD
	do_mod_exit((int)ihk_mc_syscall_arg0(ctx));
#endif

	/* XXX: send SIGKILL to all threads in this process */

	do_syscall(&request, ctx);

#define	IS_DETACHED_PROCESS(proc)	(1)	/* should be implemented in the future */
	proc->status = PS_ZOMBIE;
	if (IS_DETACHED_PROCESS(proc)) {
		/* release a reference for wait(2) */
		proc->status = PS_EXITED;
		free_process(proc);
	}

	schedule();

	return 0;
}

// MIC:9 linux:90
SYSCALL_DECLARE(mmap)
{
	struct vm_regions *region = &cpu_local_var(current)->vm->region;
	void *va;
	const unsigned long prot_flags = VR_PROT_READ | VR_PROT_WRITE | VR_PROT_EXEC;

    dkprintf("syscall.c,mmap,addr=%lx,len=%lx,prot=%lx,flags=%x,fd=%x,offset=%lx\n",
            ihk_mc_syscall_arg0(ctx), ihk_mc_syscall_arg1(ctx),
            ihk_mc_syscall_arg2(ctx), ihk_mc_syscall_arg3(ctx),
            ihk_mc_syscall_arg4(ctx), ihk_mc_syscall_arg5(ctx)
            );
    //kprintf("syscall.c,mmap,dumping kmsg...\n");
    //    send_kmsg(ctx);
    //    return -EINVAL; // debug
    
    if((ihk_mc_syscall_arg3(ctx) & 0x10) == 0x10) {
        // libc/sysdeps/unix/sysv/linux/x86_64/bits/mman.h
        // #define MAP_FIXED  0x10
        // use the given vaddr as is
        struct syscall_request request IHK_DMA_ALIGN;
        request.number = n;
        
        // do a job similar to mcos/kernel/host.c:process_msg_prepare_process
        unsigned long s = (ihk_mc_syscall_arg0(ctx)) & PAGE_MASK;
        unsigned long e = (s + ihk_mc_syscall_arg1(ctx)
                           + PAGE_SIZE - 1) & PAGE_MASK;
		int range_npages = (e - s) >> PAGE_SHIFT;

        unsigned long pa;
        int r = ihk_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, (void *)s, &pa);
        // va range is not overwrapped with existing mmap
        if(r != 0) {

#ifdef USE_LARGE_PAGES
			// use large pages if mapping is big enough
			if (e - s >= LARGE_PAGE_SIZE) {
				unsigned long p;
				unsigned long p_aligned;
				unsigned long s_orig = s;
				unsigned long head_space = 0;

				// compute head space before the first large page aligned
				// virtual address
				if ((s & (LARGE_PAGE_SIZE - 1)) != 0) {
					s = (s + (LARGE_PAGE_SIZE - 1)) & LARGE_PAGE_MASK;
					head_space = (s - s_orig);	
				}

				e = (e + (LARGE_PAGE_SIZE - 1)) & LARGE_PAGE_MASK;
				if((p = (unsigned long)ihk_mc_alloc_pages(
						(e - s + 2 * LARGE_PAGE_SIZE) >> PAGE_SHIFT, IHK_MC_AP_NOWAIT)) == (unsigned long)NULL) {
					return -ENOMEM;
				}

				p_aligned = (p + LARGE_PAGE_SIZE + (LARGE_PAGE_SIZE - 1)) 
					& LARGE_PAGE_MASK;

				// add range, mapping
				if(add_process_memory_range(cpu_local_var(current), s_orig, e,
						virt_to_phys((void *)(p_aligned - head_space)), prot_flags) != 0){
					ihk_mc_free_pages((void *)p, range_npages);
					return -ENOMEM;
				}

				dkprintf("largePTE area: 0x%lX - 0x%lX (s: %lu) -> 0x%lX -\n",
						s_orig, e, (e - s_orig), 
						virt_to_phys((void *)(p_aligned - head_space)));
			}
			else {
#endif
				// allocate physical address
				if((va = ihk_mc_alloc_pages(range_npages, IHK_MC_AP_NOWAIT)) == NULL){
					return -ENOMEM;
				}
				pa = virt_to_phys(va); 

				// add page_table, add memory-range
				if(add_process_memory_range(cpu_local_var(current), s, e, pa, prot_flags) != 0){
					ihk_mc_free_pages(va, range_npages);
					return -ENOMEM;
				}

				dkprintf("syscall.c,pa allocated=%lx\n", pa);			
#ifdef USE_LARGE_PAGES
			}
#endif
        } else {
            dkprintf("syscall.c,pa found=%lx\n", pa);
            // we need to clear to avoid BSS contamination, even when reusing physical memory range
            // because ld.so performs mmap (va:0, size:va of second section including BSS, FIXED, prot:RX, offset:0)
	    // this causes contamination of BSS section when libc.so is large enough to reach BSS section
	    // then performs mmap (va:second section including BSS, FIXED, prot:RW, offset:second section in file)
            dkprintf("syscall.c,clearing from %lx to %lx\n", s, e);
            memset((void*)phys_to_virt(pa), 0, e - s);
        }
        if ((ihk_mc_syscall_arg3(ctx) & 0x20) == 0x20) {
            // #define MAP_ANONYMOUS  0x20
            dkprintf("syscall.c,MAP_FIXED,MAP_ANONYMOUS\n");
            return ihk_mc_syscall_arg0(ctx); // maybe we should return zero
        } else {
            dkprintf("syscall.c,MAP_FIXED,!MAP_ANONYMOUS\n");
            // lseek(mmap_fd, mmap_off, SEEK_SET);
            // read(mmap_fd, mmap_addr, mmap_len);
            SYSCALL_ARGS_6(MO, D, D, D, D, D); 
            int r = do_syscall(&request, ctx);
            if(r == 0) { return ihk_mc_syscall_arg0(ctx); } else { return -EINVAL; }
        }
    } else if ((ihk_mc_syscall_arg3(ctx) & 0x20) == 0x20) {
        // #define MAP_ANONYMOUS  0x20
        dkprintf("syscall.c,!MAP_FIXED,MAP_ANONYMOUS\n");
        ihk_mc_spinlock_lock_noirq(&cpu_local_var(current)->vm->memory_range_lock);
        unsigned long s = (region->map_end + PAGE_SIZE - 1) & PAGE_MASK;
        unsigned long map_end_aligned = region->map_end;
		unsigned long len = (ihk_mc_syscall_arg1(ctx) + PAGE_SIZE - 1) & PAGE_MASK;
        dkprintf("syscall.c,mmap,len=%lx\n", len);

        unsigned long flag = 0; /* eager paging */

	flag |= VR_PROT_READ|VR_PROT_WRITE|VR_PROT_EXEC;
#if 1
        /* Intel OpenMP hack: it requests 128MB and munmap tail and head
           to create 64MB-aligned 64MB memory area 
           and then it tries to touch memory-block
           with offset of 0x10, 0x101008 */
        if(ihk_mc_syscall_arg1(ctx) == 1024*1024*64 || ihk_mc_syscall_arg1(ctx) == 1024*1024*128) {
            flag |= VR_DEMAND_PAGING; /* demand paging */
            kprintf("SC(%d)[mmap],!MAP_FIXED,MAP_ANONYMOUS,sz=%lx\n", ihk_mc_get_processor_id(), ihk_mc_syscall_arg1(ctx));
        }
        //if(ihk_mc_syscall_arg3(ctx) & 0x100) { flag |= 0x1000; };
#endif


#ifdef USE_NOCACHE_MMAP
		if ((ihk_mc_syscall_arg3(ctx) & 0x40) == 0x40) {
			dkprintf("syscall.c,mmap,nocache,len=%lx\n", len);
			region->map_end = extend_process_region(
					cpu_local_var(current), region->map_start, map_end_aligned,
					s + len, VR_IO_NOCACHE|(flag & ~VR_DEMAND_PAGING));
		}
		else
#endif
		{
			region->map_end =
				extend_process_region(cpu_local_var(current),
				                      region->map_start,
				                      map_end_aligned,
				                      s + len, flag);
		}

        if(ihk_mc_syscall_arg1(ctx) == 1024*1024*64 || ihk_mc_syscall_arg1(ctx) == 1024*1024*128) {
            kprintf("syscall.c,mmap,cpuid=%d,map_end-len=%lx,s+len=%lx,map_end=%lx\n", ihk_mc_get_processor_id(), region->map_end-len, s+len, region->map_end);
        }

        ihk_mc_spinlock_unlock_noirq(&cpu_local_var(current)->vm->memory_range_lock);

#ifdef USE_LARGE_PAGES
		if (region->map_end >= s + len) { 
			/* NOTE: extend_process_region() might have large page aligned */
			return region->map_end - len; 
		} 
#else
		if (region->map_end == s + len) return s;
#endif
		else { 
			return -EINVAL; 
		}

	} else if ((ihk_mc_syscall_arg3(ctx) & 0x02) == 0x02) {
        // #define MAP_PRIVATE    0x02

        ihk_mc_spinlock_lock_noirq(&cpu_local_var(current)->vm->memory_range_lock);

#if 1 /* takagidebug*/
        unsigned long amt_align = 0x100000; /* takagi */
        unsigned long s = ((region->map_end + amt_align - 1) & ~(amt_align - 1));
        unsigned long len = (ihk_mc_syscall_arg1(ctx) + PAGE_SIZE - 1) & PAGE_MASK;
	unsigned long flag = VR_PROT_READ|VR_PROT_WRITE|VR_PROT_EXEC;
        dkprintf("(%d),syscall.c,!MAP_FIXED,!MAP_ANONYMOUS,amt_align=%lx,s=%lx,len=%lx\n", ihk_mc_get_processor_id(), amt_align, s, len);
		region->map_end = 
			extend_process_region(cpu_local_var(current),
			                      region->map_start,
			                      s,
			                      s + len, flag);
#else
        unsigned long s = (region->map_end + PAGE_SIZE - 1) & PAGE_MASK;
		unsigned long len = (ihk_mc_syscall_arg1(ctx) + PAGE_SIZE - 1) & PAGE_MASK;
		region->map_end = 
			extend_process_region(cpu_local_var(current),
			                      region->map_start,
			                      region->map_end,
			                      s + len, flag);
#endif
        ihk_mc_spinlock_unlock_noirq(&cpu_local_var(current)->vm->memory_range_lock);
		if (region->map_end < s + len) { return -EINVAL; }
		s = region->map_end - len;

        struct syscall_request request IHK_DMA_ALIGN;
        request.number = n;

        dkprintf("syscall.c,!MAP_FIXED,!MAP_ANONYMOUS,MAP_PRIVATE\n");
        // lseek(mmap_fd, mmap_off, SEEK_SET);
        // read(mmap_fd, mmap_addr, mmap_len);
        SYSCALL_ARGS_6(D, D, D, D, D, D);
        // overwriting request.args[0]
        unsigned long __phys;                                      
        if (ihk_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, (void *)s, &__phys)) {
            return -EFAULT; 
        }                 
        request.args[0] = __phys;
        
        int r = do_syscall(&request, ctx);
        if(r == 0) { return s; } else { return -EINVAL; }
    }
	dkprintf("mmap flags not supported: fd = %lx, %lx\n",
	        ihk_mc_syscall_arg4(ctx), ihk_mc_syscall_arg5(ctx));
	while(1);
}

static int do_munmap(void *addr, size_t len)
{
	return remove_process_memory_range(
			cpu_local_var(current), (intptr_t)addr, (intptr_t)addr+len);
}

static int search_free_space(size_t len, intptr_t hint, intptr_t *addrp)
{
	struct process *proc = cpu_local_var(current);
	struct vm_regions *region = &proc->vm->region;
	intptr_t addr;
	struct vm_range *range;

	addr = hint;
	for (;;) {
#ifdef USE_LARGE_PAGES
		if (len >= LARGE_PAGE_SIZE) {
			addr = (addr + LARGE_PAGE_SIZE - 1) & LARGE_PAGE_MASK;
		}
#endif /* USE_LARGE_PAGES */

		if ((region->user_end <= addr)
				|| ((region->user_end - len) < addr)) {
			kprintf("search_free_space:no virtual: %lx %lx %lx\n",
					addr, len, region->user_end);
			return -ENOMEM;
		}

		range = lookup_process_memory_range(proc, addr, addr+len);
		if (range == NULL) {
			break;
		}
		addr = range->end;
	}

	*addrp = addr;
	return 0;
}

SYSCALL_DECLARE(new_mmap)
{
	const int supported_flags = 0
		| MAP_PRIVATE		// 02
		| MAP_FIXED		// 10
		| MAP_ANONYMOUS		// 20
		;
	const int ignored_flags = 0
#ifdef	USE_NOCACHE_MMAP
		| MAP_32BIT		// 40
#endif /* USE_NOCACHE_MMAP */
		| MAP_DENYWRITE		// 0800
		| MAP_NORESERVE		// 4000
		| MAP_STACK		// 00020000
		;
	const int error_flags = 0
		| MAP_SHARED		// 01
#ifndef	USE_NOCACHE_MMAP
		| MAP_32BIT		// 40
#endif /* ndef USE_NOCACHE_MMAP */
		| MAP_GROWSDOWN		// 0100
		| MAP_EXECUTABLE	// 1000
		| MAP_LOCKED		// 2000
		| MAP_POPULATE		// 8000
		| MAP_NONBLOCK		// 00010000
		| MAP_HUGETLB		// 00040000
		;

	const intptr_t addr0 = ihk_mc_syscall_arg0(ctx);
	const size_t len0 = ihk_mc_syscall_arg1(ctx);
	const int prot = ihk_mc_syscall_arg2(ctx);
	const int flags = ihk_mc_syscall_arg3(ctx);
	const int fd = ihk_mc_syscall_arg4(ctx);
	const off_t off = ihk_mc_syscall_arg5(ctx);

	struct process *proc = cpu_local_var(current);
	struct vm_regions *region = &proc->vm->region;
	intptr_t addr;
	size_t len;
	int error;
	intptr_t npages;
	int p2align;
	void *p;
	int vrflags;
	intptr_t phys;

	dkprintf("[%d]sys_mmap(%lx,%lx,%x,%x,%d,%lx)\n",
			ihk_mc_get_processor_id(),
			addr0, len0, prot, flags, fd, off);

	/* check constants for flags */
	if (1) {
		int dup_flags;

		dup_flags = (supported_flags & ignored_flags);
		dup_flags |= (ignored_flags & error_flags);
		dup_flags |= (error_flags & supported_flags);

		if (dup_flags) {
			kprintf("sys_mmap:duplicate flags: %lx\n", dup_flags);
			kprintf("s-flags: %08x\n", supported_flags);
			kprintf("i-flags: %08x\n", ignored_flags);
			kprintf("e-flags: %08x\n", error_flags);
			panic("sys_mmap:duplicate flags\n");
			/* no return */
		}
	}

	/* check arguments */
#define	VALID_DUMMY_ADDR	(region->user_start)
	addr = (flags & MAP_FIXED)? addr0: VALID_DUMMY_ADDR;
	len = (len0 + PAGE_SIZE - 1) & PAGE_MASK;
	if ((addr & (PAGE_SIZE - 1))
			|| (addr < region->user_start)
			|| (region->user_end <= addr)
			|| (len == 0)
			|| (len > (region->user_end - region->user_start))
			|| ((region->user_end - len) < addr)
			|| !(flags & (MAP_SHARED | MAP_PRIVATE))
			|| ((flags & MAP_SHARED) && (flags & MAP_PRIVATE))
			|| (off & (PAGE_SIZE - 1))) {
		kprintf("sys_mmap(%lx,%lx,%x,%x,%x,%lx):EINVAL\n",
				addr0, len0, prot, flags, fd, off);
		error = -EINVAL;
		goto out;
	}

	/* check not supported requests */
	if ((flags & error_flags)
			|| (flags & ~(supported_flags | ignored_flags))) {
		kprintf("sys_mmap(%lx,%lx,%x,%x,%x,%lx):unknown flags %lx\n",
				addr0, len0, prot, flags, fd, off,
				(flags & ~(supported_flags | ignored_flags)));
		error = -EINVAL;
		goto out;
	}

	ihk_mc_spinlock_lock_noirq(&proc->vm->memory_range_lock);

	if (flags & MAP_FIXED) {
		/* clear specified address range */
		error = do_munmap((void *)addr, len);
		if (error) {
			kprintf("sys_mmap:do_munmap(%lx,%lx) failed. %d\n",
					addr, len, error);
			ihk_mc_spinlock_unlock_noirq(&proc->vm->memory_range_lock);
			goto out;
		}
	}
	else {
		/* choose mapping address */
		error = search_free_space(len, region->map_end, &addr);
		if (error) {
			kprintf("sys_mmap:search_free_space(%lx,%lx) failed. %d\n",
					len, region->map_end, error);
			ihk_mc_spinlock_unlock_noirq(&proc->vm->memory_range_lock);
			goto out;
		}
		region->map_end = addr + len;
	}

	/* do the map */
	vrflags = VR_NONE;
	vrflags |= (prot & PROT_READ)? VR_PROT_READ: 0;
	vrflags |= (prot & PROT_WRITE)? VR_PROT_WRITE: 0;
	vrflags |= (prot & PROT_EXEC)? VR_PROT_EXEC: 0;
	if (flags & MAP_ANONYMOUS) {
		if (0) {
			/* dummy */
		}
#ifdef	USE_NOCACHE_MMAP
#define	X_MAP_NOCACHE	MAP_32BIT
		else if (flags & X_MAP_NOCACHE) {
			vrflags |= VR_IO_NOCACHE;
		}
#endif
		else if ((len == 64*1024*1024) || (len == 128*1024*1024)) {
			vrflags |= VR_DEMAND_PAGING;
		}
	}

	p = NULL;
	phys = 0;
	if (!(vrflags & VR_DEMAND_PAGING)) {
		npages = len >> PAGE_SHIFT;
		p2align = PAGE_P2ALIGN;
#ifdef USE_LARGE_PAGES
		if ((len >= LARGE_PAGE_SIZE)
				&& ((addr & (LARGE_PAGE_SIZE - 1)) == 0)) {
			p2align = LARGE_PAGE_P2ALIGN;
		}
#endif /* USE_LARGE_PAGES */
		p = ihk_mc_alloc_aligned_pages(npages, p2align, IHK_MC_AP_NOWAIT);
		if (p == NULL) {
			kprintf("sys_mmap:allocate_pages(%d,%d) failed.\n",
					npages, p2align);
			ihk_mc_spinlock_unlock_noirq(&proc->vm->memory_range_lock);
			error = -ENOMEM;
			goto out;
		}
		phys = virt_to_phys(p);
	}

	error = add_process_memory_range(proc, addr, addr+len, phys, vrflags);
	if (error) {
		kprintf("sys_mmap:add_process_memory_range"
				"(%p,%lx,%lx,%lx,%lx) failed %d\n",
				proc, addr, addr+len,
				virt_to_phys(p), vrflags, error);
		ihk_mc_spinlock_unlock_noirq(&proc->vm->memory_range_lock);
		if (p != NULL) {
			ihk_mc_free_pages(p, npages);
		}
		goto out;
	}

	ihk_mc_spinlock_unlock_noirq(&proc->vm->memory_range_lock);

	/* read page with pread64() */
	if (!(flags & MAP_ANONYMOUS)) {
		ihk_mc_user_context_t ctx2;
		ssize_t ss;

		ihk_mc_syscall_arg0(&ctx2) = fd;
		ihk_mc_syscall_arg1(&ctx2) = addr;
		ihk_mc_syscall_arg2(&ctx2) = len;
		ihk_mc_syscall_arg3(&ctx2) = off;

		ss = syscall_generic_forwarding(__NR_pread64, &ctx2);
		if (ss < 0) {
			kprintf("sys_mmap:pread(%d,%lx,%lx,%lx) failed %ld\n",
					fd, addr, len, off, (long)ss);
			error = do_munmap((void *)addr, len);
			if (error) {
				kprintf("sys_mmap:do_munmap(%lx,%lx) failed. %d\n",
						addr, len, error);
				/* through */
			}
			error = ss;
			goto out;
		}
	}

	error = 0;
out:
	if (error) {
		kprintf("[%d]sys_mmap(%lx,%lx,%x,%x,%d,%lx): %ld %lx\n",
				ihk_mc_get_processor_id(),
				addr0, len0, prot, flags, fd, off, error, addr);
	}
	return (!error)? addr: error;
}

SYSCALL_DECLARE(munmap)
{
	void * const addr = (void *)ihk_mc_syscall_arg0(ctx);
	const size_t len = ihk_mc_syscall_arg1(ctx);
	int error;

	ihk_mc_spinlock_lock_noirq(&cpu_local_var(current)->vm->memory_range_lock);
	error = do_munmap(addr, len);
	ihk_mc_spinlock_unlock_noirq(&cpu_local_var(current)->vm->memory_range_lock);

	return error;
}

SYSCALL_DECLARE(mprotect)
{
	dkprintf("mprotect returns 0\n");
	return 0;
}

SYSCALL_DECLARE(brk)
{
	unsigned long address = ihk_mc_syscall_arg0(ctx);
	struct vm_regions *region = &cpu_local_var(current)->vm->region;
	unsigned long r;

	dkprintf("SC(%d)[sys_brk] brk_start=%lx,end=%lx\n",
			ihk_mc_get_processor_id(), region->brk_start, region->brk_end);

	/* brk change fail, including glibc trick brk(0) to obtain current brk */
	if(address < region->brk_start) {
		r = region->brk_end;
		goto out;
	}

	/* brk change fail, because we don't shrink memory region  */
	if(address < region->brk_end) {
		r = region->brk_end;
		goto out;
	}

	/* try to extend memory region */
	ihk_mc_spinlock_lock_noirq(&cpu_local_var(current)->vm->memory_range_lock);
	region->brk_end = extend_process_region(cpu_local_var(current),
			region->brk_start, region->brk_end, address,
			VR_PROT_READ|VR_PROT_WRITE);
	ihk_mc_spinlock_unlock_noirq(&cpu_local_var(current)->vm->memory_range_lock);
	dkprintf("SC(%d)[sys_brk] brk_end set to %lx\n",
			ihk_mc_get_processor_id(), region->brk_end);

	r = region->brk_end;

out:
	return r;
}

SYSCALL_DECLARE(getpid)
{
	return cpu_local_var(current)->pid;
}

long do_arch_prctl(unsigned long code, unsigned long address)
{
	int err = 0;
	enum ihk_asr_type type;

	switch (code) {
		case ARCH_SET_FS:
		case ARCH_GET_FS:
			type = IHK_ASR_X86_FS;
			break;
		case ARCH_GET_GS:
			type = IHK_ASR_X86_GS;
			break;
		case ARCH_SET_GS:
			return -ENOTSUPP;
		default:
			return -EINVAL;
	}

	switch (code) {
		case ARCH_SET_FS:
			dkprintf("[%d] arch_prctl: ARCH_SET_FS: 0x%lX\n",
			        ihk_mc_get_processor_id(), address);
			cpu_local_var(current)->thread.tlsblock_base = address;
			err = ihk_mc_arch_set_special_register(type, address);
			break;
		case ARCH_SET_GS:
			err = ihk_mc_arch_set_special_register(type, address);
			break;
		case ARCH_GET_FS:
		case ARCH_GET_GS:
			err = ihk_mc_arch_get_special_register(type,
												   (unsigned long*)address);
			break;
		default:
			break;
	}

	return err;
}


SYSCALL_DECLARE(arch_prctl)
{
	return do_arch_prctl(ihk_mc_syscall_arg0(ctx), 
	                     ihk_mc_syscall_arg1(ctx));
}


SYSCALL_DECLARE(clone)
{
	int cpuid;
	int clone_flags = ihk_mc_syscall_arg0(ctx);
	struct process *new;
	
	dkprintf("[%d] clone(): stack_pointr: 0x%lX\n",
	         ihk_mc_get_processor_id(), 
			 (unsigned long)ihk_mc_syscall_arg1(ctx));

    cpuid = obtain_clone_cpuid();

	new = clone_process(cpu_local_var(current), ihk_mc_syscall_pc(ctx),
	                    ihk_mc_syscall_arg1(ctx));
	
	if (!new) {
		return -ENOMEM;
	}

	/* Allocate new pid */
	new->pid = ihk_atomic_inc_return(&pid_cnt);
	
	if (clone_flags & CLONE_PARENT_SETTID) {
		dkprintf("clone_flags & CLONE_PARENT_SETTID: 0x%lX\n",
		         (unsigned long)ihk_mc_syscall_arg2(ctx));
		
		*(int*)ihk_mc_syscall_arg2(ctx) = new->pid;
	}
	
	if (clone_flags & CLONE_CHILD_CLEARTID) {
		dkprintf("clone_flags & CLONE_CHILD_CLEARTID: 0x%lX\n", 
			     (unsigned long)ihk_mc_syscall_arg3(ctx));

		new->thread.clear_child_tid = (int*)ihk_mc_syscall_arg3(ctx);
	}
	
	if (clone_flags & CLONE_SETTLS) {
		dkprintf("clone_flags & CLONE_SETTLS: 0x%lX\n", 
			     (unsigned long)ihk_mc_syscall_arg4(ctx));
		
		new->thread.tlsblock_base = 
			(unsigned long)ihk_mc_syscall_arg4(ctx);
	}
	else { 
		new->thread.tlsblock_base = 
			cpu_local_var(current)->thread.tlsblock_base;
	}

	ihk_mc_syscall_ret(new->uctx) = 0;
	
	dkprintf("clone: kicking scheduler!,cpuid=%d\n", cpuid);
	runq_add_proc(new, cpuid);

	return new->pid;
}

SYSCALL_DECLARE(set_tid_address)
{
	cpu_local_var(current)->thread.clear_child_tid = 
	                        (int*)ihk_mc_syscall_arg2(ctx);

	return cpu_local_var(current)->pid;
}

SYSCALL_DECLARE(kill)
{
	int pid = ihk_mc_syscall_arg0(ctx);
	int sig = ihk_mc_syscall_arg1(ctx);

	struct process *proc = cpu_local_var(current);

	if(proc->pid == pid){
		proc->signal = sig;
		return 0;
	}

	if(pid <= 0) { return -EINVAL; }
	// search pid
	// check kill permission
	if(sig == 0) {
		return 0;
	} else {
		return -EPERM;
	}
}

// see linux-2.6.34.13/kernel/signal.c
SYSCALL_DECLARE(tgkill)
{
    int tgid = ihk_mc_syscall_arg0(ctx);
    int pid = ihk_mc_syscall_arg1(ctx);
    int sig = ihk_mc_syscall_arg2(ctx);

    if(pid <= 0 || tgid <= 0) { return -EINVAL; }
    // search pid
    // check kill permission
    if(sig == 0) {
        return 0;
    } else {
        return -EPERM; 
    }
}

SYSCALL_DECLARE(set_robust_list)
{
	return -ENOSYS;
}

int
do_sigaction(int sig, struct k_sigaction *act, struct k_sigaction *oact)
{
	struct process *proc = cpu_local_var(current);
	struct k_sigaction *k;
	// TODO: sigmask

	k = proc->sighandler->action + sig - 1;
	if(oact)
		memcpy(oact, k, sizeof(struct k_sigaction));
	if(act){
		memcpy(k, act, sizeof(struct k_sigaction));
	}
	return 0;
}

SYSCALL_DECLARE(rt_sigaction)
{
	int sig = ihk_mc_syscall_arg0(ctx);
	const struct sigaction *act = (const struct sigaction *)ihk_mc_syscall_arg1(ctx);
	struct sigaction *oact = (struct sigaction *)ihk_mc_syscall_arg2(ctx);
	size_t sigsetsize = ihk_mc_syscall_arg3(ctx);
	struct k_sigaction new_sa, old_sa;
	int rc;

	//if (sigsetsize != sizeof(sigset_t))
		//return -EINVAL;

	if(act)
		memcpy(&new_sa.sa, act, sizeof new_sa.sa);
	rc = do_sigaction(sig, act? &new_sa: NULL, oact? &old_sa: NULL);
	if(oact)
		memcpy(oact, &old_sa.sa, sizeof old_sa.sa);

	return rc;
}

static void
check_signal(unsigned long rc)
{
	struct process *proc = cpu_local_var(current);
	struct k_sigaction *k;
	int	sig = proc->signal;

	proc->signal = 0;
	if(sig){
		k = proc->sighandler->action + sig - 1;
		if(k->sa.sa_handler){
			unsigned long *usp; /* user stack */
			char *kspbottom;
			long	w;
			asm volatile ("movq %%gs:24,%0" : "=r" (usp));
			asm volatile ("movq %%gs:132,%0" : "=r" (kspbottom));
			memcpy(proc->sigstack, kspbottom - 120, 120);
			proc->sigrc = rc;
			usp--;
			*usp = (unsigned long)k->sa.sa_restorer;
			w = 56 + 3;
			asm volatile ("pushq %0" :: "r" (w));
			asm volatile ("pushq %0" :: "r" (usp));
			w = 1 << 9;
			asm volatile ("pushq %0" :: "r" (w));
			w = 48 + 3;
			asm volatile ("pushq %0" :: "r" (w));
			asm volatile ("pushq %0" :: "r" (k->sa.sa_handler));
			asm volatile ("iretq");
		}
	}
}

SYSCALL_DECLARE(rt_sigreturn)
{
	struct process *proc = cpu_local_var(current);
	char *kspbottom;
	asm volatile ("movq %%gs:132,%0" : "=r" (kspbottom));
	memcpy(kspbottom - 120, proc->sigstack, 120);

	return proc->sigrc;
}


SYSCALL_DECLARE(rt_sigprocmask)
{
    //  kprintf("sys_rt_sigprocmask called. returning zero...\n");
  return 0;
}
SYSCALL_DECLARE(madvise)
{
    //  kprintf("sys_madvise called. returning zero...\n");
  return 0;
}

SYSCALL_DECLARE(futex)
{
	uint64_t timeout = 0; // No timeout
	uint32_t val2 = 0;

	uint32_t *uaddr = (uint32_t *)ihk_mc_syscall_arg0(ctx);
	int op = (int)ihk_mc_syscall_arg1(ctx);
	uint32_t val = (uint32_t)ihk_mc_syscall_arg2(ctx);
	struct timespec *utime = (struct timespec*)ihk_mc_syscall_arg3(ctx);
	uint32_t *uaddr2 = (uint32_t *)ihk_mc_syscall_arg4(ctx);
	uint32_t val3 = (uint32_t)ihk_mc_syscall_arg5(ctx);
    
	/* Mask off the FUTEX_PRIVATE_FLAG,
	 * assume all futexes are address space private */
	op = (op & FUTEX_CMD_MASK);
	
	dkprintf("futex op=[%x, %s],uaddr=%lx, val=%x, utime=%lx, uaddr2=%lx, val3=%x, []=%x\n", 
	op,
	(op == FUTEX_WAIT) ? "FUTEX_WAIT" :
	(op == FUTEX_WAIT_BITSET) ? "FUTEX_WAIT_BITSET" :
	(op == FUTEX_WAKE) ? "FUTEX_WAKE" :
	(op == FUTEX_WAKE_OP) ? "FUTEX_WAKE_OP" :
	(op == FUTEX_WAKE_BITSET) ? "FUTEX_WAKE_BITSET" :
	(op == FUTEX_CMP_REQUEUE) ? "FUTEX_CMP_REQUEUE" :
	(op == FUTEX_REQUEUE) ? "FUTEX_REQUEUE (NOT IMPL!)" : "unknown",
	(unsigned long)uaddr, op, val, utime, uaddr2, val3, *uaddr);

	if (utime && (op == FUTEX_WAIT_BITSET || op == FUTEX_WAIT)) {
		struct syscall_request request IHK_DMA_ALIGN; 
		struct timeval tv_now;
		request.number = n;
		unsigned long __phys;                                          

		dkprintf("futex,utime and FUTEX_WAIT_*, uaddr=%lx, []=%x\n", (unsigned long)uaddr, *uaddr);

		if (ihk_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, 
					(void *)&tv_now, &__phys)) { 
			return -EFAULT; 
		}

		request.args[0] = __phys;               

		int r = do_syscall(&request, ctx);

		if (r < 0) {
			return -EFAULT;
		}

		dkprintf("futex, FUTEX_WAIT_*, arg3 != NULL, pc=%lx\n", (unsigned long)ihk_mc_syscall_pc(ctx));
		dkprintf("now->tv_sec=%016ld,tv_nsec=%016ld\n", tv_now.tv_sec, tv_now.tv_usec * 1000);
		dkprintf("utime->tv_sec=%016ld,tv_nsec=%016ld\n", utime->tv_sec, utime->tv_nsec);

		long nsec_now = ((long)tv_now.tv_sec * 1000000000ULL) + 
			tv_now.tv_usec * 1000;
		long nsec_timeout = ((long)utime->tv_sec * 1000000000ULL) + 
			utime->tv_nsec * 1;
		long diff_nsec = nsec_timeout - nsec_now;

		timeout = (diff_nsec / 1000) * 1100; // (usec * 1.1GHz)
		dkprintf("futex timeout: %lu\n", timeout);
	}

	/* Requeue parameter in 'utime' if op == FUTEX_CMP_REQUEUE.
	 * number of waiters to wake in 'utime' if op == FUTEX_WAKE_OP. */
	if (op == FUTEX_CMP_REQUEUE || op == FUTEX_WAKE_OP)
		val2 = (uint32_t) (unsigned long) ihk_mc_syscall_arg3(ctx);

	return futex(uaddr, op, val, timeout, uaddr2, val2, val3);
}

SYSCALL_DECLARE(exit)
{
	struct process *proc = cpu_local_var(current);

#ifdef DCFA_KMOD
	do_mod_exit((int)ihk_mc_syscall_arg0(ctx));
#endif

	/* XXX: for if all threads issued the exit(2) rather than exit_group(2),
	 *      exit(2) also should delegate.
	 */
	/* If there is a clear_child_tid address set, clear it and wake it.
	 * This unblocks any pthread_join() waiters. */
	if (proc->thread.clear_child_tid) {
		
		dkprintf("exit clear_child!\n");

		*proc->thread.clear_child_tid = 0;
		barrier();
		futex((uint32_t *)proc->thread.clear_child_tid,
		      FUTEX_WAKE, 1, 0, NULL, 0, 0);
	}
	
	proc->status = PS_ZOMBIE;
	if (IS_DETACHED_PROCESS(proc)) {
		/* release a reference for wait(2) */
		proc->status = PS_EXITED;
		free_process(proc);
	}

	schedule();
	
	return 0;
}

SYSCALL_DECLARE(getrlimit)
{
	int ret;
	int resource = ihk_mc_syscall_arg0(ctx);
	struct rlimit *rlm = (struct rlimit *)ihk_mc_syscall_arg1(ctx);

	switch (resource) {

	case RLIMIT_STACK:

		dkprintf("[%d] getrlimit() RLIMIT_STACK\n", ihk_mc_get_processor_id());
		rlm->rlim_cur = (512*4096);  /* Linux provides 8MB */
		rlm->rlim_max = (1024*1024*1024);
		ret = 0;
		break;

	default:

		return -ENOSYS;
	}

	return ret;
}

SYSCALL_DECLARE(sched_setaffinity)
{
#if 0
    int pid = (int)ihk_mc_syscall_arg0(ctx);
	unsigned int len = (unsigned int)ihk_mc_syscall_arg1(ctx);
#endif
    cpu_set_t *mask = (cpu_set_t *)ihk_mc_syscall_arg2(ctx);
	unsigned long __phys;
#if 0
    int i;
#endif
    /* TODO: check mask is in user's page table */
    if(!mask) { return -EFAULT; }
	if (ihk_mc_pt_virt_to_phys(cpu_local_var(current)->vm->page_table, 
	                           (void *)mask,
	                           &__phys)) {
		return -EFAULT;
	}
#if 0
    dkprintf("sched_setaffinity,\n");
    for(i = 0; i < len/sizeof(__cpu_mask); i++) {
        dkprintf("mask[%d]=%lx,", i, mask->__bits[i]);
    }
#endif
	return 0;
}

#define MIN2(x,y) (x) < (y) ? (x) : (y)
#define MIN3(x,y,z) MIN2(MIN2((x),(y)),MIN2((y),(z)))
// see linux-2.6.34.13/kernel/sched.c
SYSCALL_DECLARE(sched_getaffinity)
{
	//int pid = (int)ihk_mc_syscall_arg0(ctx);
	unsigned int len = (int)ihk_mc_syscall_arg1(ctx);
	//int cpu_id;
	cpu_set_t *mask = (cpu_set_t *)ihk_mc_syscall_arg2(ctx);
	struct ihk_mc_cpu_info *cpu_info = ihk_mc_get_cpu_info();
    if(len*8 < cpu_info->ncpus) { return -EINVAL; }
    if(len & (sizeof(unsigned long)-1)) { return -EINVAL; }
    int min_len = MIN2(len, sizeof(cpu_set_t));
    //int min_ncpus = MIN2(min_len*8, cpu_info->ncpus);

	CPU_ZERO_S(min_len, mask);
	CPU_SET_S(ihk_mc_get_hardware_processor_id(), min_len, mask);
	//for (cpu_id = 0; cpu_id < min_ncpus; ++cpu_id)
	//	CPU_SET_S(cpu_info->hw_ids[cpu_id], min_len, mask);

    //	dkprintf("sched_getaffinity returns full mask\n");

	return min_len;
}

SYSCALL_DECLARE(sched_yield)
{
	return -ENOSYS;
}

#ifdef DCFA_KMOD

#ifdef CMD_DCFA
extern int ibmic_cmd_syscall(char *uargs);
extern void ibmic_cmd_exit(int status);
#endif

#ifdef CMD_DCFAMPI
extern int dcfampi_cmd_syscall(char *uargs);
#endif

static int (*mod_call_table[]) (char *) = {
#ifdef CMD_DCFA
		[1] = ibmic_cmd_syscall,
#endif
#ifdef CMD_DCFAMPI
		[2] = dcfampi_cmd_syscall,
#endif
};

static void (*mod_exit_table[]) (int) = {
#ifdef CMD_DCFA
		[1] = ibmic_cmd_exit,
#endif
#ifdef CMD_DCFAMPI
		[2] = NULL,
#endif
};

SYSCALL_DECLARE(mod_call) {
	int mod_id;
	unsigned long long uargs;

	mod_id = ihk_mc_syscall_arg0(ctx);
	uargs = ihk_mc_syscall_arg1(ctx);

	dkprintf("mod_call id:%d, uargs=0x%llx, type=%s, command=%x\n", mod_id, uargs, mod_id==1?"ibmic":"dcfampi", *((uint32_t*)(((char*)uargs)+0)));

	if(mod_call_table[mod_id])
		return mod_call_table[mod_id]((char*)uargs);

	kprintf("ERROR! undefined mod_call id:%d\n", mod_id);

	return -ENOSYS;
}

static void do_mod_exit(int status){
	int i;
	for(i=1; i<=2; i++){
		if(mod_exit_table[i])
			mod_exit_table[i](status);
	}
}
#endif

/* select counter type */
SYSCALL_DECLARE(pmc_init)
{
    int counter = ihk_mc_syscall_arg0(ctx);

    enum ihk_perfctr_type type = (enum ihk_perfctr_type)ihk_mc_syscall_arg1(ctx);
    /* see ihk/manycore/generic/include/ihk/perfctr.h */

    int mode = PERFCTR_USER_MODE;

    return ihk_mc_perfctr_init(counter, type, mode);
}

SYSCALL_DECLARE(pmc_start)
{
    unsigned long counter = ihk_mc_syscall_arg0(ctx);
    return ihk_mc_perfctr_start(1 << counter);
}

SYSCALL_DECLARE(pmc_stop)
{
    unsigned long counter = ihk_mc_syscall_arg0(ctx);
    return ihk_mc_perfctr_stop(1 << counter);
}

SYSCALL_DECLARE(pmc_reset)
{
    int counter = ihk_mc_syscall_arg0(ctx);
    return ihk_mc_perfctr_reset(counter);
}

long syscall(int num, ihk_mc_user_context_t *ctx)
{
	long l;

	cpu_enable_interrupt();


#if 0
	if(num != 24)  // if not sched_yield
#endif
	dkprintf("SC(%d:%d)[%3d=%s](%lx, %lx,%lx, %lx, %lx, %lx)@%lx,sp:%lx",
             ihk_mc_get_processor_id(),
             ihk_mc_get_hardware_processor_id(),
             num, syscall_name[num],
             ihk_mc_syscall_arg0(ctx), ihk_mc_syscall_arg1(ctx),
             ihk_mc_syscall_arg2(ctx), ihk_mc_syscall_arg3(ctx),
             ihk_mc_syscall_arg4(ctx), ihk_mc_syscall_arg5(ctx),
             ihk_mc_syscall_pc(ctx), ihk_mc_syscall_sp(ctx));
#if 1
#if 0
	if(num != 24)  // if not sched_yield
#endif
    dkprintf(",*sp:%lx,*(sp+8):%lx,*(sp+16):%lx,*(sp+24):%lx",
             *((unsigned long*)ihk_mc_syscall_sp(ctx)),
             *((unsigned long*)(ihk_mc_syscall_sp(ctx)+8)),
             *((unsigned long*)(ihk_mc_syscall_sp(ctx)+16)),
             *((unsigned long*)(ihk_mc_syscall_sp(ctx)+24)));
#endif
#if 0
	if(num != 24)  // if not sched_yield
#endif
    dkprintf("\n");


	if ((0 <= num) && (num < (sizeof(syscall_table) / sizeof(syscall_table[0])))
			&& (syscall_table[num] != NULL)) {
		l = syscall_table[num](num, ctx);
		
		dkprintf("SC(%d)[%3d] ret: %d\n", 
				ihk_mc_get_processor_id(), num, l);
	} else {
		dkprintf("USC[%3d](%lx, %lx, %lx, %lx, %lx) @ %lx | %lx\n", num,
		        ihk_mc_syscall_arg0(ctx), ihk_mc_syscall_arg1(ctx),
		        ihk_mc_syscall_arg2(ctx), ihk_mc_syscall_arg3(ctx),
		        ihk_mc_syscall_arg4(ctx), ihk_mc_syscall_pc(ctx),
		        ihk_mc_syscall_sp(ctx));
		l = syscall_generic_forwarding(num, ctx);
	}

	check_signal(l);

	return l;
}

#if 0
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
#endif
