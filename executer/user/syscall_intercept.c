#define _GNU_SOURCE
#include <libsyscall_intercept_hook_point.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h> /* for pid_t in uprotocol.h */
#include "../include/uprotocol.h"
#include "../include/uti.h"
#include "./archdep_uti.h"

#define DEBUG_UTI

static struct uti_desc uti_desc;

static __thread int on_linux = -1;

static int
hook(long syscall_number,
	 long arg0, long arg1,
	 long arg2, long arg3,
	 long arg4, long arg5,
	 long *result)
{
	struct terminate_thread_desc term_desc;
	unsigned long code;
	int stack_top;
	long ret;

	if (!uti_desc.start_syscall_intercept) {
		return 1; /* System call isn't taken over */
	}

	/* new thread */
	if (on_linux == -1) {
		int tid = uti_syscall0(__NR_gettid);

		on_linux = (tid == uti_desc.mck_tid) ? 1 : 0;
	}
	if (on_linux == 0) {
		if (uti_desc.syscalls2 && syscall_number >= 0 && syscall_number < 512) {
			uti_desc.syscalls2[syscall_number]++;
		}
		return 1;
	}

#ifdef DEBUG_UTI
	if (uti_desc.syscalls && syscall_number >= 0 && syscall_number < 512) {
		uti_desc.syscalls[syscall_number]++;
	}
#endif

	switch (syscall_number) {
	case __NR_gettid:
		*result = uti_desc.mck_tid;
		return 0;
	case __NR_futex:
	case __NR_brk:
	case __NR_mmap:
	case __NR_munmap:
	case __NR_mprotect:
	case __NR_mremap:
		/* Overflow check */
		if (uti_desc.syscall_stack_top == -1) {
			*result = -ENOMEM;
			return 0;
		}
	
		/* Sanity check */
		if (uti_desc.syscall_stack_top < 0 || uti_desc.syscall_stack_top >= UTI_SZ_SYSCALL_STACK) {
			*result = -EINVAL;
			return 0;
		}

		/* Store the return value in the stack to prevent it from getting corrupted 
		   when an interrupt happens just after ioctl() and before copying the return
		   value to *result */
		stack_top = __sync_fetch_and_sub(&uti_desc.syscall_stack_top, 1);
		
		uti_desc.syscall_stack[stack_top].number = syscall_number;
		uti_desc.syscall_stack[stack_top].args[0] = arg0;
		uti_desc.syscall_stack[stack_top].args[1] = arg1;
		uti_desc.syscall_stack[stack_top].args[2] = arg2;
		uti_desc.syscall_stack[stack_top].args[3] = arg3;
		uti_desc.syscall_stack[stack_top].args[4] = arg4;
		uti_desc.syscall_stack[stack_top].args[5] = arg5;
		uti_desc.syscall_stack[stack_top].uti_info = uti_desc.uti_info;
		uti_desc.syscall_stack[stack_top].ret = -EINVAL;

		ret = uti_syscall3(__NR_ioctl, uti_desc.fd,
				   MCEXEC_UP_SYSCALL_THREAD,
				   (long)(uti_desc.syscall_stack + stack_top));
		*result = (ret < 0) ?
			ret : uti_desc.syscall_stack[stack_top].ret;

		/* push syscall_struct list */
		__sync_fetch_and_add(&uti_desc.syscall_stack_top, 1);

		return 0; /* System call is taken over */
	case __NR_exit_group:
		code = 0x100000000;
		goto make_remote_thread_exit;
	case __NR_exit:
		code = 0;
	make_remote_thread_exit:
		/* Make migrated-to-Linux thread on the McKernel side call do_exit() or terminate() */
		term_desc.pid = uti_desc.pid;
		term_desc.tid = uti_desc.tid; /* tid of mcexec */
		term_desc.code = code | ((arg0 & 255) << 8);
		term_desc.tsk = uti_desc.key;

		uti_syscall3(__NR_ioctl, uti_desc.fd, MCEXEC_UP_TERMINATE_THREAD, (long)&term_desc);
		return 1;
	case __NR_clone:
#ifdef __NR_fork
	case __NR_fork:
#endif /* __NR_fork */
#ifdef __NR_vfork
	case __NR_vfork:
#endif /* __NR_vfork */
	case __NR_execve:
		*result = -ENOSYS;
		return 0;
#if 0 /* debug */
	case __NR_set_robust_list:
		*result = -ENOSYS;
		return 0;
#endif
	case 888:
        *result = (long)&uti_desc;
		return 0;
	default:
		return 1;
	}

	return 0;
}

static __attribute__((constructor)) void
init(void)
{
	/* Set up the callback function */
	intercept_hook_point = hook;

	/* Initialize uti_desc */
	uti_desc.syscall_stack_top = UTI_SZ_SYSCALL_STACK - 1;

	/* Pass address of uti_desc to McKernel */
	uti_syscall1(733, (unsigned long)&uti_desc);
}

static __attribute__((destructor)) void
dtor(void)
{
}
