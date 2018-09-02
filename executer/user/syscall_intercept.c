#include <libsyscall_intercept_hook_point.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "../include/uprotocol.h"
#include "../include/uti.h"
#include "./archdep_uti.h"

static struct uti_desc uti_desc;

#define DEBUG_UTI

static int
hook(long syscall_number,
	 long arg0, long arg1,
	 long arg2, long arg3,
	 long arg4, long arg5,
	 long *result)
{
	//return 1; /* debug */
	int tid = uti_syscall0(__NR_gettid);
	struct terminate_thread_desc term_desc;
	unsigned long sig;
		
	if (!uti_desc.start_syscall_intercept) {
		return 1; /* System call isn't taken over */
	}
	if (tid != uti_desc.mck_tid) {
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
		if (!uti_desc.syscall_param_top) {
			*result = -ENOMEM;
			return 0;
		}
		else {
			/* Pop syscall_struct list for reentrant safety */
			uti_desc.syscall_param = uti_desc.syscall_param_top;
			uti_desc.syscall_param_top = *(void **)uti_desc.syscall_param;

			uti_desc.syscall_param->number = syscall_number;
			uti_desc.syscall_param->args[0] = arg0;
			uti_desc.syscall_param->args[1] = arg1;
			uti_desc.syscall_param->args[2] = arg2;
			uti_desc.syscall_param->args[3] = arg3;
			uti_desc.syscall_param->args[4] = arg4;
			uti_desc.syscall_param->args[5] = arg5;
			uti_desc.syscall_param->uti_clv = uti_desc.uti_clv;
			uti_desc.syscall_param->ret = -EINVAL;
			uti_syscall3(__NR_ioctl, uti_desc.fd, MCEXEC_UP_SYSCALL_THREAD, (long)uti_desc.syscall_param);
			*result = uti_desc.syscall_param->ret;

			/* push syscall_struct list */
			*(void **)uti_desc.syscall_param = uti_desc.syscall_param_top;
			uti_desc.syscall_param_top = uti_desc.syscall_param;

			return 0; /* System call is taken over */
		}
		break;
	case __NR_exit_group:
		sig = 0x100000000;
		goto make_remote_thread_exit;
	case __NR_exit:
		sig = 0;
	make_remote_thread_exit:
		/* Make migrated-to-Linux thread on the McKernel side call do_exit() or terminate() */
		term_desc.pid = uti_desc.pid;
		term_desc.tid = uti_desc.tid; /* tid of mcexec */
		term_desc.sig = sig | (arg0 << 8);
		term_desc.tsk = uti_desc.key;

		uti_syscall3(__NR_ioctl, uti_desc.fd, MCEXEC_UP_TERMINATE_THREAD, (long)&term_desc);
		return 1;
	case __NR_clone:
	case __NR_fork:
	case __NR_vfork:
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
	// Set up the callback function
	intercept_hook_point = hook;
	
	uti_syscall1(733, (unsigned long)&uti_desc);
}

static __attribute__((destructor)) void
dtor(void)
{
}
