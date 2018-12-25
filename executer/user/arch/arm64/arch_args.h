/* arch_args.h COPYRIGHT FUJITSU LIMITED 2017 */
#ifndef ARCH_ARGS_H
#define ARCH_ARGS_H

#include <asm/ptrace.h>

#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL	0x404	/* ARM system call number */
#endif /* !NT_ARM_SYSTEM_CALL */

typedef struct {
	struct user_pt_regs regs;
	unsigned long orig_x0;
	unsigned long ret_value;
	pid_t target_pid;
	int bypass;
} syscall_args;

enum ptrace_syscall_dir {
	PTRACE_SYSCALL_ENTER = 0,
	PTRACE_SYSCALL_EXIT,
};

static inline int
syscall_enter(syscall_args *args)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return -1;
	}

	switch (args->regs.regs[7]) {
	case PTRACE_SYSCALL_ENTER:
		return 1;
	case PTRACE_SYSCALL_EXIT:
		return 0;
	default:
		printf("%s: x7 is neither SYSCALL_ENTER nor SYSCALL_EXIT.\n",
		       __func__);
		return -1;
	}
}

static inline int
get_syscall_args(int pid, syscall_args *args)
{
	struct iovec iov;
	long ret = -1;

	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return -1;
	}
	args->target_pid = pid;
	args->bypass = 0;
	memset(&iov, 0, sizeof(iov));
	iov.iov_base = &args->regs;
	iov.iov_len = sizeof(args->regs);
	ret = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
	if (!ret) {
		if (syscall_enter(args)) {
			args->orig_x0 = args->regs.regs[0];
			args->ret_value = 0;
		}
		else {
			/* orig_x0 is saved */
			args->ret_value = args->regs.regs[0];
		}
	}
	return ret;
}

static inline int
set_syscall_args(int pid, syscall_args *args)
{
	struct iovec iov;

	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return -1;
	}
	memset(&iov, 0, sizeof(iov));
	iov.iov_base = &args->regs;
	iov.iov_len = sizeof(args->regs);
	return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
}

static inline unsigned long
get_syscall_number(syscall_args *args)
{
	int sysno = -1;
	long ret = -1;
	struct iovec iov;

	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return -1;
	}
	memset(&iov, 0, sizeof(iov));
	iov.iov_base = &sysno;
	iov.iov_len = sizeof(sysno);
	ret = ptrace(PTRACE_GETREGSET, args->target_pid, NT_ARM_SYSTEM_CALL,
		     &iov);
	if (ret) {
		printf("%s: ptrace(PTRACE_GETREGSET) failed. (%d)",
		       __func__, errno);
	}
	return sysno;
}

static inline unsigned long
get_syscall_arg1(syscall_args *args)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return 0;
	}
	return args->orig_x0;
}

static inline unsigned long
get_syscall_arg2(syscall_args *args)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return 0;
	}
	return args->regs.regs[1];
}

static inline unsigned long
get_syscall_arg3(syscall_args *args)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return 0;
	}
	return args->regs.regs[2];
}

static inline unsigned long
get_syscall_arg4(syscall_args *args)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return 0;
	}
	return args->regs.regs[3];
}

static inline unsigned long
get_syscall_arg5(syscall_args *args)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return 0;
	}
	return args->regs.regs[4];
}

static inline unsigned long
get_syscall_arg6(syscall_args *args)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return 0;
	}
	return args->regs.regs[5];
}

static inline void
set_syscall_number(syscall_args *args, unsigned long value)
{
	int sysno = (int)value;
	long ret = -1;
	struct iovec iov;

	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return;
	}
	memset(&iov, 0, sizeof(iov));
	iov.iov_base = &sysno;
	iov.iov_len = sizeof(sysno);
	ret = ptrace(PTRACE_SETREGSET, args->target_pid, NT_ARM_SYSTEM_CALL,
		     &iov);
	if (ret) {
		printf("%s: ptrace(PTRACE_GETREGSET) failed. (%d)",
		       __func__, errno);
	}
	else {
		if (value == (unsigned long)-1) {
			args->bypass = 1;
		}
	}
}

static inline void
set_syscall_ret_or_arg1(syscall_args *args, unsigned long value, int ret_flag)
{
	/* called by set_syscall_return() */
	if (ret_flag == 1) {
		/* stopped syscall-enter */
		if (syscall_enter(args) == 1) {
			/*  syscall no bypass */
			if (args->bypass != 1) {
				/* no effect */
				goto out;
			}
		}
	}
	/* called by set_syscall_arg1() */
	else if (ret_flag == 0) {
		/* stopped syscall-return */
		if (syscall_enter(args) == 0) {
			/* no effect */
			goto out;
		}
		/* set original arg1 */
		args->orig_x0 = value;
	}
	/* illegal ret_flag */
	else {
		/* no effect */
		goto out;
	}

	/* set value */
	args->regs.regs[0] = value;
out:
	return;
}

static inline void
set_syscall_return(syscall_args *args, unsigned long value)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return;
	}
	set_syscall_ret_or_arg1(args, value, 1);
}

static inline void
set_syscall_arg1(syscall_args *args, unsigned long value)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return;
	}
	set_syscall_ret_or_arg1(args, value, 0);
}

static inline void
set_syscall_arg2(syscall_args *args, unsigned long value)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return;
	}
	args->regs.regs[1] = value;
}

static inline void
set_syscall_arg3(syscall_args *args, unsigned long value)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return;
	}
	args->regs.regs[2] = value;
}

static inline void
set_syscall_arg4(syscall_args *args, unsigned long value)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return;
	}
	args->regs.regs[3] = value;
}

static inline void
set_syscall_arg5(syscall_args *args, unsigned long value)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return;
	}
	args->regs.regs[4] = value;
}

static inline void
set_syscall_arg6(syscall_args *args, unsigned long value)
{
	if (!args) {
		printf("%s: input args is NULL.\n", __func__);
		return;
	}
	args->regs.regs[5] = value;
}
#endif /* !ARCH_ARGS_H */
