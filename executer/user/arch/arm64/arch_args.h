/* arch_args.h COPYRIGHT FUJITSU LIMITED 2017-2018 */
#ifndef ARCH_ARGS_H
#define ARCH_ARGS_H

#include <asm/ptrace.h>

typedef struct user_pt_regs syscall_args;

static inline int
get_syscall_args(int pid, syscall_args *args)
{
	/* TODO: skeleton for UTI */
	return -1;
}

static inline int
set_syscall_args(int pid, syscall_args *args)
{
	/* TODO: skeleton for UTI */
	return -1;
}

static inline unsigned long
get_syscall_number(syscall_args *args)
{
	/* TODO: skeleton for UTI */
	return 0;
}

static inline unsigned long
get_syscall_return(syscall_args *args)
{
	/* TODO: skeleton for UTI */
	return 0;
}

static inline unsigned long
get_syscall_arg1(syscall_args *args)
{
	/* TODO: skeleton for UTI */
	return 0;
}

static inline unsigned long
get_syscall_arg2(syscall_args *args)
{
	/* TODO: skeleton for UTI */
	return 0;
}

static inline unsigned long
get_syscall_arg3(syscall_args *args)
{
	/* TODO: skeleton for UTI */
	return 0;
}

static inline unsigned long
get_syscall_arg4(syscall_args *args)
{
	/* TODO: skeleton for UTI */
	return 0;
}

static inline unsigned long
get_syscall_arg5(syscall_args *args)
{
	/* TODO: skeleton for UTI */
	return 0;
}

static inline unsigned long
get_syscall_arg6(syscall_args *args)
{
	/* TODO: skeleton for UTI */
	return 0;
}

static inline void
set_syscall_number(syscall_args *args, unsigned long value)
{
	/* TODO: skeleton for UTI */
}

static inline void
set_syscall_return(syscall_args *args, unsigned long value)
{
	/* TODO: skeleton for UTI */
}

static inline void
set_syscall_arg1(syscall_args *args, unsigned long value)
{
	/* TODO: skeleton for UTI */
}

static inline void
set_syscall_arg2(syscall_args *args, unsigned long value)
{
	/* TODO: skeleton for UTI */
}

static inline void
set_syscall_arg3(syscall_args *args, unsigned long value)
{
	/* TODO: skeleton for UTI */
}

static inline void
set_syscall_arg4(syscall_args *args, unsigned long value)
{
	/* TODO: skeleton for UTI */
}

static inline void
set_syscall_arg5(syscall_args *args, unsigned long value)
{
	/* TODO: skeleton for UTI */
}

static inline void
set_syscall_arg6(syscall_args *args, unsigned long value)
{
	/* TODO: skeleton for UTI */
}
#endif /* !ARCH_ARGS_H */
