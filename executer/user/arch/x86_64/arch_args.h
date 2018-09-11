#ifndef ARCH_ARGS_H
#define ARCH_ARGS_H

#ifdef POSTK_DEBUG_ARCH_DEP_77 /* arch depend hide */
#include <asm/prctl.h>
#endif /* !POSTK_DEBUG_ARCH_DEP_77 */

typedef struct user_regs_struct syscall_args;

static inline int
get_syscall_args(int pid, syscall_args *args)
{
	return ptrace(PTRACE_GETREGS, pid, NULL, args);
}

static inline int
set_syscall_args(int pid, syscall_args *args)
{
	return ptrace(PTRACE_SETREGS, pid, NULL, args);
}

static inline unsigned long
get_syscall_number(syscall_args *args)
{
	return args->orig_rax;
}

#ifndef POSTK_DEBUG_ARCH_DEP_90 /* syscall_enter check is arch depend. */
static inline unsigned long
get_syscall_return(syscall_args *args)
{
	return args->rax;
}
#endif /* !POSTK_DEBUG_ARCH_DEP_90 */

static inline unsigned long
get_syscall_arg1(syscall_args *args)
{
	return args->rdi;
}

static inline unsigned long
get_syscall_arg2(syscall_args *args)
{
	return args->rsi;
}

static inline unsigned long
get_syscall_arg3(syscall_args *args)
{
	return args->rdx;
}

static inline unsigned long
get_syscall_arg4(syscall_args *args)
{
	return args->r10;
}

static inline unsigned long
get_syscall_arg5(syscall_args *args)
{
	return args->r8;
}

static inline unsigned long
get_syscall_arg6(syscall_args *args)
{
	return args->r9;
}

static inline unsigned long
get_syscall_rip(syscall_args *args)
{
	return args->rip;
}

static inline void
set_syscall_number(syscall_args *args, unsigned long value)
{
	args->orig_rax = value;
}

static inline void
set_syscall_return(syscall_args *args, unsigned long value)
{
	args->rax = value;
}

static inline void
set_syscall_arg1(syscall_args *args, unsigned long value)
{
	args->rdi = value;
}

static inline void
set_syscall_arg2(syscall_args *args, unsigned long value)
{
	args->rsi = value;
}

static inline void
set_syscall_arg3(syscall_args *args, unsigned long value)
{
	args->rdx = value;
}

static inline void
set_syscall_arg4(syscall_args *args, unsigned long value)
{
	args->r10 = value;
}

static inline void
set_syscall_arg5(syscall_args *args, unsigned long value)
{
	args->r8 = value;
}

static inline void
set_syscall_arg6(syscall_args *args, unsigned long value)
{
	args->r9 = value;
}

#ifdef POSTK_DEBUG_ARCH_DEP_90 /* syscall_enter check is arch depend. */
#define syscall_enter(argsp) (get_syscall_return(argsp) == -ENOSYS)
#endif /* POSTK_DEBUG_ARCH_DEP_90 */
#endif
