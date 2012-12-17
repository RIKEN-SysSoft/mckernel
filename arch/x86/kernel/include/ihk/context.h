#ifndef __HEADER_X86_COMMON_CONTEXT_H
#define __HEADER_X86_COMMON_CONTEXT_H

#include <registers.h>

struct x86_kregs {
	unsigned long rsp, rbp, rbx, rsi, rdi, r12, r13, r14, r15, rflags;
	unsigned long rsp0;
};

typedef struct x86_kregs aal_mc_kernel_context_t;
/* XXX: User context should contain floating point registers */
typedef struct x86_regs aal_mc_user_context_t;

#define aal_mc_syscall_arg0(uc) (uc)->rdi
#define aal_mc_syscall_arg1(uc) (uc)->rsi
#define aal_mc_syscall_arg2(uc) (uc)->rdx
#define aal_mc_syscall_arg3(uc) (uc)->r10
#define aal_mc_syscall_arg4(uc) (uc)->r8
#define aal_mc_syscall_arg5(uc) (uc)->r9

#define aal_mc_syscall_ret(uc)  (uc)->rax

#define aal_mc_syscall_pc(uc)   (uc)->rip
#define aal_mc_syscall_sp(uc)   (uc)->rsp

#endif
