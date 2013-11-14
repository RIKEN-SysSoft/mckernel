/**
 * \file context.h
 *  License details are found in the file LICENSE.
 * \brief
 *  Define types of registers consisting of context.
 *  Define macros to retrieve arguments of system call.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#ifndef __HEADER_X86_COMMON_CONTEXT_H
#define __HEADER_X86_COMMON_CONTEXT_H

#include <registers.h>

struct x86_kregs {
	unsigned long rsp, rbp, rbx, rsi, rdi, r12, r13, r14, r15, rflags;
	unsigned long rsp0;
};

typedef struct x86_kregs ihk_mc_kernel_context_t;
/* XXX: User context should contain floating point registers */
typedef struct x86_regs ihk_mc_user_context_t;

#define ihk_mc_syscall_arg0(uc) (uc)->rdi
#define ihk_mc_syscall_arg1(uc) (uc)->rsi
#define ihk_mc_syscall_arg2(uc) (uc)->rdx
#define ihk_mc_syscall_arg3(uc) (uc)->r10
#define ihk_mc_syscall_arg4(uc) (uc)->r8
#define ihk_mc_syscall_arg5(uc) (uc)->r9

#define ihk_mc_syscall_ret(uc)  (uc)->rax

#define ihk_mc_syscall_pc(uc)   (uc)->rip
#define ihk_mc_syscall_sp(uc)   (uc)->rsp

#endif
