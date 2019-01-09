/* assert.c COPYRIGHT FUJITSU LIMITED 2015-2017 */

#include <process.h>
#include <list.h>
#include <ihk/debug.h>
#include <ihk/context.h>
#include <asm-offsets.h>
#include <cputable.h>
#include <thread_info.h>
#include <smp.h>
#include <ptrace.h>

/* assert for struct pt_regs member offset & size define */
STATIC_ASSERT(offsetof(struct pt_regs, regs[0]) == S_X0);
STATIC_ASSERT(offsetof(struct pt_regs, regs[1]) == S_X1);
STATIC_ASSERT(offsetof(struct pt_regs, regs[2]) == S_X2);
STATIC_ASSERT(offsetof(struct pt_regs, regs[3]) == S_X3);
STATIC_ASSERT(offsetof(struct pt_regs, regs[4]) == S_X4);
STATIC_ASSERT(offsetof(struct pt_regs, regs[5]) == S_X5);
STATIC_ASSERT(offsetof(struct pt_regs, regs[6]) == S_X6);
STATIC_ASSERT(offsetof(struct pt_regs, regs[7]) == S_X7);
STATIC_ASSERT(offsetof(struct pt_regs, regs[30]) == S_LR);
STATIC_ASSERT(offsetof(struct pt_regs, sp) == S_SP);
STATIC_ASSERT(offsetof(struct pt_regs, pc) == S_PC);
STATIC_ASSERT(offsetof(struct pt_regs, pstate) == S_PSTATE);
STATIC_ASSERT(offsetof(struct pt_regs, orig_x0) == S_ORIG_X0);
STATIC_ASSERT(offsetof(struct pt_regs, orig_pc) == S_ORIG_PC);
STATIC_ASSERT(offsetof(struct pt_regs, syscallno) == S_SYSCALLNO);
STATIC_ASSERT(sizeof(struct pt_regs) == S_FRAME_SIZE);

/* assert for struct cpu_info member offset & size define */
STATIC_ASSERT(offsetof(struct cpu_info, cpu_setup) == CPU_INFO_SETUP);
STATIC_ASSERT(sizeof(struct cpu_info) == CPU_INFO_SZ);

/* assert for struct thread_info member offset define */
STATIC_ASSERT(offsetof(struct thread_info, flags) == TI_FLAGS);
STATIC_ASSERT(offsetof(struct thread_info, cpu_context) == TI_CPU_CONTEXT);

/* assert for arch depend kernel stack size and common kernel stack pages */
STATIC_ASSERT((KERNEL_STACK_SIZE * 2) < (KERNEL_STACK_NR_PAGES * PAGE_SIZE));

/* assert for struct secondary_data member offset define */
STATIC_ASSERT(offsetof(struct secondary_data, stack) == SECONDARY_DATA_STACK);
STATIC_ASSERT(offsetof(struct secondary_data, next_pc) == SECONDARY_DATA_NEXT_PC);
STATIC_ASSERT(offsetof(struct secondary_data, arg) == SECONDARY_DATA_ARG);

/* assert for sve defines */
/* @ref.impl arch/arm64/kernel/signal.c::BUILD_BUG_ON in the init_user_layout */
STATIC_ASSERT(sizeof(struct sigcontext) - offsetof(struct sigcontext, __reserved) > ALIGN_UP(sizeof(struct _aarch64_ctx), 16));
STATIC_ASSERT(sizeof(struct sigcontext) - offsetof(struct sigcontext, __reserved) -
		ALIGN_UP(sizeof(struct _aarch64_ctx), 16) > sizeof(struct extra_context));
STATIC_ASSERT(SVE_PT_FPSIMD_OFFSET == sizeof(struct user_sve_header));
STATIC_ASSERT(SVE_PT_SVE_OFFSET == sizeof(struct user_sve_header));

/* assert for struct arm64_cpu_local_thread member offset define */
STATIC_ASSERT(offsetof(struct arm64_cpu_local_thread, panic_regs) == 160);
