/* coredump.c COPYRIGHT FUJITSU LIMITED 2018-2019 */
#include <process.h>
#include <elfcore.h>

void arch_fill_prstatus(struct elf_prstatus64 *prstatus, struct thread *thread, void *regs0)
{
	struct x86_user_context *uctx = regs0;
	struct x86_basic_regs *regs = &uctx->gpr;
        register unsigned long _r12 asm("r12");
        register unsigned long _r13 asm("r13");
        register unsigned long _r14 asm("r14");
        register unsigned long _r15 asm("r15");

/*
  We ignore following entries for now.

	struct elf_siginfo pr_info;
	short int pr_cursig;
	a8_uint64_t pr_sigpend;
	a8_uint64_t pr_sighold;
	pid_t pr_pid;
	pid_t pr_ppid;
	pid_t pr_pgrp;
	pid_t pr_sid;
	struct prstatus64_timeval pr_utime;
	struct prstatus64_timeval pr_stime;
	struct prstatus64_timeval pr_cutime;
	struct prstatus64_timeval pr_cstime;
 */

	prstatus->pr_reg[0] = _r15;
	prstatus->pr_reg[1] = _r14;
	prstatus->pr_reg[2] = _r13;
	prstatus->pr_reg[3] = _r12;
	prstatus->pr_reg[4] = regs->rbp;
	prstatus->pr_reg[5] = regs->rbx;
	prstatus->pr_reg[6] = regs->r11;
	prstatus->pr_reg[7] = regs->r10;
	prstatus->pr_reg[8] = regs->r9;
	prstatus->pr_reg[9] = regs->r8;
	prstatus->pr_reg[10] = regs->rax;
	prstatus->pr_reg[11] = regs->rcx;
	prstatus->pr_reg[12] = regs->rdx;
	prstatus->pr_reg[13] = regs->rsi;
	prstatus->pr_reg[14] = regs->rdi;
	prstatus->pr_reg[15] = regs->rax;	/* ??? */
	prstatus->pr_reg[16] = regs->rip;
	prstatus->pr_reg[17] = regs->cs;
	prstatus->pr_reg[18] = regs->rflags;
	prstatus->pr_reg[19] = regs->rsp;
	prstatus->pr_reg[20] = regs->ss;
	prstatus->pr_reg[21] = rdmsr(MSR_FS_BASE);
	prstatus->pr_reg[22] = rdmsr(MSR_GS_BASE);
	/* There is no ds, es, fs and gs. */

	prstatus->pr_fpvalid = 0;	/* We assume no fp */
}

void arch_fill_thread_core_info(struct note *head,
				struct thread *thread, void *regs)
{
}

int arch_get_thread_core_info_size(void)
{
	return 0;
}
