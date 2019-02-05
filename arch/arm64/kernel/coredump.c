/* coredump.c COPYRIGHT FUJITSU LIMITED 2015-2016 */
#include <process.h>
#include <elfcore.h>
#include <string.h>

void arch_fill_prstatus(struct elf_prstatus64 *prstatus, struct thread *thread, void *regs0)
{
	struct pt_regs *regs = regs0;
	struct elf_prstatus64 tmp_prstatus;
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
	/* copy x0-30, sp, pc, pstate */
	memcpy(&tmp_prstatus.pr_reg, &regs->user_regs, sizeof(tmp_prstatus.pr_reg));
	tmp_prstatus.pr_fpvalid = 0;	/* We assume no fp */

	/* copy unaligned prstatus addr */
	memcpy(prstatus, &tmp_prstatus, sizeof(*prstatus));
}
