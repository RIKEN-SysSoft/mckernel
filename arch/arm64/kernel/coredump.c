/* coredump.c COPYRIGHT FUJITSU LIMITED 2015-2019 */
#ifdef POSTK_DEBUG_ARCH_DEP_18 /* coredump arch separation. */
#include <process.h>
#include <elfcore.h>
#include <string.h>
#include <ptrace.h>
#include <cls.h>

#define	align32(x) ((((x) + 3) / 4) * 4)

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

int arch_get_thread_core_info_size(void)
{
	const struct user_regset_view *view = current_user_regset_view();
	const struct user_regset *regset = find_regset(view, NT_ARM_SVE);

	return sizeof(struct note) + align32(sizeof("LINUX"))
		+ regset_size(cpu_local_var(current), regset);
}

void arch_fill_thread_core_info(struct note *head,
				struct thread *thread, void *regs)
{
	const struct user_regset_view *view = current_user_regset_view();
	const struct user_regset *regset = find_regset(view, NT_ARM_SVE);

	/* pre saved registers */
	save_fp_regs(thread);

	if (regset->core_note_type && regset->get &&
	    (!regset->active || regset->active(thread, regset))) {
		int ret;
		size_t size = regset_size(thread, regset);
		void *namep;
		void *descp;

		namep = (void *) (head + 1);
		descp = namep + align32(sizeof("LINUX"));

		ret = regset->get(thread, regset, 0, size, descp, NULL);
		if (ret) {
			return;
		}

		head->namesz = sizeof("LINUX");
		head->descsz = size;
		head->type = NT_ARM_SVE;
		memcpy(namep, "LINUX", sizeof("LINUX"));
	}
}

#endif /* POSTK_DEBUG_ARCH_DEP_18 */
