/* elfcoregpl.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
#ifndef __HEADER_ELFCOREGPL_H
#define __HEADER_ELFCOREGPL_H

#include <ihk/types.h>

/* From /usr/include/linux/elfcore.h of Linux */

#define ELF_PRARGSZ	(80)

/* From /usr/include/linux/elfcore.h fro Linux */

struct elf_siginfo
{
	int si_signo;
	int si_code;
	int si_errno;
};

/* From bfd/hosts/x86-64linux.h of gdb. */

typedef uint64_t __attribute__ ((__aligned__ (8))) a8_uint64_t;
typedef a8_uint64_t elf_greg64_t;

#include <elf.h>

struct prstatus64_timeval
{
	a8_uint64_t tv_sec;
	a8_uint64_t tv_usec;
};

struct elf_prstatus64
{
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
	elf_gregset64_t pr_reg;
	int pr_fpvalid;
};

struct elf_prpsinfo64
{
	char pr_state;
	char pr_sname;
	char pr_zomb;
	char pr_nice;
	a8_uint64_t pr_flag;
	unsigned int pr_uid;
	unsigned int pr_gid;
	int pr_pid, pr_ppid, pr_pgrp, pr_sid;
	char pr_fname[16];
	char pr_psargs[ELF_PRARGSZ];
};

#endif /* __HEADER_ELFCOREGPL_H */
