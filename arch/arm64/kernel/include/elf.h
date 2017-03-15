/* elf.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
#ifndef __HEADER_ARM64_COMMON_ELF_H
#define __HEADER_ARM64_COMMON_ELF_H

#include <ihk/context.h>

/* ELF target machines defined */
#define EM_AARCH64	183

/* ELF header defined */
#define ELF_CLASS	ELFCLASS64
#define ELF_DATA	ELFDATA2LSB
#define ELF_OSABI	ELFOSABI_NONE
#define ELF_ABIVERSION	El_ABIVERSION_NONE
#define ELF_ARCH	EM_AARCH64

#define ELF_NGREG64 (sizeof (struct user_pt_regs) / sizeof(elf_greg64_t))

/* PTRACE_GETREGSET and PTRACE_SETREGSET requests. */
#define NT_ARM_TLS		0x401	/* ARM TLS register */
#define NT_ARM_HW_BREAK		0x402	/* ARM hardware breakpoint registers */
#define NT_ARM_HW_WATCH		0x403	/* ARM hardware watchpoint registers */
#define NT_ARM_SYSTEM_CALL	0x404	/* ARM system call number */

typedef elf_greg64_t elf_gregset64_t[ELF_NGREG64];

#endif /* __HEADER_ARM64_COMMON_ELF_H */
