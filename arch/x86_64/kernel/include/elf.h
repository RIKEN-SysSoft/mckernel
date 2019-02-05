/* elf.h COPYRIGHT FUJITSU LIMITED 2018 */
#ifndef __HEADER_X86_COMMON_ELF_H
#define __HEADER_X86_COMMON_ELF_H

/* NOTE segment type defined */
#define NT_X86_STATE	0x202

/* ELF target machines defined */
#define EM_K10M		181	/* Intel K10M */
#define EM_X86_64	62	/* AMD x86-64 architecture */

/* ELF header defined */
#define ELF_CLASS	ELFCLASS64
#define ELF_DATA	ELFDATA2LSB
#define ELF_OSABI	ELFOSABI_NONE
#define ELF_ABIVERSION	El_ABIVERSION_NONE
#ifdef CONFIG_MIC
#define ELF_ARCH	EM_K10M
#else /* CONFIG_MIC */
#define ELF_ARCH	EM_X86_64
#endif /* CONFIG_MIC */

struct user_regs64_struct
{
	a8_uint64_t r15;
	a8_uint64_t r14;
	a8_uint64_t r13;
	a8_uint64_t r12;
	a8_uint64_t rbp;
	a8_uint64_t rbx;
	a8_uint64_t r11;
	a8_uint64_t r10;
	a8_uint64_t r9;
	a8_uint64_t r8;
	a8_uint64_t rax;
	a8_uint64_t rcx;
	a8_uint64_t rdx;
	a8_uint64_t rsi;
	a8_uint64_t rdi;
	a8_uint64_t orig_rax;
	a8_uint64_t rip;
	a8_uint64_t cs;
	a8_uint64_t eflags;
	a8_uint64_t rsp;
	a8_uint64_t ss;
	a8_uint64_t fs_base;
	a8_uint64_t gs_base;
	a8_uint64_t ds;
	a8_uint64_t es;
	a8_uint64_t fs;
	a8_uint64_t gs;
};

#define ELF_NGREG64 (sizeof (struct user_regs64_struct) / sizeof(elf_greg64_t))

typedef elf_greg64_t elf_gregset64_t[ELF_NGREG64];

#endif /* __HEADER_S64FX_COMMON_ELF_H */
