/* elfcore.h COPYRIGHT FUJITSU LIMITED 2015-2019 */
#ifndef __HEADER_ELFCORE_H
#define __HEADER_ELFCORE_H

/*
 * Structures and definitions for ELF core file.
 * Extracted from 
 * System V Application Binary Interface - DRAFT - 10 June 2013,
 * http://www.sco.com/developers/gabi/latest/contents.html
 */
#include <ihk/types.h>

typedef	uint16_t	Elf64_Half;
typedef	uint32_t	Elf64_Word;
typedef	uint64_t	Elf64_Xword;
typedef	uint64_t	Elf64_Addr;
typedef	uint64_t	Elf64_Off;

#define	EI_NIDENT	16

typedef struct {
	unsigned char e_ident[EI_NIDENT];
	Elf64_Half e_type;
	Elf64_Half e_machine;
	Elf64_Word e_version;
	Elf64_Addr e_entry;
	Elf64_Off e_phoff;
	Elf64_Off e_shoff;
	Elf64_Word e_flags;
	Elf64_Half e_ehsize;
	Elf64_Half e_phentsize;
	Elf64_Half e_phnum;
	Elf64_Half e_shentsize;
	Elf64_Half e_shnum;
	Elf64_Half e_shstrndx;
} Elf64_Ehdr;

/* e_ident table defined. */
/* offset */
#define EI_MAG0		0
#define EI_MAG1		1
#define EI_MAG2		2
#define EI_MAG3		3
#define EI_CLASS	4
#define EI_DATA		5
#define EI_VERSION	6
#define EI_OSABI	7
#define EI_ABIVERSION	8
#define EI_PAD		9

/* EI_MAG */
#define ELFMAG0		0x7f
#define ELFMAG1		'E'
#define ELFMAG2		'L'
#define ELFMAG3		'F'

/* EI_CLASS */
#define ELFCLASS64		2	/* 64-bit object */

/* EI_DATA */
#define ELFDATA2LSB		1	/* LSB */
#define ELFDATA2MSB		2	/* MSB */

/* EI_VERSION */
#define El_VERSION		1	/* defined to be the same as EV CURRENT */
#define EV_CURRENT		1	/* Current version */

/* EI_OSABI */
#define ELFOSABI_NONE		0	/* unspecied */

/* EI_ABIVERSION */
#define El_ABIVERSION_NONE	0	/* unspecied */

/* e_type defined */
#define ET_CORE			4	/* Core file */

typedef struct {
	Elf64_Word p_type;
	Elf64_Word p_flags;
	Elf64_Off p_offset;
	Elf64_Addr p_vaddr;
	Elf64_Addr p_paddr;
	Elf64_Xword p_filesz;
	Elf64_Xword p_memsz;
	Elf64_Xword p_align;
} Elf64_Phdr;

#define PT_LOAD		1
#define PT_NOTE		4

#define PF_X		1	/* executable bit */
#define PF_W		2	/* writable bit */
#define PF_R		4	/* readable bit */

struct note {
	Elf64_Word namesz;
	Elf64_Word descsz;
	Elf64_Word type;
	/* name char[namesz] and desc[descsz] */
};

#define NT_PRSTATUS	1
#define NT_PRFPREG	2
#define NT_PRPSINFO	3
#define NT_AUXV		6

#include "elfcoregpl.h"

/* functions */
struct thread;
extern void arch_fill_prstatus(struct elf_prstatus64 *prstatus, struct thread *thread, void *regs0);
extern int arch_get_thread_core_info_size(void);
extern void arch_fill_thread_core_info(struct note *head,
		struct thread *thread, void *regs);

#endif /* __HEADER_ELFCORE_H */
