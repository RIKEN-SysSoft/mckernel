/*
 * Structures and definitions for ELF core file.
 * Extracted from 
 * System V Application Binary Interface - DRAFT - 10 June 2013,
 * http://www.sco.com/developers/gabi/latest/contents.html
 */

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

#define	EI_MAG0		0
#define	EI_MAG1		1
#define EI_MAG2		2
#define	EI_MAG3		3
#define	EI_CLASS	4
#define EI_DATA		5
#define	EI_VERSION	6
#define	EI_OSABI	7
#define	EI_ABIVERSION	8
#define EI_PAD		9


#define	ELFMAG0		0x7f
#define	ELFMAG1		'E'
#define	ELFMAG2		'L'
#define	ELFMAG3		'F'

#define	ELFCLASS64	2	/* 64-bit object */
#define	ELFDATA2LSB	1	/* LSB */
#define	El_VERSION	1	/* defined to be the same as EV CURRENT */
#define	ELFOSABI_NONE	0	/* unspecied */
#define	El_ABIVERSION_NONE	0	/* unspecied */
#define	ET_CORE		4	/* Core file */
#define	EM_X86_64	62	/* AMD x86-64 architecture */
#define	EM_K10M		181	/* Intel K10M */
#define	EV_CURRENT	1	/* Current version */

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

#define	PT_LOAD		1
#define	PT_NOTE		4

#define	PF_X		1	/* executable bit */
#define	PF_W		2	/* writable bit */
#define	PF_R		4	/* readable bit */

struct note {
	Elf64_Word namesz;
	Elf64_Word descsz;
	Elf64_Word type;
	/* name char[namesz] and desc[descsz] */
};

#define	NT_PRSTATUS	1
#define	NT_PRFRPREG	2
#define	NT_PRPSINFO	3
#define	NT_AUXV		6
#define	NT_X86_STATE	0x202

#include "elfcoregpl.h"

