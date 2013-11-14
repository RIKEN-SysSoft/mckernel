/**
 * \file main.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Load an ELF image on data_start and jump to its entry point.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#include <elf.h>

extern char data_start[], data_end[];

#define LARGE_PAGE_SIZE  (1UL << 21)
#define LARGE_PAGE_MASK  (~((unsigned long)LARGE_PAGE_SIZE - 1))

#define MAP_ST_START       0xffff800000000000UL
#define MAP_KERNEL_START   0xffffffff80000000UL

#define PTL4_SHIFT         39
#define PTL3_SHIFT         30
#define PTL2_SHIFT         21

unsigned long page_tables[3][512] __attribute__((aligned(4096)));

static void *memcpy(void *dest, void *src, unsigned long len)
{
	char *d = dest, *s = src;

	for ( ; len ; len--) {
		*(d++) = *(s++);
	}

	return d;
}
static void *memset(void *dest, int v, unsigned long len)
{
	char *d = dest;

	for ( ; len ; len--) {
		*(d++) = (char)v;
	}

	return d;
}

void memzerol(unsigned long *p, unsigned long size)
{
	unsigned long i;

	size /= sizeof(unsigned long);

	for (i = 0; i < size; i++) {
		p[i] = 0;
	}
}

static unsigned long load_programs(unsigned char *image, Elf64_Phdr *hdrs,
                                   int nhdr, unsigned long offset)
{
	int i;
	unsigned long end = MAP_KERNEL_START;

	for (i = 0; i < nhdr; i++) {
		if (hdrs[i].p_type == PT_LOAD) {
			memcpy((void *)(hdrs[i].p_vaddr - offset),
			       image + hdrs[i].p_offset,
			       hdrs[i].p_filesz);
			if (hdrs[i].p_filesz < hdrs[i].p_memsz) {
				memset((void *)(hdrs[i].p_vaddr + 
				                hdrs[i].p_filesz - offset), 0,
				       hdrs[i].p_memsz - hdrs[i].p_filesz);
			}
			if (end < hdrs[i].p_vaddr + hdrs[i].p_memsz) {
				end = hdrs[i].p_vaddr + hdrs[i].p_memsz;
			}
		}
	}

	return end;
}

/*
 * Return value: If success, the entry point address. Otherwise, 0.
 */
unsigned long load_elf(unsigned char *image, unsigned long offset)
{
	Elf64_Ehdr *hdr = (Elf64_Ehdr *)image;

	if (hdr->e_ident[0] != 0x7f || hdr->e_ident[1] != 'E'
	    || hdr->e_ident[2] != 'L' || hdr->e_ident[3] != 'F') {
		return 0;
	}
	/* TODO: We may overlap. So copying should be more sophisticated */
	if (!hdr->e_phoff || hdr->e_phentsize != sizeof(Elf64_Phdr)) {
		return 0;
	}
	return load_programs(image,
	                     (Elf64_Phdr *)(image + hdr->e_phoff), hdr->e_phnum,
	                     offset);
}

void main(unsigned long param)
{
	/* Assume phys == virt */
	unsigned long load_address, end, *org_cr3;
	unsigned long i, n;
	Elf64_Ehdr *hdr;
	void (*entry)(unsigned long param, unsigned long load_address);

	load_address = (unsigned long)data_end;
	load_address = (load_address + LARGE_PAGE_SIZE - 1) & LARGE_PAGE_MASK;

	asm volatile("movq %%cr3, %0" : "=r"(org_cr3));

	memzerol((unsigned long *)page_tables, sizeof(page_tables));

	page_tables[0][0] = org_cr3[0];
	page_tables[0][(MAP_ST_START >> PTL4_SHIFT) & 511] = org_cr3[0];
	page_tables[0][(MAP_KERNEL_START >> PTL4_SHIFT) & 511] = 
		((unsigned long)page_tables[1]) | 3;
	page_tables[1][(MAP_KERNEL_START >> PTL3_SHIFT) & 511] = 
		((unsigned long)page_tables[2]) | 3;

	end = load_elf(data_start, MAP_KERNEL_START - load_address);

	/* map 4MB more in case */
	n = (end - MAP_KERNEL_START + (1 << PTL2_SHIFT) - 1) >> PTL2_SHIFT;
	n += 2;

	for (i = 0; i < n; i++) {
		page_tables[2][i] = (load_address + (i << PTL2_SHIFT)) | 0x83;
	}

	hdr = (Elf64_Ehdr *)data_start;

	asm volatile("movq %0, %%cr3" : : "r"(page_tables) : "memory");
	
	entry = (void *)hdr->e_entry;
	entry(param, load_address);
}
