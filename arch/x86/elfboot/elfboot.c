/**
 * \file elfboot.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Load an ELF image.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#include <elf.h>
#include "test.h"

#ifdef TEST
static void *memcpy(void *dest, void *src, unsigned long len)
{
	dprintf("Copying %p to %p for %08ld bytes\n", src, dest, len);

	return dest;
}
static void *memset(void *dest, int v, unsigned long len)
{
	dprintf("Filling %p with %02x for %08ld bytes\n", dest, (unsigned char)v, len);

	return dest;
}
#else
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
#endif

static void load_programs(unsigned char *image, Elf64_Phdr *hdrs, int nhdr)
{
	int i;

	for (i = 0; i < nhdr; i++) {
		if (hdrs[i].p_type == PT_LOAD) {
			dprintf("PT_LOAD : %lx: %lx - %lx (%lx)\n",
			        hdrs[i].p_vaddr,
			        hdrs[i].p_offset, hdrs[i].p_filesz,
			        hdrs[i].p_memsz);

			memcpy((void *)hdrs[i].p_vaddr,
			       image + hdrs[i].p_offset,
			       hdrs[i].p_filesz);
			if (hdrs[i].p_filesz < hdrs[i].p_memsz) {
				memset((void *)hdrs[i].p_vaddr + 
				       hdrs[i].p_filesz, 0,
				       hdrs[i].p_memsz - hdrs[i].p_filesz);
			}
		}
	}
}


/*
 * Return value: If success, the entry point address. Otherwise, 0.
 */
unsigned long elfboot_main(unsigned char *image)
{
	Elf64_Ehdr *hdr;

	hdr = (Elf64_Ehdr *)image;
	if (hdr->e_ident[0] != 0x7f || hdr->e_ident[1] != 'E'
	    || hdr->e_ident[2] != 'L' || hdr->e_ident[3] != 'F') {
		return 0;
	}
	/* TODO: We may overlap. So copying should be more sophisticated */
	if (!hdr->e_phoff || hdr->e_phentsize != sizeof(Elf64_Phdr)) {
		return 0;
	}
	load_programs(image, 
	              (Elf64_Phdr *)(image + hdr->e_phoff), hdr->e_phnum);
	return hdr->e_entry;
}

