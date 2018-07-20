/**
 * \file test_main.c
 *  License details are found in the file LICENSE.
 * \brief
 *  Test of loading an ELF file.
 * \author Taku Shimosawa  <shimosawa@is.s.u-tokyo.ac.jp> \par
 *      Copyright (C) 2011 - 2012  Taku Shimosawa
 */
/*
 * HISTORY
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>

unsigned long elfboot_main(unsigned char *image);

int main(int argc, char **argv)
{
	int fd;
	struct stat st;
	void *p;

	if (argc < 2) {
		fprintf(stderr, "Usage : %s (elf)\n", argv[0]);
		return 1;
	}
	fd = open(argv[1], O_RDONLY);
	if (fd < 0){ 
		perror("open");
		return 1;
	}

	fstat(fd, &st);
	
	p = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		return 2;
	}

	printf("read result : %lx\n", elfboot_main(p));

	munmap(p, st.st_size);
	close(fd);

	return 0;
}
