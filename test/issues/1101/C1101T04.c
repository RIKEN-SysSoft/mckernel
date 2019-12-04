#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <numaif.h>
#include <sys/mman.h>
#include <errno.h>

int
main(int argc, char **argv)
{
	void *p;
	unsigned long mask;

	p = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,
		 -1, 0);
	if (p == ((void *)-1)) {
		perror("mmap");
		exit(1);
	}
	mask = 1;
	if (mbind(p, 4096, MPOL_INTERLEAVE, &mask, 2, MPOL_MF_MOVE) == -1) {
		perror("mbind");
		exit(1);
	}
	munmap(p, 4096);
	exit(0);
}
