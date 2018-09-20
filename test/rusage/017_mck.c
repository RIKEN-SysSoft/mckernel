#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "util.h"

#define DEBUG

int sz_mem[] = {
	4 * (1ULL<<10),
	2 * (1ULL<<20),
	1 * (1ULL<<30),
	134217728};

#define SZ_INDEX 0
#define NUM_AREAS 1

int main(int argc, char **argv)
{
	void *mem;
	int ret = 0;
	int fd;

	fd = open("./file", O_RDWR);
	CHKANDJUMP(fd == -1, 255, "open failed\n");

	mem = mmap(0, 3 * sz_mem[SZ_INDEX], PROT_READ | PROT_WRITE,
		   MAP_PRIVATE, fd, 0);
	CHKANDJUMP(mem == MAP_FAILED, 255, "mmap failed\n");

	*(unsigned long *)((char *)mem + 0) = 0x123456789abcdef0;
	*(unsigned long *)((char *)mem + sz_mem[SZ_INDEX]) =
		0xbeefbeefbeefbeef;
	*(unsigned long *)((char *)mem + 2 * sz_mem[SZ_INDEX]) =
		0xbeefbeefbeefbeef;

	ret = mprotect(mem + sz_mem[SZ_INDEX], sz_mem[SZ_INDEX],
		       PROT_READ | PROT_WRITE | PROT_EXEC);
	CHKANDJUMP(ret != 0, 255, "mprotect failed\n");

	munmap(mem, 3 * sz_mem[SZ_INDEX]);

 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}
