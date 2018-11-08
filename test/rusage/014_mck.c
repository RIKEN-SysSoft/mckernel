#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "util.h"

#define DEBUG

int sz_unit[] = {
	4 * (1ULL<<10),
	2 * (1ULL<<20),
	1 * (1ULL<<30)};

#define SZ_INDEX 0

int main(int argc, char **argv)
{
	void *mem;
	int ret = 0;
	int fd;

	fd = open("./file", O_RDWR);
	CHKANDJUMP(fd == -1, 255, "open failed\n");

	mem = mmap(0, 2 * sz_unit[SZ_INDEX], PROT_READ | PROT_WRITE,
		   MAP_SHARED, fd, 0);
	CHKANDJUMP(mem == MAP_FAILED, 255, "mmap failed\n");

	ret = remap_file_pages(mem + 0 * sz_unit[SZ_INDEX],
			       sz_unit[SZ_INDEX], 0, 1, MAP_SHARED);
	CHKANDJUMP(ret != 0, 255, "remap_file_pages failed\n");

	ret = remap_file_pages(mem + 1 * sz_unit[SZ_INDEX],
			       sz_unit[SZ_INDEX], 0, 0, MAP_SHARED);
	CHKANDJUMP(ret != 0, 255, "remap_file_pages failed\n");

	*((unsigned long *)mem) = 0x123456789abcdef0;
	*(unsigned long *)((char *)mem + 1 * sz_unit[SZ_INDEX]) =
		0x123456789abcdef0;

	munmap(mem, 2 * sz_unit[SZ_INDEX]);

 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}
