#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include "util.h"

#define DEBUG

int sz_anon[] = {
	4 * (1ULL<<10),
	2 * (1ULL<<20),
	1 * (1ULL<<30),
	134217728};

#define SZ_INDEX 0
#define NUM_AREAS 1

int main(int argc, char **argv)
{
	void *mem;
	void *newmem;
	int ret = 0;

	mem = mmap(0, sz_anon[SZ_INDEX], PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	CHKANDJUMP(mem == MAP_FAILED, 255, "mmap failed\n");
	*((unsigned long *)mem) = 0x123456789abcdef0;

	newmem = mremap(mem, sz_anon[SZ_INDEX], sz_anon[SZ_INDEX + 1],
			MREMAP_MAYMOVE);
	CHKANDJUMP(newmem == MAP_FAILED, 255, "mmap failed\n");
	*((unsigned long *)mem) = 0xbeefbeefbeefbeef;

	munmap(newmem, sz_anon[SZ_INDEX + 1]);

 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}
