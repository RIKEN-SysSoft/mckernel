#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include "./test_chk.h"

#define TEST_NAME "CT_005"
#define MAP_SIZE 0x2000000

int main(int argc, char **argv)
{
	void *map, *remap;
	int __errno;

	printf("*** %s start *******************************\n", TEST_NAME);

	map = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	OKNG(map == MAP_FAILED, "mmap   returned :%p", map);

	errno = 0;
	remap = mremap(map, MAP_SIZE, 0xffffffffffffe000, MREMAP_MAYMOVE);
	__errno = errno;

	OKNG(remap != MAP_FAILED, "mremap returned :%p"
		" (expect return is MAP_FAILED)", remap);
	OKNG(__errno != ENOMEM, "errno after mremap :%d"
		" (expect error is ENOMEM(%d))", __errno, ENOMEM);

	printf("*** %s PASSED\n\n", TEST_NAME);

	return 0;

fn_fail:
	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;
}
