/* 005.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <sys/mman.h>
#include "test_mck.h"
#include "testsuite.h"

static const size_t shift = PAGE_SHIFT + CONT_PAGE_SHIFT;

static char* addr = MAP_FAILED;
static size_t length;

SETUP_EMPTY(TEST_SUITE, TEST_NUMBER)

RUN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	const int prot = PROT_READ | PROT_WRITE;
	const int flag = MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | (shift << MAP_HUGE_SHIFT);
	const int fd = -1;
	const off_t offset = 0;

	/* mmap */
	length = 1UL << shift;
	addr = mmap(NULL, length, prot, flag, fd, offset);
	tp_assert(addr != MAP_FAILED, "mmap error.");
	return NULL;
}

TEARDOWN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	if (addr != MAP_FAILED) {
		munmap(addr, length);
	}
}
