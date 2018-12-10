/* 007.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <sys/mman.h>
#include "test_mck.h"
#include "testsuite.h"

static const size_t shift = LARGE_PAGE_SHIFT;

static char *addr = MAP_FAILED;
static size_t length;

SETUP_EMPTY(TEST_SUITE, TEST_NUMBER)

RUN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	int prot = PROT_NONE;
	int flag = MAP_PRIVATE
		| MAP_ANONYMOUS
		| MAP_HUGETLB
		| (shift << MAP_HUGE_SHIFT);
	int fd = -1;
	off_t offset = 0;

	char *alloc;

	/* reserve */
	length = 1UL << shift;
	addr = mmap(NULL, length, prot, flag, fd, offset);
	tp_assert(addr != MAP_FAILED, "mmap error.(addr)");

	/* allocate */
	{
		size_t alloc_len;

		alloc_len = 1UL << CONT_PAGE_SHIFT;
		prot = PROT_READ | PROT_WRITE;
		flag = MAP_PRIVATE
			| MAP_ANONYMOUS
			| MAP_FIXED;

		alloc = mmap(addr, alloc_len,
			     prot, flag, fd, offset);
		tp_assert(alloc != MAP_FAILED,
			  "mmap error.(alloc)");
		*alloc = 'z';
	}

	/* check*/
	{
		struct memory_info info = {0};
		get_memory_info_self((unsigned long)alloc, &info);
		tp_assert(info.present == 1, "alloc error.");
		tp_assert(info.pgsize == (1UL << CONT_PAGE_SHIFT),
			  "pgsize error.");
	}
	return NULL;
}

TEARDOWN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	if (addr != MAP_FAILED) {
		munmap(addr, length);
	}
}
