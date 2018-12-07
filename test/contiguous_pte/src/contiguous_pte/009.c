/* 009.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <sys/mman.h>
#include "test_mck.h"
#include "testsuite.h"

static const size_t shift = CONT_PAGE_SHIFT;

static char *addr = MAP_FAILED;
static size_t length;

SETUP_EMPTY(TEST_SUITE, TEST_NUMBER)

RUN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	char *aligned_addr;

	/* mmap */
	length = (1UL << shift) * 2;
	addr = mmap(NULL, length, PROT_READ|PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS,
		    -1, 0);
	tp_assert(addr != MAP_FAILED, "mmap error.");

	aligned_addr = (void *)align_up((unsigned long)addr,
				(1UL << shift));
	aligned_addr[0] = 'z';

	// check
	{
		struct memory_info info = {0};

		get_memory_info_self((unsigned long)aligned_addr,
				     &info);
		tp_assert(info.present == 1,
			  "alloc error.");
		tp_assert(info.pgsize == (1UL << shift),
			  "size error.");
	}
	return NULL;
}

TEARDOWN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	if (addr != MAP_FAILED) {
		munmap(addr, length);
	}
}
