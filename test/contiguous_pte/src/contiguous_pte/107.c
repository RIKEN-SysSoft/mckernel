/* 107.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <sys/mman.h>
#include "test_mck.h"
#include "testsuite.h"

static const size_t shift = PAGE_SHIFT;
static const size_t cmpshift = PAGE_SHIFT + CONT_PAGE_SHIFT;

static char* none_addr = MAP_FAILED;
static size_t none_length;

SETUP_EMPTY(TEST_SUITE, TEST_NUMBER)

RUN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	const size_t pgsize = 1UL << shift;
	const size_t cmppgsize = 1UL << cmpshift;
	char* aligned_addr = MAP_FAILED;

	/* reserve */
	none_length = cmppgsize * 2;
	none_addr = mmap(NULL, none_length,
			 PROT_NONE,
			 MAP_PRIVATE | MAP_ANONYMOUS,
			 -1, 0);
	tp_assert(none_addr != MAP_FAILED, "mmap(none) error.");
	aligned_addr = (void*)align_up((unsigned long)none_addr, cmppgsize);

	/* alloc */
	aligned_addr = mmap(aligned_addr, pgsize,
			    PROT_READ|PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_POPULATE,
			    -1, 0);
	tp_assert(aligned_addr != MAP_FAILED, "mmap(rw) error.");

	check_page_size((unsigned long)aligned_addr, pgsize);
	return NULL;
}

TEARDOWN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	if (none_addr != MAP_FAILED) {
		munmap(none_addr, none_length);
	}
}
