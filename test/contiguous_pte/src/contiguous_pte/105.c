/* 105.c COPYRIGHT FUJITSU LIMITED 2018 */
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
	int res = -1;

	/* reserve */
	none_length = cmppgsize * 2;
	none_addr = mmap(NULL, none_length,
			 PROT_NONE,
			 MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | (cmpshift << MAP_HUGE_SHIFT),
			 -1, 0);
	tp_assert(none_addr != MAP_FAILED, "mmap(none) error.");
	aligned_addr = (void*)align_up((unsigned long)none_addr, cmppgsize);

	/* neighbor */
	{
		char* neighbor_addr;
		neighbor_addr = aligned_addr + (cmppgsize - pgsize);
		res = mprotect(neighbor_addr, pgsize, PROT_READ|PROT_WRITE);
		tp_assert(res != -1, "mprotect(neighbor) error.");
		neighbor_addr[0] = -1;
	}

	/* alloc */
	//  aligned_addr
	//  |
	//  V
        //  +-----------------------+---------+
	//  | !present              | present |
        //  +-----------------------+---------+
        //  |<----        vm_range       ---->|
	//  A
	//  |
	// 'z'
	res = mprotect(aligned_addr, cmppgsize, PROT_READ|PROT_WRITE);
	tp_assert(res != -1, "mprotect(fixed) error.");
	*(aligned_addr) = 'z';

	check_page_size((unsigned long)aligned_addr, pgsize);
	return NULL;
}

TEARDOWN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	if (none_addr != MAP_FAILED) {
		munmap(none_addr, none_length);
	}
}
