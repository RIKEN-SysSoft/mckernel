/* 200.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <sys/mman.h>
#include "test_mck.h"
#include "testsuite.h"

static char* addr = MAP_FAILED;
static size_t length;

char* do_2xx(int shift, int cmpshift, int nr_cmppage,
	     ssize_t adjust_lower, ssize_t adjust_upper)
{
	size_t pgsize = 1UL << shift;
	size_t cmppgsize = 1UL << cmpshift;

	char* cmpaddr;
	char* loaddr;
	char* hiaddr;

	char* unmap_addr;
	char* unmap_end;
	size_t unmap_length;

	int res;

	// alloc
	addr = map_contiguous_pte(&length, &cmpaddr, &loaddr, &hiaddr,
				  cmppgsize, nr_cmppage);
	tp_assert(addr != MAP_FAILED, "map contiguous error.");

	// test
	unmap_addr = (cmpaddr) + adjust_lower;
	unmap_end  = (cmpaddr + cmppgsize * nr_cmppage) + adjust_upper;
	unmap_length = (unsigned long)unmap_end - (unsigned long)unmap_addr;
	res = munmap(unmap_addr, unmap_length);
	tp_assert(res != -1, "munmap error.");

	// check
	{
		struct memory_info info;

		if (cmpaddr <= unmap_addr) {
			info.present = 0;
			get_memory_info_self((unsigned long)unmap_addr - 1, &info);
			tp_assert(info.present == 1 && info.pgsize ==  pgsize, "unmap_addr - 1 error.");
		}

		info.present = 1;
		get_memory_info_self((unsigned long)unmap_addr, &info);
		tp_assert(info.present == 0, "unmap_addr error.");

		info.present = 1;
		get_memory_info_self((unsigned long)unmap_end - 1, &info);
		tp_assert(info.present == 0, "unmap_end - 1 error.");

		if (unmap_end <= (cmpaddr + cmppgsize * nr_cmppage)) {
			info.present = 0;
			get_memory_info_self((unsigned long)unmap_end, &info);
			tp_assert(info.present == 1 && info.pgsize ==  pgsize, "unmap_end error.");
		}
	}
	return NULL;
}

void teardown_2xx(void)
{
	if (addr != MAP_FAILED) {
		munmap(addr, length);
	}
}
