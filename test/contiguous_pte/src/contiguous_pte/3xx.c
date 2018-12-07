/* 300.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <sys/mman.h>
#include "test_mck.h"
#include "testsuite.h"

static char *addr = MAP_FAILED;
static size_t length;

static char *remap_addr = MAP_FAILED;
static size_t remap_length;

char *do_3xx(size_t shift, size_t contshift, int nr_contpage,
	     ssize_t adjust_lower, ssize_t adjust_upper, int keep_align)
{
	size_t pgsize = 1UL << shift;
	size_t contpgsize = 1UL << contshift;

	char *cmpaddr;
	char *loaddr;
	char *hiaddr;

	char *from_addr;
	char *from_end;
	size_t from_length;

	char *to_addr;
	char *to_end;
	size_t to_length;

	int flags;

	struct {
		char *addr;
		unsigned long pgsize;
	} to_exp[10];
	int nr_to_exp;

	// alloc
	addr = map_contiguous_pte(&length, &cmpaddr, &loaddr, &hiaddr,
				  contpgsize, nr_contpage);
	tp_assert(addr != MAP_FAILED, "map contiguous error.");

	remap_length = contpgsize + (contpgsize * nr_contpage) + contpgsize;
	flags = MAP_PRIVATE
		| MAP_ANONYMOUS
		| MAP_HUGETLB
		| (contshift << MAP_HUGE_SHIFT);
	remap_addr = mmap(NULL, remap_length,
			 PROT_NONE,
			 flags,
			 -1, 0);
	tp_assert(remap_addr != MAP_FAILED, "allocate remap area error.");

	// test
	from_addr = (cmpaddr) + adjust_lower;
	from_end = (cmpaddr + contpgsize * nr_contpage) + adjust_upper;
	from_length = (unsigned long)from_end - (unsigned long)from_addr;

	to_addr = (void *)align_up((unsigned long)remap_addr, contpgsize);
	to_addr += contpgsize + (from_addr - cmpaddr);
	if (!keep_align) {
		if (!((unsigned long)to_addr & (contpgsize - 1))) {
			to_addr -= pgsize;
		}
	}
	to_length = from_length;
	to_end = to_addr + to_length;
	{
		unsigned long from = (unsigned long)from_addr;
		unsigned long to = (unsigned long)to_addr;
		struct memory_info info;
		int i = 0;

		while (from < (unsigned long)from_end) {
			unsigned long next;

			tp_assert(i < ARRAY_SIZE(to_exp),
				  "to_exp index error.");

			to_exp[i].addr = (void *)to;
			if ((unsigned long)to_exp[i].addr & (contpgsize - 1)) {
				to_exp[i].pgsize = pgsize;
			} else {
				to_exp[i].pgsize = contpgsize;
			}
			if (to_end < (to_exp[i].addr + to_exp[i].pgsize)) {
				to_exp[i].pgsize = pgsize;
			}
			if (!keep_align) {
				to_exp[i].pgsize = pgsize;
			}

			get_memory_info_self(from, &info);
			next = align_up(from + 1, info.pgsize);

			to += (next - from);
			from = next;
			i++;
		}
		nr_to_exp = i;
	}

	to_addr = mremap(from_addr, from_length,
			 to_length, MREMAP_MAYMOVE|MREMAP_FIXED, to_addr);
	tp_assert(to_addr != MAP_FAILED, "mremap error.");

	// check
	{
		struct memory_info info;
		int i;

		// from
		if (cmpaddr <= from_addr) {
			info.present = 0;
			get_memory_info_self((unsigned long)from_addr - 1,
					     &info);
			tp_assert(info.present == 1 && info.pgsize == pgsize,
				  "from_addr - 1 error.");
		}

		info.present = 1;
		get_memory_info_self((unsigned long)from_addr, &info);
		tp_assert(info.present == 0, "from_addr error.");

		info.present = 1;
		get_memory_info_self((unsigned long)from_end - 1, &info);
		tp_assert(info.present == 0, "from_end - 1 error.");

		if (from_end <= (cmpaddr + contpgsize * nr_contpage)) {
			info.present = 0;
			get_memory_info_self((unsigned long)from_end, &info);
			tp_assert(info.present == 1 && info.pgsize == pgsize,
				  "from_end error.");
		}

		// to
		for (i = 0; i < nr_to_exp; i++) {
			info.present = 0;
			get_memory_info_self((unsigned long)to_exp[i].addr,
					     &info);
			tp_assert(info.present == 1 &&
				  info.pgsize == to_exp[i].pgsize,
				  "to error.");
		}
	}
	return NULL;
}

void teardown_3xx(void)
{
	if (addr != MAP_FAILED) {
		munmap(addr, length);
	}

	if (remap_addr != MAP_FAILED) {
		munmap(remap_addr, remap_length);
	}
}
