#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include "../util.h"

#define PAGE_SHIFT_2M 21
#define PAGE_SIZE_2M (1UL << PAGE_SHIFT_2M)

#define PAGE_SHIFT_1G 30
#define PAGE_SIZE_1G (1UL << PAGE_SHIFT_1G)

#define MAP_HUGE_SHIFT 26

int trial_num;

int mmap_flag(size_t page_size, unsigned long page_shift)
{
	char *addr_mmap;

	addr_mmap = mmap(0, page_size,
			 PROT_READ | PROT_WRITE,
			 MAP_ANONYMOUS | MAP_PRIVATE |
			 MAP_HUGETLB | (page_shift << MAP_HUGE_SHIFT),
			 -1, 0);
	NG(addr_mmap != (void *)-1, "mmap failed\n");

	addr_mmap[0] = 'z';
	NG(__atomic_load_n(addr_mmap, __ATOMIC_SEQ_CST) == 'z',
	   "memory access failed\n");

	printf("large page request, trial#: %03d, addr: %016lx, size: %ld\n",
	       trial_num++, (unsigned long)addr_mmap, page_size);

	munmap(addr_mmap, page_size);

	return 0;
 fn_fail:
	return 1;
}

int main(int argc, char **argv)
{
	int ret;

	ret = mmap_flag(PAGE_SIZE_2M, PAGE_SHIFT_2M);
	NG(ret == 0, "mmap_flag failed, size: %ld\n",
	   PAGE_SIZE_2M);

	ret = mmap_flag(PAGE_SIZE_1G, PAGE_SHIFT_1G);
	NG(ret == 0, "mmap_flag failed, size: %ld\n",
	   PAGE_SIZE_1G);

	return 0;
 fn_fail:
	return 1;
}
