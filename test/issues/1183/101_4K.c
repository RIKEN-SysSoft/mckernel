#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include "util.h"

#define PAGE_SHIFT_64K 16
#define PAGE_SIZE_64K (1UL << PAGE_SHIFT_64K)

#define PAGE_SHIFT_2M 21
#define PAGE_SIZE_2M (1UL << PAGE_SHIFT_2M)

#define PAGE_SHIFT_32M 25
#define PAGE_SIZE_32M (1UL << PAGE_SHIFT_32M)

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

	if (addr_mmap == (void *)-1) {
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	int i;
	unsigned long memtotal = (1UL << 35); /* 32GB */
	unsigned long pgsize = PAGE_SIZE_2M;
	int pgshift = PAGE_SHIFT_2M;
	
	for (i = 0; i < memtotal / pgsize; i++) {
		ret = mmap_flag(pgsize, pgshift);
		if (ret == -1) {
			printf("[ OK ] mmap returned -1\n");
			goto out;
		}
	}
	printf("[ NG ] all mmaps succeeded\n");
	
 out:
	return 0;
}
