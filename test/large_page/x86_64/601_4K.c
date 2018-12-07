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
char fn_2M[] = "/mnt/hugetlbfs-2M/tmp";

#define PAGE_SHIFT_1G 30
#define PAGE_SIZE_1G (1UL << PAGE_SHIFT_1G)
char fn_1G[] = "/mnt/hugetlbfs-1G/tmp";

int trial_num;

int mmap_hugetlbfs(char *fn, size_t page_size)
{
	int fd;
	char *addr_mmap;

	fd = open(fn, O_CREAT | O_RDWR, 0755);
	NG(fd != -1, "open failed, fn: %s\n", fn);

	addr_mmap = mmap(0, page_size,
			 PROT_READ | PROT_WRITE,
			 MAP_SHARED,
			 fd, 0);
	NG(addr_mmap != (void *)-1, "mmap failed\n");
	addr_mmap[0] = 'z';
	NG(__atomic_load_n(addr_mmap, __ATOMIC_SEQ_CST) == 'z',
	   "memory access failed\n");

	printf("large page request, trial#: %03d, addr: %016lx, size: %ld\n",
	       trial_num++, (unsigned long)addr_mmap, page_size);

	munmap(addr_mmap, page_size);
	close(fd);
	unlink(fn);

	return 0;
 fn_fail:
	return 1;
}

int main(int argc, char **argv)
{
	int ret;

	ret = mmap_hugetlbfs(fn_2M, PAGE_SIZE_2M);
	NG(ret == 0, "mmap_hugetlbfs failed, fn: %s", fn_2M);

	ret = mmap_hugetlbfs(fn_1G, PAGE_SIZE_1G);
	NG(ret == 0, "mmap_hugetlbfs failed, fn: %s", fn_1G);

	return 0;
 fn_fail:
	return 1;
}
