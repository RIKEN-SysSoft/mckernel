#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

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
	if (fd == -1) {
		printf("open failed, fn:%s\n");
		goto fn_fail;
	}

	addr_mmap = mmap(0, page_size,
			 PROT_READ | PROT_WRITE,
			 MAP_SHARED,
			 fd, 0);
	if (addr_mmap == (void *)-1) {
		printf("mmap failed\n");
		goto fn_fail;
	}
	addr_mmap[0] = 'z';

	printf("large page request, addr: %016lx, size: %ld\n",
	       (unsigned long)addr_mmap, page_size);

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
	if (ret != 0) {
		printf("mmap_hugetlbfs failed, fn: %s", fn_2M);
		goto fn_fail;
	}

	ret = mmap_hugetlbfs(fn_1G, PAGE_SIZE_1G);
	if (ret != 0) {
		printf("mmap_hugetlbfs failed, fn: %s", fn_1G);
		goto fn_fail;
	}

	return 0;
 fn_fail:
	return 1;
}
