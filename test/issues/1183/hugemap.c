#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

#define MAP_HUGE_SHIFT 26

void print_usage(void)
{
	printf("usage: hugemap <total_mapsize(GB)> <mapsize(GB)> <pgshift>\n");
}

int mmap_flag(size_t mapsize, int page_shift)
{
	char *addr_mmap;
	int flags = MAP_ANONYMOUS | MAP_PRIVATE;

	if (page_shift >= 0) {
		/* mean use MAP_HUGETLB */
		flags |= MAP_HUGETLB | (page_shift << MAP_HUGE_SHIFT);
	}

	addr_mmap = mmap(0, mapsize,
			PROT_READ | PROT_WRITE,
			flags, -1, 0);

	if (addr_mmap == MAP_FAILED) {
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	int i;
	unsigned long maptotal;
	size_t mapsize;
	int pgshift;

	void *addr = NULL;

	if (argc < 4) {
		print_usage();
		return 1;
	}

	maptotal = atol(argv[1]) << 30;
	mapsize = atol(argv[2]) << 30;
	pgshift = atoi(argv[3]);

	printf("*** total_mapsize: %ld GB, mapsize: %ld pgshift: %d\n",
		maptotal >> 30, mapsize >> 30, pgshift);

	for (i = 0; i < maptotal / mapsize; i++) {
		printf("** mmap %ld GB: ", mapsize >> 30);

		ret = mmap_flag(mapsize, pgshift);

		if (ret != 0) {
			printf("failed\n");
			goto out;
		}
		else {
			printf("succeed\n");
		}
	}
	printf("** all mmaps succeeded\n");
out:
	return ret;
}
