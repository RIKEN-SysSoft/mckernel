#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PAGES 3
#define MAP_HUGE_SHIFT 26

static unsigned long ps, hps;

void *hugetlb_mmap(unsigned long size, int pgshift)
{
	return mmap(NULL, size, PROT_WRITE | PROT_READ,
			MAP_ANONYMOUS | MAP_PRIVATE |
			MAP_HUGETLB | (pgshift << MAP_HUGE_SHIFT),
			-1, 0);
}

int main(int argc, char **argv)
{
	void *p1, *p2, *p3, *p4, *old_addr, *new_addr;
	int i, pgshift, err, ret = 0;
	unsigned long base_start, base_size, new_start, new_size;
	size_t size, remap_size;

	if (argc < 2) {
		printf("error: too few arguments\n");
		ret = -1;
		goto out;
	}
	pgshift = atoi(argv[1]);
	hps = (1 << pgshift);
	ps = getpagesize();
	size = hps * PAGES;

	for (i = 0; i < 4; i++) {
		p1 = hugetlb_mmap(size, pgshift);
		if (p1 == MAP_FAILED) {
			perror("mmap fail: ");
			ret = -1;
			goto out;
		}
		printf("** mmap p1: %p - %p\n", p1, p1 + size);

		p2 = hugetlb_mmap(size, pgshift);
		if (p2 == MAP_FAILED) {
			perror("mmap fail: ");
			ret = -1;
			goto out;
		}
		printf("** mmap p2: %p - %p\n", p2, p2 + size);

		p3 = hugetlb_mmap(size, pgshift);
		if (p3 == MAP_FAILED) {
			perror("mmap fail: ");
			ret = -1;
			goto out;
		}
		printf("** mmap p3: %p - %p\n", p3, p3 + size);

		/* make page populate */
		memset(p1, 0xff, size);
		memset(p2, 0xff, size);
		memset(p3, 0x77, size);

		remap_size = size - ps;
		old_addr = p1 + ps * (i >> 1);
		new_addr = p3 + ps * (i & 1);

		p4 = mremap(old_addr, remap_size, remap_size,
				MREMAP_FIXED | MREMAP_MAYMOVE, new_addr);
		if (p4 == MAP_FAILED) {
			perror("mremap fail: ");
			ret = -1;
			goto out;
		}
		if (memcmp(p4, p2, remap_size)) {
			printf("memcmp detect DIFF!!\n");
			ret = -1;
			goto out;
		}
		printf("*** mremap p4: %p - %p\n", p4, p4 + remap_size);

	}

	printf("[OK] mremap on HUGETLB\n");
out:
	return ret;
}
