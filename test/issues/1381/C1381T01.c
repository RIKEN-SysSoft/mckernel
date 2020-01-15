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

void *test_mmap(unsigned long size, int pgshift)
{
	int lp_flags = 0;

	if (pgshift != 0) {
		lp_flags = MAP_HUGETLB | (pgshift << MAP_HUGE_SHIFT);
	}

	return mmap(NULL, size, PROT_WRITE | PROT_READ,
			MAP_ANONYMOUS | MAP_SHARED |
			lp_flags,
			-1, 0);
}

int main(int argc, char **argv)
{
	void *addr;
	int i, pgshift, err, ret = 0;
	size_t size;

	if (argc < 2) {
		printf("error: too few arguments\n");
		ret = -1;
		goto out;
	}
	pgshift = atoi(argv[1]);
	hps = (1 << pgshift);
	ps = getpagesize();

	printf("** Case 1: specified MAP_HUGETLB\n");
	size = hps * PAGES;
	addr = test_mmap(size, pgshift);
	if (addr == MAP_FAILED) {
		perror("mmap fail: ");
		ret = -1;
	}

	memset(addr, 'a', size);
	errno = 0;
	err = munmap(addr + size - ps, ps);
	if (err == -1 && errno == EINVAL) {
		printf("[OK] munmap returned %d and errno: EINVAL\n", err);
	}
	else {
		printf("[NG] munamp succceeded\n");
		ret = -1;
//		goto out;
	}

	printf("** Case 2: size is aligned on large page\n");
	size = hps * PAGES;
	addr = test_mmap(size, 0);
	if (addr == MAP_FAILED) {
		perror("mmap fail: ");
		ret = -1;
	}

	memset(addr, 'a', size);
	errno = 0;
	err = munmap(addr + size - ps, ps);
	if (err == -1 && errno == EINVAL) {
		printf("[OK] munmap returned %d and errno: EINVAL\n", err);
	}
	else {
		printf("[NG] munamp succceeded\n");
		ret = -1;
//		goto out;
	}

	printf("** Case 3: size is NOT aligned on large page\n");
	size = hps * PAGES - ps;
	addr = test_mmap(size, 0);
	if (addr == MAP_FAILED) {
		perror("mmap fail: ");
		ret = -1;
	}

	memset(addr, 'a', size);
	errno = 0;
	err = munmap(addr + size - ps, ps);
	if (err == 0 && errno == 0) {
		printf("[OK] munamp succceeded\n");
	}
	else {
		printf("[NG] munmap returned %d and errno: EINVAL\n", err);
		ret = -1;
//		goto out;
	}

out:
	return ret;
}
