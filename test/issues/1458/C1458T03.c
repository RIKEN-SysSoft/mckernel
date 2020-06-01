#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define PAGES 3
#define MAP_HUGE_SHIFT 26

static unsigned long ps, hps;

void *test_shmget(key_t key, unsigned long size, int pgshift)
{
	int shm_flags = 0;
	int shmid = 0;

	if (pgshift != 0) {
		shm_flags |= SHM_HUGETLB;
	}

	shmid = shmget(key, size, IPC_CREAT | 0660 | shm_flags);
	if (shmid == -1) {
		perror("shmget fail:");
		return NULL;
	}
	return shmat(shmid, NULL, 0);
}

int main(int argc, char **argv)
{
	void *addr;
	int i, pgshift, err, ret = 0;
	size_t size, unmap_off;
	key_t key = ftok(argv[0], 0);

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
	unmap_off = hps * (PAGES - 1) - ps;
	addr = test_shmget(key, size, pgshift);
	if (addr == MAP_FAILED) {
		perror("mmap fail: ");
		ret = -1;
	}

	errno = 0;
	memset(addr, 'a', size);
	err = munmap(addr + (hps * (PAGES - 1)) - ps, ps);
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
	unmap_off = hps * (PAGES - 1) - ps;
	addr = test_shmget(key, size, 0);
	if (addr == MAP_FAILED) {
		perror("mmap fail: ");
		ret = -1;
	}

	errno = 0;
	memset(addr, 'a', size);
	err = munmap(addr + (hps * (PAGES - 1)) - ps, ps);
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
	unmap_off = hps * (PAGES - 1) - ps;
	addr = test_shmget(key, size, 0);
	if (addr == MAP_FAILED) {
		perror("mmap fail: ");
		ret = -1;
	}

	errno = 0;
	memset(addr, 'a', size);
	err = munmap(addr + (hps * (PAGES - 1)) - ps, ps);
	if (err == -1 && errno == EINVAL) {
		printf("[OK] munmap returned %d and errno: EINVAL\n", err);
	}
	else {
		printf("[NG] munamp succceeded\n");
		ret = -1;
//		goto out;
	}

out:
	return ret;
}
