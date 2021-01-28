#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
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

int check_data(char *data_head, char chk_data, unsigned long off1,
		unsigned long off2, unsigned long off3)
{
	int ret = -1;

	if (*(data_head + off1) == chk_data &&
			*(data_head + off2) == chk_data &&
			*(data_head + off3) == chk_data) {
		ret = 0;
	}

	return ret;
}

int main(int argc, char **argv)
{
	void *addr;
	int map_pgshift, unmap_pgshift, pid, status, err, ret = 0;
	size_t size, unmap_off;

	if (argc < 3) {
		printf("error: too few arguments\n");
		ret = -1;
		goto out;
	}
	map_pgshift = atoi(argv[1]);
	unmap_pgshift = atoi(argv[2]);
	hps = (1 << map_pgshift);
	ps = (1 << unmap_pgshift);
	unmap_off = hps * (PAGES - 1) - ps;

	printf("** Case 1: specified MAP_HUGETLB\n");
	size = hps * PAGES;
	unmap_off = hps * (PAGES - 1) - ps;
	addr = test_mmap(size, map_pgshift);
	if (addr == MAP_FAILED) {
		perror("mmap fail: ");
		ret = -1;
	}

	errno = 0;
	err = munmap(addr + unmap_off, ps);
	if (err == 0 && errno == 0) {
		printf("[OK] munamp succceeded\n");
	}
	else {
		printf("[NG] munmap returned %d and errno: EINVAL\n", err);
		ret = -1;
//		goto out;
	}

	pid = fork();
	if (pid == 0) {
		/* Child */
		memset(addr, 'b', unmap_off);
		memset(addr + unmap_off + ps, 'b', hps);
		memset(addr + unmap_off, '0', ps); /* expect SEGV */
		return 0;
	}
	else if (pid > 0) {
		/* Parent */
		if (waitpid(pid, &status, 0) == pid) {
			if (WIFSIGNALED(status) &&
					WTERMSIG(status) == SIGSEGV) {
				printf("[OK] Occurred SEGV on unmap area\n");
			}
			else {
				printf("[NG] Didn't occur SEGV\n");
				ret = -1;
			}
		}
		else {
			printf("[NG] waitpid failed\n");
			ret = -1;
		}
	}
	else {
		printf("[NG] fork failed\n");
		ret = -1;
	}

	if (check_data((char *)addr, 'b',
			0, unmap_off - 1, unmap_off + ps) == 0) {
		printf("[OK] data is correct\n");
	}
	else {
		printf("[NG] data is NOT correct\n");
		ret = -1;
	}

	printf("** Case 2: size is aligned on large page\n");
	size = hps * PAGES;
	addr = test_mmap(size, 0);
	if (addr == MAP_FAILED) {
		perror("mmap fail: ");
		ret = -1;
	}

	errno = 0;
	err = munmap(addr + unmap_off, ps);
	if (err == 0 && errno == 0) {
		printf("[OK] munamp succceeded\n");
	}
	else {
		printf("[NG] munmap returned %d and errno: EINVAL\n", err);
		ret = -1;
//		goto out;
	}

	pid = fork();
	if (pid == 0) {
		/* Child */
		memset(addr, 'b', unmap_off);
		memset(addr + unmap_off + ps, 'b', hps);
		memset(addr + unmap_off, '0', ps); /* expect SEGV */
		return 0;
	}
	else if (pid > 0) {
		/* Parent */
		if (waitpid(pid, &status, 0) == pid) {
			if (WIFSIGNALED(status) &&
					WTERMSIG(status) == SIGSEGV) {
				printf("[OK] Occurred SEGV on unmap area\n");
			}
			else {
				printf("[NG] Didn't occur SEGV\n");
				ret = -1;
			}
		}
		else {
			printf("[NG] waitpid failed\n");
			ret = -1;
		}
	}
	else {
		printf("[NG] fork failed\n");
		ret = -1;
	}

	if (check_data((char *)addr, 'b',
			0, unmap_off - 1, unmap_off + ps) == 0) {
		printf("[OK] data is correct\n");
	}
	else {
		printf("[NG] data is NOT correct\n");
		ret = -1;
	}

	printf("** Case 3: size is NOT aligned on large page\n");
	size = hps * PAGES - ps;
	addr = test_mmap(size, 0);
	if (addr == MAP_FAILED) {
		perror("mmap fail: ");
		ret = -1;
	}

	errno = 0;
	err = munmap(addr + unmap_off, ps);
	if (err == 0 && errno == 0) {
		printf("[OK] munamp succceeded\n");
	}
	else {
		printf("[NG] munmap returned %d and errno: EINVAL\n", err);
		ret = -1;
//		goto out;
	}

	pid = fork();
	if (pid == 0) {
		/* Child */
		memset(addr, 'b', unmap_off);
		memset(addr + unmap_off + ps, 'b', hps);
		memset(addr + unmap_off, '0', ps); /* expect SEGV */
		return 0;
	}
	else if (pid > 0) {
		/* Parent */
		if (waitpid(pid, &status, 0) == pid) {
			if (WIFSIGNALED(status) &&
					WTERMSIG(status) == SIGSEGV) {
				printf("[OK] Occurred SEGV on unmap area\n");
			}
			else {
				printf("[NG] Didn't occur SEGV\n");
				ret = -1;
			}
		}
		else {
			printf("[NG] waitpid failed\n");
			ret = -1;
		}
	}
	else {
		printf("[NG] fork failed\n");
		ret = -1;
	}

	if (check_data((char *)addr, 'b',
			0, unmap_off - 1, unmap_off + ps) == 0) {
		printf("[OK] data is correct\n");
	}
	else {
		printf("[NG] data is NOT correct\n");
		ret = -1;
	}

out:
	return ret;
}
