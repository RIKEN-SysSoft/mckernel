#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#define GB (1024 * 1024 * 1024)
#define MAP_SIZE (1 * GB)

int main(int argc, char **argv)
{
	int rc, ret;
	void *addr1, *addr2;
	stack_t *ss, *oss;
	ssize_t stack_t_size = sizeof(stack_t);

	addr1 = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (addr1 == MAP_FAILED) {
		ret = -1;
		perror("failed to mmap 1st: ");
		goto out;
	}

	addr2 = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (addr2 == MAP_FAILED) {
		ret = -1;
		perror("failed to mmap 2nd: ");
		goto out;
	}

	oss = addr1 + MAP_SIZE - stack_t_size;
	memset(oss, '0', stack_t_size);
	ss = addr2 + MAP_SIZE - stack_t_size;
	memset(ss, '0', stack_t_size);

	rc = sigaltstack(NULL, oss);
	if (rc == 0) {
		printf("[OK] sigaltstack 1st is successful\n");
	}
	else {
		ret = -1;
		perror("[NG] failed to sigaltstack 1st: ");
		goto out;
	}

	ss->ss_sp = oss->ss_sp;
	ss->ss_flags = oss->ss_flags;
	ss->ss_size = oss->ss_size;
	rc = sigaltstack(ss, NULL);
	if (rc == 0) {
		printf("[OK] sigaltstack 2nd is successful\n");
	}
	else {
		ret = -1;
		perror("[NG] failed to sigaltstack 2nd: ");
		goto out;
	}

out:
	return ret;
}
