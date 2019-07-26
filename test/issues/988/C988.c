#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>

#define DEF_PROT (PROT_READ | PROT_WRITE | PROT_EXEC)

int main(void)
{
	long pgsize = getpagesize();
	void *ptr1, *ptr2;
	int rc, ret;

	printf("*** Check VMA's prot ***\n");

	ptr1 = mmap(0, pgsize, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (ptr1 == MAP_FAILED) {
		perror("mmap");
		ret = -1;
		goto out;
	}
	memset(ptr1, '1', pgsize);
	printf("** mmap %p: Succeed\n", ptr1);

	// Check default prot
	rc = syscall(899, ptr1);
	if (rc == PROT_READ | PROT_WRITE | PROT_EXEC) {
		printf("[OK] default : %d\n", rc);
	}
	else {
		printf("[NG] default : %d\n", rc);
		ret = -1;
		goto out;
	}

	// mprotec PROT_WRITE | PROT_EXEC to ptr1
	rc = mprotect(ptr1, pgsize, PROT_NONE);
	if (rc != 0) {
		perror("mprotect");
		ret = -1;
		goto out;
	}
	rc = mprotect(ptr1, pgsize, PROT_WRITE | PROT_EXEC);
	if (rc != 0) {
		perror("mprotect");
		ret = -1;
		goto out;
	}
	printf("** mprotect PROT_WRITE | PROT_EXEC: Succeed\n");

	// Check prot after mprotect
	rc = syscall(899, ptr1);
	if (rc == PROT_WRITE | PROT_EXEC) {
		printf("[OK] after mprotect : %d\n", rc);
	}
	else {
		printf("[NG] after mprotect : %d\n", rc);
		ret = -1;
		goto out;
	}

	munmap(ptr1, pgsize);
	printf("** munmap %p: Done\n", ptr1);

	// Check after munmap
	rc = syscall(899, ptr1);
	if (rc == DEF_PROT) {
		printf("[OK] after munmap : %d\n", rc);
	}
	else {
		printf("[NG] after munmap : %d\n", rc);
		ret = -1;
		goto out;
	}

	ptr2 = mmap(0, pgsize, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (ptr2 == MAP_FAILED) {
		perror("mmap");
		ret = -1;
		goto out;
	}
	memset(ptr2, '2', pgsize);
	printf("** mmap %p: Succeed\n", ptr2);

	// mprotec PROT_NONE to ptr2
	rc = mprotect(ptr2, pgsize, PROT_NONE);
	if (rc != 0) {
		perror("mprotect");
		ret = -1;
		goto out;
	}
	printf("** mprotect PROT_NONE: Succeed\n");

	// Check prot after mprotect
	rc = syscall(899, ptr2);
	if (rc != DEF_PROT) {
		printf("[OK] after mprotect : %d\n", rc);
	}
	else {
		printf("[NG] after mprotect : %d\n", rc);
		ret = -1;
		goto out;
	}
	munmap(ptr2, pgsize);

	// Check after munmap
	rc = syscall(899, ptr2);
	if (rc == DEF_PROT) {
		printf("[OK] after munmap : %d\n", rc);
	}
	else {
		printf("[NG] after munmap : %d\n", rc);
		ret = -1;
		goto out;
	}

out:
	if (ret != 0) {
		printf("TEST_FAILED\n");
	}

	return ret;
}
