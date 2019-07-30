/* issue_1325.c COPYRIGHT FUJITSU LIMITED 2019 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* for 512MiB allocated McKernel failure sizes */
#define MALLOC1_SIZE (350 * 1024 * 1024)
#define MALLOC2_SIZE (400 * 1024 * 1024)

int main(int argc, char *argv[])
{
	const long pgsize = sysconf(_SC_PAGESIZE);
	char *p1 = NULL;
	char *p2 = NULL;
	size_t off = 0;
	int ret = -1;

	p1 = malloc(MALLOC1_SIZE);
	if (p1 == NULL) {
		printf("malloc1:allocate failed.\n");
		goto err;
	}
	printf("malloc1:allocate 0x%lx\n", (unsigned long)p1);

	for (off = 0; off < MALLOC1_SIZE; off += pgsize) {
		*(p1 + off) = 'Z';
	}
	printf("malloc1:access ok, free\n");
	free(p1);

	p2 = malloc(MALLOC2_SIZE);
	if (p2 == NULL) {
		printf("malloc2:allocate failed.\n");
		goto err;
	}
	printf("malloc2:allocate 0x%lx\n", (unsigned long)p2);

	for (off = 0; off < MALLOC2_SIZE; off += pgsize) {
		*(p2 + off) = 'Z';
	}
	printf("malloc2:access ok, free\n");
	free(p2);

	ret = 0;
err:
	return ret;
}
