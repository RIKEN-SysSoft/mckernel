/* extend_heap.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static void show_usage(void)
{
	printf("./extend_heap <extend-heap-by(byte)>\n");
}

int main(int argc, char *argv[])
{
	FILE *fp = 0;
	int result = -1;
	unsigned long exheap = 0;
	unsigned long start = 0;	/* dummy */
	unsigned long bf_end = 0;
	unsigned long af_end = 0;
	char buf[4096];
	char *tmp = NULL;
	const unsigned long page_size = sysconf(_SC_PAGESIZE);
	unsigned long align_size = page_size;

	if (argc != 2) {
		show_usage();
		result = 0;
		goto err;
	}
	exheap = atoll(argv[1]);

	/* check default heap-end */
	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL) {
		printf("fopen() failed. %d\n", errno);
		goto err;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (strstr(buf, "[heap]")) {
			sscanf(buf, "%lx-%lx", &start, &bf_end);
		}
	}

	if (fclose(fp)) {
		printf("fclose() failed. %d\n", errno);
		goto err;
	}

	/* heap-end adjustment */
	if (brk((void *)bf_end)) {
		printf("brk() failed. %d\n", errno);
		goto err;
	}

	/* heap extend 1byte */
	if (sbrk(1) == (void *)-1) {
		printf("sbrk() failed. %d\n", errno);
		goto err;
	}

	/* check extended heap-end */
	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL) {
		printf("fopen() failed. %d\n", errno);
		goto err;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (strstr(buf, "[heap]")) {
			sscanf(buf, "%lx-%lx", &start, &af_end);
		}
	}

	if (fclose(fp)) {
		printf("fclose() failed. %d\n", errno);
		goto err;
	}

	if (page_size < exheap) {
		align_size = page_size / 8 * page_size;
	}

	if ((af_end - bf_end) < exheap) {
		printf("extend size ng.\n");
		goto err;
	}

	if (af_end & (align_size - 1)) {
		printf("extend align ng.\n");
		goto err;
	}
	result = 0;
err:
	return result;
}
