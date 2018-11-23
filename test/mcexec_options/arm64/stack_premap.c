/* stack_premap.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define PAGEMAP_PRESENT (1UL << 63)

static void show_usage(void)
{
	printf("./stack_premap <stack_premap(byte)>\n");
}

int main(int argc, char *argv[])
{
	FILE *fp_maps = 0;
	FILE *fp_pgmap = 0;
	int result = -1;
	unsigned long premap = 0;
	unsigned long start = 0;
	unsigned long end = 0;
	char buf[4096];
	char *tmp = NULL;
	const unsigned long page_size = sysconf(_SC_PAGESIZE);
	unsigned long align_size = 0;
	unsigned long pagemap = 0;
	long offset = 0;

	if (argc != 2) {
		show_usage();
		result = 0;
		goto err;
	}
	premap = atoll(argv[1]);

	/* alignment check */
	if (premap & (page_size - 1)) {
		align_size = ((premap + page_size) & ~(page_size - 1));
	} else {
		align_size = premap;
	}

	fp_maps = fopen("/proc/self/maps", "r");
	if (fp_maps == NULL) {
		printf("fopen() failed. %d\n", errno);
		goto err;
	}

	fp_pgmap = fopen("/proc/self/pagemap", "r");
	if (fp_pgmap == NULL) {
		printf("fopen() failed. %d\n", errno);
		goto maps_close;
	}

	/* check stack area */
	while (fgets(buf, sizeof(buf), fp_maps) != NULL) {
		if (strstr(buf, "[stack]")) {
			sscanf(buf, "%lx-%lx", &start, &end);
		}
	}

	/* check premapping */
	offset = (end - align_size) / page_size * 8;
	if (fseek(fp_pgmap, offset, SEEK_SET)) {
		printf("fseek() failed. %d\n", errno);
		goto pgmap_close;
	}

	if (fread(&pagemap, 8, 1, fp_pgmap) != 1) {
		printf("fread() failed. %d\n", errno);
		goto pgmap_close;
	}

	if (!(pagemap & PAGEMAP_PRESENT)) {
		printf("not premapped. (stack(0x%lx-0x%lx), va=0x%lx)\n",
			start, end, end - align_size);
		goto pgmap_close;
	}
	result = 0;

pgmap_close:
	if (fp_pgmap) {
		if (fclose(fp_pgmap)) {
			printf("fclose() failed. %d\n", errno);
			result = -1;
			goto err;
		}
	}

maps_close:
	if (fp_maps) {
		if (fclose(fp_maps)) {
			printf("fclose() failed. %d\n", errno);
			result = -1;
			goto err;
		}
	}

err:
	return result;
}
