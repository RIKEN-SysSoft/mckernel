#include <stdio.h>
#include <stdlib.h>
#include <langinfo.h>
#include <locale.h>
#include <sys/mman.h>

#include "perftool.h"

#define IS_GROUP 1

/* perf flow: Start -> calc -> Stop -> Reset -> Read */

void
usage()
{
	printf("Usage: perf_case_c mode cntr_num [<type> <config>]...\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	long fds[PERF_CNTR_NUM];
	long long counts[PERF_CNTR_NUM + 1];
	int types[PERF_CNTR_NUM];
	int configs[PERF_CNTR_NUM];
	int group_fd = -1;

	int cntr_num;
	int mode;
	int i;

	if (argc < 3) {
		printf("ERROR: Too few arguments.\n");
		usage();
	}

	mode = atoi(argv[1]);
	cntr_num = atoi(argv[2]);

	/* perse args */
	if (argc < cntr_num * 2 + 2) {
		printf("ERROR: Too few arguments.\n");
		usage();
	}

	for (i = 0; i < cntr_num; i++) {
		types[i] = atoi(argv[i * 2 + 3]);
		configs[i] = atoi(argv[i * 2 + 4]);
	}

	/* perf_event_open */
	for (i = 0; i < cntr_num; i++) {
		fds[i] = pe_opener(group_fd, mode,
			types[i], configs[i], IS_GROUP);
		if (group_fd == -1) {
			group_fd = fds[i];
		}
	}

	/* perf_start */
	PERF_BEGIN(group_fd, PERF_IOC_FLAG_GROUP);

	/* calc */
	calc_task();

	/* perf end and reset */
	PERF_END(group_fd, PERF_IOC_FLAG_GROUP);
	PERF_RESET(group_fd, PERF_IOC_FLAG_GROUP);

	/* perf read */
	PERF_READ(group_fd, counts, sizeof(counts));

	for (i = 0; i < cntr_num; i++) {
		close(fds[i]);
	}

	/* print result */
	for (i = 0; i < counts[0]; i++) {
		if (types[i] == PERF_TYPE_HARDWARE) {
			printf("%s: %16ld\n",
			       hw_event_names[configs[i]], counts[i + 1]);
		}
		else if (types[i] == PERF_TYPE_HW_CACHE) {
			printf("%s_%s_%s: %16ld\n",
			       id_names[(configs[i] >> 0) & 0xff],
			       op_id_names[(configs[i] >> 8) & 0xff],
			       result_names[(configs[i] >> 16) & 0xff],
			       counts[i + 1]);
		}
	}

	return 0;
}
