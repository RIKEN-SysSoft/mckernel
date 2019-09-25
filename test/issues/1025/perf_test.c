#include <stdio.h>
#include <stdlib.h>
#include <langinfo.h>
#include <locale.h>
#include <sys/mman.h>

#include "perftool.h"

void
usage()
{
	printf("Usage: perf_test mode cntr_num [<type> <config>]...\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	long fds[PERF_CNTR_NUM];
	long long counts[PERF_CNTR_NUM];
	int types[PERF_CNTR_NUM];
	int configs[PERF_CNTR_NUM];

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
		fds[i] = pe_opener(-1, mode, types[i], configs[i], 0);
	}


	/* perf_start */
	for (i = 0; i < cntr_num; i++) {
		PERF_BEGIN(fds[i], 0);
	}

	calc_task();

	/* perf_end and read */
	for (i = 0; i < cntr_num; i++) {
		PERF_END(fds[i], 0);
		PERF_READ(fds[i], &counts[i], sizeof(long long));
		close(fds[i]);
	}

	/* print result */
	for (i = 0; i < cntr_num; i++) {
		if (types[i] == PERF_TYPE_HARDWARE) {
			printf("%s: %16ld\n",
			       hw_event_names[configs[i]], counts[i]);
		}
		else if (types[i] == PERF_TYPE_HW_CACHE) {
			printf("%s_%s_%s: %16ld\n",
			       id_names[(configs[i] >> 0) & 0xff],
			       op_id_names[(configs[i] >> 8) & 0xff],
			       result_names[(configs[i] >> 16) & 0xff],
			       counts[i]);
		}
	}
	return 0;
}
