#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include "util.h"

/* Messaging */
enum test_loglevel test_loglevel = TEST_LOGLEVEL_DEBUG;

int print_cpu_last_executed_on(const char *name) {
	char fn[256];
	char *result;
	pid_t tid = syscall(SYS_gettid);
	int fd;
	int offset;
	int mpi_errno = 0;
	int rc;

	sprintf(fn, "/proc/%d/task/%d/stat", getpid(), (int)tid);
	//printf("fn=%s\n", fn);
	fd = open(fn, O_RDONLY);
	if (fd == -1) {
		printf("open() failed\n");
		goto fn_fail;
	}

	result = malloc(65536);
	if (result == NULL) {
		printf("malloc() failed");
		goto fn_fail;
	}

	int amount = 0;
	offset = 0;
	while (1) {
		amount = read(fd, result + offset, 65536);
		//		printf("amount=%d\n", amount);
		if (amount == -1) {
			printf("read() failed");
			goto fn_fail;
		}
		if (amount == 0) {
			goto eof;
		}
		offset += amount;
	}
 eof:;
    //printf("result:%s\n", result);

	char *next_delim = result;
	char *field;
	int i;
	for (i = 0; i < 39; i++) {
		field = strsep(&next_delim, " ");
	}

	int cpu = sched_getcpu();
	if (cpu == -1) {
		printf("getpu() failed\n");
		goto fn_fail;
	}

	rc = syscall(732);

	printf("%s: pmi_rank=%02d,os=%s,stat-cpu=%02d,sched_getcpu=%02d,tid=%d\n", name, atoi(getenv("PMI_RANK")), rc == -1 ? "lin" : "mck", atoi(field), cpu, tid); fflush(stdout);
 fn_exit:
    free(result);
    return mpi_errno;
 fn_fail:
	mpi_errno = -1;
    goto fn_exit;
}
