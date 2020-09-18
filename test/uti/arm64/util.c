#define _GNU_SOURCE		 /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include "util.h"

#define TS2NS(sec, nsec) \
	((unsigned long)(sec) * 1000000000ULL + \
	 (unsigned long)(nsec))

#define N_INIT 10000000

static inline void FIXED_SIZE_WORK(unsigned long *ptr)
{
	asm volatile("mov %x0, x20\n"
			 "add x20, x20, #1\n"
			 "mov x20, %x0\n"
			 : "+rm" (*ptr)
			 :
			 : "x20", "cc", "memory");
}

static inline void BULK_FSW(unsigned long n,
				unsigned long *ptr)
{
	int j;

	for (j = 0; j < (n); j++) {
		FIXED_SIZE_WORK(ptr);
	}
}

double nspw; /* nsec per work */
unsigned long nsec;

void fwq_init(unsigned long *mem)
{
	struct timespec start, end;
	unsigned long nsec;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	BULK_FSW(N_INIT, mem);
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	nsec = (TS2NS(end.tv_sec, end.tv_nsec) -
		TS2NS(start.tv_sec, start.tv_nsec));
	nspw = nsec / (double)N_INIT;
	printf("nsec=%ld, nspw=%f\n", nsec, nspw);
}

void fwq(long delay_nsec, unsigned long *mem)
{
	BULK_FSW(delay_nsec / nspw, mem);
}

int print_cpu_last_executed_on(const char *name) {
	char fn[256];
	char* result;
	pid_t tid = syscall(SYS_gettid);
	int fd;
	int offset;
	int mpi_errno = 0;

	sprintf(fn, "/proc/%d/task/%d/stat", getpid(), (int)tid);
	//printf("fn=%s\n", fn);
	fd = open(fn, O_RDONLY);
	if(fd == -1) {
		printf("open() failed\n");
		goto fn_fail;
	}

	result = malloc(65536);
	if(result == NULL) {
		printf("malloc() failed");
		goto fn_fail;
	}

	int amount = 0;
	offset = 0;
	while(1) {
		amount = read(fd, result + offset, 65536);
		//		printf("amount=%d\n", amount);
		if(amount == -1) {
			printf("read() failed");
			goto fn_fail;
		}
		if(amount == 0) {
			goto eof;
		}
		offset += amount;
	}
 eof:;
	//printf("result:%s\n", result);

	char* next_delim = result;
	char* field;
	int i;
	for(i = 0; i < 39; i++) {
		field = strsep(&next_delim, " ");
	}

	int cpu = sched_getcpu();
	if(cpu == -1) {
		printf("getcpu() failed\n");
		goto fn_fail;
	}

	printf("[INFO] %s (tid: %d) is running on %02d,%02d\n", name, tid, atoi(field), cpu);
 fn_exit:
	free(result);
	return mpi_errno;
 fn_fail:
	mpi_errno = -1;
	goto fn_exit;
}

