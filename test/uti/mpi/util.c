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

/* rdtsc */
inline uint64_t rdtsc_light(void)
{
    uint64_t x;
    __asm__ __volatile__("rdtscp;" /* rdtscp don't jump over earlier instructions */
                         "shl $32, %%rdx;"
                         "or %%rdx, %%rax" :
                         "=a"(x) :
                         :    
                         "%rcx", "%rdx", "memory");
    return x;
}

/* Calculation */
static inline void fixed_size_work() {
	asm volatile(
	    "movq $0, %%rcx\n\t"
		"1:\t"
		"addq $1, %%rcx\n\t"
		"cmpq $99, %%rcx\n\t"
		"jle 1b\n\t"
		:
		: 
		: "rcx", "cc");
}

static inline void bulk_fsw(unsigned long n) {
	int j;
	for (j = 0; j < (n); j++) {
		fixed_size_work(); 
	} 
}

double nspw; /* nsec per work */
unsigned long nsec;

void fwq_init() {
	struct timespec start, end;
	int i;
	clock_gettime(TIMER_KIND, &start);
#define N_INIT 10000000
	bulk_fsw(N_INIT);
	clock_gettime(TIMER_KIND, &end);
	nsec = DIFFNSEC(end, start);
	nspw = nsec / (double)N_INIT;
}

#if 0
void fwq(long delay_nsec) {
	if (delay_nsec < 0) { 
        return;
	}
	bulk_fsw(delay_nsec / nspw);
}
#else /* For machines with large core-to-core performance variation (e.g. OFP) */
void fwq(long delay_nsec) {
	struct timespec start, end;
	
	if (delay_nsec < 0) { return; }
	clock_gettime(TIMER_KIND, &start);

	while (1) {
		clock_gettime(TIMER_KIND, &end);
		if (DIFFNSEC(end, start) >= delay_nsec) {
			break;
		}
		bulk_fsw(2); /* ~150 ns per iteration on FOP */
	}
}
#endif

int print_cpu_last_executed_on(const char *name) {
	char fn[256];
	char* result;
	pid_t tid = syscall(SYS_gettid);
	int fd;
	int offset;
    int mpi_errno = 0;
	int rc;

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
