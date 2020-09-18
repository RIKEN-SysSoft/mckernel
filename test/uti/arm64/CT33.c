#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include "util.h"

#define WAITER_CPU 0
#define WAKER_CPU 1

int sem;
pthread_barrier_t bar;
int flag;
pthread_t thr;
long t_fwq, t_futex_wake, t_futex_wait;
long t_fwq2;
long nloop;
long blocktime = 10 * 1000 * 1000L;

void *util_fn(void *arg)
{
	int i;
	int ret;
    long start, end;
    long start2, end2;
	unsigned long mem;

	print_cpu_last_executed_on("Utility thread");

	ret = syscall(732);
	OKNGNOJUMP(ret == -1, "Utility thread is running on Linux\n");

	/* Measure fwq time */
	start = rdtsc_light();
	for (i = 0; i < nloop; i++) {
		fwq(blocktime, &mem);
	}
	end = rdtsc_light();
	t_fwq2 += end - start;

	/* Measure fwq + futex time */
	syscall(701, 1 | 2 | 0x80000000);
	pthread_barrier_wait(&bar);
	start = rdtsc_light();
	for (i = 0; i < nloop; i++) {
		start2 = rdtsc_light();

		fwq(blocktime, &mem);

		end2 = rdtsc_light();
		t_fwq += end2 - start2;

		if ((ret = syscall(__NR_futex, &sem, FUTEX_WAKE, 1, NULL, NULL, 0)) != 1) {
			printf("Error: futex wake failed (%d,%s)\n", ret, strerror(errno));
		}

		//pthread_barrier_wait(&bar);
	}
	end = rdtsc_light();
	t_futex_wake += end - start;

	syscall(701, 4 | 8 | 0x80000000);

 fn_fail:
	return NULL;
}

static struct option options[] = {
	/* end */
	{ NULL, 0, NULL, 0, }
};

int main(int argc, char **argv)
{
	int i, j;
	int ret;
	long start, end;
	cpu_set_t cpuset;
	pthread_attr_t attr;
	pthread_barrierattr_t bar_attr;
	struct sched_param param = { .sched_priority = 99 };
	int opt;
	unsigned long mem;

	while ((opt = getopt_long(argc, argv, "+b:", options, NULL)) != -1) {
		switch (opt) {
			case 'b':
				blocktime = atoi(optarg);
				break;
			default: /* '?' */
				printf("unknown option %c\n", optopt);
				exit(1);
		}
	}
	nloop = 10 * 1000000000UL / blocktime;
	printf("[INFO] nloop=%ld,blocktime=%ld\n", nloop, blocktime);

	
 	CPU_ZERO(&cpuset);
	CPU_SET(WAITER_CPU, &cpuset);
	if ((ret = sched_setaffinity(0, sizeof(cpu_set_t), &cpuset))) {
 		printf("Error: sched_setaffinity: %s\n", strerror(errno));
		goto fn_fail;
	}
	print_cpu_last_executed_on("Master thread");

	fwq_init(&mem);

	pthread_barrierattr_init(&bar_attr);
	pthread_barrier_init(&bar, &bar_attr, 2);

	ret = syscall(732);
	OKNGNOJUMP(ret != -1, "Master thread is running on McKernel\n");

	ret = syscall(731, 1, NULL);
	OKNGNOJUMP(ret != -1, "util_indicate_clone\n");

	if ((ret = pthread_attr_init(&attr))) {
 		printf("Error: pthread_attr_init failed: %s\n", strerror(errno));
		goto fn_fail;
	}

 	CPU_ZERO(&cpuset);
	CPU_SET(WAKER_CPU, &cpuset);

	if ((ret = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset))) {
 		printf("Error: pthread_attr_setaffinity_np: %s\n", strerror(errno));
		goto fn_fail;
	}

	if ((ret = pthread_create(&thr, &attr, util_fn, NULL))) {
		printf("Error: pthread_create: %s\n", strerror(errno));
		goto fn_fail;
	}

	if ((ret = sched_setscheduler(0, SCHED_FIFO, &param))) {
		printf("Error: sched_setscheduler: %s\n", strerror(errno));
		goto fn_fail;
	}

	pthread_barrier_wait(&bar);
	start = rdtsc_light();
	for (i = 0; i < nloop; i++) {
		
		if ((ret = syscall(__NR_futex, &sem, FUTEX_WAIT, 0, NULL, NULL, 0))) {
			printf("Error: futex wait: %s\n", strerror(errno));
		}

		//pthread_barrier_wait(&bar);
	}
	end = rdtsc_light();
	t_futex_wait += end - start;

	pthread_join(thr, NULL);
	printf("[INFO] compute: %ld, wake: %ld, wait: %ld, wake - compute: %ld, wait - compute: %ld (cycles)\n", t_fwq, t_futex_wake, t_futex_wait, (t_futex_wake - t_fwq) / nloop, (t_futex_wait - t_fwq) / nloop);

 fn_fail:
	return ret;
}
