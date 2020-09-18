#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <signal.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "util.h"

#define WAITER_CPU 0
#define WAKER_CPU 1

pthread_mutex_t mutex;
pthread_cond_t cond;
pthread_barrier_t bar;
int flag;
pthread_t thr;
long t_cond_wait, t_fwq;
long nloop;
long blocktime = 10L * 1000 * 1000;
int linux_run;

void *util_fn(void *arg)
{
	int i;
	int ret;
	long start, end;
	unsigned long mem;

	print_cpu_last_executed_on("Utility thread");

	if (!linux_run) {
		ret = syscall(732);
		OKNGNOJUMP(ret == -1, "Utility thread is running on Linux\n");
	}

	pthread_barrier_wait(&bar);
	for (i = 0; i < nloop; i++) {
		start = rdtsc_light();
		
		pthread_mutex_lock(&mutex); /* no futex */
		while(!flag) {
			pthread_cond_wait(&cond, &mutex); /* 1st futex */
		}
		flag = 0;
		pthread_mutex_unlock(&mutex); /* 2nd futex */

		end = rdtsc_light();
		t_cond_wait += end - start;
	}

 fn_fail:
	return NULL;
}

static struct option options[] = {
	/* end */
	{ NULL, 0, NULL, 0, }
};

int main(int argc, char **argv)
{
	int i;
	int ret;
	long start, end;
	cpu_set_t cpuset;
	pthread_attr_t attr;
	pthread_barrierattr_t bar_attr;
	struct sched_param param = { .sched_priority = 99 };
	int opt;
	unsigned long mem;

	while ((opt = getopt_long(argc, argv, "+b:l", options, NULL)) != -1) {
		switch (opt) {
		case 'b':
			blocktime = atoi(optarg);
			break;
		case 'l':
			linux_run = 1;
			break;
		default: /* '?' */
			printf("unknown option %c\n", optopt);
			exit(1);
		}
	}
	nloop = (10 * 1000000000UL) / blocktime;
	printf("[INFO] nloop=%ld,blocktime=%ld\n", nloop, blocktime);

	
 	CPU_ZERO(&cpuset);
	CPU_SET(WAITER_CPU, &cpuset);
	if ((ret = sched_setaffinity(0, sizeof(cpu_set_t), &cpuset))) {
 		printf("Error: sched_setaffinity: %s\n", strerror(errno));
		goto fn_fail;
	}
	print_cpu_last_executed_on("Master thread");

	fwq_init(&mem);

	pthread_mutex_init(&mutex, NULL);
	pthread_cond_init(&cond, NULL);

	pthread_barrierattr_init(&bar_attr);
	pthread_barrier_init(&bar, &bar_attr, 2);

	if (!linux_run) {
		ret = syscall(732);
		OKNGNOJUMP(ret != -1, "Master thread is running on McKernel\n");

		ret = syscall(731, 1, NULL);
		OKNGNOJUMP(ret != -1, "util_indicate_clone\n");
	}

	if ((ret = pthread_attr_init(&attr))) {
 		printf("%s: Error: pthread_attr_init failed (%d)\n", __FUNCTION__, ret);
		goto fn_fail;
	}

 	CPU_ZERO(&cpuset);
	CPU_SET(WAKER_CPU, &cpuset);

	if ((ret = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset))) {
 		printf("%s: Error: pthread_attr_setaffinity_np failed (%d)\n", __FUNCTION__, ret);
		goto fn_fail;
	}

	if ((ret = pthread_create(&thr, &attr, util_fn, NULL))) {
		fprintf(stderr, "Error: pthread_create failed (%d)\n", ret);
		goto fn_fail;
	}

	if ((ret = sched_setscheduler(0, SCHED_FIFO, &param))) {
		fprintf(stderr, "Warning: sched_setscheduler: %s\n",
			strerror(errno));
	}

	if (!linux_run) {
		syscall(701, 1 | 2);
	}
	pthread_barrier_wait(&bar);
	for (i = 0; i < nloop; i++) {
		start = rdtsc_light();

		fwq(blocktime, &mem);

		end = rdtsc_light();
		t_fwq += end - start;

		pthread_mutex_lock(&mutex);
		flag = 1;
		pthread_cond_signal(&cond);
		pthread_mutex_unlock(&mutex);
	}
	if (!linux_run) {
		syscall(701, 4 | 8);
	}

	pthread_join(thr, NULL);
	printf("[INFO] waker: %ld nsec, waiter: %ld nsec, (waiter - waker) / nloop: %ld nsec\n", t_fwq * 10, t_cond_wait * 10, (t_cond_wait - t_fwq) * 10 / nloop);

	ret = 0;
 fn_fail:
	return ret;
}
