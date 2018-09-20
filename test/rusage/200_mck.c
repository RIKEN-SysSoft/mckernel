#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "util.h"


#define DELAY0 (100UL * 1000 * 1000)
#define DELAY1 (200UL * 1000 * 1000)

struct thr_arg {
	unsigned long delay;
};

struct thr_arg thr_arg[2] = { { .delay = DELAY0 }, { .delay = DELAY1 } };
pthread_t thr[2];

#define DIFFNSEC(end, start) ((end.tv_sec - start.tv_sec) * 1000000000UL + \
		(end.tv_nsec - start.tv_nsec))
#define TIMER_KIND CLOCK_MONOTONIC_RAW /* CLOCK_THREAD_CPUTIME_ID */

static int print_cpu_last_executed_on(void)
{
	int ret = 0;
	char fn[256];
	char *result;
	pid_t tid = syscall(SYS_gettid);
	int fd;
	int offset;
	int amount = 0;
	char *list;
	char *token;
	int i;
	int cpu;

	sprintf(fn, "/proc/%d/task/%d/stat", getpid(), (int)tid);
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

	list = result;
	for (i = 0; i < 39; i++) {
		token = strsep(&list, " ");
	}

	cpu = sched_getcpu();
	if (cpu == -1) {
		printf("getcpu() failed\n");
		goto fn_fail;
	}

	printf("[INFO] stat-cpu=%02d,sched_getcpu=%02d,tid=%d\n",
		token ? atoi(token) : -1, cpu, tid);
 fn_exit:
	free(result);
	return ret;
 fn_fail:
	ret = -1;
	goto fn_exit;
}

static inline void asm_loop(unsigned long n)
{
	int j;

	for (j = 0; j < (n); j++) {
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
}

double nspw; /* nsec per work */
unsigned long nsec;

void fwq_init(void)
{
	struct timespec start, end;

	clock_gettime(TIMER_KIND, &start);
#define N_INIT 10000000
	asm_loop(N_INIT);
	clock_gettime(TIMER_KIND, &end);
	nsec = DIFFNSEC(end, start);
	nspw = nsec / (double)N_INIT;
}

#if 1
void fwq(long delay_nsec)
{
	if (delay_nsec < 0) {
		return;
	}
	asm_loop(delay_nsec / nspw);
}
#else
/* For machines with large core-to-core performance variation (e.g. OFP) */
void fwq(long delay_nsec)
{
	struct timespec start, end;

	if (delay_nsec < 0) {
		return;
	}
	clock_gettime(TIMER_KIND, &start);

	while (1) {
		clock_gettime(TIMER_KIND, &end);
		if (DIFFNSEC(end, start) >= delay_nsec) {
			break;
		}
		asm_loop(2); /* ~150 ns per iteration on FOP */
	}
}
#endif

void *util_thread(void *_arg)
{
	struct thr_arg *arg = (struct thr_arg *)_arg;

	print_cpu_last_executed_on();
	fwq(arg->delay);
	pthread_exit(NULL);
}

int main(int argc, char **argv)
{
	int i;
	int ret = 0;
	cpu_set_t cpuset;
	pthread_attr_t attr[2];

	fwq_init();

	/* Migrate to cpu#0 */
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
	print_cpu_last_executed_on();

	for (i = 0; i < 2; i++) {
		CPU_ZERO(&cpuset);
		CPU_SET(i + 1, &cpuset);

		if ((ret = pthread_attr_init(&attr[i]))) {
			printf("%s: ERROR: pthread_attr_init failed (%d)\n",
				__func__, ret);
			ret = -EINVAL;
			goto out;
		}

		if ((ret = pthread_attr_setaffinity_np(&attr[i],
			sizeof(cpu_set_t), &cpuset))) {
			printf("%s: ERROR: pthread_attr_setaffinity_np "
				"failed (%d)\n", __func__, ret);
			ret = -EINVAL;
			goto out;
		}

		if ((ret = pthread_create(&thr[i], &attr[i],
			util_thread, &thr_arg[i]))) {
			fprintf(stderr, "ERROR: pthread_create failed (%d)\n",
				ret);
			ret = -EINVAL;
			goto out;
		}
	}

	for (i = 0; i < 2; i++) {
		pthread_join(thr[i], NULL);
	}

	if ((ret = syscall(900))) {
		fprintf(stderr, "%s: syscall failed\n", __func__);
		ret = -EINVAL;
		goto out;
	}
 out:
	return ret;
}

