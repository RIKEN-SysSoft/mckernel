/* CT14.c COPYRIGHT FUJITSU LIMITED 2019 */
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
#include "uti.h"

pthread_mutex_t mutex;
int owned;
pthread_t thr;

#define TS2NS(sec, nsec) \
	((unsigned long)(sec) * 1000000000ULL + \
	 (unsigned long)(nsec))

static inline void BULK_FSW(unsigned long n,
				unsigned long *ptr)
{
	int j;

	for (j = 0; j < (n); j++) {
		FIXED_SIZE_WORK(ptr);
	}
}

/* nsec per work */
double nspw;

#define N_INIT 10000000

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

void fwq(unsigned long delay_nsec, unsigned long *mem)
{
	//printf("delay_nsec=%ld,count=%f\n",
	//		delay_nsec, delay_nsec / nspw);
	BULK_FSW(delay_nsec / nspw, mem);
}

void *util_thread(void *arg)
{
	int rc;
	unsigned long mem;

	rc = syscall(__NR_get_system);
	if (rc == -1) {
		fprintf(stderr,
			"CT14100 running on Linux OK\n");
	}
	else {
		fprintf(stderr,
			"CT14100 running on Linux NG (%d)\n", rc);
	}
	errno = 0;

	/* Sending debug messages through serial takes 0.05 sec */
	fwq(500 * 1000 * 1000UL, &mem);

	pthread_mutex_lock(&mutex);
	if (owned) {
		fprintf(stderr, "CT14101 lock second OK\n");
	}
	else {
		fprintf(stderr, "CT14101 lock second NG\n");
	}
	owned = 1;
	pthread_mutex_unlock(&mutex);

	return NULL;
}

int main(int argc, char **argv)
{
	int rc;
	unsigned long mem;

	pthread_mutex_init(&mutex, NULL);
	fwq_init(&mem);

	fprintf(stderr, "CT14001 futex START\n");

	rc = syscall(__NR_util_indicate_clone,
			SPAWN_TO_REMOTE, NULL);
	if (rc) {
		fprintf(stderr,
			"CT14002 util_indicate_clone NG (rc=%d, errno=%d)\n",
			rc, errno);
		fflush(stderr);
	}
	else {
		fprintf(stderr, "CT14002 util_indicate_clone OK\n");
	}

	rc = pthread_create(&thr, NULL, util_thread, NULL);
	if (rc) {
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stderr, "CT14003 pthread_create OK\n");

	pthread_mutex_lock(&mutex);
	if (!owned) {
		fprintf(stderr, "CT14004 lock first OK\n");
	}
	else {
		fprintf(stderr, "CT14004 lock first NG\n");
	}
	owned = 1;

	/* Need 2 sec to make child sleep */
	fwq(2000 * 1000 * 1000UL, &mem);
	pthread_mutex_unlock(&mutex);

	pthread_join(thr, NULL);
	fprintf(stderr, "CT14005 pthread_join OK\n");

	fprintf(stderr, "CT14006 END\n");
	exit(0);
}
