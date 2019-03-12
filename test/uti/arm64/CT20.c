/* CT20.c COPYRIGHT FUJITSU LIMITED 2019 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <linux/futex.h>
#include <sys/time.h>
#include <string.h>
#include "uti.h"

int passed, sem, flag;
pthread_t thr;
#define TS2NS(sec, nsec) \
	((unsigned long)(sec) * 1000000000ULL + \
	 (unsigned long)(nsec))

void *util_thread(void *arg)
{
	int rc;
	struct timespec start, timeout, end;
	unsigned long elapsed;

	rc = syscall(__NR_get_system);
	if (rc == -1) {
		fprintf(stderr, "CT20100 running on Linux CPU OK\n");
	}
	else {
		fprintf(stderr, "CT20100 running on Linux CPU NG (%d)\n", rc);
	}

	passed = 1;

	rc = clock_gettime(CLOCK_REALTIME, &start);
	if (rc != 0) {
		fprintf(stderr, "clock_gettime failed\n");
		return NULL;
	}
	fprintf(stderr, "start=%ld.%09ld\n", start.tv_sec, start.tv_nsec);

	timeout.tv_sec = 0;
	timeout.tv_nsec = 800ULL * 1000 * 1000;
	rc = syscall(__NR_futex, &sem, FUTEX_WAIT, 0, &timeout, NULL, 0);

	rc = clock_gettime(CLOCK_REALTIME, &end);
	if (rc != 0) {
		fprintf(stderr, "clock_gettime failed\n");
		return NULL;
	}
	fprintf(stderr, "end=%ld.%09ld\n", end.tv_sec, end.tv_nsec);

	if (rc != 0) {
		fprintf(stderr, "CT20101 FUTEX_WAIT NG (%s)\n",
			strerror(errno));
	}
	else {
		fprintf(stderr, "CT20101 FUTEX_WAIT OK\n");
	}

	elapsed = TS2NS(end.tv_sec, end.tv_nsec) -
			TS2NS(start.tv_sec, start.tv_nsec);
	if (flag == 0 || elapsed < 800UL * 1000 * 1000 +
		80UL * 1000 * 1000) {
		fprintf(stderr, "CT20102 timeout OK\n");
	}
	else {
		fprintf(stderr, "CT20101 timeout NG\n");
	}
	return NULL;
}

int main(int argc, char **argv)
{
	int rc;

	fprintf(stderr, "CT20001 futex START\n");
	rc = syscall(__NR_util_indicate_clone,
			SPAWN_TO_REMOTE, NULL);
	if (rc) {
		fprintf(stderr,
			"util_indicate_clone rc=%d, errno=%d\n",
			rc, errno);
		fflush(stderr);
	}

	rc = pthread_create(&thr, NULL, util_thread, NULL);
	if (rc) {
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stderr, "CT20002 pthread_create OK\n");

	while (!passed) {
		cpu_pause();
	}
	usleep(2000 * 1000UL);

	flag = 1;
	rc = syscall(__NR_futex, &sem, FUTEX_WAKE, 1, NULL, NULL, 0);
	if (rc != 0) {
		fprintf(stderr,
			"CT20003 FUTEX_WAKE missing the waiter NG (%d,%s)\n",
			rc, strerror(errno));
	}
	else {
		fprintf(stderr,
			"CT20003 FUTEX_WAKE missing the waiter OK\n");
	}

	pthread_join(thr, NULL);
	fprintf(stderr, "CT20004 pthread_join OK\n");

	fprintf(stderr, "CT20005 END\n");
	exit(0);
}
