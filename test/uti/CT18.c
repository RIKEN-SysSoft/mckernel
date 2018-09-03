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

int passed, sem, flag;
pthread_t thr;
#define TS2NS(sec, nsec) ((unsigned long)(sec) * 1000000000ULL + (unsigned long)(nsec))

void *util_thread(void *arg) {
	int rc;
	struct timespec start, timeout, end;
	unsigned long elapsed;

	rc = syscall(732);
	if (rc == -1)
		fprintf(stderr, "CT18101 running on Linux CPU OK\n");
	else {
		fprintf(stderr, "CT18101 running on Linux CPU NG (%d)\n", rc);
	}

	passed = 1;

	rc = clock_gettime(CLOCK_REALTIME, &start);
	if (rc != 0) {
		fprintf(stderr, "clock_gettime failed\n");
		return NULL;
	}
	fprintf(stderr, "start=%ld.%09ld\n", start.tv_sec, start.tv_nsec);

	timeout.tv_sec = start.tv_sec;
	timeout.tv_nsec = start.tv_nsec + 800UL * 1000 * 1000;
	if (timeout.tv_nsec > 1000UL * 1000 * 1000) {
		timeout.tv_sec += 1;
		timeout.tv_nsec -= 1000UL * 1000* 1000;
	}
	rc = syscall(__NR_futex, &sem, FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME, 0, &timeout, NULL, 0x12345678);
	fprintf(stderr, "op=%x\n", FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME);

	rc = clock_gettime(CLOCK_REALTIME, &end);
	if (rc != 0) {
		fprintf(stderr, "clock_gettime failed\n");
		return NULL;
	}
	fprintf(stderr, "end=%ld.%09ld\n", end.tv_sec, end.tv_nsec);

	if (rc != 0) {
		fprintf(stderr, "CT18102 FUTEX_WAIT NG (%s)\n", strerror(errno));
	} else {
		fprintf(stderr, "CT18102 FUTEX_WAIT OK\n");
	}

	elapsed = TS2NS(end.tv_sec, end.tv_nsec) - TS2NS(start.tv_sec, start.tv_nsec);
	if (flag == 0 || elapsed < 800UL * 1000 * 1000 + 80UL * 1000 * 1000) {
		fprintf(stderr, "CT18103 timeout OK\n");
	} else {
		fprintf(stderr, "CT18103 timeout NG (%lx)\n", elapsed);
	}

	return NULL;
}

int
main(int argc, char **argv)
{
	int rc;

	fprintf(stderr, "CT18001 futex START\n");
	rc = syscall(731, 1, NULL);
	if (rc) {
		fprintf(stderr, "util_indicate_clone rc=%d, errno=%d\n", rc, errno);
		fflush(stderr);
	}

	rc = pthread_create(&thr, NULL, util_thread, NULL);
	if (rc){
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stderr, "CT18002 pthread_create OK\n");

 retry:
	while (!passed) {
		asm volatile("pause" ::: "memory"); 
	}
	usleep(800 * 1000UL * 10);

	flag = 1;
	rc = syscall(__NR_futex, &sem, FUTEX_WAKE_BITSET, 1, NULL, NULL, 0x12345678);
	if (rc != 0) {
		fprintf(stderr, "CT18003 FUTEX_WAKE missing the waiter NG (%d,%s)\n", rc, strerror(errno));
	} else {
		fprintf(stderr, "CT18003 FUTEX_WAKE missing the waiter OK\n");
	}

	pthread_join(thr, NULL);
	fprintf(stderr, "CT18004 pthread_join OK\n");

	fprintf(stderr, "CT18005 END\n");
	exit(0);
}
