#include <stdlib.h>
#include <stdio.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>

long
ts_delta(struct timespec *t1, struct timespec *t2)
{
	long delta = (t2->tv_sec - t1->tv_sec) * 1000000000L;

	delta += (t2->tv_nsec - t1->tv_nsec);
	return delta;
}

int
main(int argc, char **argv)
{
	struct timespec d1;
	struct timespec d2;
	struct timespec d3;
	long delta1;
	long delta2;

	printf("*** C1186T02: test start\n");
	clock_gettime(CLOCK_REALTIME, &d1);
	syscall(SYS_clock_gettime, CLOCK_REALTIME, &d2);
	clock_gettime(CLOCK_REALTIME, &d3);
	delta1 = ts_delta(&d1, &d2);
	delta2 = ts_delta(&d2, &d3);
	printf("%ld.%09ld\n", d1.tv_sec, d1.tv_nsec);
	printf("%ld.%09ld %ld\n", d2.tv_sec, d2.tv_nsec, delta1);
	printf("%ld.%09ld %ld\n", d3.tv_sec, d3.tv_nsec, delta2);
	if (delta1 <= 0 || delta2 <= 0) {
		printf("*** C1186T02: NG\n");
		exit(1);
	}
	else {
		printf("*** C1186T02: OK\n");
	}
	exit(0);
}
