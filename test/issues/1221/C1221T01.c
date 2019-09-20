#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>

void tv_sub(struct timeval *t1, struct timeval *t2)
{
	t2->tv_sec -= t1->tv_sec;
	t2->tv_usec -= t1->tv_usec;
	if (t2->tv_usec < 0) {
		t2->tv_usec += 1000000;
		t2->tv_sec--;
	}
}

int main(int argc, char **argv)
{
	struct timeval t1;
	struct timeval t2;
	struct rusage ru0;
	struct rusage ru;
	long xe;
	long xs;

	fprintf(stderr, "*** C1221T01 test start\n");
	gettimeofday(&t1, NULL);
	getrusage(RUSAGE_SELF, &ru0);
	if (syscall(750, 1) == -1) {
		fprintf(stderr, "*** C1221T01 FAIL no patched kernel\n");
		exit(1);
	}
	getrusage(RUSAGE_SELF, &ru);
	gettimeofday(&t2, NULL);
	tv_sub(&t1, &t2);
	tv_sub(&ru0.ru_utime, &ru.ru_utime);
	tv_sub(&ru0.ru_stime, &ru.ru_stime);
	fprintf(stderr, "etime=%d.%06d\n", (int)t2.tv_sec, (int)t2.tv_usec);
	fprintf(stderr, "utime=%d.%06d\n", (int)ru.ru_utime.tv_sec,
		(int)ru.ru_utime.tv_usec);
	fprintf(stderr, "stime=%d.%06d\n", (int)ru.ru_stime.tv_sec,
		(int)ru.ru_stime.tv_usec);
	xe = t2.tv_sec * 1000000L + t2.tv_usec;
	xs = ru.ru_stime.tv_sec * 1000000L + ru.ru_stime.tv_usec;
	if (xs > (xe * 100 / 95)) {
		fprintf(stderr, "*** C1221T01 FAIL\n");
	}
	else {
		fprintf(stderr, "*** C1221T01 PASS\n");
	}
	exit(0);
}
