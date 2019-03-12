/* CT12.c COPYRIGHT FUJITSU LIMITED 2019 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/time.h>
#include "uti.h"

int passed = 0, sem = 0;
pthread_t thr;

void *util_thread(void *arg)
{
	int rc;

	rc = syscall(__NR_get_system);
	if (rc == -1) {
		fprintf(stderr,
			"CT12100 running on Linux CPU OK\n");
	}
	else {
		fprintf(stderr,
			"CT12100 running on Linux CPU NG (%d)\n",
			rc);
	}
	passed = 1;

	rc = syscall(__NR_futex, &sem,
			FUTEX_WAIT, 0, NULL, NULL, 0);
	if (rc != 0) {
		fprintf(stderr,
			"CT12101 FUTEX_WAIT NG (%s)\n",
			strerror(errno));
	}
	else {
		fprintf(stderr,
			"CT12101 FUTEX_WAIT OK\n");
	}
	return NULL;
}

int main(int argc, char **argv)
{
	int rc;

	fprintf(stderr, "CT12001 futex START\n");

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
	fprintf(stderr, "CT12002 pthread_create OK\n");

	while (!passed) {
		cpu_pause();
	}
	usleep(100000);

	rc = syscall(__NR_futex, &sem,
			FUTEX_WAKE, 1, NULL, NULL, 0);
	if (rc != 1) {
		fprintf(stderr,
			"CT12003 FUTEX_WAKE NG (%d,%s)\n",
			rc, strerror(errno));
	}
	else {
		fprintf(stderr, "CT12003 FUTEX_WAKE OK\n");
	}

	pthread_join(thr, NULL);
	fprintf(stderr, "CT12004 pthread_join OK\n");

	fprintf(stderr, "CT12005 END\n");
	exit(0);
}
