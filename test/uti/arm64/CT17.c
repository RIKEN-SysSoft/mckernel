/* CT17.c COPYRIGHT FUJITSU LIMITED 2019 */
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
pthread_cond_t cond;
int passed, flag;
pthread_t thr;

void *util_thread(void *arg)
{
	int rc;

	rc = syscall(__NR_get_system);
	if (rc == -1) {
		fprintf(stderr,
			"CT17100 running on Linux OK\n");
	}
	else {
		fprintf(stderr,
			"CT17100 running on Linux NG (%d)\n", rc);
	}

	while (!passed) {
		cpu_pause();
	}

	/* Send debug message through serial takes 0.05 sec */
	usleep(100 * 1000UL);

	pthread_mutex_lock(&mutex);
	flag = 1;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);

	return NULL;
}

int main(int argc, char **argv)
{
	int rc;

	pthread_mutex_init(&mutex, NULL);
	pthread_cond_init(&cond, NULL);

	fprintf(stderr, "CT17001 futex START\n");

	rc = syscall(__NR_util_indicate_clone,
			SPAWN_TO_REMOTE, NULL);
	if (rc) {
		fprintf(stderr,
			"CT17002 util_indicate_clone NG (rc=%d, errno=%d)\n",
			rc, errno);
		fflush(stderr);
	}
	else {
		fprintf(stderr, "CT17002 util_indicate_clone OK\n");
	}

	rc = pthread_create(&thr, NULL, util_thread, NULL);
	if (rc) {
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stderr, "CT17003 pthread_create OK\n");

	passed = 1;
	pthread_mutex_lock(&mutex);
	fprintf(stderr, "CT17004 lock on %p OK\n", &mutex);
	while (!flag) {
		pthread_cond_wait(&cond, &mutex);
		fprintf(stderr, "CT17005 wake on %p OK\n", &cond);
	}
	flag = 0;

	pthread_mutex_unlock(&mutex);

	pthread_join(thr, NULL);
	fprintf(stderr, "CT17006 pthread_join OK\n");

	fprintf(stderr, "CT17007 END\n");
	exit(0);
}
