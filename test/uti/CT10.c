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

pthread_mutex_t mutex1;
pthread_cond_t cond1;
pthread_mutex_t mutex2;
pthread_cond_t cond2;
char *m;
int flag1, flag2;

int sigst;
pthread_t thr;

void *
util_thread(void *arg)
{
	int rc;

	rc = syscall(732);
	if (rc == -1)
		fprintf(stderr, "CT10100 running on Linux OK\n");
	else {
		fprintf(stderr, "CT10100 running on Linux NG (%d)\n", rc);
	}
	errno = 0;

	pthread_mutex_lock(&mutex1);
	flag1 = 1;
	pthread_cond_signal(&cond1);
	pthread_mutex_unlock(&mutex1);

	pthread_mutex_lock(&mutex2);
	while(!flag2) {
		pthread_cond_wait(&cond2, &mutex2);
	}
	flag2 = 0;
	pthread_mutex_unlock(&mutex2);

	pthread_mutex_lock(&mutex1);
	flag1 = 1;
	pthread_cond_signal(&cond1);
	pthread_mutex_unlock(&mutex1);
	return NULL;
}

int
main(int argc, char **argv)
{
	int rc;

	pthread_mutex_init(&mutex1, NULL);
	pthread_cond_init(&cond1, NULL);
	pthread_mutex_init(&mutex2, NULL);
	pthread_cond_init(&cond2, NULL);

	fprintf(stderr, "CT10001 futex START\n");
#if 1
	rc = syscall(731, 1, NULL);
	if (rc) {
		fprintf(stderr, "util_indicate_clone rc=%d, errno=%d\n", rc, errno);
		fflush(stderr);
	}
#endif
	rc = pthread_create(&thr, NULL, util_thread, NULL);
	if(rc){
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stderr, "CT10002 pthread_create OK\n");

	pthread_mutex_lock(&mutex1);
	while(!flag1) {
		pthread_cond_wait(&cond1, &mutex1);
	}
	flag1 = 0;
	pthread_mutex_unlock(&mutex1);

	pthread_mutex_lock(&mutex2);
	flag2 = 1;
	pthread_cond_signal(&cond2);
	pthread_mutex_unlock(&mutex2);

	pthread_mutex_lock(&mutex1);
	while(!flag1) {
		pthread_cond_wait(&cond1, &mutex1);
	}
	flag1 = 0;
	pthread_mutex_unlock(&mutex1);

	pthread_join(thr, NULL);
	fprintf(stderr, "CT10003 pthread_join OK\n");

	fprintf(stderr, "CT10004 END\n");
	exit(0);
}
