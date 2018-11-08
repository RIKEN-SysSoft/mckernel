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

int flag1;
pthread_mutex_t mutex1;
pthread_cond_t cond1;

int flag2;
pthread_mutex_t mutex2;
pthread_cond_t cond2;

char *a;
char *b;
char *c;


void *
util_thread(void *arg)
{
	int rc;

	rc = syscall(732);
	if (rc == -1)
		fprintf(stderr, "CT04003 get_system OK\n");
	else {
		fprintf(stderr, "CT04003 get_system NG get_system=%d\n", rc);
		exit(1);
	}
	errno = 0;
	a = sbrk(0);
	fprintf(stderr, "CT04004 sbrk OK\n");
	b = sbrk(4096);
	strcpy(a, "sbrk OK");

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

	b = sbrk(0);
	if (c == b) {
		fprintf(stderr, "CT04006 sbrk OK\n");
	}
	else {
		fprintf(stderr, "CT04006 sbrk NG %p != %p\n", c, b);
	}
	return NULL;
}

int
main(int argc, char **argv)
{
	pthread_t thr;
	int rc;

	pthread_mutex_init(&mutex1, NULL);
	pthread_cond_init(&cond1, NULL);
	pthread_mutex_init(&mutex2, NULL);
	pthread_cond_init(&cond2, NULL);

	fprintf(stderr, "CT04001 brk START\n");
	rc = syscall(731, 1, NULL);
	if (rc) {
		fprintf(stderr, "util_indicate_clone rc=%d, errno=%d\n", rc, errno);
		fflush(stderr);
	}
	rc = pthread_create(&thr, NULL, util_thread, NULL);
	if(rc){
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stderr, "CT04002 pthread_create OK\n");

	pthread_mutex_lock(&mutex1);
	while(!flag1) {
		pthread_cond_wait(&cond1, &mutex1);
	}
	flag1 = 0;
	pthread_mutex_unlock(&mutex1);
	fprintf(stderr, "CT04005 %s\n", a);

	c = sbrk(0);
	pthread_mutex_lock(&mutex2);
	flag2 = 1;
	pthread_cond_signal(&cond2);
	pthread_mutex_unlock(&mutex2);
	pthread_join(thr, NULL);
	fprintf(stderr, "CT04007 pthread_join OK\n");
	fprintf(stderr, "CT04008 END\n");
	exit(0);
}
