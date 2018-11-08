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
char *m;

int sigst;
pthread_t thr;

void
sigsegv(int s)
{
	if (sigst == 1) {
		fprintf(stderr, "CT02007 mremap OK (SIGSEGV)\n");
		pthread_mutex_lock(&mutex2);
		flag2 = 1;
		pthread_cond_signal(&cond2);
		pthread_mutex_unlock(&mutex2);
		pthread_join(thr, NULL);
		fprintf(stderr, "CT02009 pthread_join OK\n");
		fprintf(stderr, "CT02010 END\n");
		exit(0);
	}
	printf("BAD SIGSEGV\n");
	exit(1);
}

void *
util_thread(void *arg)
{
	int rc;
	char *n;

	rc = syscall(732);
	if (rc == -1)
		fprintf(stderr, "CT02003 get_system OK\n");
	else {
		fprintf(stderr, "CT02003 get_system NG get_system=%d\n", rc);
		exit(1);
	}
	errno = 0;
	m = mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (m != (void *)-1) {
		fprintf(stderr, "CT02004 mmap OK\n");
	}
	else {
		fprintf(stderr, "CT02004 mmap NG errno=%d\n", errno);
		exit(1);
	}
	strcpy(m + 4096, "mmap OK");
	pthread_mutex_lock(&mutex1);
	flag1 = 1;
	pthread_cond_signal(&cond1);
	pthread_mutex_unlock(&mutex1);
	pthread_mutex_lock(&mutex2);
	while (!flag2) {
		pthread_cond_wait(&cond2, &mutex2);
	}
	flag2 = 0;
	pthread_mutex_unlock(&mutex2);
	n = mremap(m, 8192, 4096, 0);
	if (n == m) {
		fprintf(stderr, "CT02006 mremap OK\n");
	}
	else if (n != (void *)-1){
		fprintf(stderr, "CT02006 mremap remapped, test stop\n");
		exit(1);
	}
	else {
		fprintf(stderr, "CT02006 mremap NG errno=%d\n", errno);
		exit(1);
	}
	pthread_mutex_lock(&mutex1);
	flag1 = 1;
	pthread_cond_signal(&cond1);
	pthread_mutex_unlock(&mutex1);

	pthread_mutex_lock(&mutex2);
	while (!flag2) {
		pthread_cond_wait(&cond2, &mutex2);
	}
	flag2 = 0;
	pthread_mutex_unlock(&mutex2);
	rc = munmap(m, 4096);
	if (rc == 0) {
		fprintf(stderr, "CT02008 munmap OK\n");
	}
	else {
		fprintf(stderr, "CT02008 munmap NG errno=%d\n", errno);
		exit(1);
	}
	return NULL;
}

int
main(int argc, char **argv)
{
	int rc;

	signal(SIGSEGV, sigsegv);
	pthread_mutex_init(&mutex1, NULL);
	pthread_cond_init(&cond1, NULL);
	pthread_mutex_init(&mutex2, NULL);
	pthread_cond_init(&cond2, NULL);

	fprintf(stderr, "CT02001 mremap START\n");
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
	fprintf(stderr, "CT02002 pthread_create OK\n");
	pthread_mutex_lock(&mutex1);
	while (!flag1) {
		pthread_cond_wait(&cond1, &mutex1);
	}
	flag1 = 0;
	pthread_mutex_unlock(&mutex1);
	fprintf(stderr, "CT02005 %s\n", m + 4096);

	pthread_mutex_lock(&mutex2);
	flag2 = 1;
	pthread_cond_signal(&cond2);
	pthread_mutex_unlock(&mutex2);

	pthread_mutex_lock(&mutex1);
	while (!flag1) {
		pthread_cond_wait(&cond1, &mutex1);
	}
	flag1 = 0;
	pthread_mutex_unlock(&mutex1);
	sigst = 1;
	fprintf(stderr, "%s\n", m + 4096);
	fprintf(stderr, "CT02007 mremap NG\n");
	pthread_mutex_lock(&mutex2);
	flag2 = 1;
	pthread_cond_signal(&cond2);
	pthread_mutex_unlock(&mutex2);
	pthread_join(thr, NULL);
	fprintf(stderr, "CT02009 pthread_join OK\n");
	fprintf(stderr, "CT02010 END\n");
	exit(0);
}
