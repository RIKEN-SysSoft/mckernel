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

pthread_mutex_t mutex;
pthread_cond_t cond;
int passed, flag;
pthread_t thr;

void *
util_thread(void *arg)
{
	int rc;
	unsigned long mem;

	rc = syscall(732);
	if (rc == -1)
		fprintf(stderr, "CT16101 running on Linux OK\n");
	else {
		fprintf(stderr, "CT16101 running on Linux NG (%d)\n", rc);
	}
	errno = 0;

	passed = 1;
	pthread_mutex_lock(&mutex);
	while(!flag) {
		pthread_cond_wait(&cond, &mutex);
	}
	flag = 0;
	pthread_mutex_unlock(&mutex);

	fprintf(stderr, "CT16102 return from pthread_cond_wait() OK\n");

	return NULL;
}

int main(int argc, char **argv) {
	int rc;
	unsigned long mem;

	pthread_mutex_init(&mutex, NULL);
	pthread_cond_init(&cond, NULL);

	fprintf(stderr, "CT16001 futex START\n");

	rc = syscall(731, 1, NULL);
	if (rc) {
		fprintf(stderr, "CT16002 util_indicate_clone NG (rc=%d, errno=%d)\n", rc, errno);
		fflush(stderr);
	} else {
		fprintf(stderr, "CT16002 util_indicate_clone OK\n");
	}

	rc = pthread_create(&thr, NULL, util_thread, NULL);
	if(rc){
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stderr, "CT16003 pthread_create OK\n");

	while (!passed) {
		asm volatile("pause" ::: "memory"); 
	}
	usleep(100 * 1000UL); /* Send debug message through serial takes 0.05 sec */

	pthread_mutex_lock(&mutex);
	flag = 1;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);

	pthread_join(thr, NULL);
	fprintf(stderr, "CT16004 pthread_join OK\n");

	fprintf(stderr, "CT16005 END\n");
	exit(0);
}
