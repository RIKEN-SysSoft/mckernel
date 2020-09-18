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
int owned;
pthread_t thr;

#define TS2NS(sec, nsec) ((unsigned long)(sec) * 1000000000ULL + (unsigned long)(nsec))
static inline void FIXED_SIZE_WORK(unsigned long *ptr) {
	asm volatile("movq %0, %%rax\n\t" 
				 "addq $1, %%rax\n\t"			\
				 "movq %%rax, %0\n\t"			\
				 : "+rm" (*ptr)						\
				 :									\
				 : "rax", "cc", "memory");			\
}

static inline void BULK_FSW(unsigned long n, unsigned long *ptr) {
	int j;
	for (j = 0; j < (n); j++) {
		FIXED_SIZE_WORK(ptr); 
	} 
}

double nspw; /* nsec per work */

#define N_INIT 10000000

void *
util_thread(void *arg)
{
	int rc;
	unsigned long mem;

	rc = syscall(732);
	if (rc == -1)
		fprintf(stderr, "CT14100 running on Linux OK\n");
	else {
		fprintf(stderr, "CT14100 running on Linux NG (%d)\n", rc);
	}
	errno = 0;

	pthread_mutex_lock(&mutex);
	if (!owned) {
		fprintf(stderr, "CT14101 lock first OK\n");
	} else {
		fprintf(stderr, "CT14101 lock first NG\n");
	}
	owned = 1;
	fwq(2000 * 1000 * 1000UL); /* Need 2 sec to make parent sleep */
	pthread_mutex_unlock(&mutex);

	return NULL;
}

int main(int argc, char **argv) {
	int rc;
	unsigned long mem;

	pthread_mutex_init(&mutex, NULL);
	fwq_init();

	fprintf(stderr, "CT14001 futex START\n");

	rc = syscall(731, 1, NULL);
	if (rc) {
		fprintf(stderr, "CT14002 util_indicate_clone NG (rc=%d, errno=%d)\n", rc, errno);
		fflush(stderr);
	} else {
		fprintf(stderr, "CT14002 util_indicate_clone OK\n");
	}

	rc = pthread_create(&thr, NULL, util_thread, NULL);
	if(rc){
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stderr, "CT14003 pthread_create OK\n");

	fwq(500 * 1000 * 1000UL); /* Sending debug messages through serial takes 0.05 sec */

	pthread_mutex_lock(&mutex);
	if (owned) {
		fprintf(stderr, "CT14004 lock second OK\n");
	} else {
		fprintf(stderr, "CT14004 lock second NG\n");
	}
	owned = 1;
	pthread_mutex_unlock(&mutex);

	pthread_join(thr, NULL);
	fprintf(stderr, "CT14005 pthread_join OK\n");

	fprintf(stderr, "CT14006 END\n");
	exit(0);
}
