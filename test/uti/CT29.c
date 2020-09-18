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
#include <signal.h>

int passed = 0;
pthread_t thr;

unsigned long mem; /* delay functions issue ld/st instructions on this address */
double nspw; /* nsec per work */

/* Timer related macros */
#define TS2NS(sec, nsec) ((unsigned long)(sec) * 1000000000ULL + (unsigned long)(nsec))

static inline void fixed_size_work() {
	asm volatile(
	    "movq $0, %%rcx\n\t"
		"1:\t"
		"addq $1, %%rcx\n\t"
		"cmpq $99, %%rcx\n\t"
		"jle 1b\n\t"
		:
		: 
		: "rcx", "cc");
}

static inline void bulk_fsw(unsigned long n) {
	int j;
	for (j = 0; j < (n); j++) {
		fixed_size_work(); 
	} 
}

#define N_INIT 1000000

void *util_thread(void *arg) {
	int rc;

	fwq(1000*1000);

	return NULL;
}

int
main(int argc, char **argv)
{
	int rc;
	pthread_attr_t attr;
	struct sigaction act;

	fwq_init();

	fprintf(stderr, "CT29001 INFO start (tid=%d)\n", syscall(__NR_gettid));
	rc = syscall(731, 1, NULL);
	if (rc) {
		fprintf(stderr, "CT29002 INFO uti not supported (rc=%d, errno=%d)\n", rc, errno);
		fflush(stderr);
	}

	rc = pthread_attr_init(&attr);
	if (rc){
		fprintf(stderr, "pthread_attr_init: %d\n", rc);
		exit(1);
	}
#if 1
	rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (rc){
		fprintf(stderr, "pthread_attr_setdetachstate: %d\n", rc);
		exit(1);
	}
#endif
	rc = pthread_create(&thr, &attr, util_thread, NULL);
	if (rc){
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stderr, "CT29003 pthread_create OK\n");

	fwq(100*1000*1000);

#if 0
	pthread_join(thr, NULL);
	fprintf(stderr, "CT29004 pthread_join OK\n");
#endif
	exit(0);
}
