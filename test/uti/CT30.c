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
#include "util.h"

#define NTHR 1
#define TS2NS(sec, nsec) ((unsigned long)(sec) * 1000000000ULL + (unsigned long)(nsec))
#define CALC_DELAY (93000) /* 93   usec */
#define INIT_DELAY  (2000) /*  2   usec, CPU sends CTS packet */
#define NIC_DELAY   (3000) /*  3   usec, NIC reads by RDMA-read  */
#define POLL_DELAY  (200) /*    .2 usec, CPU fetces event queue entry from DRAM */
#define RESP_DELAY  (2000) /*  2   usec, CPU sends DONE packet and updates MPI_Request */
#define NSPIN 1
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


pthread_mutex_t ep_lock; /* Ownership of channel instance */
pthread_barrier_t bar;

struct thr_arg {
	pthread_t pthread;
	unsigned long mem; /* Per-thread storage */
};

struct thr_arg thr_args[NTHR];

unsigned long mem; /* Per-thread storage */
volatile int nevents;
volatile int terminate;
int wps = 1; /* work per sec */
double nspw; /* nsec per work */

#define N_INIT 10000000

void fwq_omp(unsigned long delay_nsec, unsigned long* mem) {
#pragma omp parallel
	{
		BULK_FSW(delay_nsec / nspw, mem);
	}
}

void mydelay(long delay_nsec, long *mem) {
	struct timespec start, end;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);

	while (1) {
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
		if (TS2NS(end.tv_sec, end.tv_nsec) - TS2NS(start.tv_sec, start.tv_nsec) > delay_nsec) {
			break;
		}
		FIXED_SIZE_WORK(mem);
	}
}

void *util_fn(void *_arg) {
	struct thr_arg *arg = (struct thr_arg *)_arg;
	int ret;
	int i;

	ret = syscall(732);
	OKNGNOJUMP(ret == -1, "util_fn running on Linux, tid=%d\n", syscall(SYS_gettid));

	pthread_barrier_wait(&bar);

	/* Start progress */
	while (1) {
		pthread_mutex_lock(&ep_lock);
		if (terminate) {
			pthread_mutex_unlock(&ep_lock);
			break;
		}

		if (nevents > 0) {
			nevents--;
			fwq(random() % 100000000); /* 0 - 0.1 sec */
		}
		pthread_mutex_unlock(&ep_lock);
	}

 fn_fail:
	return NULL;
}

int main(int argc, char **argv) {
	int ret;
	int i;
	struct timespec start, end;

	ret = syscall(732);
	OKNGNOJUMP(ret != -1, "Master is running on McKernel\n");

	fwq_init();
	pthread_mutex_init(&ep_lock, NULL);

	pthread_barrier_init(&bar, NULL, NTHR + 1);

	if ((ret = syscall(731, 1, NULL))) {
		fprintf(stdout, "Error: util_indicate_clone: %s\n", strerror(errno));
	}

	for (i = 0; i < NTHR; i++) {
		if ((ret = pthread_create(&thr_args[i].pthread, NULL, util_fn, &thr_args[i]))) {
			fprintf(stdout, "Error: pthread_create: %s\n", strerror(errno));
			exit(1);
		}
	}

	pthread_barrier_wait(&bar);

#pragma omp parallel for
	for (i = 0; i < omp_get_num_threads(); i++) {
		printf("[INFO] thread_num=%d,tid=%d\n", i, syscall(SYS_gettid));
	}

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	for (i = 0; i < 10; i++) {
		pthread_mutex_lock(&ep_lock);
		nevents++;
		fwq_omp(random() % 100000000, &mem); /* 0 - 0.1 sec */
		pthread_mutex_unlock(&ep_lock);

		while (nevents > 0) {
			FIXED_SIZE_WORK(&mem);
		}
	}
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	
	terminate = 1;
	
	for (i = 0; i < NTHR; i++) {
		pthread_join(thr_args[i].pthread, NULL);
	}

	printf("[INFO] Time: %ld usec\n", (TS2NS(end.tv_sec, end.tv_nsec) - TS2NS(start.tv_sec, start.tv_nsec)) / 1000);

	ret = 0;
 fn_fail:
	return ret;
}
