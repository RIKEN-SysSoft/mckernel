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

#define DEBUG

#ifdef DEBUG
#define	dprintf(...)											\
	do {														\
		char msg[1024];											\
		sprintf(msg, __VA_ARGS__);								\
		fprintf(stdout, "%s,%s", __FUNCTION__, msg);			\
	} while (0);
#define	eprintf(...)											\
	do {														\
		char msg[1024];											\
		sprintf(msg, __VA_ARGS__);								\
		fprintf(stdout, "%s,%s", __FUNCTION__, msg);			\
	} while (0);
#else
#define dprintf(...) do {  } while (0)
#define eprintf(...) do {  } while (0)
#endif

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

struct thr_arg {
	int bar_count; /* Barrier before entering loop */
	pthread_mutex_t bar_lock;
	pthread_cond_t bar_cond;
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

void *progress_fn(void *_arg) {
	struct thr_arg *arg = (struct thr_arg *)_arg;
	int rc;
	int i;

	rc = syscall(732);
	if (rc == -1)
		fprintf(stdout, "CT09100 progress_fn running on Linux OK\n");
	else {
		fprintf(stdout, "CT09100 progress_fn running on McKernel NG\n", rc);
		return NULL;
	}

	pthread_mutex_lock(&arg->bar_lock);
	while(arg->bar_count == 0) {
		pthread_cond_wait(&arg->bar_cond, &arg->bar_lock);
	}
	pthread_mutex_unlock(&arg->bar_lock);

	for (i = 0; i < 100; i++) {
		pthread_mutex_lock(&ep_lock);
		nevents++;
		fwq(random() % 100000000); /* 0 - 0.1 sec */
		pthread_mutex_unlock(&ep_lock);
		while (nevents > 0) {
			FIXED_SIZE_WORK(&mem);
		}
	}
	terminate = 1;
	return NULL;
}

int main(int argc, char **argv) {
	int rc;
	int i;
	struct timespec start, end;

	fprintf(stdout, "CT09001 MPI progress thread skelton START\n");

	rc = syscall(732);
	if (rc == -1)
		fprintf(stdout, "CT09002 main running on Linux INFO\n");
	else {
		fprintf(stdout, "CT09002 main running on McKernel INFO\n");
	}

	fwq_init();
	pthread_mutex_init(&ep_lock, NULL);

	for(i = 0; i < NTHR; i++) {
		thr_args[i].bar_count = 0;
		pthread_cond_init(&thr_args[i].bar_cond, NULL);
		pthread_mutex_init(&thr_args[i].bar_lock, NULL);
	}

	rc = syscall(731, 1, NULL);
	if (rc) {
		fprintf(stdout, "util_indicate_clone rc=%d, errno=%d\n", rc, errno);
		fflush(stdout);
	}
	for (i = 0; i < NTHR; i++) {
		rc = pthread_create(&thr_args[i].pthread, NULL, progress_fn, &thr_args[i]);
		if (rc){
			fprintf(stdout, "pthread_create: %d\n", rc);
			exit(1);
		}
	}
	for (i = 0; i < NTHR; i++) {
		pthread_mutex_lock(&thr_args[i].bar_lock);
		thr_args[i].bar_count++;
		pthread_cond_signal(&thr_args[i].bar_cond);
		pthread_mutex_unlock(&thr_args[i].bar_lock);
	}

	fprintf(stdout, "CT09004 pthread_create OK\n");
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	/* Start progress */
	pthread_mutex_lock(&ep_lock);
	while(1) {
		if (terminate) {
			break;
		}

		/* Event found */
		if (nevents > 0) {
			nevents = 0;
		}

		pthread_mutex_unlock(&ep_lock);
		fwq(random() % 100000000); /* 0 - 0.1 sec */
		pthread_mutex_lock(&ep_lock);
	}
	pthread_mutex_unlock(&ep_lock);
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	
	for (i = 0; i < NTHR; i++) {
		pthread_join(thr_args[i].pthread, NULL);
	}
	fprintf(stdout, "CT09005 takes %ld nsec INFO\n", TS2NS(end.tv_sec, end.tv_nsec) - TS2NS(start.tv_sec, start.tv_nsec));
	fprintf(stdout, "CT09006 END\n");


	exit(0);
}
