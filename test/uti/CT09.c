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

#define TS2NS(sec, nsec) ((unsigned long)(sec) * 1000000000ULL + (unsigned long)(nsec))
#define CALC_DELAY (98600)  /* 98.6 usec */
#define RTS_DELAY   (1000)  /*  1   usec, CPU time for sending Request-to-Send packet */
#define NIC_DELAY   (3000)  /*  5   usec, RTS packet propagation time + RDMA-read on the responder side + CPU time for sending DONE packet + DONE packet network propagation time */
#define POLL_DELAY  ( 200) /*  0.2 usec, CPU time for checking DRAM event queue */
#define COMPL_DELAY ( 200) /*  0.2 usec, CPU time for updates MPI_Request */
#define NSPIN 1
static inline void FIXED_SIZE_WORK(unsigned long *ptr) {
#if 0
	asm volatile("movq %0, %%rax\n\t" 
				 "addq $1, %%rax\n\t"
				 "movq %%rax, %0\n\t"
				 : "+rm" (*ptr)
				 :
				 : "rax", "cc", "memory");
#endif
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

struct thr_arg thr_args;

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
	int spin_count = 0;
	int i;

	rc = syscall(732);
	if (rc == -1)
		fprintf(stdout, "CT09100 progress_fn running on Linux OK\n");
	else {
		fprintf(stdout, "CT09100 progress_fn running on McKernel NG\n", rc);
	}

	printf("tid=%d,bar_count=%d\n", syscall(__NR_gettid), arg->bar_count);

	pthread_mutex_lock(&arg->bar_lock);
	arg->bar_count++;
	if (arg->bar_count == 2) {
		if ((rc = pthread_cond_broadcast(&arg->bar_cond))) {
			printf("pthread_cond_broadcast failed,rc=%d\n", rc);
		}
	}
	while (arg->bar_count != 2) {
		if ((rc = pthread_cond_wait(&arg->bar_cond, &arg->bar_lock))) {
			printf("pthread_cond_wait failed,rc=%d\n", rc);
		}
	}
	pthread_mutex_unlock(&arg->bar_lock);
	
	printf("after barrier\n");

	/* Start progress */
	pthread_mutex_lock(&ep_lock);
	while(1) {
		if (terminate) {
			break;
		}

		fwq(POLL_DELAY);
		
		/* Event found */
		if (nevents > 0) {
			fwq(COMPL_DELAY); /* Simulate MPI protocol response */
			nevents = 0;
		}

		spin_count++;
		if (spin_count >= NSPIN) {
			spin_count = 0;
			pthread_mutex_unlock(&ep_lock);
			sched_yield();
			pthread_mutex_lock(&ep_lock);
		}
	}
	return NULL;
}

int main(int argc, char **argv) {
	int rc;
	int i;
	char *uti_str;
	int uti_val;
	struct timespec start, end;
	int disable_progress;

	fprintf(stdout, "CT09001 MPI progress thread skelton START\n");

	rc = syscall(732);
	if (rc == -1)
		fprintf(stdout, "CT09002 main running on Linux INFO\n");
	else {
		fprintf(stdout, "CT09002 main running on McKernel INFO\n");
	}

	fwq_init();
	pthread_mutex_init(&ep_lock, NULL);

	thr_args.bar_count = 0;
	pthread_cond_init(&thr_args.bar_cond, NULL);
	pthread_mutex_init(&thr_args.bar_lock, NULL);

	disable_progress = (argc > 1 && strcmp(argv[1], "-d") == 0) ? 1 : 0;

	if (disable_progress) {
		goto skip1;
	}

	uti_str = getenv("DISABLE_UTI");
	uti_val = uti_str ? atoi(uti_str) : 0;
	if (!uti_val) {
		rc = syscall(731, 1, NULL);
		if (rc) {
			fprintf(stdout, "CT09003 INFO: uti not available (rc=%d)\n", rc);
		} else {
			fprintf(stdout, "CT09003 INFO: uti available\n");
		}
	} else {
		fprintf(stdout, "CT09003 INFO: uti disabled\n", rc);
	}

	rc = pthread_create(&thr_args.pthread, NULL, progress_fn, &thr_args);
	if (rc){
		fprintf(stdout, "pthread_create: %d\n", rc);
		exit(1);
	}
	pthread_mutex_lock(&thr_args.bar_lock);
	thr_args.bar_count++;
	if (thr_args.bar_count == 2) {
		if ((rc = pthread_cond_broadcast(&thr_args.bar_cond))) {
			printf("pthread_cond_broadcast failed,rc=%d\n", rc);
		}
	}
	while (thr_args.bar_count != 2) {
		if ((rc = pthread_cond_wait(&thr_args.bar_cond, &thr_args.bar_lock))) {
			printf("pthread_cond_wait failed,rc=%d\n", rc);
		}
	}
	pthread_mutex_unlock(&thr_args.bar_lock);
	
	fprintf(stdout, "CT09004 pthread_create OK\n");
 skip1:
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	for (i = 0; i < 10000; i++) { /* It takes 1 sec */
		if(!disable_progress) {

			/* Acquire endpoint and send request-to-send packet */
			pthread_mutex_lock(&ep_lock);
			fwq(RTS_DELAY);
			pthread_mutex_unlock(&ep_lock);

			/* Start calculation */

			/* Generate event on behaf of responder */
			fwq(NIC_DELAY);
			nevents++;

			fwq(CALC_DELAY - NIC_DELAY); /* Overlap remainder */

			/* Wait until async thread consumes the event */
			while (nevents > 0) {
				FIXED_SIZE_WORK(&mem);
			}
		} else {
			/* No overlap case */
			fwq(RTS_DELAY + CALC_DELAY + POLL_DELAY + COMPL_DELAY);
		}
	}
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	
	if(!disable_progress) {
		terminate = 1;
		
		pthread_join(thr_args.pthread, NULL);
	}
	fprintf(stderr, "total %ld nsec\n", TS2NS(end.tv_sec, end.tv_nsec) - TS2NS(start.tv_sec, start.tv_nsec));
	fprintf(stdout, "CT09006 END\n");


	exit(0);
}
