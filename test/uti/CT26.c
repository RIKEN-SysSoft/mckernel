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
#define N_INIT 10000000

static inline void fixed_size_work(unsigned long *ptr) {
    asm volatile("movq %0, %%rax\n\t"
                 "addq $1, %%rax\n\t"           \
                 "movq %%rax, %0\n\t"           \
                 : "+rm" (*ptr)                     \
                 :                                  \
                 : "rax", "cc", "memory");          \
}

static inline void delay_loop(unsigned long n, unsigned long *ptr) {
    int j;
    for (j = 0; j < (n); j++) {
        fixed_size_work(ptr);
    }
}

void delay_init(unsigned long *mem) {
	struct timespec start, end;
	unsigned long nsec;
	int i;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	delay_loop(N_INIT, mem);
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	nsec = (TS2NS(end.tv_sec, end.tv_nsec) - TS2NS(start.tv_sec, start.tv_nsec));
	nspw = nsec / (double)N_INIT;
	printf("nsec=%ld, nspw=%f\n", nsec, nspw);
}

void delay_nsec(unsigned long delay_nsec, unsigned long* mem) {
	//printf("delay_nsec=%ld,count=%f\n", delay_nsec, delay_nsec / nspw);
	delay_loop(delay_nsec / nspw, mem);
}

void halt(int sig) {
	while(1) { }
}

void *util_thread(void *arg) {
	int rc;
	fprintf(stderr, "CT12101 enter OK\n");

	rc = syscall(732);
	if (rc == -1)
		fprintf(stderr, "CT12102 running on Linux CPU OK (tid=%d)\n", syscall(__NR_gettid));
	else {
		fprintf(stderr, "CT12102 running on Linux CPU NG (tid=%d,rc=%d)\n", syscall(__NR_gettid), rc);
	}

	passed = 1;

	rc = syscall(888);
	if (rc != -1) {
		fprintf(stderr, "CT12103 syscall(888) OK (%x)\n", rc);
	} else {
		fprintf(stderr, "CT12103 syscall(888) NG (%x)\n", rc);
	}

	return NULL;
}

int
main(int argc, char **argv)
{
	int rc;
	pthread_attr_t attr;
	struct sigaction act;

	fprintf(stderr, "CT12001 futex START (tid=%d)\n", syscall(__NR_gettid));
#if 0
	rc = syscall(731, 1, NULL);
	if (rc) {
		fprintf(stderr, "util_indicate_clone rc=%d, errno=%d\n", rc, errno);
		fflush(stderr);
	}
#endif
	sigaction(SIGINT, NULL, &act);
	act.sa_handler = halt;
	act.sa_flags &= ~(SA_RESTART);
	sigaction(SIGINT, &act, NULL);

	rc = pthread_attr_init(&attr);
	if (rc){
		fprintf(stderr, "pthread_attr_init: %d\n", rc);
		exit(1);
	}
#if 0
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
	fprintf(stderr, "CT12002 pthread_create OK\n");

#if 1
	while (!passed) {
		asm volatile("pause" ::: "memory"); 
	}
#endif
	usleep(200000);

#if 1
	pthread_join(thr, NULL);
	fprintf(stderr, "CT12004 pthread_join OK\n");
#endif
	//fprintf(stderr, "CT12005 END\n");
	exit(0);
}
