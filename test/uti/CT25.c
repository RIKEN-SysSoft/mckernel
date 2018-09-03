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
#include <semaphore.h>

pthread_t thr;

unsigned long mem; /* delay functions issue ld/st instructions on this address */
double nspw; /* nsec per work */

sem_t sem_kick, sem_report;
int nentry, szentry;
char **sendv, **recvv;



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

void *util_thread(void *arg) {
	int rc;
	int i;

	rc = syscall(732);
	if (rc == -1)
		fprintf(stderr, "CT25101 running on Linux CPU OK\n");
	else {
		fprintf(stderr, "CT25101 running on Linux CPU NG (%d)\n", rc);
	}

	sem_wait(&sem_kick);

	/* Cause remote page fault */
	for (i = 0; i < nentry; i++) {
		memset(recvv[i], 0, szentry);
	}

	sem_post(&sem_report);

	return NULL;
}

pid_t gettid(void)
{
    return syscall(SYS_gettid);
}

int
main(int argc, char **argv)
{
	int ret = 0;
	int rc;
	int i;
	pthread_attr_t attr;

    if(argc == 3) {
        szentry = (1ULL << atoi(argv[1]));
        nentry = atoi(argv[2]);
    }

	if (argc != 3 || szentry == 0) {
		fprintf(stderr, "usage: CT25 <log-size of one buffer entry> <# of entries>\n");
		ret = 1;
		goto fn_fail;
	}

    sem_init(&sem_kick, 0, 0);
    sem_init(&sem_report, 0, 0);

	fprintf(stderr, "CT25001 START\n");
	fprintf(stderr, "CT25001 INFO (pid=%d,tid=%d)\n", getpid(), gettid());

	sendv = malloc(sizeof(char *) * nentry);
	if(!sendv) { printf("malloc failed"); goto fn_fail; }
	for (i = 0; i < nentry; i++) {
		sendv[i] = (char*)mmap(0, szentry, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if(sendv[i] == MAP_FAILED) { printf("mmap failed"); goto fn_fail; }
		memset(sendv[i], 0xaa, szentry);
	}

	recvv = malloc(sizeof(char *) * nentry);
	if(!recvv) { printf("malloc failed"); goto fn_fail; }
	for (i = 0; i < nentry; i++) {
		recvv[i] = (char*)mmap(0, szentry, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		if(recvv[i] == MAP_FAILED) { printf("mmap failed"); goto fn_fail; }
		memset(recvv[i], 0, szentry);
	}

	rc = syscall(731, 1, NULL);
	if (rc) {
		fprintf(stderr, "CT25002 util_indicate_clone INFO (rc=%d, errno=%d)\n", rc, errno);
	} else {
		fprintf(stderr, "CT25002 util_indicate_clone OK\n", rc, errno);
	}

	pthread_attr_init(&attr);
	//pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&thr, &attr, util_thread, NULL);
	if (rc){
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stderr, "CT25002 pthread_create OK\n");

	sem_post(&sem_kick);
	sem_wait(&sem_report);

	pthread_join(thr, NULL);

	fprintf(stderr, "CT25003 END\n");
	ret = 0;

 fn_exit:
	exit(ret);

 fn_fail:
	goto fn_exit;
}
