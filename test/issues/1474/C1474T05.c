#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sched.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>

int ok;

void *
util_thread(void *arg)
{
	char *p = arg;
	int f;
	int r;

	r = syscall(732);
	if (r == -1) {
		fprintf(stderr, "thread is running on Linux OK\n");
	}
	else {
		fprintf(stderr, "thread is running on McKernel NG(%d)\n", r);
		ok = -1;
		return NULL;
	}
	while (ok == 0)
		;

	f = open("outfile", O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if (f == -1) {
		perror("open(outfile)");
		ok = -1;
		return NULL;
	}
	if ((r = write(f, p, 1024)) == -1) {
		perror("write");
		ok = -1;
		return NULL;
	}
	fprintf(stderr, "remote page fault OK\n");
	close(f);
	if (r != 1024) {
		fprintf(stderr, "BAD out size: %d\n", r);
		ok = -1;
		return NULL;
	}
	ok = 1;
	return NULL;
}

void *
wait_thread(void *arg)
{
	sleep(5);
	return NULL;
}


int
main(int argc, char **argv)
{
	int f;
	int r;
	char *p;
	pthread_t thr;
	pthread_t wthr;
	cpu_set_t cpu_set0;
	cpu_set_t cpu_set1;
	cpu_set_t cpu_set;
	int i;

	fprintf(stderr, "*** C1474T05 START ***\n");
	if ((f = open("testfile", O_RDONLY)) == -1) {
		perror("open(testfile)");
		goto ng;
	}
	p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, f, 0);
	if (p == (void *)-1) {
		perror("mmap");
		goto ng;
	}
	close(f);

	if (sched_getaffinity(getpid(), sizeof(cpu_set_t), &cpu_set0) == -1) {
		perror("sched_getaffinity");
		goto ng;
	}
	CPU_ZERO(&cpu_set);
	CPU_ZERO(&cpu_set1);
	for (i = 0; i < sizeof(cpu_set) * 8; i++) {
		if (CPU_ISSET(i, &cpu_set0)) {
			CPU_SET(i, &cpu_set1);
			break;
		}
	}
	for (i++; i < sizeof(cpu_set) * 8; i++) {
		if (CPU_ISSET(i, &cpu_set0)) {
			CPU_SET(i, &cpu_set);
			break;
		}
	}
	if (sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpu_set)) {
		perror("sched_setaffinity");
		goto ng;
	}

	r = pthread_create(&wthr, NULL, wait_thread, NULL);
	if (r) {
		fprintf(stderr, "pthread_create: %d\n", r);
		goto ng;
	}

	r = syscall(731, 1, NULL);
	if (r) {
		fprintf(stderr, "util_indicate_clone r=%d, err=%d\n", r, errno);
		goto ng;
	}
	r = pthread_create(&thr, NULL, util_thread, p);
	if (r) {
		fprintf(stderr, "pthread_create: %d\n", r);
		goto ng;
	}

	if (sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpu_set1)) {
		perror("sched_setaffinity");
		goto ng;
	}

	ok = 2;
	while (ok == 2)
		;
	pthread_join(thr, NULL);
	pthread_join(wthr, NULL);
	if (ok == 1) {
		fprintf(stderr, "*** C1474T05 OK ***\n");
		exit(0);
	}
ng:
	fprintf(stderr, "*** C1474T05 NG ***\n");
	exit(1);
}
