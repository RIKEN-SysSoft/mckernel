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

int
main(int argc, char **argv)
{
	int f;
	int r;
	char *p;
	pthread_t thr;

	fprintf(stderr, "*** C1474T06 START ***\n");
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

	ok = 2;
	while (ok == 2)
		;
	pthread_join(thr, NULL);
	if (ok == 1) {
		fprintf(stderr, "*** C1474T06 OK ***\n");
		exit(0);
	}
ng:
	fprintf(stderr, "*** C1474T06 NG ***\n");
	exit(1);
}
