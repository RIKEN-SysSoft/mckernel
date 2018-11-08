#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/mman.h>

volatile char *m;

void *
thr(void *arg)
{
	int rc;
	char *mm;

	fprintf(stderr, "thread start tid=%d\n", (int)syscall(SYS_gettid));
	fflush(stderr);
	errno = 0;
	mm = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS,
		  -1, 0);
	fprintf(stderr, "mmap m=%p errno=%d\n", mm, errno);
	fflush(stderr);
	memset(mm, '\0', 4096);
	m = mm;
	*mm = '1';
	while (*m);
	rc = munmap(mm, 4096);
	fprintf(stderr, "munmap rc=%d, errno=%d\n", rc, errno);
	fflush(stderr);
	return NULL;
}

int
main(int argc, char **argv)
{
	pthread_t th;
	int rc;

	fprintf(stderr, "process start pid=%d\n", getpid());
	fflush(stderr);
	rc = pthread_create(&th, NULL, thr, NULL);
	if (rc) {
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stderr, "pthread_create: %d\n", rc);
	fflush(stderr);
	while (!m);
	fprintf(stderr, "update m=%p\n", m);
	fflush(stderr);
	while (!*m);
	fprintf(stderr, "update *m=%c\n", *m);
	fflush(stderr);
	*m = '\0';
	pthread_join(th, NULL);
	fprintf(stderr, "main done\n");
	fflush(stderr);
	exit(0);
}
