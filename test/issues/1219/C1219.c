#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>

pthread_t thr;

void *thread_fn(void *arg)
{
	int *ptr = NULL;

	*ptr = 0xdead;
}

int main(int argc, char **argv)
{
	int ret;

	ret = pthread_create(&thr, NULL, thread_fn, NULL);
	if (ret) {
		fprintf(stderr, "pthread_create: %d\n", ret);
		exit(1);
	}

	pthread_join(thr, NULL);
	exit(0);
}
