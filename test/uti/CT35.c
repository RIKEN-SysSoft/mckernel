#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sched.h>
#include "util.h"

void *util_fn(void *arg)
{
	int ret;
	ret = syscall(732);
	OKNGNOJUMP(ret == -1, "Utility thread is running on Linux\n");
 fn_fail:
	return NULL;
}

int my_thread_create()
{
	pthread_t thr;
	int ret = 0;

	ret = syscall(731, 1, NULL);
	OKNGNOJUMP(ret == 0, "util_indicate_clone,ret=%d,errno=%d\n", ret, errno);

	if ((ret = pthread_create(&thr, NULL, util_fn, NULL))) {
		printf("Error: pthread_create: %s\n", strerror(errno));
	}
	
	if ((ret = pthread_join(thr, NULL))) {
		printf("Error: pthread_join: %s\n", strerror(errno));
	}

 fn_exit:
	return ret;

 fn_fail:
	ret = -1;
	goto fn_exit;
}

int
main(int argc, char **argv)
{
	int ret = 0;

	if ((ret = my_thread_create())) {
		printf("Error: my_thread_create,ret=%d\n", ret);
	}

 fn_exit:
	return ret;

 fn_fail:
	ret = -1;
	goto fn_exit;
}
