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
#include "test_chk.h"

void *util_thread(void *arg)
{
	int rc;
	rc = syscall(732);
	OKNG(rc != -1, "running on Linux");
	return NULL;
}

int my_thread_create()
{
	pthread_t thr;
	int rc = 0;

	rc = syscall(731, 1, NULL);
	OKNG(rc, "util_indicate_clone,rc=%d,errno=%d", rc, errno);

	rc = pthread_create(&thr, NULL, util_thread, NULL);
	OKNGJUMP(rc, "pthread_create,rc=%d,errno=%d", rc, errno);

	rc = pthread_join(thr, NULL);
	OKNGJUMP(rc, "pthread_join,rc=%d", rc);
	
 fn_exit:
	return rc;

 fn_fail:
	rc = -1;
	goto fn_exit;
}

int
main(int argc, char **argv)
{
	int rc = 0;

	rc = my_thread_create();
	OKNGJUMP(rc, "my_thread_create,rc=%d", rc);
			 
	my_thread_create();
	OKNGJUMP(rc, "my_thread_create,rc=%d", rc);

 fn_exit:
	exit(rc);

 fn_fail:
	rc = -1;
	goto fn_exit;
}
