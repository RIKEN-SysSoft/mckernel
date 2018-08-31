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
#include <sys/types.h>

void *
util_thread(void *arg)
{
	long rc;
	rc = syscall(732);
	if (rc == -1)
		fprintf(stderr, "CT07003 get_system OK\n");
	else {
		fprintf(stderr, "CT07003 get_system NG get_system=%d\n", rc);
		exit(1);
	}

	rc = syscall(SYS_clone);
	if (rc == -1 && errno == ENOSYS) {
		fprintf(stderr, "CT07004 clone OK\n");
	}
	else {
		fprintf(stderr, "CT07004 clone NG rc=%ld errno=%d\n", rc, errno);
	}

	rc = syscall(SYS_fork);
	if (rc == -1 && errno == ENOSYS) {
		fprintf(stderr, "CT07005 fork OK\n");
	}
	else {
		fprintf(stderr, "CT07005 fork NG rc=%ld errno=%d\n", rc, errno);
	}

#if 0 /* It looks like syscall_intercept can't hook vfork */
	rc = syscall(SYS_vfork);
	//rc = vfork();
	fprintf(stderr, "CT07006 vfork rc=%d,errno=%d\n", rc, errno);
	if (rc == -1 && errno == ENOSYS) {
		fprintf(stderr, "CT07006 vfork OK\n");
	}
	else {
		fprintf(stderr, "CT07006 vfork NG rc=%ld errno=%d\n", rc, errno);
	}
#endif

	rc = syscall(SYS_execve);
	if (rc == -1 && errno == ENOSYS) {
		fprintf(stderr, "CT07007 execve OK\n");
	}
	else {
		fprintf(stderr, "CT07007 execve NG rc=%ld errno=%d\n", rc, errno);
	}
	return NULL;
}

int
main(int argc, char **argv)
{
	int rc;
	pthread_t thr;

	fprintf(stderr, "CT07001 syscall error START\n");
	rc = syscall(731, 1, NULL);
	if (rc) {
		fprintf(stderr, "util_indicate_clone rc=%d, errno=%d\n", rc, errno);
		fflush(stderr);
	}
	rc = pthread_create(&thr, NULL, util_thread, NULL);
	if(rc){
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stderr, "CT07002 pthread_create OK\n");

	pthread_join(thr, NULL);
	fprintf(stderr, "CT07008 pthread_join OK\n");
	fprintf(stderr, "CT07010 END\n");
	exit(0);
}
