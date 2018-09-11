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

void *
util_thread(void *arg)
{
	int rc;
	int tid;

	rc = syscall(732);
	if (rc == 0)
		fprintf(stderr, "CT05003 get_system OK\n");
	else {
		fprintf(stderr, "CT05003 get_system NG get_system=%d\n", rc);
		exit(1);
	}
	tid = syscall(SYS_gettid);
	fprintf(stderr, "CT05004 gettid OK %d\n", tid);
	rc = syscall(730);
	if (rc == 0) {
		fprintf(stderr, "CT05005 util_migrate_inter_kernel OK\n");
	}
	else {
		fprintf(stderr, "CT05005 util_migrate_inter_kernel NG rc=%d errno=%d\n", rc, errno);
	}
	rc = syscall(732);
	if (rc == -1)
		fprintf(stderr, "CT05006 get_system OK\n");
	else {
		fprintf(stderr, "CT05006 get_system NG get_system=%d\n", rc);
		exit(1);
	}
	if ((rc = syscall(SYS_gettid)) == tid) {
		fprintf(stderr, "CT05007 gettid OK %d\n", tid);
	}
	else {
		fprintf(stderr, "CT05007 gettid NG %d\n", rc);
	}
	return NULL;
}

int
main(int argc, char **argv)
{
	pthread_t thr;
	int rc;

	fprintf(stderr, "CT05001 gettid START\n");
	rc = pthread_create(&thr, NULL, util_thread, NULL);
	if(rc){
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}
	fprintf(stderr, "CT05002 pthread_create OK\n");
	pthread_join(thr, NULL);
	fprintf(stderr, "CT05008 pthread_join OK\n");
	fprintf(stderr, "CT05009 END\n");
	exit(0);
}
