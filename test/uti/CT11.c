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

int flag1 = 1, flag2 = 1;
pthread_t thr;

void * util_thread(void *arg) {
	int rc;

	rc = syscall(732);
	if (rc == -1)
		fprintf(stderr, "CT11003 get_system OK\n");
	else {
		fprintf(stderr, "CT11003 get_system NG get_system=%d\n", rc);
	}
	errno = 0;

	rc = syscall(__NR_futex, &flag1, FUTEX_WAKE, 1, NULL, NULL, 0);
	if (rc == -1) {
		fprintf(stderr, "CT11100 FUTEX_WAKE returns %s\n", strerror(errno));
	}

	rc = syscall(__NR_futex, &flag2, FUTEX_WAIT, flag2, NULL, NULL, 0);
	if (rc == -1) {
		fprintf(stderr, "CT11101 FUTEX_WAIT returns %s\n", strerror(errno));
	}

	rc = syscall(__NR_futex, &flag1, FUTEX_WAKE, 1, NULL, NULL, 0);
	if (rc == -1) {
		fprintf(stderr, "CT11102 FUTEX_WAKE returns %s\n", strerror(errno));
	}
	return NULL;
}

int
main(int argc, char **argv)
{
	int rc;

	fprintf(stderr, "CT11001 futex START\n");
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
	fprintf(stderr, "CT11002 pthread_create OK\n");

	rc = syscall(__NR_futex, &flag1, FUTEX_WAIT, flag1, NULL, NULL, 0);
	if (rc == -1) {
		fprintf(stderr, "CT11200 FUTEX_WAIT returns %s\n", strerror(errno));
	}

	rc = syscall(__NR_futex, &flag2, FUTEX_WAKE, 1, NULL, NULL, 0);
	if (rc == -1) {
		fprintf(stderr, "CT11201 FUTEX_WAKE returns %s\n", strerror(errno));
	}

	rc = syscall(__NR_futex, &flag1, FUTEX_WAIT, flag1, NULL, NULL, 0);
	if (rc == -1) {
		fprintf(stderr, "CT11202 FUTEX_WAIT returns %s\n", strerror(errno));
	}

	pthread_join(thr, NULL);
	fprintf(stderr, "CT10004 exit(pthread_join) OK\n");

	fprintf(stderr, "CT10005 END\n");
	exit(0);
}
