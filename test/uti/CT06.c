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
	long rc;

	rc = syscall(732);
	if (rc == -1)
		fprintf(stderr, "CT06003 get_system OK\n");
	else {
		fprintf(stderr, "CT06003 get_system NG get_system=%d\n", rc);
		exit(1);
	}

	syscall(SYS_exit_group, 99);

	return NULL;
}

int
main(int argc, char **argv)
{
	int rc;
	pthread_t thr;
	int st;
	pid_t pid;

	fprintf(stderr, "CT06001 syscall error START\n");

	pid = fork();
	if (pid) {
		if (pid == -1) {
			perror("fork");
			exit(1);
		}
		while ((rc = waitpid(pid, &st, 0)) == -1 && errno == EINTR);
		if (rc == -1) {
			fprintf(stderr, "CT06004 exit_group NG rc=%d errno=%d\n", rc, errno);
			exit(1);
		}
		if (!WIFEXITED(st)) {
			fprintf(stderr, "CT06004 exit_group NG st=%08x\n", st);
			exit(1);
		}
		if (WEXITSTATUS(st) != 99) {
			fprintf(stderr, "CT06004 exit_group NG st=%d\n", WEXITSTATUS(st));
			exit(1);
		}
		fprintf(stderr, "CT06004 exit_group OK\n");
		exit(0);
	}

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
	fprintf(stderr, "CT06002 pthread_create OK\n");

	pthread_join(thr, NULL);
	fprintf(stderr, "CT06004 pthread_join NG\n");
	fprintf(stderr, "CT06004 END\n");
	exit(0);
}
