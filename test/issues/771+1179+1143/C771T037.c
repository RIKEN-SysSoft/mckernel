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
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

volatile char *m;
volatile int *x;

void *
thr(void *arg)
{
	pid_t tid;

	tid = syscall(SYS_gettid);
	*x = tid;
	while (*x == tid);
	return NULL;
}

int
main(int argc, char **argv)
{
	pthread_t th;
	pid_t tid;
	pid_t pid;
	int st;
	int rc;

	x = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS,
		 -1, 0);

	if (x == (void *)-1) {
		perror("mmap");
		exit(1);
	}
	*x = 0;

	rc = pthread_create(&th, NULL, thr, NULL);
	if (rc) {
		fprintf(stderr, "pthread_create: %d\n", rc);
		exit(1);
	}

	while (*x == 0);
	tid = *x;
	fprintf(stderr, "pid=%d\n", getpid());
	fprintf(stderr, "tid=%d\n", tid);

	if ((pid = fork()) == 0) {
		pid = getppid();
		if (ptrace(PTRACE_ATTACH, tid, 0, 0) == -1) {
			fprintf(stderr, "*** C771T037 ATTACH NG err=%d\n",
				errno);
			exit(1);
		}
		if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
			fprintf(stderr, "*** C771T037 ATTACH NG err=%d\n",
				errno);
			exit(1);
		}

		rc = wait4(pid, &st, WNOHANG, NULL);
		if (rc == -1) {
			fprintf(stderr, "*** C771T037 wait4(pid) NG err=%d\n",
				errno);
		}
		else {
			fprintf(stderr, "*** C771T037 wait4(pid) OK\n");
		}

		rc = wait4(tid, &st, WNOHANG, NULL);
		if (rc == -1 && errno == ECHILD) {
			fprintf(stderr, "*** C771T038 wait4(tid) OK\n");
		}
		else {
			fprintf(stderr, "*** C771T038 wait4(tid) NG err=%d\n",
				errno);
		}

		rc = wait4(pid, &st, WNOHANG|__WCLONE, NULL);
		if (rc == -1 && errno == ECHILD) {
			fprintf(stderr,
				"*** C771T039 wait4(pid, __WCLONE) OK\n");
		}
		else {
			fprintf(stderr,
				"*** C771T039 wait4(pid, __WCLONE) NG err=%d\n",
				errno);
		}

		rc = wait4(tid, &st, WNOHANG|__WCLONE, NULL);
		if (rc == -1) {
			fprintf(stderr,
				"*** C771T040 wait4(tid, __WCLONE) NG err=%d\n",
				errno);
		}
		else {
			fprintf(stderr,
				"*** C771T040 wait4(tid, __WCLONE) OK\n");
		}

		rc = wait4(pid, &st, WNOHANG|__WALL, NULL);
		if (rc == -1) {
			fprintf(stderr,
				"*** C771T041 wait4(pid, __WALL) NG err=%d\n",
				errno);
		}
		else {
			fprintf(stderr,
				"*** C771T041 wait4(pid, __WALL) OK\n");
		}

		rc = wait4(tid, &st, WNOHANG|__WALL, NULL);
		if (rc == -1) {
			fprintf(stderr,
				"*** C771T042 wait4(tid, __WALL) NG err=%d\n",
				errno);
		}
		else {
			fprintf(stderr,
				"*** C771T042 wait4(tid, __WALL) OK\n");
		}

		if (ptrace(PTRACE_DETACH, tid, NULL, NULL) == -1) {
			fprintf(stderr, "*** C771T042 DETACH NG err=%d\n",
				errno);
			exit(1);
		}
		if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
			fprintf(stderr, "*** C771T042 DETACH NG err=%d\n",
				errno);
			exit(1);
		}
		*x = 0;
		exit(0);
	}

	while (*x == tid);
	exit(0);
}
