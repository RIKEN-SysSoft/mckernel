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
	int rc;
	pid_t tid;
	char *mm;

	tid = syscall(SYS_gettid);
	*x = tid;
	while (*x == tid);

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
	pid_t tid;
	pid_t pid;
	int sig;
	int st;

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
	fprintf(stderr, "tid=%d\n", tid);

	if ((pid = fork()) == 0) {
		if (ptrace(PTRACE_ATTACH, tid, 0, 0) == -1) {
			fprintf(stderr, "*** C771T033 *** ATTACH NG err=%d\n",
				errno);
			exit(1);
		}
		rc = waitpid(-1, &st, __WALL);
		if (rc == tid) {
			fprintf(stderr, "*** C771T033 *** ATTACH OK\n");
		}
		else {
			fprintf(stderr, "*** C771T033 *** ATTACH NG rc=%d\n",
				rc);
			exit(1);
		}
		if (ptrace(PTRACE_SETOPTIONS, tid, 0, PTRACE_O_TRACESYSGOOD) ==
		    -1) {
			fprintf(stderr, "PTRACE_SETOPTIONS errno=%d\n", errno);
			exit(1);
		}
		*x = 0;
		sig = 0;
		for (;;) {
			rc = ptrace(PTRACE_SYSCALL, tid, 0, sig);
			if (rc == -1) {
				fprintf(stderr,
					"*** C771T034 *** SYSCALL NG err=%d\n",
					errno);
				exit(1);
			}
			rc = waitpid(-1, &st, __WALL);
			if (rc == tid) {
				fprintf(stderr,
					"*** C771T034 *** SYSCALL OK\n");
			}
			else {
				fprintf(stderr,
					"*** C771T034 *** SYSCALL NG rc=%d\n",
					rc);
				exit(1);
			}

			if (WIFEXITED(st) || WIFSIGNALED(st)) {
				fprintf(stderr, "thread terminated %08x\n", st);
				exit(1);
			}
			if (!WIFSTOPPED(st)) {
				fprintf(stderr, "warning: st=%08x\n", st);
				continue;
			}
			if (WSTOPSIG(st) & 0x80) { // syscall
				struct user_regs_struct arg;
				int num;
				long ret;

				if (ptrace(PTRACE_GETREGS, tid, NULL, &arg) ==
				    -1) {
				}
				num = arg.orig_rax;
				ret = arg.rax;
				if (ret == -ENOSYS) {
					fprintf(stderr,
						"syscall enter n=%d\n", num);
				}
				else {
					fprintf(stderr,
						"syscall return n=%d r=%ld\n",
						num, ret);
					if (ptrace(PTRACE_DETACH, tid, NULL,
						   NULL) == -1) {
						fprintf(stderr,
							"*** C771T035 DETACH NG"
							"err=%d\n", errno);
						exit(1);
					}
					else {
						fprintf(stderr,
							"*** C771T035 DETACH OK"
							"\n");
						exit(0);
					}
				}
			}
			else { // signal
				sig = WSTOPSIG(st) & 0x7f;
			}
		}
	}

	while (!m);
	fprintf(stderr, "update m=%p\n", m);
	fflush(stderr);
	while (!*m);
	fprintf(stderr, "update *m=%c\n", *m);
	fflush(stderr);
	*m = '\0';
	waitpid(pid, &st, 0);
	pthread_join(th, NULL);
	fprintf(stderr, "main done\n");
	fflush(stderr);
	exit(0);
}
