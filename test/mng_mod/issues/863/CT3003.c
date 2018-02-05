#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>

void
child()
{
	struct sigaction act;
	int fds[2];
	char c;
	int rc;

	alarm(3);
	pipe(fds);
	rc = read(fds[0], &c, 1);
}

int
main(int argc, char **argv)
{
	pid_t pid;
	int st;
	int rc;

	pid = fork();
	if (pid == 0) {
		child();
		exit(1);
	}
	while ((rc = waitpid(pid, &st, 0)) == -1 && errno == EINTR);
	if (rc != pid) {
		fprintf(stderr, "CT3003 NG BAD wait rc=%d errno=%d\n", rc, errno);
		exit(1);
	}
	if (!WIFSIGNALED(st)) {
		fprintf(stderr, "CT3003 NG no signaled st=%08x\n", st);
		exit(1);
	}
	if (WTERMSIG(st) != SIGALRM) {
		fprintf(stderr, "CT3003 NG BAD signal sig=%d\n", WTERMSIG(st));
		exit(1);
	}
	fprintf(stderr, "CT3003 OK\n");
	exit(0);
}
