#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>

pid_t pid;
int fd;

void
sig(int s)
{
	static int cnt = 0;

	cnt++;
	if (cnt == 1) {
		char line[80];

		fprintf(stderr, "kill SIGTERM (ignored)\n");
		sprintf(line, "%d %d %d\n", 0, pid, SIGTERM);
		write(fd, line, strlen(line));
	}
	else if (cnt == 2) {
		fprintf(stderr, "kill SIGINT\n");
		kill(pid, SIGINT);
	}
	alarm(2);
}

void
child()
{
	struct sigaction act;
	int fds[2];
	char c;
	int rc;

	pipe(fds);
	rc = read(fds[0], &c, 1);
}

int
main(int argc, char **argv)
{
	int st;
	int rc;

	fd = atoi(argv[1]);
	pid = fork();
	if (pid == 0) {
		signal(SIGTERM, SIG_IGN);
		child();
		exit(1);
	}
	signal(SIGALRM, sig);
	alarm(2);
	while ((rc = waitpid(pid, &st, 0)) == -1 && errno == EINTR);
	if (rc != pid) {
		fprintf(stderr, "CT2007 NG BAD wait rc=%d errno=%d\n", rc, errno);
		exit(1);
	}
	if (!WIFSIGNALED(st)) {
		fprintf(stderr, "CT2007 NG no signaled st=%08x\n", st);
		exit(1);
	}
	if (WTERMSIG(st) != SIGINT) {
		fprintf(stderr, "CT2007 NG BAD signal sig=%d\n", WTERMSIG(st));
		exit(1);
	}
	fprintf(stderr, "CT2007 OK\n");
	exit(0);
}
