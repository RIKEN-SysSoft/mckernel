#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>

void
sig(int s)
{
	fprintf(stderr, "signal hanlder is called\n");
}

int
main(int argc, char **argv)
{
	struct sigaction act;
	int fds[2];
	char c;
	int rc;

	memset(&act, '\0', sizeof act);
	act.sa_handler = sig;
	sigaction(SIGALRM, &act, NULL);
	alarm(3);
	pipe(fds);
	rc = read(fds[0], &c, 1);
	if (rc != -1) {
		fprintf(stderr, "CT3001 NG BAD read rc=%d\n", rc);
		exit(1);
	}
	if (errno != EINTR) {
		fprintf(stderr, "CT3001 NG BAD error errno=%d\n", errno);
		exit(1);
	}
	fprintf(stderr, "CT3001 OK\n");
	exit(0);
}
