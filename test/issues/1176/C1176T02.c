#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

int sighandler;

void
sig(int s)
{
	sighandler = 1;
}

int
main(int argc, char **argv)
{
	pid_t pid;
	int st;

	if ((pid = fork()) == 0) {
		struct sigaction act;
		char ch;
		int rc;

		memset(&act, '\0', sizeof(act));
		act.sa_handler = sig;
		sigaction(SIGINT, &act, NULL);
		rc = read(0, &ch, 1);
		if (rc != -1 || errno != EINTR) {
			exit(rc == -1 ? 1 : 2);
		}
		if (sighandler == 0) {
			exit(3);
		}
		exit(0);
	}
	sleep(1);
	kill(pid, SIGINT);
	if (waitpid(pid, &st, 0) == -1) {
		fprintf(stderr, "*** C1176T02: NG wait %d\n", errno);
		exit(1);
	}
	if (WIFSIGNALED(st)) {
		fprintf(stderr, "*** C1176T02: NG termsig %d\n", WTERMSIG(st));
		exit(1);
	}
	if (WEXITSTATUS(st) == 1) {
		fprintf(stderr, "*** C1176T02: NG BAD read\n");
		exit(1);
	}
	else if (WEXITSTATUS(st) == 2) {
		fprintf(stderr, "*** C1176T02: NG BAD read error\n");
		exit(1);
	}
	else if (WEXITSTATUS(st) == 3) {
		fprintf(stderr, "*** C1176T02: NG don't called sighandler\n");
		exit(1);
	}
	else if (WEXITSTATUS(st) != 0) {
		fprintf(stderr, "*** C1176T02: NG unknown\n");
		exit(1);
	}
	fprintf(stderr, "*** C1176T02: OK\n");
	exit(0);
}
