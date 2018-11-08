#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>
#include <errno.h>

int
main(int argc, char **argv)
{
	pid_t pid;
	cpu_set_t cpuset;
	int st;

	CPU_ZERO(&cpuset);
	CPU_SET(1, &cpuset);

	if (!(pid = fork())) {
		if (sched_setaffinity(0, sizeof(cpuset), &cpuset)) {
			fprintf(stderr, "*** C1176T04: NG\n");
			exit(1);
		}
		fprintf(stderr, "child call sleep\n");
		fflush(stderr);
		sleep(1);
		fprintf(stderr, "child return from sleep\n");
		fflush(stderr);
		exit(0);
	}

	if (sched_setaffinity(0, sizeof(cpuset), &cpuset)) {
		fprintf(stderr, "*** C1176T04: NG\n");
		exit(1);
	}
	fprintf(stderr, "parent call sleep\n");
	fflush(stderr);
	sleep(1);
	fprintf(stderr, "parent return from sleep\n");
	fflush(stderr);

	if (waitpid(pid, &st, 0) == -1) {
		fprintf(stderr, "*** C1176T04: NG %d\n", errno);
		exit(1);
	}
	if (!WIFEXITED(st) || WEXITSTATUS(st)) {
		fprintf(stderr, "*** C1176T04: NG %08x\n", st);
		exit(1);
	}

	fprintf(stderr, "*** C1176T04: OK\n");
	exit(0);
}
