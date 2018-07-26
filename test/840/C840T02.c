#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

int
main(int argc, char **argv)
{
	pid_t pid;
	int pfd[2];
	char c;

	pid = fork();
	if (pid == 0) {
		sleep(1);
		kill(getppid(), SIGKILL);
		exit(0);
	}

	pipe(pfd);
	read(pfd[0], &c, 1);
	exit(0);
}
