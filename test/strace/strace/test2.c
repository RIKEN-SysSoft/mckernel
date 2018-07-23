#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

int
main(int argc, char **argv)
{
	pid_t pid;
	int rc;
	int st;

	if (argv[1] && !strcmp(argv[1], "exec")) {
		exit(1);
	}

	pid = fork();
	if (pid == 0) {
		sleep(1);
		execl("test2", "test2", "exec", NULL);
		exit(99);
	}
	sleep(2);
	rc = wait(&st);
	if (rc != pid) {
		printf("test2 NG\n");
		exit(1);
	}
	exit(0);
}
