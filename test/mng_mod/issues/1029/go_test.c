#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#define DEF_LOOPS 10

int main(int argc, char** argv) {
	pid_t pid[256];
	int result, i, j;
	int loops = DEF_LOOPS;
	char *_argv[3];

	if (argc > 1) {
		loops = atoi(argv[1]);
	}

	for (i = 0; i < loops && (pid[i] = fork()) > 0; i++);

	if (i == loops) { // parent
		for (i = 0; i < loops; i++) {
			waitpid(pid[i], NULL, 0);
		}
	}
	else if (pid[i] == 0) {
		_argv[0] = "./sched_test";
		_argv[1] = "4";
		_argv[2] = NULL;
		execve(_argv[0], _argv, NULL);
	
		perror("execve");
	}
	else {
		perror("Error fork()");
		return(1);
	}

	return(0);
}
