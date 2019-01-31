#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
	char *command;
	char *exargv[2] = {NULL, NULL};
	char *exenvp[1] = {NULL};
	int pid = 0;
	int status;
	int rc, ret = -1;

	if (argc < 2) {
		printf("Error: too few arguments\n");
		return -1;
	}

	pid = fork();
	if (fork < 0) {
		printf("failed to fork\n");
		return -1;
	}
	else if (pid == 0) {
		/* child */
		exargv[0] = argv[1];
		rc = execve(argv[1], exargv, exenvp);

		/* Don't reach here */
		if (rc == -1) {
			perror("Error: failed to execve");
		}
	}

	/* parent */
	waitpid(pid, &status, 0);
	if (WIFEXITED(status)) {
		if (!WEXITSTATUS(status)) {
			printf(" Child exited normaly\n");
			ret = 0;
		}
	}

	return ret;
}
