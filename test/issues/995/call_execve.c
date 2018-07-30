#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
	char *command;
	char *exargv[128] = {};
	char *exenvp[1] = {NULL};
	int i, rc;

	if (argc < 2) {
		printf("Error: too few arguments\n");
		return -1;
	}

	exargv[0] = argv[1];

	for (i = 2; i < argc; i++) {
		exargv[i - 1] = argv[i];
	}
	exargv[i - 1] = NULL;

	rc = execve(argv[1], exargv, exenvp);

	/* Don't reach here */
	if (rc == -1) {
		perror("Error: failed to execve");
	}

	return -1;
}
