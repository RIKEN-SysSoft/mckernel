#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[])
{
	char* command;
	char* exargv[] = {NULL, NULL};
	char* exenvp[] = {NULL};
	int rc;

	if (argc < 2) {
		printf("Error: too few arguments\n");
		return -1;
	}

	exargv[0] = argv[1];

	rc = execve(argv[1], exargv, exenvp);

	/* Don't reach here */
	if (rc == -1) {
		perror("Error: failed to execve");
	}

	return -1;
}
