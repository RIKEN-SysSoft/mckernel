#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/prctl.h>

#define EXARG_MAX 64
#define CMD_MAX_LEN 1024

int main(int argc, char *argv[])
{
	int rc = 0, i;
	int thp_disable = 0;
	char *exargv[EXARG_MAX] = {};
	char *exenvp[1] = {NULL};
	char execcmd[CMD_MAX_LEN] = {};

	if (argc < 3) {
		printf("err: too few arguments\n");
		return -1;
	}

	if (argc > EXARG_MAX + 1) {
		printf("err: too many arguments\n");
		return -1;
	}

	thp_disable = atoi(argv[1]);

	rc = prctl(PR_SET_THP_DISABLE, thp_disable, 0, 0, 0);
	if (rc < 0) {
		perror("err: PR_SET_THP_DISABLE");
	}
	printf("set thp_disable: %d\n", thp_disable);

	for (i = 1; i < argc; i++) {
		exargv[i - 2] = argv[i];
	}

	for (i = 0; i < EXARG_MAX; i++) {
		if (!exargv[i]) {
			break;
		}
		if (i != 0) {
			strncat(execcmd, " ", CMD_MAX_LEN - 2);
		}
		strncat(execcmd, exargv[i], CMD_MAX_LEN - strlen(execcmd) - 1);
	}

	printf("exec: %s\n", execcmd);
	execve(exargv[0], exargv, exenvp);

	/* can't reach here */
	printf("err: execve failed\n");
	return -1;
}
