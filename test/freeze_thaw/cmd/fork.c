/* fork.c COPYRIGHT FUJITSU LIMITED 2019 */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>

static void waitChildren(void)
{
	for (;;) {
		int status = 0;
		pid_t pid = wait(&status);

		if (pid == -1) {
			const char msg[] = "wait fail\n";

			if (errno == ECHILD) {
				return;
			} else if (errno == EINTR) {
				continue;
			}
			write(STDERR_FILENO, msg, sizeof(msg));
			_exit(-1);
		}
	}
}

int main(int argc, char **argv)
{
	int ret = 0;
	int nr_fork;
	int i;

	if (argc < 2) {
		printf("usage: %s <nr_fork>\n", argv[0]);
		return 1;
	}
	nr_fork = atoi(argv[1]);

	for (i = 0; i < nr_fork; i++) {
		pid_t pid = fork();

		if (pid < 0) {
			perror("fork");
			ret = -1;
			break;
		} else if (pid == 0) {
			exit(0);
		}
	}
	waitChildren();
	return ret;
}
