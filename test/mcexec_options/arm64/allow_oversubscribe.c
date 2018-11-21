/* allow_oversubscribe.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>

#define PROG "/usr/bin/date"

static int
do_fork(int proc_num)
{
	int i;

	for (i = 0; i < proc_num; i += 1) {
		pid_t pid = fork();

		if (pid < 0) {
			perror("fork failed");
			return -1;
		}
		else if (0 == pid) {
			printf("%d: in child (%d/%d)\n",
			    getpid(), (i+1), proc_num);
			execl(PROG, PROG, NULL);
			exit(0);
			/* NOTREACHED */
		}
	}

	return 0;
}

static int
do_wait(int proc_num)
{
	pid_t mypid = getpid();
	int i;

	printf("%d: in parent\n", mypid);
	for (i = 0; i < proc_num; i += 1) {
		int status;
		pid_t pid = waitpid(-1, &status, 0);

		if (pid < 0) {
			perror("waitpid failed");
			return -1;
		}
		printf("%d: waited %d (%d/%d)\n",
		    mypid, pid, (i+1), proc_num);
	}
	printf("%d: all done\n", mypid);

	return 0;
}

int
main(int argc, char *argv[])
{
	int result = 0;
	int proc_num = atoi(argv[1]);

	if (do_fork(proc_num)) {
		result = -1;
	}

	if (do_wait(proc_num)) {
		result = -1;
	}
	return result;
}
