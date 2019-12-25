#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<sys/types.h>
#include <sys/wait.h>
#include<sys/select.h>
#include<sys/time.h>
#include<signal.h>
#include<errno.h>

int sig;

void
usr1(int s)
{
	sig = 1;
}

void
usr2(int s)
{
	if (sig == 1) {
		printf("*** C1361T01: FAIL : BAD USR1\n");
		exit(1);
	}
	printf("*** C1361T01: PASS\n");
	exit(0);
}

int
main(int argc, char **argv)
{
	pid_t pid;
	int st;

	if ((pid = fork()) == 0) {
		sigset_t mask;
		struct timespec to;
		int rc;

		sigprocmask(0, NULL, &mask);
		sigaddset(&mask, SIGUSR1);
		signal(SIGUSR1, usr1);
		signal(SIGUSR2, usr2);
		to.tv_sec = 3;
		to.tv_nsec = 0;
		rc = pselect(0, NULL, NULL, NULL, &to, &mask);
		if (rc == -1 && errno == EINTR) {
			printf("*** C1361T01: FAIL : BAD SIGNAL\n");
			exit(1);
		}
		printf("*** C1361T01 FAIL: : timeout\n");
		exit(2);
	}
	sleep(1);
	kill(pid, SIGUSR1);
	sleep(1);
	kill(pid, SIGUSR2);
	while (waitpid(pid, &st, 0) == -1 && errno == EINTR)
		;
	exit(0);
}
