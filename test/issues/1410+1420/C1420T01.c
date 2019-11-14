#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

void
cont(int s)
{
	printf("SIGCONT\n");
	exit(1);
}

void
child()
{
	int mask;

	mask = sigmask(SIGCONT);
	sigprocmask(SIG_BLOCK, (sigset_t *)&mask, NULL);
	signal(SIGCONT, cont);
	for (;;) {
		printf(".\n");
		sleep(1);
	}
}

int
main(int argc, char **argv)
{
	pid_t pid = fork();
	int st;

	if (!pid)
		child();
	printf("*** C1420T01: START\n");
	sleep(3);
	printf("send SIGSTOP\n");
	kill(pid, SIGSTOP);
	sleep(3);
	printf("send SIGCONT\n");
	kill(pid, SIGCONT);
	sleep(3);
	printf("send SIGINT\n");
	kill(pid, SIGINT);
	waitpid(pid, &st, 0);
	printf("*** C1420T01 ");
	if (WIFEXITED(st)) {
		printf("FAIL: child exited st=%d\n", WEXITSTATUS(st));
	}
	else if (WIFSIGNALED(st)) {
		if (WTERMSIG(st) == SIGINT) {
			printf("PASS");
		}
		else {
			printf("FAIL");
		}
		printf(": child terminated by signal %d\n", WTERMSIG(st));
	}
	else {
		printf("FAIL: child status=%08x\n", st);
	}
	exit(0);
}
