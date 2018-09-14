#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <asm/prctl.h>
#include <sys/prctl.h>

int arch_prctl(int code, unsigned long *addr);

void
sigusr(int sig)
{
	if (sig == SIGUSR1) {
		printf("SIGUSR1\n");
	}
	else if (sig == SIGUSR2) {
		printf("SIGUSR2\n");
	}
	else {
		printf("other sig\n");
	}
	fflush(stdout);
}

int
main(int argc, char **argv)
{
	struct sigaction act;
	pid_t pid1 = 0;
	pid_t pid2 = 0;
	pid_t parent;
	int pfd[2];
	char ch;
	int rc;
	unsigned long val;

	memset(&act, '\0', sizeof(act));
	act.sa_handler = sigusr;
	act.sa_flags = SA_RESTART;
	sigaction(SIGUSR1, &act, NULL);
	sigaction(SIGUSR2, &act, NULL);

	pipe(pfd);

	parent = getpid();
	val = 1;
	if (arch_prctl(999, (unsigned long *)val) == -1) {
		fprintf(stderr, "C1009T01 WARN: no mckernel patch detected.\n");
		exit(1);
	}

	if ((pid1 = fork())) {
		pid2 = fork();
	}

	if (!pid1 || !pid2) {
		int sig;

		close(pfd[0]);
		if (pid1)
			sig = SIGUSR2;
		else
			sig = SIGUSR1;

		sleep(1);
		kill(parent, sig);
		if (pid1) {
			sleep(2);
			ch = 'B';
		}
		else {
			sleep(1);
			ch = 'A';
		}
		write(pfd[1], &ch, 1);
		close(pfd[1]);
		exit(0);
	}
	rc = read(pfd[0], &ch, 1);
	if (rc != 1) {
		printf("C1009T01 NG: read error rc=%d errno=%d\n", rc, errno);
		exit(1);
	}
	if (ch != 'A') {
		printf("C1009T01 NG: read BAD DATA ch=%c\n", ch);
		exit(1);
	}
	val = 0;
	arch_prctl(999, (unsigned long *)val);
	printf("read %c OK\n", ch);
	rc = read(pfd[0], &ch, 1);
	if (rc != 1) {
		printf("C1009T01 NG: read error rc=%d errno=%d\n", rc, errno);
		exit(1);
	}
	if (ch != 'B') {
		printf("C1009T01 NG: read BAD DATA ch=%c\n", ch);
		exit(1);
	}

	printf("read %c OK\n", ch);
	printf("*** C1009T01: OK\n");
	exit(0);
}
