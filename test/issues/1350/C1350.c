#include <stdio.h>
#include <signal.h>
#include <unistd.h>

static int catch_cnt;

void sig_handler(int signum)
{
	switch (signum) {
	case SIGUSR1:
		puts("suspender caught SIGUSR1");
		catch_cnt++;
		break;
	default:
		printf("suspender caught unexpected signal %d\n", signum);
	}
	fflush(stdout);
}

int main(void)
{
	sigset_t sigset;
	struct sigaction sact;
	pid_t pid;
	int ret = 0;
	catch_cnt = 0;

	if (fork() == 0) {
		/* child (signal sender) */
		sleep(3);
		printf("child is sending SIGUSR1 (should be caught)\n");
		kill(getppid(), SIGUSR1);
		return 0;
	}

	/* parent (signal catcher) */
	sigemptyset(&sact.sa_mask);
	sact.sa_flags = 0;
	sact.sa_handler = sig_handler;
	if (sigaction(SIGUSR1, &sact, NULL) != 0) {
		perror("sigaction() error");
		ret = -1;
		goto out;
	}

	sigfillset(&sigset);
	sigdelset(&sigset, SIGUSR1);
	printf("parent is waiting SIGUSR1\n");
	if (sigsuspend(&sigset) == -1) {
		printf("sigsuspend return -1 as expected\n");
	}

	if (catch_cnt == 1) {
		printf("[OK] caught SIGUSR1\n");
	}
	else {
		printf("[NG] SIGUSR1 count:%d\n", catch_cnt);
		ret = -1;
		goto out;
	}

out:
	return ret;
}
