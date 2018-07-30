#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>

#define EXEC_CNT (1024 * 1024)
#define FORK_CNT 24

void
killall()
{
	fprintf(stderr, "*** C1024T01 NG\n");
	fflush(stderr);
	kill(-getpid(), SIGKILL);
	exit(1);
}

void
print(int c)
{
	time_t t;
	char tbuf[16];

	time(&t);
	strftime(tbuf, 16, "%H:%M:%S", localtime(&t));
	fprintf(stderr, "%s c=%d\n", tbuf, c);
	fflush(stderr);
}

int
main(int argc, char **argv)
{
	int *c;
	pid_t pids[FORK_CNT];
	int pfd[FORK_CNT];
	int i;
	int st;
	int maxfd = -1;
	int rc;
	char buf[1024];

	fprintf(stderr, "*** C1024T01 START\n");
	c = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS,
	         -1, 0);
	if (c == (void *)-1) {
		perror("mmap");
		exit(1);
	}

	*c = 0;
	print(*c);
	setpgid(0, 0);
	for (i = 0; i < FORK_CNT; i++) {
		int fds[2];

		if (pipe(fds) == -1) {
			perror("pipe");
			exit(1);
		}
		fflush(stderr);
		if ((pids[i] = fork()) == 0) {
			close(fds[0]);
			close(0);
			close(1);
			close(2);
			open("/dev/null", O_RDONLY);
			dup(fds[1]);
			dup(fds[1]);
			while (*c <= EXEC_CNT) {
				pid_t pid;

				if ((pid = fork()) == 0) {
					execl("./mcexec", "./mcexec",
					      "/bin/sleep", "0", NULL);
					perror("execve");
					exit(1);
				}
				if (pid == -1) {
					perror("fork");
					exit(1);
				}
				while ((rc = waitpid(pid, &st, 0)) == -1 &&
				       errno == EINTR);
				if (rc == -1) {
					perror("wait");
					exit(1);
				}
				if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
					sprintf(buf, "exit: %08x\n", st);
					write(2, buf, strlen(buf));
					exit(1);
				}
				__sync_fetch_and_add(c, 1);
			}
			exit(0);
		}
		close(fds[1]);
		pfd[i] = fds[0];
		if (pfd[i] > maxfd)
			maxfd = pfd[i];
		if (pids[i] == -1) {
			perror("fork");
			killall();
		}
	}
	for (;;) {
		fd_set readfds;
		int e = 0;
		struct timeval to;

		FD_ZERO(&readfds);
		for (i = 0; i < FORK_CNT; i++) {
			if (pfd[i] != -1) {
				FD_SET(pfd[i], &readfds);
				e++;
			}
		}
		if (!e)
			break;
		to.tv_sec = 300;
		to.tv_usec = 0;
		rc = select(maxfd + 1, &readfds, NULL, NULL, &to);
		if (rc == 0) {
			print(*c);
			continue;
		}
		for (i = 0; i < FORK_CNT; i++) {
			if (pfd[i] != -1 && FD_ISSET(pfd[i], &readfds)) {
				if ((rc = read(pfd[i], buf, 1024)) == -1) {
					perror("read");
					killall();
				}
				if (rc == 0) {
					close(pfd[i]);
					pfd[i] = -1;
				}
				else {
					write(2, buf, rc);
					killall();
				}
			}
		}
	}
	for (i = 0; i < FORK_CNT; i++) {
		while ((rc = waitpid(pids[i], &st, 0)) == -1 && errno == EINTR);
		if (rc == -1) {
			perror("wait");
			killall();
		}
		if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
			sprintf(buf, "%d: exit: %08x\n", pids[i], st);
			killall();
		}
	}
	print(*c);
	if (*c <= EXEC_CNT) {
		fprintf(stderr, "*** C1024T01 NG\n");
	}

	fprintf(stderr, "*** C1024T01 OK\n");
	exit(0);
}
