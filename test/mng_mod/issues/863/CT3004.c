#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>

#define FILESIZE (2L * 1024 * 1024 * 1024)

void
child()
{
	char *buf;
	long rc;
	long l;
	long r;
	int fd;

	buf = malloc(FILESIZE);
	fd = open("testfile", O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Could not open file\n");
		unlink("testfile");
		exit(1);
	}

	alarm(1);
	rc = read(fd, buf, FILESIZE);
}

int
main(int argc, char **argv)
{
	pid_t pid;
	int st;
	int rc;

	pid = fork();
	if (pid == 0) {
		child();
		exit(1);
	}
	while ((rc = waitpid(pid, &st, 0)) == -1 && errno == EINTR);
	if (rc != pid) {
		fprintf(stderr, "CT3004 NG BAD wait rc=%d errno=%d\n", rc, errno);
		exit(1);
	}
	if (!WIFSIGNALED(st)) {
		fprintf(stderr, "CT3004 NG no signaled st=%08x\n", st);
		exit(1);
	}
	if (WTERMSIG(st) != SIGALRM) {
		fprintf(stderr, "CT3004 NG BAD signal sig=%d\n", WTERMSIG(st));
		exit(1);
	}
	fprintf(stderr, "CT3004 OK\n");
	exit(0);
}
