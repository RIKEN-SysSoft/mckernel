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

pid_t pid;
int fd;

void
sig(int s)
{
	char line[80];
	fprintf(stderr, "kill SIGTERM (ignored)\n");
	sprintf(line, "%d %d %d\n", 0, pid, SIGTERM);
	write(fd, line, strlen(line));
}

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

	rc = read(fd, buf, FILESIZE);
}

int
main(int argc, char **argv)
{
	int st;
	int rc;

	fd = atoi(argv[1]);
	pid = fork();
	if (pid == 0) {
		signal(SIGTERM, SIG_IGN);
		child();
		exit(99);
	}
	signal(SIGALRM, sig);
	alarm(2);
	while ((rc = waitpid(pid, &st, 0)) == -1 && errno == EINTR);
	if (rc != pid) {
		fprintf(stderr, "CT2008 NG BAD wait rc=%d errno=%d\n", rc, errno);
		exit(1);
	}
	if (WIFSIGNALED(st)) {
		fprintf(stderr, "CT2008 NG BAD signal st=%08x\n", st);
		exit(1);
	}
	if (!WIFEXITED(st)) {
		fprintf(stderr, "CT2008 NG BAD terminated st=%08x\n", st);
		exit(1);
	}
	if (WEXITSTATUS(st) != 99) {
		fprintf(stderr, "CT2008 NG BAD exit status st=%08x\n", st);
		exit(1);
	}
	fprintf(stderr, "CT2008 OK\n");
	exit(0);
}
