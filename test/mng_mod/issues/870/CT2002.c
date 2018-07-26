#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>

#define FILESIZE (2L * 1024 * 1024 * 1024)
int sigcalled = 0;

void
sig(int s)
{
	sigcalled = 1;
	fprintf(stderr, "signal hanlder is called\n");
}

int
main(int argc, char **argv)
{
	struct sigaction act;
	char *buf;
	long rc;
	long l;
	long r;
	int fd;
	int ofd;
	char line[80];

	fd = atoi(argv[1]);
	buf = malloc(FILESIZE);
	ofd = open("testfile", O_RDONLY);
	if (ofd == -1) {
		fprintf(stderr, "Could not open file\n");
		unlink("testfile");
		exit(1);
	}

	memset(&act, '\0', sizeof act);
	act.sa_handler = sig;
	sigaction(SIGALRM, &act, NULL);
	sprintf(line, "%d %d %d\n", 1, getpid(), SIGALRM);
	write(fd, line, strlen(line));
	rc = read(ofd, buf, FILESIZE);
	if (rc == -1) {
		fprintf(stderr, "CT2002 NG BAD read rc=%ld errno=%d\n", rc, errno);
		exit(1);
	}
	if (sigcalled == 0) {
		fprintf(stderr, "CT2002 NG signal handler was not called\n");
		exit(1);
	}
	fprintf(stderr, "CT2002 OK\n");
	exit(0);
}
