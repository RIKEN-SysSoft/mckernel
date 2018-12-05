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

char *
gettime(char *buf, struct timeval *tv)
{
	struct tm *tm;

	gettimeofday(tv, NULL);
	tm = localtime(&tv->tv_sec);
	sprintf(buf, "%02d:%02d:%02d.%06d", tm->tm_hour, tm->tm_min, tm->tm_sec, tv->tv_usec);
	return buf;
}

void
tv_sub(struct timeval *tv1, const struct timeval *tv2)
{
	tv1->tv_sec -= tv2->tv_sec;
	tv1->tv_usec -= tv2->tv_usec;
	if (tv1->tv_usec < 0) {
		tv1->tv_sec--;
		tv1->tv_usec += 1000000;
	}
}

struct timeval tv1;
struct timeval tv2;
int fd;

void
child()
{
	char *buf;
	long rc;
	long l;
	long r;
	int ofd;
	char line[80];

	buf = malloc(FILESIZE);
	ofd = open("testfile", O_RDONLY);
	if (ofd == -1) {
		fprintf(stderr, "Could not open file\n");
		unlink("testfile");
		exit(1);
	}

	sprintf(line, "%d %d %d\n", 1, getpid(), SIGALRM);
	write(fd, line, strlen(line));
	rc = read(ofd, buf, FILESIZE);
}

int
main(int argc, char **argv)
{
	pid_t pid;
	int st;
	int rc;
	char buf[16];

	fd = atoi(argv[1]);
	fprintf(stderr, "%s test start, kill after 1 seconds\n", gettime(buf, &tv1));
	pid = fork();
	if (pid == 0) {
		child();
		exit(1);
	}
	while ((rc = waitpid(pid, &st, 0)) == -1 && errno == EINTR);
	fprintf(stderr, "%s child process terminated\n", gettime(buf, &tv2));
	if (rc != pid) {
		fprintf(stderr, "CT2004 NG BAD wait rc=%d errno=%d\n", rc, errno);
		exit(1);
	}
	if (!WIFSIGNALED(st)) {
		fprintf(stderr, "CT2004 NG no signaled st=%08x\n", st);
		exit(1);
	}
	if (WTERMSIG(st) != SIGALRM) {
		fprintf(stderr, "CT2004 NG BAD signal sig=%d\n", WTERMSIG(st));
		exit(1);
	}
	tv_sub(&tv2, &tv1);
	if (tv2.tv_sec != 1)
		fprintf(stderr, "CT2004 OK (%d.%06d)\n", tv2.tv_sec, tv2.tv_usec);
	else
		fprintf(stderr, "CT2004 OK\n");
	exit(0);
}
