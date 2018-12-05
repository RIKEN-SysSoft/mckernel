#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <errno.h>

int
readline(int fd, char *buf)
{
	int r;
	int rc = 0;

	while ((r = read(fd, buf, 1)) == 1) {
		rc++;
		if (*buf == '\n')
			break;
		buf++;
	}
	if (r == -1) {
		perror("read");
		exit(1);
	}
	if (!rc) {
		fprintf(stderr, "CT200x read: BAD EOF\n");
		exit(1);
	}
	*buf = '\0';
	return rc;
}

int
main(int argc, char **argv)
{
	int fds[2];
	pid_t mcexec;
	struct stat sb;
	char line[80];
	char *m;
	int rc;
	int t;
	int p;
	int s;
	int st;

	if (syscall(732) != -1) {
		fprintf(stderr, "run under Linux!\n");
		exit(1);
	}

	if (stat(argv[1], &sb) == -1) {
		fprintf(stderr, "no %s found\n", argv[1]);
		exit(1);
	}
	if (pipe(fds) == -1) {
		perror("pipe");
		exit(1);
	}

	if ((mcexec = fork()) == 0) {
		char param[10];
		char *args[4];

		close(fds[0]);
		args[0] = "mcexec";
		args[1] = argv[1];
		sprintf(param, "%d", fds[1]);
		args[2] = param;
		args[3] = NULL;
		if (stat("mcexec", &sb) == -1) {
			execvp("mcexec", args);
		}
		else {
			execv("./mcexec", args);
		}
		perror("execvp");
		exit(1);
	}
	if (mcexec == -1) {
		perror("fork");
		exit(1);
	}
	close(fds[1]);

	readline(fds[0], line);
	sscanf(line, "%d %d %d", &t, &p, &s);

	sleep(t);
	kill(p, s);

	while(waitpid(mcexec, &st, 0) == -1 && errno == EINTR);

	exit(0);
}
