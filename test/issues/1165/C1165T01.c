#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>

int
main(int argc, char **argv)
{
	pid_t pid;
	char buf[1024];
	int fd;
	int rc;
	int st;
	int i;

	fd = open("/dev/zero", O_RDONLY);
	if (fd < 0) {
		perror("open");
		goto err;
	}
	if ((rc = read(fd, buf, 1024)) != 1024) {
		if (rc < 0) {
			perror("read");
		}
		else if (rc == 0) {
			fprintf(stderr, "EOF\n");
		}
		else {
			fprintf(stderr, "read too short %d\n", rc);
		}
		goto err;
	}
	close(fd);

	for (i = 0; i < 1024; i++)
		buf[i] = 0x55;

	pid = fork();
	if (!pid) {
		for (i = 0; i < 1024; i++)
			if (buf[i] != 0x55) {
				exit(2);
			}
		fd = open("/dev/zero", O_RDONLY);
		if (fd < 0) {
			perror("open");
			exit(1);
		}
		if ((rc = read(fd, buf, 1024)) != 1024) {
			exit(1);
		}
		close(fd);
		for (i = 0; i < 1024; i++)
			if (buf[i] != 0) {
				exit(3);
			}
		exit(0);
	}

	while (waitpid(pid, &st, 0) == -1 && errno == EINTR);

	if (!WIFEXITED(st)) {
		fprintf(stderr, "child failed %08x\n", st);
		goto err;
	}
	else if (WEXITSTATUS(st) != 0) {
		if (WEXITSTATUS(st) == 1) {
			fprintf(stderr, "child I/O error\n");
		}
		else if (WEXITSTATUS(st) == 2) {
			fprintf(stderr, "child memory error\n");
		}
		else if (WEXITSTATUS(st) == 3) {
			fprintf(stderr, "child read error\n");
		}
		else {
			fprintf(stderr, "child error %08x\n", st);
		}
		goto err;
	}

	for (i = 0; i < 1024; i++)
		if (buf[i] != 0x55) {
			fprintf(stderr, "BAD value 0x%02x != 0x55\n", buf[i]);
			goto err;
		}

	fprintf(stderr, "*** C1165T01 OK\n");
	exit(0);
err:
	fprintf(stderr, "*** C1165T01 NG\n");
	exit(1);
}
