#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
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
		fprintf(stderr, "CT02 read: BAD EOF\n");
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
	struct iovec rvec[1];
	struct iovec lvec[1];
	int rc;

	if (syscall(732) != -1) {
		fprintf(stderr, "run under Linux!\n");
		exit(1);
	}

	if (stat("CT02m", &sb) == -1) {
		fprintf(stderr, "no CT02m found\n");
		exit(1);
	}
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1) {
		perror("socketpair");
		exit(1);
	}

	if ((mcexec = fork()) == 0) {
		char param[10];
		char *args[4];

		close(fds[1]);
		args[0] = "mcexec";
		args[1] = "./CT02m";
		sprintf(param, "%d", fds[0]);
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
	close(fds[0]);

	rvec[0].iov_len = 8;
	lvec[0].iov_base = line;
	lvec[0].iov_len = 8;

	readline(fds[1], line);
	sscanf(line, "%p", &m);

	strcpy(line, "ABCDEFG");
	rvec[0].iov_base = m;
	rc = process_vm_readv(mcexec, lvec, 1, rvec, 1, 0);
	if (rc != -1 || errno != EFAULT) {
		fprintf(stderr, "CT02001 NG process_vm_readv rc=%d errno=%d\n", rc, errno);
	}
	else {
		fprintf(stderr, "CT02001 OK process_vm_readv failed\n");
	}
	if (strcmp(line, "ABCDEFG")) {
		fprintf(stderr, "CT02002 NG broken data: %s\n", line);
	}
	else {
		fprintf(stderr, "CT02002 OK no data updated\n");
	}
	fflush(stderr);

	write(fds[1], "\n", 1);

	readline(fds[1], line);
	sscanf(line, "%p", &m);

	strcpy(line, "ABCDEFG");
	rvec[0].iov_base = m;
	rc = process_vm_readv(mcexec, lvec, 1, rvec, 1, 0);
	if (rc == -1) {
		fprintf(stderr, "CT02003 NG process_vm_readv rc=%d errno=%d\n", rc, errno);
	}
	else {
		fprintf(stderr, "CT02003 OK process_vm_readv was success\n");
	}
	if (strcmp(line, "1234567")) {
		fprintf(stderr, "CT02004 NG broken data: %s\n", line);
	}
	else {
		fprintf(stderr, "CT02004 OK data updated\n");
	}
	fflush(stderr);

	write(fds[1], "\n", 1);

	readline(fds[1], line);
	sscanf(line, "%p", &m);

	strcpy(line, "ABCDEFG");
	rvec[0].iov_base = m;
	rc = process_vm_readv(mcexec, lvec, 1, rvec, 1, 0);
	if (rc != -1 || errno != EFAULT) {
		fprintf(stderr, "CT02005 NG process_vm_readv rc=%d errno=%d\n", rc, errno);
	}
	else {
		fprintf(stderr, "CT02005 OK process_vm_readv failed after munmap\n");
	}
	fflush(stderr);

	write(fds[1], "\n", 1);

	readline(fds[1], line);
	sscanf(line, "%p", &m);

	strcpy(line, "ABCDEFG");
	rvec[0].iov_base = m;
	rc = process_vm_writev(mcexec, lvec, 1, rvec, 1, 0);
	if (rc != -1 || errno != EFAULT) {
		fprintf(stderr, "CT02006 NG process_vm_writev rc=%d errno=%d\n", rc, errno);
	}
	else {
		fprintf(stderr, "CT02006 OK process_vm_writev failed\n");
	}
	fflush(stderr);

	write(fds[1], "\n", 1);

	readline(fds[1], line);
	sscanf(line, "%p", &m);

	strcpy(line, "ABCDEFG");
	rvec[0].iov_base = m;
	rc = process_vm_writev(mcexec, lvec, 1, rvec, 1, 0);
	if (rc == -1) {
		fprintf(stderr, "CT02008 NG process_vm_writev rc=%d errno=%d\n", rc, errno);
	}
	else {
		fprintf(stderr, "CT02008 OK process_vm_writev was success\n");
	}
	fflush(stderr);

	write(fds[1], "\n", 1);

	readline(fds[1], line);
	sscanf(line, "%p", &m);

	strcpy(line, "ABCDEFG");
	rvec[0].iov_base = m;
	rc = process_vm_writev(mcexec, lvec, 1, rvec, 1, 0);
	if (rc != -1 || errno != EFAULT) {
		fprintf(stderr, "CT02010 NG process_vm_writev rc=%d errno=%d\n", rc, errno);
	}
	else {
		fprintf(stderr, "CT02010 OK process_vm_writev failed after munmap\n");
	}
	fflush(stderr);

	exit(0);
}
