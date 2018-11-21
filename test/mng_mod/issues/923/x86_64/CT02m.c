#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
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
		fprintf(stderr, "CT02m read: BAD EOF\n");
		exit(1);
	}
	*buf = '\0';
	return rc;
}

int
main(int argc, char **argv)
{
	int fd;
	char buf[80];
	char *m;
	int f;

	if (syscall(732) == -1) {
		fprintf(stderr, "run under Mckernel!\n");
		exit(1);
	}

	if (argv[1] == NULL) {
		fprintf(stderr, "No parameter\n");
		exit(1);
	}

	fd = atoi(argv[1]);

	m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (m == (void *)-1) {
		perror("mmap");
		exit(1);
	}

// CT02001
	sprintf(buf, "%p 1\n", m);
	strcpy(m, "1234567");
	write(fd, buf, strlen(buf));

	readline(fd, buf);
// CT02003
	f = open("/dev/zero", O_RDONLY);
	read(f, m, 4096);
	close(f);
	sprintf(buf, "%p 2\n", m);
	strcpy(m, "1234567");
	write(fd, buf, strlen(buf));

	readline(fd, buf);

// CT02005
	munmap(m, 4096);
	sprintf(buf, "%p 3\n", m);
	write(fd, buf, strlen(buf));

	readline(fd, buf);

	m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (m == (void *)-1) {
		perror("mmap");
		exit(1);
	}

// CT02006
	sprintf(buf, "%p\n", m);
	strcpy(m, "1234567");
	write(fd, buf, strlen(buf));

	readline(fd, buf);
	if (strcmp(m, "1234567")) {
		fprintf(stderr, "CT02007 NG broken data: %s\n", m);
	}
	else {
		fprintf(stderr, "CT02007 OK no data updated\n");
	}
	fflush(stderr);
// CT02008
	f = open("/dev/zero", O_RDONLY);
	read(f, m, 4096);
	close(f);
	sprintf(buf, "%p\n", m);
	strcpy(m, "1234567");
	write(fd, buf, strlen(buf));

	readline(fd, buf);
	if (strcmp(m, "ABCDEFG")) {
		fprintf(stderr, "CT02009 NG broken data: %s\n", m);
	}
	else {
		fprintf(stderr, "CT02009 OK data updated\n");
	}
	fflush(stderr);
// CT02010
munmap(m, 4096); sprintf(buf, "%p 6\n", m); write(fd, buf, strlen(buf)); 
	close(fd);

	exit(0);
}
