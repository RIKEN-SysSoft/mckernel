#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

int
main(int argc, char **argv)
{
	int fd;
	void *p;
	long l;
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		sleep(1);
		kill(getppid(), SIGKILL);
		exit(0);
	}

	fd = open("rpf.data", O_RDONLY);
	if (fd == -1) {
		perror("open(rpf.data)");
		exit(1);
	}
	p = mmap(NULL, 512*1024*1024, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == (void *)-1) {
		perror("mmap");
		exit(1);
	}
	close(fd);
	fd = open("rpf.out", O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if (fd == -1) {
		perror("open(fpt.out)");
		exit(1);
	}
	l = write(fd, p, 512*1024*1024);
	printf("write=%ld\n", l);
	close(fd);
	munmap(p, 512*1024*1024);
	exit(0);
}
