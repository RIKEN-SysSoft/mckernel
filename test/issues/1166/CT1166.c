#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

int
main(int argc, char **argv)
{
	int fd;
	int *p2;
	pid_t pid;
	int st;
	int ok = 0;
	int ng = 0;

	printf("CT1166 START\n");

	fd = open("/dev/fb0", O_RDWR, 0);
	if (fd == -1) {
		printf("CT1166T01 could not open /dev/fb0: %s\n",
		       strerror(errno));
		exit(1);
	}
	printf("CT1166T01: OK open(/dev/fb0)\n");

	p2 = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (p2 == (void *)-1) {
		printf("CT1166T02: NG could not mmap: %s\n", strerror(errno));
		ng++;
		exit(1);
	}
	printf("CT1166T02: OK mmap(MAP_PRIVATE)\n");
	ok++;
	close(fd);

	p2[0] = 50;
	printf("CT1166T03: OK store to parent fb0\n");
	ok++;
	if (p2[0] == 50) {
		printf("CT1166T04: OK load from parent fb0\n");
		ok++;
	}
	else {
		printf("CT1166T04: NG load from parent fb0\n");
		ng++;
	}

	fflush(stdout);
	pid = fork();
	if (pid == -1) {
		printf("CT1166T05: NG could not fork: %s\n", strerror(errno));
		ng++;
		exit(1);
	}

	if (pid == 0) {
		printf("CT1166T05: OK fork\n");
		ok++;

		p2[0] = 10;
		printf("CT1166T06: OK store to child fb0\n");
		ok++;
		if (p2[0] == 10) {
			printf("CT1166T07: OK load from child fb0\n");
			ok++;
		}
		else {
			printf("CT1166T07: NG load from child fb0\n");
			ng++;
		}
		exit(0);
	}

	while (waitpid(pid, &st, 0) == -1 && errno == EINTR)
		;

	if (p2[0] == 50) {
		printf("CT1166T08: OK parent fb0 isn't modified\n");
		ok++;
	}
	else {
		printf("CT1166T08: NG private fb0 is modified (%d)\n", p2[0]);
		ng++;
	}
	exit(0);
}
