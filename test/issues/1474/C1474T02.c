#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>

int
main(int argc, char **argv)
{
	pid_t pid1;
	pid_t pid2;
	cpu_set_t cpu_set0;
	cpu_set_t cpu_set;
	int st;
	int st1;
	int i;
	int pfd[2];

	fprintf(stderr, "*** C1474T02 START ***\n");
	pipe(pfd);
	if (sched_getaffinity(getpid(), sizeof(cpu_set_t), &cpu_set0) == -1) {
		perror("sched_getaffinity");
		goto ng;
	}

	CPU_ZERO(&cpu_set);
	for (i = 0; i < sizeof(cpu_set) * 8; i++) {
		if (CPU_ISSET(i, &cpu_set0)) {
			break;
		}
	}
	for (i++; i < sizeof(cpu_set) * 8; i++) {
		if (CPU_ISSET(i, &cpu_set0)) {
			CPU_SET(i, &cpu_set);
			break;
		}
	}

	if ((pid1 = fork()) == 0) {
		close(pfd[1]);
		if (sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpu_set)) {
			perror("sched_setaffinity");
			exit(1);
		}
		read(pfd[0], &i, 1);
		exit(1);
	}
	if ((pid2 = fork()) == 0) {
		int f;
		char *p;
		int r;

		close(pfd[0]);
		close(pfd[1]);
		if (sched_setaffinity(getpid(), sizeof(cpu_set_t), &cpu_set)) {
			perror("sched_setaffinity");
			exit(1);
		}
		if ((f = open("testfile", O_RDONLY)) == -1) {
			perror("open(testfile)");
			exit(1);
		}
		p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, f, 0);
		if (p == (void *)-1) {
			perror("mmap");
			exit(1);
		}
		close(f);
		f = open("outfile", O_WRONLY|O_CREAT|O_TRUNC, 0600);
		if (f == -1) {
			perror("open(outfile)");
			exit(1);
		}
		if ((r = write(f, p, 1024)) == -1) {
			perror("write");
			exit(1);
		}
		fprintf(stderr, "remote page fault OK\n");
		close(f);
		if (r != 1024) {
			fprintf(stderr, "BAD out size: %d\n", r);
			exit(1);
		}
		exit(0);
	}
	close(pfd[0]);
	if (waitpid(pid2, &st, 0) == -1) {
		perror("waitpid");
		goto ng;
	}
	write(pfd[1], &st, 1);
	if (waitpid(pid1, &st1, 0) == -1) {
		perror("waitpid");
		goto ng;
	}
	if (WEXITSTATUS(st) == 0) {
		fprintf(stderr, "*** C1474T02 OK ***\n");
		exit(0);
	}
ng:
	fprintf(stderr, "*** C1474T02 NG ***\n");
	exit(1);
}
