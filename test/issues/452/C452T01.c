#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

int
main(int argc, char **argv)
{
	pid_t pid;
	int st;

	fprintf(stderr, "*** C452T01 test start\n");
	fflush(stderr);
	pid = fork();
	if (pid == 0) {
		char file[32];

		sleep(1);
		sprintf(file, "/proc/%d/maps", getppid());
		execlp("cat", "cat", file, NULL);
		exit(1);
	}
	fflush(stdout);
	if (syscall(740, 1) == -1) {
		fprintf(stderr, "*** C452T01 FAIL no patched kernel\n");
		exit(1);
	}
	mmap(NULL, 4096, PROT_READ|PROT_WRITE,
	     MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	syscall(740, 0);
	while (waitpid(pid, &st, 0) == -1 && errno == EINTR)
		;
	fprintf(stderr, "*** C452T01 PASS\n");
	exit(0);
}
