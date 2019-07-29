#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <errno.h>

int cmd;
int procs;
int rc;

void *
rwtest(void *arg)
{
	int r = syscall(750, cmd, procs);

	if (r)
		rc = 1;

	return NULL;
}

int
main(int argc, char **argv)
{
	pthread_t *threads;
	int i;

	if (!argv[1]) {
		long val = syscall(750, 10);
		int running = syscall(750, 11);
		long lockval = syscall(750, 12);

		fprintf(stderr, "%ld %d %016lx\n", val, running, lockval);
		exit(0);
	}
	cmd = atoi(argv[1]);
	if (cmd < 1 || cmd > 4) {
		fprintf(stderr, "invalid test ID (%s)\n", argv[1]);
		exit(1);
	}
	if (!argv[2]) {
		fprintf(stderr, "no procs present\n");
		exit(1);
	}
	procs = atoi(argv[2]);
	if (procs < 1) {
		fprintf(stderr, "invalid procs (%s)\n", argv[2]);
		exit(1);
	}
	if (syscall(750, 0) == -1) {
		fprintf(stderr, "invalid test environment\n");
		exit(1);
	}
	threads = malloc(sizeof(pthread_t) * procs);
	for (i = 0; i < procs; i++) {
		if (pthread_create(threads + i, NULL, rwtest, NULL)) {
			fprintf(stderr, "pthread_create: %s\n",
				strerror(errno));
			exit(1);
		}
	}
	rc = 0;
	for (i = 0; i < procs; i++) {
		pthread_join(threads[i], NULL);
	}
	if (rc) {
		fprintf(stderr, "rwlock test %d FAIL\n", cmd);
		exit(1);
	}
	fprintf(stderr, "rwlock test %d PASS\n", cmd);
	exit(0);
}
