#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sched.h>

#define DEF_LOOPS 10

int main(int argc, char** argv) {
	pid_t pid[256];
	cpu_set_t cpu_set;
	int result, i, j;
	int loops = DEF_LOOPS;

	if (argc > 1) {
		loops = atoi(argv[1]);
	}
		
	CPU_ZERO(&cpu_set);
	CPU_SET(1, &cpu_set);

	result = sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set);

	if (result != 0) {
		perror("Error sched_setaffinity()");
		return(1);
	}

	for (i = 0; i < loops && (pid[i] = fork()) > 0; i++);

	if (i == loops) { // parent
		for (i = 0; i < loops; i++) {
			printf("sched_test parent pid=%d\n", getpid());
			waitpid(pid[i], NULL, 0);
		}
	}
	else if (pid[i] == 0) {
		printf("sched_test child pid=%d\n", getpid());
		cpu_set_t child_set;

		CPU_ZERO(&child_set);
		CPU_SET(2, &child_set);
		result = sched_setaffinity(0, sizeof(cpu_set_t), &child_set);
		if (result != 0) {
			perror("Error sched_setaffinity() on child");
		}

		result = sched_yield();
		if (result != 0) {
			perror("Error sched_yield()");
		}

		CPU_ZERO(&child_set);
		CPU_SET(1, &child_set);
		result = sched_setaffinity(0, sizeof(cpu_set_t), &child_set);
		if (result != 0) {
			perror("Error sched_setaffinity() on child");
		}

		result = sched_yield();
		if (result != 0) {
			perror("Error sched_yield()");
		}
	
		printf("child[%d] is done.\n", i);
		return(0);
	}
	else {
		perror("Error fork()");
		return(1);
	}
	printf("parent is done.\n");

	return(0);
}
