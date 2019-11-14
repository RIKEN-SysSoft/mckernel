#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#ifndef PAUSE_INST
#define PAUSE_INST "pause"
#endif
#define cpu_pause()						\
	({							\
		__asm__ __volatile__(PAUSE_INST ::: "memory");	\
	})

static sem_t *sync_sem1;
static sem_t *sync_sem2;
static int *parent_core;
static int *sync_flag;
#define CHILD_DONE 1
#define PARENT_DONE 2

static int *child_count;

static void child_func(void)
{
	pid_t pid = getpid();

	printf("[child] pid = %d\n", pid);

	for (;;) {
		*sync_flag = CHILD_DONE;
		while (*sync_flag != PARENT_DONE) {
			cpu_pause();
		}
		(*child_count)++;
		cpu_pause();
	}
}

static void parent_func(void)
{
	pid_t pid;
	int i = 0;

	pid = getpid();
	printf("[parent] pid = %d\n", pid);

	for (;;) {
		*sync_flag = PARENT_DONE;
		while (*sync_flag != CHILD_DONE) {
			cpu_pause();
		}

		printf("[parent] loop ok. (%d)\n", i);
		if (*child_count != -1) {
			printf("[child] loop ok. (%d)\n", *child_count);
		}
		else {
			return;
		}
		i++;
		cpu_pause();
	}
}

int main(int argc, char *argv[])
{
	pid_t pid = 0;

	/* get shared memory */
	sync_sem1 = (sem_t *)mmap(NULL, sizeof(sem_t),
		PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	sync_sem2 = (sem_t *)mmap(NULL, sizeof(sem_t),
		PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	parent_core = (int *)mmap(NULL, sizeof(int),
		PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	sync_flag = (int *)mmap(NULL, sizeof(int),
		PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	child_count = (int *)mmap(NULL, sizeof(int),
		PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	*parent_core = 0;
	*sync_flag = 0;
	*child_count = 0;

	/* semaphore init */
	sem_init(sync_sem1, 1, 0);
	sem_init(sync_sem2, 1, 0);

	/* create child process */
	pid = fork();

	switch (pid) {
	case -1:
		/* fork() error. */
		perror("fork()");
		return -1;
	case 0: {
		/* child process */
		/* before migrate, get cpunum */
		int old_mycore = sched_getcpu();
		int new_mycore = -1;

		printf("[child] running core %d\n", old_mycore);

		/* sync parent */
		sem_post(sync_sem1);

		/* sync parent */
		sem_wait(sync_sem2);

		/* after migrate, get cpunum */
		new_mycore = sched_getcpu();

		/* corenum check. */
		if (*parent_core != old_mycore) {
			printf("[child] before migrate prevcore "
				"%d, nowcore %d\n", old_mycore, new_mycore);

			if (old_mycore == new_mycore) {
				printf("TP failed, "
					"not migrate child process.\n");
				exit(-1);
			}
		} else {
			printf("[child] migrate not required.\n");
		}

		/* loop */
		child_func();

		/* unmap */
		munmap(sync_sem1, sizeof(sem_t));
		munmap(sync_sem2, sizeof(sem_t));
		munmap(parent_core, sizeof(int));
		munmap(sync_flag, sizeof(int));
		munmap(child_count, sizeof(int));

		/* child exit */
		exit(-1);
		break;
	}

	default: {
		/* parent process */
		cpu_set_t cpuset;
		int result = -1;

		/* sync child */
		sem_wait(sync_sem1);

		/* parent corenum get */
		*parent_core = sched_getcpu();

		/* child process to migrate parent core */
		printf("[parent] running core %d\n", *parent_core);
		printf("[parent] child process migrate/bind "
			"to core %d\n", *parent_core);

		CPU_ZERO(&cpuset);
		CPU_SET(*parent_core, &cpuset);

		result = sched_setaffinity(pid, sizeof(cpuset), &cpuset);
		if (result == -1) {
			printf("errno = %d\n", errno);
			break;
		}

		/* parent core bind */
		printf("[parent] parent process bind "
			"to core %d\n", *parent_core);
		result = sched_setaffinity(0, sizeof(cpuset), &cpuset);
		if (result == -1) {
			printf("errno = %d\n", errno);
			break;
		}

		/* sync child */
		sem_post(sync_sem2);

		/* loop */
		parent_func();

		/* unmap */
		munmap(sync_sem1, sizeof(sem_t));
		munmap(sync_sem2, sizeof(sem_t));
		munmap(parent_core, sizeof(int));
		munmap(sync_flag, sizeof(int));
		munmap(child_count, sizeof(int));
		break;
	}
	}

	/* never return */
	printf("RESULT: NG.\n");
	return 0;
}
