/* 1400_arm64.c COPYRIGHT FUJITSU LIMITED 2020 */
#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>

#define POINT_ORDER_NUM	2
#define SLEEP_SEC 2

#ifdef __x86_64__
#define PAUSE_INST "pause"
#elif defined(__aarch64__)
#define PAUSE_INST "yield"
#else
#error "unexpected archtecture."
#endif

#define cpu_pause()				\
	({							\
		__asm__ __volatile__(PAUSE_INST ::: "memory");	\
	})

static int *sync1 = MAP_FAILED;
static int *parent_core = MAP_FAILED;
static int *point_order = MAP_FAILED;
static int *od = MAP_FAILED;

int main(int argc, char *argv[])
{
	pid_t pid = -1;
	pid_t ret_pid = -1;
	int status = 0;
	int i = 0, rc;
	int *resp;
	int result = -1;
	int ret = -1;
	int failed = 0;

	/* get shared memory */
	sync1 = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	parent_core = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	point_order = (int *)mmap(NULL, sizeof(int) * POINT_ORDER_NUM,
				PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	od = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	/* mmap check */
	if (sync1 == MAP_FAILED ||
	    parent_core == MAP_FAILED ||
	    point_order == MAP_FAILED ||
	    od == MAP_FAILED) {
		printf("mmap() Failed.\n");
		goto out;
	}

	for (i = 0; i < POINT_ORDER_NUM; i++) {
		point_order[i] = 0;
	}
	*od = 0;
	*sync1 = 0;

	/* create child process */
	pid = fork();

	switch (pid) {
	case -1:
		/* error */
		printf("fork() Failed.\n");
		goto out;

	case 0: {
		/* child */
		/* before migrate, get cpunum */
		int old_mycore = sched_getcpu();

		printf("[child:%d] running core %d\n", getpid(), old_mycore);

		/* sync parent */
		*sync1 = 1;

#ifdef MIGRATE_ON_OFFLOAD
		int sec = SLEEP_SEC;
		resp = (int *)mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		/* debug syscall */
		rc = syscall(888, sec, resp, 0, 0, 0, 0);
		if (rc != sec || *resp != sec) {
			printf("[child:%d] debug_syscall failed\n", getpid());
			_exit(-1);
		}
#endif

		/* wait until migrated */
		while (sched_getcpu() == old_mycore) {
			cpu_pause();
		}
		point_order[0] = ++(*od);

		_exit(0);
		break;
	}

	default: {
		/* parent */
		cpu_set_t cpuset;

		/* sync child */
		while (*sync1 != 1) {
			cpu_pause();
		}

		/* parent corenum get */
		*parent_core = sched_getcpu();

		/* child process to migrate parent core */
		printf("[parent:%d] running core %d\n", getpid(), *parent_core);
		printf("[parent] child process(pid=%d) "
			"migrate/bind to core %d\n",
			pid, *parent_core);

		CPU_ZERO(&cpuset);
		CPU_SET(*parent_core, &cpuset);

		/* sched_setaffinity interval */
		usleep(10000);

		result = sched_setaffinity(pid, sizeof(cpuset), &cpuset);
		if (result == -1) {
			printf("errno = %d\n", errno);
			printf("child migrate/bind "
				"sched_setaffinity failed.\n");
		}

		/* parent core bind */
		printf("[parent] parent process bind to core %d\n",
			*parent_core);
		result = sched_setaffinity(0, sizeof(cpuset), &cpuset);
		if (result == -1) {
			printf("errno = %d\n", errno);
			printf("parent bind sched_setaffinity failed.\n");
		}

#ifdef MIGRATE_ON_OFFLOAD
		/* wait for child woken up */
		usleep(SLEEP_SEC * 1000000 + 1000);
#endif

		/* sync child, switch to child process */
		printf("[parent] send sched_yield.\n");

		result = 0;

		result = sched_yield();

		point_order[1] = ++(*od);

		break;
	}
	}

	if (result == -1) {
		printf("sched_yield failed.\n");
	}

	/* child process status check. */
	ret_pid = wait(&status);
	if (ret_pid == pid) {
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status)) {
				printf("TP failed, child migrate fail.\n");
			}
			else {
				goto wait_ok;
			}
		}
		else {
			printf("TP failed, child is not exited.\n");
		}

		if (WIFSIGNALED(status)) {
			printf("TP failed, child signaled by %d.\n",
				WTERMSIG(status));

			if (WCOREDUMP(status)) {
				printf("coredumped.\n");
			}
		}
		else {
			printf("TP failed, child is not signaled.\n");
		}


		if (WIFSTOPPED(status)) {
			printf("TP failed, child is stopped by signal %d.\n",
				WSTOPSIG(status));
		}
		else {
			printf("TP failed, child is not stopped.\n");
		}

		if (WIFCONTINUED(status)) {
			printf("TP failed, child is continued.\n");
		}
		else {
			printf("TP failed, child is not continued.\n");
		}

		for (i = 0; i < POINT_ORDER_NUM; i++) {
			printf("point_order[%d] = %d\n", i, point_order[i]);
		}
		goto out;
	}
	else {
		printf("TP failed, child process wait() fail.\n");

		for (i = 0; i < POINT_ORDER_NUM; i++) {
			printf("point_order[%d] = %d\n", i, point_order[i]);
		}
		goto out;
	}

wait_ok:
	for (i = 0; i < POINT_ORDER_NUM; i++) {
		printf("point_order[%d] = %d\n", i, point_order[i]);

		if (point_order[i] == 0) {
			failed = 1;
		}
	}

	if (failed != 0) {
		printf("TP failed, parent or child process is not running.\n");
		goto out;
	}

	if (result != -1) {
		if (point_order[0] < point_order[1]) {
			ret = 0;
		}
		else {
			printf("TP failed, out of order.\n");
		}
	}

out:
	/* unmap semaphore memory */
	if (od != MAP_FAILED) {
		munmap(od, sizeof(int));
	}

	if (point_order != MAP_FAILED) {
		munmap(point_order, sizeof(int) * POINT_ORDER_NUM);
	}

	if (parent_core != MAP_FAILED) {
		munmap(parent_core, sizeof(int));
	}

	if (sync1 != MAP_FAILED) {
		munmap(sync1, sizeof(int));
	}
	return ret;
}
