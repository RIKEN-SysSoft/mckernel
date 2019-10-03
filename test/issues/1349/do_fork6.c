/* do_fork6.c COPYRIGHT FUJITSU LIMITED 2020 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <sys/syscall.h>
#include <string.h>
#include <errno.h>

#define FORK1()					\
	do {					\
		int pid = fork();		\
		if (pid < 0) {			\
			onError("fork");	\
		} else if (pid == 0) {		\
			printf("grandchild\n");	\
			exit(0);		\
		}				\
	} while (0)

#define FORK10()				\
	do {					\
		FORK1();			\
		FORK1();			\
		FORK1();			\
		FORK1();			\
		FORK1();			\
		FORK1();			\
		FORK1();			\
		FORK1();			\
		FORK1();			\
		FORK1();			\
	} while (0)

#define FORK100()				\
	do {					\
		FORK10();			\
		FORK10();			\
		FORK10();			\
		FORK10();			\
		FORK10();			\
		FORK10();			\
		FORK10();			\
		FORK10();			\
		FORK10();			\
		FORK10();			\
	} while (0)

enum fin_mode {
	FIN_MODE_NULL,
	FIN_MODE_EXIT,
	FIN_MODE_WAIT,
};

#define MAXNUMTHREADS	256
#define DEFAULTTIMETOWAIT 500

int argc;
char **argv;
int numthreads = 1;
enum fin_mode fin_mode = FIN_MODE_NULL;
int timetowait = DEFAULTTIMETOWAIT;

struct timeval timeBeforeFork;
struct timeval timeBeforeTest;
struct timeval timeAfterTest;

#define LAPTIME_MS(start, stop) \
	((stop.tv_sec - start.tv_sec) * 1000 \
	 + (stop.tv_usec - start.tv_usec) / 1000)

struct Thread {
	int tid;
	pthread_t pthread;
} thread[MAXNUMTHREADS];

pthread_barrier_t barrier;

void onError(char *message)
{
	fprintf(stderr,  "%s: %s: %m\n", argv[0], message);
	exit(-1);
}

void waitChildren(void)
{
	for (;;) {
		int status = 0;
		pid_t pid = wait(&status);

		if (pid == -1) {
			if (errno == ECHILD) {
				return;
			} else if (errno == EINTR) {
				continue;
			}
			onError("wait");
			exit(-1);
		}
	}
}

void examinerProcess(pid_t subject)
{
	printf("[%d] I am the examiner for %d.\n", getpid(), subject);
	waitChildren();
}

void subjectTask(struct Thread *thread)
{
	pthread_barrier_wait(&barrier);

	gettimeofday(&timeBeforeTest, NULL);
	printf("[%d] setup: %ld ms\n",
	       thread->tid,
	       LAPTIME_MS(timeBeforeFork, timeBeforeTest));
	printf("[%d] START TEST\n", thread->tid);

	FORK100();

	printf("[%d] END FORK\n", thread->tid);

	{
		struct timespec req, rem;

		req.tv_sec = timetowait / 1000;
		req.tv_nsec = (timetowait % 1000) * 1000000;
		if (nanosleep(&req, &rem) < 0) {
			fprintf(stderr,
				"nanosleep is interrupted, but ignore\n");
		}
	}

	printf("[%d] FINISH CHILDREN\n", thread->tid);
	switch (fin_mode) {
	case FIN_MODE_EXIT:
		exit(0);
		break;
	case FIN_MODE_WAIT:
		waitChildren();
		exit(0);
		break;
	default:
		break;
	}

	printf("%d(%d) TEST FAIL OVERRUN\n", thread->tid, fin_mode);
	gettimeofday(&timeAfterTest, NULL);
	for (;;)
		;
}

void subjectCleanup(void *arg)
{
	struct Thread *thread = (struct Thread *)arg;

	printf("[%d] cleanup\n", thread->tid);
}

void *subjectThread(void *arg)
{
	struct Thread *thread = (struct Thread *)arg;

	printf("[%d] I am a %s %d, %lx %lx\n",
	       getpid(),
	       __func__,
	       thread->tid,
	       thread->pthread,
	       pthread_self());

	pthread_cleanup_push(subjectCleanup, arg);

	pthread_barrier_wait(&barrier);

	subjectTask(thread); //< no return

	pthread_cleanup_pop(1);

	return NULL;
}

void createThreads(void)
{
	if (pthread_barrier_init(&barrier, NULL, numthreads)) {
		onError("pthread_barrier_init fail");
	}

	int i;

	for (i = 1; i < numthreads; i++) {
		int rval;

		thread[i].tid = i;
		rval = pthread_create(&thread[i].pthread,
				      NULL,
				      subjectThread,
				      &thread[i]);
		if (rval) {
			onError("pthread_create fail");
		}
	}
	thread[0].tid = 0;
	thread[0].pthread = pthread_self();
	subjectThread(&thread[0]);
}

int main(int _argc, char **_argv)
{
	pid_t pid;

	argc = _argc;
	argv = _argv;

	printf("DO FORK6\n");

	int i;

	for (i = 1; i < argc; i++) {
		if (strcmp("-nt", argv[i]) == 0) {
			i++;
			if (i < argc) {
				numthreads = atoi(argv[i]);
				continue;
			}
			fprintf(stderr, "%s: num threads required\n", argv[0]);
			exit(-1);
		}
		if (strcmp("-mode-exit", argv[i]) == 0) {
			fin_mode = FIN_MODE_EXIT;
			continue;
		}
		if (strcmp("-mode-wait", argv[i]) == 0) {
			fin_mode = FIN_MODE_WAIT;
			continue;
		}
		if (strcmp("-t", argv[i]) == 0) {
			i++;
			if (i < argc) {
				timetowait = atoi(argv[i]);
				continue;
			}
		}
		fprintf(stderr,
			"Usage: %s"
			" -nt <num threads>"
			" -t <time to wait(msec)>"
			" {-mode-exit | -mode-wait}\n",
			argv[0]);
		exit(-1);
	}

	if (numthreads < 1 || numthreads > MAXNUMTHREADS) {
		fprintf(stderr, "%s: invalid num threads\n", argv[0]);
		exit(-1);
	}

	if (fin_mode == FIN_MODE_NULL) {
		fprintf(stderr, "%s: invalid mode\n", argv[0]);
		exit(-1);
	}

	printf("NUMTHREADS: %d\n", numthreads);
	printf("TIMETOWAIT: %d msec\n", timetowait);
	printf("MODE: %s\n",
	       (fin_mode == FIN_MODE_EXIT) ? "exit" :
	       (fin_mode == FIN_MODE_WAIT) ? "wait" :
	       "null");

	pid = fork();
	if (pid < 0) {
		onError("fork");
	} else if (pid == 0) {
		createThreads(); //< no return
		//joinThreads();
	} else {
		examinerProcess(pid);
		printf("FINISH PARENT\n");
	}
	return 0;
}
