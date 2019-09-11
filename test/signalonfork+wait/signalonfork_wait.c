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
#include <signal.h>
#include <errno.h>

#define MAXNUMTHREADS	256
#define DEFAULTTIMETOWAIT 500

int argc;
char **argv;
int numthreads = 1;
int nosignal;
int timetowait = DEFAULTTIMETOWAIT;

struct timeval timeBeforeFork;
struct timeval timeBeforeTest;
struct timeval timeAfterTest;


#define LAPTIME_MS(start, stop) \
	((stop.tv_sec - start.tv_sec) * 1000 + \
	 (stop.tv_usec - start.tv_usec) / 1000)

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


void *subjectThread(void *);

static void waitChildren(void)
{
	for (;;) {
		int status = 0;
		pid_t pid = wait(&status);

		if (pid == -1) {
			const char msg[] = "wait fail\n";

			if (errno == ECHILD) {
				return;
			} else if (errno == EINTR) {
				continue;
			}
			write(STDERR_FILENO, msg, sizeof(msg));
			_exit(-1);
		}
	}
}

static void signal_handler(int signum, siginfo_t *info, void *uctx)
{
	waitChildren();
	if (signum == SIGTERM) {
		raise(SIGTERM);
		return;
	}
	_exit(-1);
}

void createThreads(void)
{
	int i;

	if (pthread_barrier_init(&barrier, NULL, numthreads)) {
		onError("pthread_barrier_init fail");
	}

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


void joinThreads(void)
{
	int i;

	for (i = 1; i < numthreads; i++) {
		void *rval;

		if (pthread_join(thread[i].pthread, &rval)) {
			onError("pthread_join fail");
		}
	}

	printf("Join done\n");
}


void subjectTask(struct Thread *thread)
{
	pthread_barrier_wait(&barrier);

	gettimeofday(&timeBeforeTest, NULL);
	printf("[%d] setup: %ld ms\n",
		thread->tid,
		LAPTIME_MS(timeBeforeFork,
		timeBeforeTest));

	printf("[%d] START TEST\n", thread->tid);

	for (;;) {
		int pid;

		pid = fork();
		if (pid < 0) {
			onError("fork");
		} else if (pid == 0) {
			exit(0);
		}
	}

	printf("%d TEST FAIL OVERRUN\n", thread->tid);

	gettimeofday(&timeAfterTest, NULL);

	for (;;)
		;
//	exit(0);
}


void subjectProcess(void)
{
	printf("[%d] I am a subject.\n", getpid());

//	Subjecttask();
}


void subjectCleanup(void *arg)
{
	struct Thread *thread = (struct Thread *) arg;

	printf("[%d] cleanup\n", thread->tid);
}


void *subjectThread(void *arg)
{
	struct Thread *thread = (struct Thread *)arg;
	struct sigaction act = {
		.sa_sigaction = signal_handler,
		.sa_flags = SA_SIGINFO | SA_RESETHAND,
	};

	if (sigaction(SIGTERM, &act, NULL) == -1) {
		onError("sigaction fail");
	}

	printf("[%d] I am a %s %d, %lx %lx\n",
		getpid(), __func__, thread->tid,
		thread->pthread, pthread_self());

	pthread_cleanup_push(subjectCleanup, arg);

	//sleep(random() % 5 + 1);
	//printf("[%d:%d] wake up\n", getpid(), thread->tid);

	pthread_barrier_wait(&barrier);

	subjectTask(thread);

	pthread_cleanup_pop(1);

	return NULL;
}


void examinerProcess(pid_t subject)
{
	struct timespec req, rem;
	int status;

	printf("[%d] I am the examiner for %d.\n", getpid(), subject);

	req.tv_sec = timetowait / 1000;
	req.tv_nsec = (timetowait % 1000) * 1000000;

	if (nanosleep(&req, &rem) < 0) {
		fprintf(stderr, "nanosleep is interrupted, but ignore\n");
	}

	if (kill(subject, SIGTERM) < 0) {
		printf("TEST FAIL (EXIT ALREADY)\n");
		exit(-1);
	}

	if (waitpid(subject, &status, 0) < 0) {
		onError("waitpid fail");
	}

	if (WIFEXITED(status)) {
		printf("The TEST process unexpectedly "
			"exited with return value %d\n",
			WEXITSTATUS(status));
		printf("TEST FAILED\n");
		if (WEXITSTATUS(status) == 0) {
			exit(-1);
		} else {
			exit(WEXITSTATUS(status));
		}
		return;
	}

	if (WIFSIGNALED(status)) {
		printf("The TEST process is terminated by the signal %d\n",
			WTERMSIG(status));
		if (WTERMSIG(status) == SIGTERM) {
			printf("TEST SUCCEEDED\n");
		} else {
			printf("TEST FAILED\n");
			exit(WTERMSIG(status));
		}
	}

//	printf("TEST SUCCEEDED IF YOU DID NOT SEE 'OVERRUN'\n");
//	printf("TEST FINISHED\n");
}


int main(int _argc, char **_argv)
{
	pid_t pid;
	int i;

	argc = _argc;
	argv = _argv;

	printf("DANGERTEST SIGNALONFORK\n");

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
		if (strcmp("-nosignal", argv[i]) == 0) {
			nosignal = 1;
			continue;
		}
		if (strcmp("-t", argv[i]) == 0) {
			i++;
			if (i < argc) {
				timetowait = atoi(argv[i]);
				continue;
			}
		}
		fprintf(stderr, "%s: argument error\n"
			"Usage:\n"
			"\t-nt <num threads>\n"
			"\t-nosignal\n"
			"\t-t <time to wait (msec)>\n",
			argv[0]);
		exit(-1);
	}

	if (numthreads < 1 || numthreads > MAXNUMTHREADS) {
		fprintf(stderr, "%s: invalid num threads\n", argv[0]);
		exit(-1);
	}

	printf("NUMTHREADS: %d\n", numthreads);
	printf("NOSIGNAL: %d\n", nosignal);
	printf("TIMETOWAIT: %d msec\n", timetowait);

	//	setup();

	gettimeofday(&timeBeforeFork, NULL);

	if (nosignal) {
		createThreads();
		joinThreads();
	} else {
		pid = fork();
		if (pid < 0) {
			onError("fork");
		} else if (pid == 0) {
			createThreads();
			joinThreads();
		} else {
			examinerProcess(pid);
		}
	}

	return 0;
}
