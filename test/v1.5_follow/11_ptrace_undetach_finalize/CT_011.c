#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "./test_chk.h"

#define TEST_NAME "CT_011"

int main(int argc, char** argv)
{
	pid_t tracer_pid = 0, tracee_pid =0;
	sem_t *pwait = NULL;
	sem_t *tracer_wait = NULL;
	sem_t *tracee_wait = NULL;
	void *mem, *attach;
	int rc = 0;
	int status;

	printf("*** %s start *******************************\n", TEST_NAME);

	pwait = (sem_t *)mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	tracer_wait = (sem_t *)mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	tracee_wait = (sem_t *)mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	CHKANDJUMP(!pwait || !tracer_wait || !tracee_wait, "mmap for sem");

	rc |= sem_init(pwait, 1, 0);
	rc |= sem_init(tracer_wait, 1, 0);
	rc |= sem_init(tracee_wait, 1, 0);

	CHKANDJUMP(rc, "sem_init");

	tracee_pid = fork();
	CHKANDJUMP(tracee_pid == -1, "fork tracee");

	if (tracee_pid == 0) { /* tracee */
		/* wake tracer*/
		sem_post(tracer_wait);

		/* wait */
		sem_wait(tracee_wait);

		_exit(123);
	} else { /* parent */
		tracer_pid = fork();
		CHKANDJUMP(tracer_pid == -1, "fork tracer");
		if (tracer_pid == 0) { /* tracer */
			/* wait */
			sem_wait(tracer_wait);

			/* attach tracee */
			rc = ptrace(PTRACE_ATTACH, tracee_pid, NULL, NULL);
			OKNG(rc != 0, "ptrace_attach");

			/* wake tracee */
			sem_post(tracee_wait);

			/* wait tracee stop */
			rc = waitpid(tracee_pid, &status, 0);
			CHKANDJUMP(rc == -1, "waitpid");

			CHKANDJUMP(!WIFSTOPPED(status), "tracee is not stopped");

			/* continue child */
			rc = ptrace(PTRACE_CONT, tracee_pid, NULL, NULL);
			OKNG(rc != 0, "ptrace_cont");

			/* wait tracee's exit */
			rc = waitpid(tracee_pid, &status, 0);
			CHKANDJUMP(rc == -1, "waitpid");

			OKNG(!WIFEXITED(status), "waitpid for tracee by tracer without detach");

			_exit(234);
		} else { /* parent */
			rc = waitpid(tracee_pid, &status, 0);
			CHKANDJUMP(rc == -1, "waitpid");

			OKNG(!WIFEXITED(status), "waitpid for tracee by parent");

			rc = waitpid(tracer_pid, &status, 0);
			CHKANDJUMP(rc == -1, "waitpid");

			CHKANDJUMP(!WIFEXITED(status), "child(tracer) is not exited");
		}
	}

	printf("*** %s PASSED\n\n", TEST_NAME);
	return 0;

fn_fail:
	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;
}
