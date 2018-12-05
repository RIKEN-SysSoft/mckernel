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

#define TEST_NAME "CT_008"

int main(int argc, char** argv)
{
	pid_t pid = 0;
	sem_t *pwait = NULL;
	sem_t *cwait = NULL;
	void *mem, *attach;
	int rc = 0;
	int status;

	printf("*** %s start *******************************\n", TEST_NAME);

	pwait = (sem_t *)mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	cwait = (sem_t *)mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	CHKANDJUMP(!pwait || !cwait, "mmap for sem");

	rc |= sem_init(pwait, 1, 0);
	rc |= sem_init(cwait, 1, 0);

	CHKANDJUMP(rc, "sem_init");

	pid = fork();
	CHKANDJUMP(pid == -1, "fork");

	if (pid == 0) { /* child */
		/* wake parent */
		sem_post(pwait);

		/* wait */
		sem_wait(cwait);

		_exit(123);
	} else { /* parent */
		/* wait */
		sem_wait(pwait);

		/* invalid detach */
		rc = ptrace(PTRACE_DETACH, 0, NULL, NULL);
		OKNG(rc == 0, "ptrace_detach 0 failed [invalid pid]");

		/* invalid detach */
		rc = ptrace(PTRACE_DETACH, 1, NULL, NULL);
		OKNG(rc == 0, "ptrace_detach 1 failed [invalid pid]");

		/* invalid detach */
		rc = ptrace(PTRACE_DETACH, pid, NULL, NULL);
		OKNG(rc == 0, "ptrace_detach child failed [not attached]");

		/* invalid detach */
		rc = ptrace(PTRACE_DETACH, pid, NULL, NULL);
		OKNG(rc == 0, "ptrace_detach self failed [invalid pid]");

		/* wake child */
		sem_post(cwait);

		/* wait child's exit */
		rc = waitpid(pid, &status, 0);
		CHKANDJUMP(rc == -1, "waitpid");

		CHKANDJUMP(!WIFEXITED(status), "child is not exited");

	}

	printf("*** %s PASSED\n\n", TEST_NAME);
	return 0;

fn_fail:
	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;
}
