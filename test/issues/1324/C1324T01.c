#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <signal.h>


#define GB (1024 * 1024 * 1024)
#define MAP_SIZE (1 * GB)

int main(int argc, char **argv)
{
	int rc, ret = 0;
	int pid, status;
	void *addr;
	unsigned long test_val = 0x1129;
	ssize_t val_size = sizeof(test_val);
	ssize_t offset = MAP_SIZE - val_size;

	addr = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (addr == MAP_FAILED) {
		ret = -1;
		perror("failed to mmap: ");
		goto out;
	}
	memset(addr, '0', MAP_SIZE);

	pid = fork();
	if (pid < 0) {
		ret = -1;
		perror("failed to fork: ");
		goto out;
	}

	if (pid == 0) {
		/* child */
		printf("[OK] fork is successful\n");

		rc = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		if (rc < 0) {
			printf("[NG]: traceme is failed\n");
		}
		raise(SIGSTOP);

		if (*((unsigned long *)(addr + offset)) == test_val) {
			printf("[OK] POKED value is correct!!\n");
		}
		else {
			printf("[NG] POKED value is NOT correct!!\n");
			exit(-1);
		}

		exit(0);
	}
	else {
		waitpid(pid, &status, 0);
		if (!WIFSTOPPED(status)) {
			ret = -1;
			goto out;
		}

		rc = ptrace(PTRACE_POKETEXT, pid, addr + offset, test_val);
		if (rc < 0) {
			ret = -1;
			goto out;
		}

		rc = ptrace(PTRACE_DETACH, pid, NULL, NULL);
		if (rc < 0) {
			ret = -1;
			goto out;
		}

		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) == 0) {
				printf("[OK] child exited normaly\n");
			}
			else {
				ret = -1;
				goto out;
			}
		}
		else {
			ret = -1;
			goto out;
		}
	}

out:
	if (ret) {
		printf("[NG] Test Program failed\n");
	}
	return ret;
}
