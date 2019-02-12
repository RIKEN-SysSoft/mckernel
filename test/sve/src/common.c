/* common.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
#include <sys/types.h> 
#include <sys/wait.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <errno.h>
#include "common.h"

int wait_child_stop(pid_t cpid)
{
	int status = 0;
	int ret = -1;
	pid_t pid = 0;

	/* wait child stop */
	pid = wait(&status);
	if (pid == cpid) {
		if (!WIFSTOPPED(status)) {
			printf("child is not stopped.\n");
			goto out;
		}
	} else {
		perror("wait()");
		goto out;
	}
	ret = 0;
out:
	return ret;
}

int wait_child_exit(pid_t cpid)
{
	int status = 0;
	int ret = -1;
	pid_t pid = 0;

	pid = wait(&status);
	if (pid == cpid) {
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status)) {
				goto out;
			}
		} else {
			printf("child-process unfinished.\n");
			goto out;
		}
	} else if (pid == -1) {
		perror("wait()");
		goto out;
	} else {
		printf("wait() return invalid pid.\n");
		goto out;
	}
	ret = 0;
out:
	return ret;
}

int rewrite_brk_inst(pid_t cpid, void *inst_addr)
{
	unsigned long addr = 0;
	const unsigned long inst = ((NOP_INST << 32UL) | NOP_INST);

	/* read child brk address */
	addr = ptrace(PTRACE_PEEKDATA, cpid, inst_addr, NULL);
	if ((addr == -1) && errno) {
		perror("ptrace(PTRACE_PEEKDATA)");
		return -1;
	}

	/* write nop instruction */
	if (ptrace(PTRACE_POKETEXT, cpid, addr, inst)) {
		perror("ptrace(PTRACE_POKETEXT)");
		return -1;
	}
	return 0;
}

void print_test_overview(int tp_num)
{
	printf("# %2d : %s\n", tp_num, usage_messages[tp_num]);
}

