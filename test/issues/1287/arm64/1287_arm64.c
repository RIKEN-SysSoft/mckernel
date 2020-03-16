/* 1287_arm64.c COPYRIGHT FUJITSU LIMITED 2019 */
/* ptrace(PTRACE_SYSCALL) args and ret check testcase */
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <sys/uio.h>
#include <asm/ptrace.h>
#include <linux/elf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

static unsigned long __inst_addr;

#define SYSCALL_ARG0	0x11111111
#define SYSCALL_ARG1	0x22222222
#define SYSCALL_ARG2	0x33333333
#define SYSCALL_ARG3	0x44444444
#define SYSCALL_ARG4	0x55555555
#define SYSCALL_ARG5	0x66666666

#define NOP_INST	0xd503201fUL

static int rewrite_brk_inst(pid_t cpid, void *inst_addr)
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

static int get_check_regs(pid_t cpid, int regnum, long exp)
{
	int ret = -1;
	struct iovec iov;
	struct user_pt_regs gregs;

	if (regnum < 0 || 30 < regnum) {
		printf("regnum=%d invalid. (0 <= regnum <= 30)\n", regnum);
		goto out;
	}

	/* read child regs (REGSET_GPR) */
	iov.iov_base = &gregs;
	iov.iov_len = sizeof(gregs);
	if (ptrace(PTRACE_GETREGSET, cpid, NT_PRSTATUS, &iov)) {
		perror("ptrace(PTRACE_GETREGSET, NT_PRSTATUS)");
		goto out;
	}

	/* check */
	if (gregs.regs[regnum] != exp) {
		printf("reg[%d] check NG.\n", regnum);
		printf("expection:0x%lx readsysno:0x%llx\n",
			exp, gregs.regs[regnum]);
		goto out;
	}

	/* success */
	ret = 0;
out:
	return ret;
}

static int child_func(void)
{
	int ret = -1;

	/* send PTRACE_TRACEME */
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
		perror("ptrace(PTRACE_TRACEME)");
		goto out;
	}

	/* stop mine, brk instruction */
	/* rewrite nop from parent process */
	asm volatile(
		"adr x10, 1f\n"
		"str x10, [%0]\n"
		"nop\n"
		"nop\n"
		"1:\n"
		"brk #0\n"
		"nop\n"
		: /* nothing */
		: "r"(&__inst_addr)
		: "x10"
	);

	/* send magicno syscall */
	syscall(__NR_getpid, SYSCALL_ARG0, SYSCALL_ARG1, SYSCALL_ARG2,
		SYSCALL_ARG3, SYSCALL_ARG4, SYSCALL_ARG5);

	/* success */
	ret = 0;
out:
	return ret;
}

static int parent_func(pid_t cpid)
{
	pid_t pid = 0;
	int status = 0;
	int ret = -1;
	int i = 0;
	const long syscall_args[] = {
		SYSCALL_ARG0, SYSCALL_ARG1, SYSCALL_ARG2,
		SYSCALL_ARG3, SYSCALL_ARG4, SYSCALL_ARG5
	};

	/* wait child stop */
	pid = wait(&status);
	if (pid == cpid) {
		if (!WIFSTOPPED(status)) {
			printf("child is not stopped.\n");
			goto out;
		}
	}
	else {
		perror("wait()");
		goto out;
	}

	/* rewrite child brk instruction */
	if (rewrite_brk_inst(cpid, &__inst_addr)) {
		goto cont;
	}

	/* child continue (until next syscall enter) */
	if (ptrace(PTRACE_SYSCALL, cpid, NULL, NULL)) {
		perror("ptrace(PTRACE_SYSCALL)");
		goto cont;
	}

	/* wait child stop */
	pid = wait(&status);
	if (pid == cpid) {
		if (!WIFSTOPPED(status)) {
			printf("child is not stopped.\n");
			goto out;
		}
	}
	else {
		perror("wait()");
		goto out;
	}

	/* check syscall arguments */
	for (i = 0; i < sizeof(syscall_args) /
		sizeof(syscall_args[0]); i++) {
		if (get_check_regs(cpid, i, syscall_args[i]) != 0) {
			printf("syscall enter regs[%d] NG.\n", i);
			goto out;
		}
	}

	/* child continue (until syscall exit) */
	if (ptrace(PTRACE_SYSCALL, cpid, NULL, NULL)) {
		perror("ptrace(PTRACE_SYSCALL)");
		goto cont;
	}

	/* wait child stop */
	pid = wait(&status);
	if (pid == cpid) {
		if (!WIFSTOPPED(status)) {
			printf("child is not stopped.\n");
			goto out;
		}
	}
	else {
		perror("wait()");
		goto out;
	}

	/* check syscall return */
	if (get_check_regs(cpid, 0, cpid) != 0) {
		printf("syscall exit return val NG.\n");
		goto cont;
	}

	/* success */
	ret = 0;
cont:
	/* child continue */
	if (ptrace(PTRACE_CONT, cpid, NULL, NULL)) {
		perror("ptrace(PTRACE_CONT)");
		ret = -1;
	}
out:
	return ret;
}

int main(int argc, char *argv[])
{
	pid_t pid = 0;
	int ret = -1;
	int func_ret = 0;
	int status = 0;

	/* create child process */
	pid = fork();

	switch (pid) {
	case -1:
		/* fork() error. */
		perror("fork()");
		goto out;
	case 0:
		/* child process */
		func_ret = child_func();

		/* child exit */
		exit(func_ret);
		break;
	default:
		/* parent process */
		func_ret = parent_func(pid);

		/* wait child */
		pid = wait(&status);
		if (pid != -1) {
			if (WEXITSTATUS(status)) {
				printf("WEXITSTATUS() is not 0.\n");
				goto out;
			}
		}
		else {
			perror("wait()");
			goto out;
		}

		/* parent_func check */
		if (func_ret) {
			goto out;
		}
		break;
	}

	/* sccess. */
	ret = 0;
out:
	return ret;
}

