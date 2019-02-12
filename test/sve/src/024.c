/* 024.c COPYRIGHT FUJITSU LIMITED 2017-2019 */
/* Preservation VL check migrate cpus before and after. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h> 
#include <sys/ptrace.h>
#include "common.h"

static unsigned long inst_addr = 0;

static int child_func(unsigned int vl, unsigned int vq, int *c2p)
{
	const unsigned int set_vl = gen_set_vl(vl);
	const unsigned int set_vq = sve_vq_from_vl(set_vl);
	int ret = -1;
	unsigned int before_id, after_id;
	unsigned int before_vl, after_vl;
	typedef struct fpsimd_sve_state(set_vq) sve_regs_t;
	sve_regs_t before_buf;
	sve_regs_t after_buf;
	unsigned int fpscr[2] = { 0, 0 };

	/* send PTRACE_TRACEME */
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
		perror("ptrace(PTRACE_TRACEME)");
		goto out;
	}

	/* clear buffer */
	memset(&before_buf, 0, sizeof(before_buf));
	memset(&after_buf, 0, sizeof(after_buf));

	/* get running core number and notify parent */
	before_id = sched_getcpu();
	printf("[child] before migrate. (cpuid=%d)\n", before_id);
	write(c2p[1], &before_id, sizeof(before_id));

	if (set_and_compare_vl(set_vl | PR_SVE_VL_INHERIT)) {
		printf("prctl: error.\n");
		goto out;
	}

	/* write, read and show register */
	gen_test_sve(&before_buf, set_vq);
	write_sve(&before_buf, set_vq, fpscr);

	before_vl = sve_get_vl();

	/* stop mine, brk instruction */
	asm volatile(
		"adr x10, 1f\n"
		"str x10, [%0]\n"
		"nop\n"
		"nop\n"
		"1:\n"
		"brk #0\n"
		"nop\n"
		: /* nothing */
		: "r"(&inst_addr)
		: "x10"
	);

	after_vl = sve_get_vl();

	/* get after migrate running core number and notify parent */
	after_id = sched_getcpu();
	printf("[child] after migrate. (cpuid=%d)\n", after_id);

	/* migrate check */
	if (before_id == after_id) {
		printf("not migrate process.\n");
		goto out;
	}

	if (before_vl != after_vl) {
		printf("bevore VL=%d, after VL=%d\n", before_vl, after_vl);
		printf("VL compare failed.\n");
		goto out;
	}

	/* read and show register */
	read_sve(&after_buf, set_vq, fpscr);

	/* compare */
	if (sve_compare(&before_buf, &after_buf, set_vq)) {
		printf("child-process compare failed.\n");
		goto out;
	}

	/* success */
	ret = 0;
out:
	return ret;
}

static int parent_func(pid_t cpid, int *c2p)
{
	int ret = -1;
	int i = 0;
	cpu_set_t *cpusetp_child;
	size_t size;
	unsigned int c_before_id;
	unsigned int migrate_cpu = -1;
	unsigned int parent_cpu;

	/* wait child stop */
	if (wait_child_stop(cpid)) {
		goto out;
	}

	/* read child process running core number */
	read(c2p[0], &c_before_id, sizeof(c_before_id));

	/* getaffinity mask allocate */
	size = CPU_ALLOC_SIZE(SMP_MAX_CPUS);
	cpusetp_child = CPU_ALLOC(SMP_MAX_CPUS);

	if (!cpusetp_child) {
		printf("(child process) alloc failed.\n");
		goto cont;
	}
	CPU_ZERO_S(size, cpusetp_child);

	/* get child affinity */
	if (sched_getaffinity(cpid, size, cpusetp_child)) {
		perror("sched_getaffinity()");
		goto cont;
	}

	/* calc migrate core number */
	parent_cpu = sched_getcpu();
	for (i = 0; i < SMP_MAX_CPUS; i++) {
		if (CPU_ISSET(i, cpusetp_child)) {
			if ((i != parent_cpu) && (i != c_before_id)) {
				migrate_cpu = i;
				break;
			}
		}
	}

	/* migrate core number check */
	if (migrate_cpu < 0) {
		printf("Bad target to migrate child process.\n");
		goto cont;
	}

	/* set affinity */
	CPU_ZERO_S(size, cpusetp_child);
	CPU_SET_S(migrate_cpu, size, cpusetp_child);

	if (sched_setaffinity(cpid, size, cpusetp_child)) {
		perror("sched_setaffinity()");
		goto out;
	}
	CPU_FREE(cpusetp_child);

	/* success */
	ret = 0;
cont:
	/* rewrite child brk instruction */
	if (rewrite_brk_inst(cpid, &inst_addr)) {
		/* Through */
	}

	/* child continue */
	if (ptrace(PTRACE_CONT, cpid, NULL, NULL)) {
		perror("ptrace(PTRACE_CONT)");
		ret = -1;
	}
out:
	return ret;
}

TEST_FUNC(TEST_NUMBER, vl, vq, unused1, unused2)
{
	pid_t cpid = 0;
	int func_ret = -1;
	int ret = -1;
	int c2p[2] = { -1, -1 };

	print_test_overview(tp_num);

	/* allocation pipe */
	if (pipe(c2p)) {
		printf("pipe() Failed.\n");
		goto out;
	}

	/* create child process */
	cpid = fork();
	switch (cpid) {
	case -1:
		/* fork() error */
		perror("fork()");
		goto close_out;
		break;
	case 0:
		/* child process */
		exit(child_func(vl, vq, c2p));
		break;

	default:
		/* parent process */
		func_ret = parent_func(cpid, c2p);

		/* wait child */
		if (wait_child_exit(cpid)) {
			goto close_out;
		}

		/* parent_func check */
		if (func_ret) {
			goto close_out;
		}
		break;
	}

	/* success. */
	ret = 0;
close_out:
	/* close pipe */
	close(c2p[0]);
	close(c2p[1]);
out:
	if (ret == 0) {
		printf("RESULT: OK.\n");
	} else {
		printf("RESULT: NG.\n");
	}
	return 0;
}
