#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <error.h>
#include <sys/mman.h>
#include "./test_chk.h"

#include <signal.h>

#define TEST_NAME "CT_001"

int main(int argc, char *argv[])
{
	int rc = 0;
	stack_t cur_stack;
	stack_t set_stack;
	void *stack_area = NULL;
	char *exargv[3] = {argv[0], "stop", NULL};
	char *exenvp[1] = {NULL};

	printf("*** %s start ********************************\n", TEST_NAME);
	rc = sigaltstack(NULL, &cur_stack);
	OKNG(rc != 0, "sigaltstack() to get current  returned %d"
		"\n      (expect return is 0)", rc);

	OKNG(cur_stack.ss_sp != NULL, "default ss_sp is %p"
		"\n      (expect ss_sp is NULL)", cur_stack.ss_sp);

	stack_area = mmap(0, MINSIGSTKSZ, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	OKNG(stack_area == MAP_FAILED, "alloc altstack area %p"
		"\n      (expect area is valid vaddr)", stack_area);

	set_stack.ss_sp = stack_area;
	set_stack.ss_flags = 0;
	set_stack.ss_size = MINSIGSTKSZ;

	rc = sigaltstack(&set_stack, NULL);
	OKNG(rc != 0, "sigaltstack() to set new stack  returned %d"
		"\n      (expect return is 0)", rc);

	rc = sigaltstack(NULL, &cur_stack);
	OKNG(rc != 0, "sigaltstack() to get current  returned %d"
		"\n      (expect return is 0)", rc);

	OKNG(cur_stack.ss_sp != stack_area, "new ss_sp is %p"
		"\n      (expect ss_sp is %p)", cur_stack.ss_sp, stack_area);

	if (argc < 2) {
		printf("** Re-run by execve\n");
		execve(exargv[0], exargv, exenvp);
	}

	printf("*** %s PASSED\n\n", TEST_NAME);

	return 0;

fn_fail:
	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;
}
