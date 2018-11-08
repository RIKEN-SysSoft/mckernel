#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include "util.h"

#define DEBUG

int sz_mem[] = {
	4 * (1ULL<<10),
	2 * (1ULL<<20),
	1 * (1ULL<<30),
	134217728};

#define SZ_INDEX 0
#define NUM_AREAS 1

int main(int argc, char **argv)
{
	void *mem;
	int ret = 0;
	pid_t pid;
	int status;
	int fd;
	unsigned long val;

	fd = open("./file", O_RDWR);
	CHKANDJUMP(fd == -1, 255, "open failed\n");

	mem = mmap(0, sz_mem[SZ_INDEX], PROT_READ | PROT_WRITE, MAP_SHARED,
		   fd, 0);
	CHKANDJUMP(mem == MAP_FAILED, 255, "mmap failed\n");

	val = *((unsigned long *)mem);
	printf("val=%lx\n", val);

	pid = fork();
	CHKANDJUMP(pid == -1, 255, "fork failed\n");
	if (pid == 0) {
		_exit(123);
	} else {
		ret = waitpid(pid, &status, 0);
		CHKANDJUMP(ret == -1, 255, "waitpid failed\n");
		printf("exit status=%d\n", WEXITSTATUS(status));
	}

 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}
