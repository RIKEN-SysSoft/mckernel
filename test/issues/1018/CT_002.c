#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "./test_chk.h"

#define TEST_NAME "CT_002"

#define MEGA (1024 * 1024)

#define PROCFILE_LEN 128
#define MAP_LEN (8 * MEGA)

int main(int argc, char *argv[])
{
	int fd = 0;
	pid_t pid = getpid();
	char pfname[PROCFILE_LEN];
	off_t ret = 0;

	printf("*** %s start *******************************\n", TEST_NAME);

	/* generate proc_mem path */
	sprintf(pfname, "/proc/%d/mem", pid);

	/* open proc_mem */
	fd = open(pfname, O_WRONLY);
	OKNG(fd != -1, "open /proc/<PID>/mem is failed");

	OKNG(errno != EACCES, "errno is EACCES");

	printf("*** %s PASSED\n\n", TEST_NAME);

	return 0;

fn_fail:

	if (fd > 0) {
		close(fd);
	}

	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;

}
