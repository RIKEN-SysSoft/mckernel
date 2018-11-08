#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "./test_chk.h"

#define TEST_NAME "devmap_and_segv"

#define PROCFILE_LEN 128
#define MAP_LEN 4096
#define DEV_NAME "/dev/test_mck/mmap_dev2"

int main(int argc, char *argv[])
{
	int dev_fd = 0;
	pid_t pid = getpid();
	void *dev_map = NULL;
	char *segv_addr = NULL;
	char cmd[128];

	printf("*** %s start *******************************\n", TEST_NAME);

	/* open device file */
	dev_fd = open(DEV_NAME, O_RDONLY);
	OKNG(dev_fd < 0, "open test_device_file:%s", DEV_NAME);

	/* mmap device file */
	dev_map = mmap(NULL, MAP_LEN, PROT_READ, MAP_SHARED, dev_fd, 0);
	OKNG(dev_map == MAP_FAILED, "mmap device file");
	printf("  map dev_file to %p\n", dev_map);

	/* print maps */
	sprintf(cmd, "cat /proc/%d/maps", pid);
	system(cmd);

	/* occur segv */
	*segv_addr = '0';

	printf("*** Why reached here? ***\n");
	return 0;

fn_fail:

	if (dev_fd > 0) {
		close(dev_fd);
	}

	return -1;
}
