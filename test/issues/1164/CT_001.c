#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "./test_chk.h"

#define TEST_NAME "CT_001"

#define PROCFILE_LEN 128
#define MAP_LEN 4096
#define DEV_NAME "/dev/test_mck/mmap_dev2"

int main(int argc, char *argv[])
{
	int dev_fd = 0, fd = 0, i = 0;
	pid_t pid = getpid();
	char pfname[PROCFILE_LEN];
	void *dev_map = NULL;
	unsigned long *read_buf = NULL;
	off_t ret = 0;

	printf("*** %s start *******************************\n", TEST_NAME);

	/* open device file */
	dev_fd = open(DEV_NAME, O_RDONLY);
	OKNG(dev_fd < 0, "open test_device_file:%s", DEV_NAME);

	/* mmap device file */
	dev_map = mmap(NULL, MAP_LEN, PROT_READ, MAP_SHARED, dev_fd, 0);
	OKNG(dev_map == MAP_FAILED, "mmap device file");
	printf("  map dev_file to %p\n", dev_map);

	/* allocate read_buf */
	read_buf = malloc(MAP_LEN);
	CHKANDJUMP(read_buf == NULL, "malloc read_buf");

	/* generate proc_mem path */
	sprintf(pfname, "/proc/%d/mem", pid);

	/* open proc_mem */
	fd = open(pfname, O_RDONLY);
	CHKANDJUMP(fd < 0, "open proc_mem");

	/* lseek */
	ret = lseek(fd, (off_t)dev_map, SEEK_SET);
	CHKANDJUMP(ret == -1, "lseek");

	/* read */
	ret = read(fd, read_buf, MAP_LEN);
	OKNG(ret != -1 || errno != EIO, "failed to read host's phys_memory");

	free(read_buf);
	close(dev_fd);
	close(fd);

	printf("*** %s PASSED\n\n", TEST_NAME);

	return 0;

fn_fail:

	if (read_buf) {
		free(read_buf);
	}
	if (dev_fd > 0) {
		close(dev_fd);
	}
	if (fd > 0) {
		close(fd);
	}

	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;

}
