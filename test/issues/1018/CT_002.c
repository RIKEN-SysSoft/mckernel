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
	int fd = 0, i = 0;
	pid_t pid = getpid();
	char pfname[PROCFILE_LEN];
	unsigned long *anon_map = NULL;
	unsigned long *tmp_buf = NULL;
	int data_pos[3] = {0 * MEGA / sizeof(unsigned long),
			1 * MEGA / sizeof(unsigned long),
			4 * MEGA / sizeof(unsigned long)};
	off_t ret = 0;

	printf("*** %s start *******************************\n", TEST_NAME);

	/* anonymous mmap */
	anon_map = (unsigned long *)mmap(NULL, MAP_LEN, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	OKNG(anon_map == MAP_FAILED, "anonymous map");
	printf("  anonymous map to %p, size:%.2f MB\n",
	       anon_map, (double)MAP_LEN / MEGA);

	/* allocate tmp_buf */
	tmp_buf = (unsigned long *)mmap(NULL, MAP_LEN, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHKANDJUMP(tmp_buf == MAP_FAILED, "alloc tmp_buf");

	/* set magic_number */
	tmp_buf[data_pos[0]] = 0x1111;
	tmp_buf[data_pos[1]] = 0x2222;
	tmp_buf[data_pos[2]] = 0x3333;

	/* generate proc_mem path */
	sprintf(pfname, "/proc/%d/mem", pid);

	/* open proc_mem */
	fd = open(pfname, O_RDWR);
	CHKANDJUMP(fd < 0, "open proc_mem");

	/* pwrite 2MB */
	errno = 0;
	ret = pwrite(fd, tmp_buf, 2 * MEGA, (off_t)anon_map);
	OKNG(ret != 2 * MEGA || errno != 0, "2MB pwrite");

	/* pwrite 4MB */
	errno = 0;
	ret = pwrite(fd, tmp_buf, 4 * MEGA, (off_t)anon_map);
	OKNG(ret != 4 * MEGA || errno != 0, "4MB pwrite");

	/* pwrite 8MB */
	errno = 0;
	ret = pwrite(fd, tmp_buf, 8 * MEGA, (off_t)anon_map);
	OKNG(ret != 8 * MEGA || errno != 0, "8MB pwrite");

	close(fd);

	printf("*** %s PASSED\n\n", TEST_NAME);

	return 0;

fn_fail:

	if (fd > 0) {
		close(fd);
	}

	printf("*** %s FAILED\n\n", TEST_NAME);

	return -1;

}
