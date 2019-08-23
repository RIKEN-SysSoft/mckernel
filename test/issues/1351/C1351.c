#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <inttypes.h>

#define MAP_HUGE_SHIFT 26
#define MADV_SHOW_ATTR 201 /* for TEST */
#define RANGE_NUM 3
#define PAGE_NUM 2

int main(int argc, char **argv)
{
	void *mems[RANGE_NUM];
	int ret = 0;
	int i, rc, fd;
	int fds[RANGE_NUM];
	int  pgnum;
	size_t pgsize, map_size, def_pgsize = getpagesize();

	if ((fd = open("TestFile", O_RDWR | O_CREAT, 0666)) == -1) {
		perror("open");
		return -1;
	}

	pgsize = getpagesize();
	map_size = pgsize * PAGE_NUM;

	for (i = 0; i < RANGE_NUM; i++) {
		mems[i] = mmap(0, map_size, PROT_READ | PROT_WRITE,
				MAP_SHARED, fd, 0);
	}
	for (i = 0; i < RANGE_NUM; i++) {
		if (i > 0) {
			if (mems[i] != mems[i - 1] + map_size) {
				printf("maps is not continuous\n");
				ret = -1;
				goto out;
			}
		}
	}
	printf("** mmap continuous areas: Done\n");

	rc = madvise(mems[0], map_size * RANGE_NUM, MADV_DONTDUMP);
	if (rc != 0) {
		perror("madvise MADV_DONTDUMP");
		ret = -1;
		goto out;
	}
	printf("** madvise MADV_DONTDUMP: Done\n");

	rc = madvise(mems[0], map_size * RANGE_NUM, MADV_SHOW_ATTR);
	if (rc != 0) {
		perror("madvise MAD_SHOW_ATTR");
		ret = -1;
		goto out;
	}
	printf("** madvise MADV_SHOW_ATTR: Done\n");

	munmap(mems[0], map_size * RANGE_NUM);

out:
	close(fd);

	return ret;
}
