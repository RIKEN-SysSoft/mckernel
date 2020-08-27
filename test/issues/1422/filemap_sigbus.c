/* filemap_sigbus.c COPYRIGHT FUJITSU LIMITED 2019 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

int main(int argc, char *argv[])
{
	int ret = -1;
	int fd = -1;
	int i = 0;
	unsigned long *buf = NULL;
	const long pgsize = sysconf(_SC_PAGESIZE);

	if (argc != 2) {
		printf("args invalid.\n");
		ret = 0;
		goto out;
	}

	fd = open(argv[1], O_RDWR);
	if (fd == -1) {
		perror("open");
		goto out;
	}

	buf = (unsigned long *)mmap(0, 3 * pgsize, PROT_READ | PROT_WRITE,
		MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	/* Generate SIGBUS */
	for (i = 0; i < 3 * pgsize / sizeof(unsigned long); i++) {
		buf[i] = i;
	}

	munmap(buf, 3 * pgsize);

	close(fd);

	ret = 0;
out:
	return ret;
}
