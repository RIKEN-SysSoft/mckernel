#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>

#define TEST_TEXT "Test Text"

int main(int argc, char *argv[])
{
	int fd;
	long pgsize = getpagesize();
	void *addr;
	int rc = 0;
	char *ch;

	if (argc < 2) {
		printf("ERROR: too few arguments\n");
		return -1;
	}

	printf("** FileMap(2pages) %s and read\n", argv[1]);
	if ((fd = open(argv[1], O_RDONLY)) == -1) {
		perror("open");
		exit(-1);
	}

	addr = mmap(0, pgsize * 2, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	ch = addr;
	printf("value: 0x%lx\n", (unsigned long)*ch);
	printf("Touch head of 1st page: OK\n");

	ch = addr + (pgsize / 2) + 64;
	printf("value: 0x%lx\n", (unsigned long)*ch);
	printf("Touch middle of 1st page: OK\n");

	ch = addr + pgsize + 64;
	printf("value: 0x%lx\n", (unsigned long)*ch);
	printf("Touch middle of 2nd page: OK\n");

	munmap(addr, pgsize * 2);
	close(fd);
}
