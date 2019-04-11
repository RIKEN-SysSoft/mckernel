#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PAGE_SIZE 4096
#define MEM_SIZE (PAGE_SIZE * 2)

int main(int argc, char **argv)
{
	int fd;
	char *mem;
	char cmd[4096];
	int *ptr = NULL;

	fd = open(argv[0], O_RDONLY);
	if (fd == -1) {
		printf("open failed\n");
		exit(1);
	}

	mem = (char *)mmap(0, MEM_SIZE, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE, fd, 0);
	if (mem == (void *)-1) {
		printf("mmap failed\n");
		exit(1);
	}

	//mem[PAGE_SIZE] = 255;

	printf("%lx-%lx\n",
	       (unsigned long)mem + PAGE_SIZE,
	       (unsigned long)mem + MEM_SIZE);


	sprintf(cmd, "cat /proc/%d/maps", getpid());
	system(cmd);

	*ptr = 0xdead;

	return 0;
}
