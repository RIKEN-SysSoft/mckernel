#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>

#define FILE_SIZE 1024
#define CMD_SIZE 128

int main(int argc, char* argv[])
{
	int fd;
	void *file_map;
	long page_size, file_map_size;
	char command[CMD_SIZE];

	if (argc < 2) {
		printf("Error: too few arguments\n");
		return -1;
	}

	fd = open(argv[1], O_RDWR);

	if (fd < 0) {
		printf("Error: open %s\n", argv[1]);
		return -1;
	}

	page_size = sysconf(_SC_PAGESIZE);
	file_map_size = (FILE_SIZE / page_size + 1) * page_size;

	file_map = mmap(0, file_map_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (file_map == MAP_FAILED) {
		printf("Error: mmap file\n");
		return -1;
	}

	sprintf(command, "cat /proc/%d/maps", getpid());
	system(command);

	close(fd);
	munmap(file_map, file_map_size);

	return 0;
}
