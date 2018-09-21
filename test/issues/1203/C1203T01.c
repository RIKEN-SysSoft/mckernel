#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAP_SIZE (2 * (2 * 1024 * 1024))

int main(int argc, char *argv[])
{
	int fd;
	long int *addr;
	pid_t pid;


	if ((fd = open("/dev/hugepages/foo", O_CREAT|O_RDWR, 0600)) < 0) {
		perror("open");
		return -1;
	}
	unlink("/dev/hugepages/foo");
	if ((pid = fork()) == 0) {
		if ((addr = mmap(NULL, MAP_SIZE, PROT_READ|PROT_WRITE,
				 MAP_SHARED, fd, 0)) == MAP_FAILED) {
			perror("mmap");
			return -1;
		}
		for (int i = 0; i < MAP_SIZE / sizeof(long int); i++) {
			if (addr[i] != 0) {
				fprintf(stderr,
					"memory wasn't zeroed at offset %lx\n",
					i * sizeof(long int));
				return -1;
			}
		}
		addr[42] = 12;
		if (munmap(addr, MAP_SIZE) < 0) {
			perror("munmap");
			return -1;
		}
		return 0;
	}
	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (waitpid(pid, NULL, 0) <= 0) {
		perror("waitpid");
		return -1;
	}

	/* bigger extent: check what was set is still here and rest is zero */
	if ((addr = mmap(NULL, 2 * MAP_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED,
			 fd, 0)) == MAP_FAILED) {
		perror("mmap, 2");
		return -1;
	}
	if (addr[42] != 12) {
		perror("unexpected content");
		return -1;
	}
	for (int i = 0; i < MAP_SIZE / sizeof(long int); i++) {
		if (addr[MAP_SIZE / sizeof(long int) + i] != 0) {
			fprintf(stderr, "memory wasn't zeroed at offset %lx\n",
				MAP_SIZE + i * sizeof(long int));
			return -1;
		}
	}
	addr[MAP_SIZE / sizeof(long int) + 17] = 42;
	if (munmap(addr, MAP_SIZE) < 0) {
		perror("munmap, 2");
		return -1;
	}

	/* same with offset */
	if ((addr = mmap(NULL, 2 * MAP_SIZE, PROT_READ|PROT_EXEC,
			 MAP_PRIVATE|MAP_NORESERVE, fd, MAP_SIZE))
							== MAP_FAILED) {
		perror("mmap, 2");
		return -1;
	}
	if (addr[17] != 42) {
		perror("unexpected content (2)");
		return -1;
	}
	for (int i = 0; i < MAP_SIZE / sizeof(long int); i++) {
		if (addr[MAP_SIZE / sizeof(long int) + i] != 0) {
			fprintf(stderr, "memory wasn't zeroed at offset %lx\n",
				2 * MAP_SIZE + i * sizeof(long int));
			return -1;
		}
	}
	if (munmap(addr, MAP_SIZE) < 0) {
		perror("munmap, 3");
		return -1;
	}

	return 0;
}
