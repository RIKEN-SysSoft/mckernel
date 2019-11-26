#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define GB (1024 * 1024 * 1024)
#define MAP_SIZE (1 * GB)

int main(int argc, char **argv)
{
	int fd = -1, ret = 0;
	void *addr;
	unsigned long test_val = 0x1129;
	ssize_t val_size = sizeof(test_val);
	unsigned long buf;
	ssize_t offset = MAP_SIZE - val_size;

	addr = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (addr == MAP_FAILED) {
		ret = -1;
		perror("failed to mmap: ");
		goto out;
	}
	memcpy(addr + offset, &test_val, val_size);

	fd = open("/proc/self/mem", O_RDWR);
	lseek(fd, (off_t)addr + offset, SEEK_SET);

	read(fd, &buf, val_size);

	if (buf == test_val) {
		printf("[OK] value read by proc_mem is correct\n");
	}
	else {
		ret = -1;
		goto out;
	}

out:
	if (fd >= 0) {
		close(fd);
	}
	if (ret) {
		printf("[NG] Test Program failed\n");
	}
	return ret;
}
