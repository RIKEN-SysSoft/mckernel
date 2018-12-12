#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>

#define MAP_SIZE (16 << 20)

int main(int argc, char **argv)
{
	int ret = 0;
	void *mem = NULL;

	mem = mmap(NULL, MAP_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (!mem) {
		printf("mmap failed\n");
		ret = -1;
		goto out;
	}

	printf("mmap to %p, size: %ldM\n", mem, MAP_SIZE / 1024 / 1024);

	memset(mem, 0, MAP_SIZE);

 out:
	if (mem) {
		munmap(mem, MAP_SIZE);
	}
	return 0;
}
