#include <stdio.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

main() {
	int rst = 0;
	
	rst = syscall(950);
	printf("mem_destroy result:%d\n",rst);

	return;
}
