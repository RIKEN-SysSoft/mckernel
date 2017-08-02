#include <stdio.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

main() {

	int rst = 0;

	rst = syscall(902);
	printf("freemem_destroy result:%d\n",rst);

	return;
}
