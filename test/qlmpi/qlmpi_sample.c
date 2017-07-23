#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#define BUF_SIZE (16*1024)

#include <qlmpilib.h>

int data[1024*1024];
char sym2[1024*1024] = { 10, 20, 30, 0 };
char *sym1 = "aaaaaa";
char buffer[BUF_SIZE];
char *ptr1, *ptr2;

int
swapout(char *fname, void *buf, size_t sz, int flag)
{
	int rc;
	rc = syscall(801, fname, buf, sz, flag);
	return rc;
}
int
linux_mlock(const void *addr, size_t len)
{
	int rc;
	rc = syscall(802, addr, len);
	return rc;
}

int
main(int argc, char **argv)
{
	int rc;
	int i;

	MPI_Init(&argc, &argv);

ql_loop:
	printf("***** Arguments Info ****************\n");
	printf(" argc: %d\n", argc);
	for (i = 0; i < argc; i++) {
		printf(" argv[%d]: %s\n", i, argv[i]);
	}
	printf("QL_SUCCESS:%d\n", QL_SUCCESS);
	printf("************************************\n\n");

	printf("&data = %p\n", data);
	printf("&sym1 = %p\n", &sym1);
	printf("&sym2 = %p\n", sym2);
	printf("&rc = %p\n", &rc);
	ptr1 = malloc(1024);
	ptr2 = malloc(1024*1024);
	printf("ptr1 = %p\n", ptr1);
	printf("ptr1 = %p\n", ptr2);
	/*
	 * testing mlock in mckernel side
	 */
	rc = mlock(data, 16*1024);
	printf("McKernel mlock returns: %d\n", rc);
	/*
	 * testing mlock in linux side
	 */
	sprintf((char*) data, "hello\n");
	rc = linux_mlock(data, 16*1024);
	printf("linux_mlock returns: %d\n", rc);

	rc = ql_client(&argc, &argv);

	printf("ql_client returns: %d\n", rc);
	if (rc == QL_CONTINUE) {
		goto ql_loop;
	}

	MPI_Finalize();
	printf("qlmpi_sample finished!!\n");
	return 0;
}
