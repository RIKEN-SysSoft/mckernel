#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BUF_SIZE	(32*1024)

int	data[1024*1024];
char	sym2[1024*1024] = { 10, 20, 30, 0 };
char	sym3[1024*1024] = { 10, 20, 30, 0 };
char	*sym1 = "aaaaaa";
char	buffer[BUF_SIZE];
char	*ptr1, *ptr2;
char	fnamebuf[1024];

int
swapout(char *fname, void *buf, size_t sz, int flag)
{
    int		cc;
    cc = syscall(801, fname, buf, sz, flag);
    return cc;
}
int
linux_mlock(const void *addr, size_t len)
{
    int		cc;
    cc = syscall(802, addr, len);
    return cc;
}


int
main(int argc, char **argv)
{
    int		cc;
    int		flag = 0;

    if (argc == 2) {
	flag = atoi(argv[1]);
    }
    switch (flag) {
    case 1:
	printf("skipping real paging for debugging and just calling swapout in Linux\n");
	break;
    case 2:
	printf("skipping calling swapout in Linux\n");
	break;
    }
    printf("&data = %p\n", data);
    printf("&sym1 = %p\n", &sym1);
    printf("&sym2 = %p\n", sym2);
    printf("&sym3 = %p\n", sym3);
    printf("&cc = %p\n", &cc);
    ptr1 = malloc(1024);
    ptr2 = malloc(1024*1024);
    printf("ptr1 = %p\n", ptr1);
    printf("ptr2 = %p\n", ptr2);
    sprintf((char*) data, "hello\n");
    /*
     * testing mlock in mckernel side
     */
    cc = mlock(data, 16*1024);
    printf("McKernel mlock returns: %d\n", cc);
    /*
     * testing mlock in linux side
     */
    cc = linux_mlock(data, 16*1024);
    printf("linux_mlock returns: %d\n", cc);
    strcpy(sym2, "returns: %d\n");
    strcpy(sym3, "data =  %s\n");

    /* buf area will be used in swapout systemcall for debugging */
    strcpy(fnamebuf, "/tmp/pages");
    cc = swapout(fnamebuf, buffer, BUF_SIZE, flag);
    printf("swapout returns: %d\n", cc);
    printf("data = %s", data);
    printf(sym2, cc);
    printf(sym3, data);
    return 0;
}
