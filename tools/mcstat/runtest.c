#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>

#define SIZE 10000
double	a[SIZE], b[SIZE], c[SIZE];

int
main()
{
    int		i, j, pid;

    printf("invoked\n");
    for (i = 0; i < 3; i++) {
	sleep(1);
	printf("wakeup %d\n", i);
    }
    printf("getpid 1000 times\n");
    for (i = 0; i < 1000; i++) {
	pid = getpid();
    }
    for (i = 0; i < SIZE; i++) {
	a[i] = 0; b[i] = 1.0; c[i] = 3.0;
    }
    for (j = 0; j < 1000; j++) {
	for (i = 0; i < SIZE; i++) {
	    a[i] = b[i] / c[i];
	}
    }
    printf("done\n");
    return 0;
}
