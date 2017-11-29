#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
int
main(int argc, char **argv)
{
	execlp("ls", "ls", NULL);
}
