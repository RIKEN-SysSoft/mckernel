#define __BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>

int
main(int argc, char **argv)
{
	syscall(SYS_gettid);
	open("/", O_WRONLY);
	syscall(9999);
	exit(15);
}
