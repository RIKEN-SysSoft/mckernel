#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define CMD_SIZE 128

int main(void)
{
	char command[CMD_SIZE];

	memset(command, '0', CMD_SIZE);
	sprintf(command, "cat /proc/%d/maps", getpid());
	system(command);

	memset(command, '0', CMD_SIZE);
	sprintf(command, "cat /proc/%d/cmdline 1>&2", getpid());
	system(command);

	return 0;
}
