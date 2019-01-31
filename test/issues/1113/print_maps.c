#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
	char command[128];

	sprintf(command, "cat /proc/%d/maps", getpid());
	system(command);

	return 0;
}
