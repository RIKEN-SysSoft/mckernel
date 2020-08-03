#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define __unused __attribute__((unused))
#define ARRAY_SIZE (2 * 1024 * 1024)

static __unused int data[ARRAY_SIZE] = { 1, 0 };
static __unused int data_zero[ARRAY_SIZE] = { 0 };

int main(void)
{
	char command[128];

	sprintf(command, "cat /proc/%d/maps", getpid());
	system(command);

	return 0;
}
