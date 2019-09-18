#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	int num;

	if (argc < 2) {
		printf("usage: %s <num>\n", argv[0]);
		return 1;
	}
	num = atoi(argv[1]);
	printf("hello world[%d]\n", num);
	return 0;
}
