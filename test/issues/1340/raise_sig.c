#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

int main(int argc, char **argv)
{
	int sig = 0;

	sig = atoi(argv[1]);
	raise(sig);

	printf("Send sig %d to self\n", sig);

	return 0;
}
