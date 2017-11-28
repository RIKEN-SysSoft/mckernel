#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#define ARRAY_SIZE 10

void handler(int sig) {
	printf("[OK] unhandled_page_fault_01: received SIGSEGV\n");	
	exit(0);
}
	

int main(int argc, char** argv){
	int* test = NULL;
	
	signal(SIGSEGV, handler);
	printf("try to access out of range!\n");
	*test = 99;

	return 0;
}
