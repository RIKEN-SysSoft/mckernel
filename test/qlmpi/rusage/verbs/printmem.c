#include <stdio.h>
#include "mtype.h"

void print_mem(addr_t addr, int size){
	int i;
	printf("print memory[0x%lx]\n", addr);
	for(i = 0; i < size; i++){
		printf("%02x ", *(unsigned char *)(addr+i));
	}
	printf("\n");
}

