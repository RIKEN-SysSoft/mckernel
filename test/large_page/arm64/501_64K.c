#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include "../util.h"

#define TARGET_PAGE_SHIFT 21
#define TARGET_PAGE_SIZE (1UL << TARGET_PAGE_SHIFT)

/* .data */
char addr_data[TARGET_PAGE_SIZE] = { 1 };

/* .bss */
char addr_bss[TARGET_PAGE_SIZE];

int main(int argc, char **argv)
{
	int trial_num = 0;
	char addr_stack[TARGET_PAGE_SIZE]
		__attribute__((aligned(TARGET_PAGE_SIZE)));

	/* .data */
	addr_data[0] = 'z';
	printf("large page request, trial#: %03d, addr: %016lx, size: %ld\n",
	       trial_num++, (unsigned long)addr_data, TARGET_PAGE_SIZE);

	/* .bss */
	addr_bss[0] = 'z';
	printf("large page request, trial#: %03d, addr: %016lx, size: %ld\n",
	       trial_num++, (unsigned long)addr_bss, TARGET_PAGE_SIZE);

	/* stack */
	addr_stack[0] = 'z';
	printf("large page request, trial#: %03d, addr: %016lx, size: %ld\n",
	       trial_num++, (unsigned long)addr_stack, TARGET_PAGE_SIZE);

	return 0;
}
