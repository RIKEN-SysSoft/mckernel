#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include "../util.h"

#define TARGET_PAGE_SHIFT 29
#define TARGET_PAGE_SIZE (1UL << TARGET_PAGE_SHIFT)

/* .data */
char addr_data[TARGET_PAGE_SIZE] = { 1 };

/* .bss */
char addr_bss[TARGET_PAGE_SIZE];

int main(int argc, char **argv)
{
	int trial_num = 0;

	/* .data */
	addr_data[0] = 'z';
	NG(__atomic_load_n(addr_data, __ATOMIC_SEQ_CST) == 'z',
	   "memory access failed\n");
	printf("large page request, trial#: %03d, addr: %016lx, size: %ld\n",
	       trial_num++, (unsigned long)addr_data, TARGET_PAGE_SIZE);

	/* .bss */
	addr_bss[0] = 'z';
	NG(__atomic_load_n(addr_bss, __ATOMIC_SEQ_CST) == 'z',
	   "memory access failed\n");
	printf("large page request, trial#: %03d, addr: %016lx, size: %ld\n",
	       trial_num++, (unsigned long)addr_bss, TARGET_PAGE_SIZE);

	return 0;
 fn_fail:
	return 1;
}
