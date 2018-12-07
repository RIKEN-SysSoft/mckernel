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

int main(int argc, char **argv)
{
	char *addr_brk;
	int trial_num = 0;

	/* Assuming heap size starts from zero and
	 * incremented by the amount specified with mcexec -h
	 */
	addr_brk = sbrk(TARGET_PAGE_SIZE);
	NG(addr_brk != (void *)-1, "sbrk failed");

	addr_brk[0] = 'z';
	NG(__atomic_load_n(addr_brk, __ATOMIC_SEQ_CST) == 'z',
	   "memory access failed\n");

	printf("large page request, trial#: %03d, addr: %016lx, size: %ld\n",
	       trial_num++, (long unsigned int)addr_brk, TARGET_PAGE_SIZE);

	return 0;
 fn_fail:
	return 1;
}
