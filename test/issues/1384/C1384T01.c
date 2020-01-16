#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <numa.h>
#include <numaif.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include "./C1384.h"

#define PAGES 5

static unsigned long pagesize;

struct mbind_info base = {1, 3, MPOL_BIND};
struct mbind_info new = {0, 3, MPOL_DEFAULT};
static int expect_policies[PAGES] = {M_D, M_D, M_D, M_B, M_D};

int main(int argc, char **argv)
{
	void *addr;
	int i, node, err, policy, ret = 0;
	unsigned long base_start, base_size, new_start, new_size;
	struct bitmask *nmask = numa_allocate_nodemask();

	pagesize = getpagesize();
	node = 1;

	numa_bitmask_setbit(nmask, node);

	addr = mmap(NULL, pagesize * PAGES, PROT_WRITE,
		MAP_ANON | MAP_PRIVATE, 0, 0);
	if (addr == MAP_FAILED) {
		perror("mmap faile: ");
		ret = -1;
		goto out;
	}

	/* make page populate */
	memset(addr, 0, pagesize * PAGES);

	/* base mbind */
	base_start = (unsigned long)addr + pagesize * base.offset;
	base_size = pagesize * base.size;
	err = mbind((void *)base_start, base_size, base.policy, nmask->maskp,
			nmask->size, MPOL_MF_MOVE_ALL);
	if (err != 0) {
		perror("base mbind fail: ");
		ret = -1;
		goto out;
	}
	printf("base mbind: 0x%lx - 0x%lx  policy:%d\n",
			base_start, base_start + base_size, base.policy);

	/* new mbind */
	new_start = (unsigned long)addr + pagesize * new.offset;
	new_size = pagesize * new.size;
	err = mbind((void *)new_start, new_size, new.policy,
			NULL, 0, 0);
	if (err != 0) {
		perror("new mbind fail: ");
		ret = -1;
		goto out;
	}
	printf("new mbind:  0x%lx - 0x%lx  policy:%d\n",
			new_start, new_start + new_size, new.policy);

	for (i = 0; i < PAGES; i++) {
		err = get_mempolicy(&policy, nmask->maskp, nmask->size,
			addr + pagesize * i, MPOL_F_ADDR);
		if (err != 0) {
			perror("get_mempolicy  fail: ");
			ret = -1;
			goto out;
		}

		if (policy != expect_policies[i]) {
			printf("[NG] policy[%d] is %d (expected %d)\n",
					i, policy, expect_policies[i]);
			ret = -1;
			goto out;
		}
	}

	printf("[OK] policies are expected\n");
out:
	return ret;
}
