/* node_bind.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <stdio.h>
#include <stdlib.h>
#include <numaif.h>
#include <numa.h>
#include <errno.h>

static void show_usage(void)
{
	printf("./node_bind <numa node>\n");
}

int main(int argc, char *argv[])
{
	int mode = 0;
	int result = -1;
	unsigned long mask = 0;
	unsigned long exp_mask = 0;
	struct bitmask *bind_mask;

	if (argc != 2) {
		show_usage();
		result = 0;
		goto err;
	}

	bind_mask = numa_parse_nodestring_all(argv[1]);
	if (bind_mask) {
		int node;

		for (node = 0; node <= numa_max_possible_node(); ++node) {
			if (numa_bitmask_isbitset(bind_mask, node)) {
				exp_mask |= (1UL << node);
			}
		}
	}

	if (get_mempolicy(&mode, &mask, sizeof(mask) * 8, 0, MPOL_F_NODE)) {
		printf("get_mempolicy() failed. %d\n", errno);
		goto err;
	}

	if (mask != exp_mask) {
		printf("node_bind mask mismatch, ng. (exp:%lx, mask:%lx)\n",
			exp_mask, mask);
		goto err;
	}
	result = 0;

err:
	return result;
}
