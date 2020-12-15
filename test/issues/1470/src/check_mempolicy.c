#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <numaif.h>
#include <okng.h>

#define PLD_PROCESS_NUMA_MASK_BITS 256

int main(int argc, char **argv)
{
	long ret;
	int mode;
	unsigned long nodemask[PLD_PROCESS_NUMA_MASK_BITS /
			       (sizeof(unsigned long) * 8)] = { 0 };
	int mode_expected = -1;
	unsigned long nodemask_expected[PLD_PROCESS_NUMA_MASK_BITS /
					(sizeof(unsigned long) * 8)] = { 0 };
	int opt;

	while ((opt = getopt(argc, argv, "m:n:")) != -1) {
		switch (opt) {
		case 'm':
			mode_expected = atol(optarg);
			break;
		case 'n':
			nodemask_expected[0] = atoi(optarg);
			break;
		default: /* '?' */
			INTERR(1, "unknown option %c\n", optopt);
		}
	}

	INTERR(mode_expected == -1, "specify -m <mode>\n");

	ret = get_mempolicy(&mode, nodemask, PLD_PROCESS_NUMA_MASK_BITS,
			    NULL, 0);
	INTERR(ret, "get_mempolicy failed with %ld\n", ret);

	OKNG(mode == mode_expected, "mode: actual (%d), expected (%d)\n",
	     mode, mode_expected);

	/* nodemask is "don't care" when mode is MPOL_DEFAULT */
	if (mode_expected != 0) {
		OKNG(nodemask[0] == nodemask_expected[0],
		     "nodemask: actual (%ld), expected (%ld)\n",
		     nodemask[0],
		     nodemask_expected[0]);
	}

	ret = 0;
 out:
	return ret;
}
