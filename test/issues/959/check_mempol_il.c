#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <numaif.h>
#include <sys/mman.h>
#include <errno.h>
#include <ihklib.h>
#include <ihk/ihk_rusage.h>

#define NUMA_NUM 2

long long numa_stat_bfr[NUMA_NUM], numa_stat_aft[NUMA_NUM];
long long exp_diff[NUMA_NUM];

int
get_current_numa_stat(long long *stat, int numa_cnt)
{
	int i, ret = 0;
	struct ihk_os_rusage mck_rusage;

	memset(&mck_rusage, 0, sizeof(mck_rusage));
	ret = ihk_os_getrusage(0, &mck_rusage, sizeof(mck_rusage));
	if (ret) {
		perror("ihk_os_getrusage()");
		goto out;
	}

	for (i = 0; i < numa_cnt; i++) {
		if (mck_rusage.memory_numa_stat[i] != 0) {
			stat[i] = mck_rusage.memory_numa_stat[i];
		}
	}
out:
	return ret;
}

int
main(int argc, char **argv)
{
	void *p;
	unsigned long mask, bind_mask = 1;
	unsigned long ps;
	int i, mode, pgshift, pgnum, exp_0, exp_1, ret = 0;

	if (argc < 7) {
		printf("error: too few arguments\n");
		ret = -1;
		goto out;
	}

	mode = atoi(argv[1]); /* 1: set_mempolicy, 2: mbind */
	pgshift = atoi(argv[2]);
	pgnum = atoi(argv[3]);
	mask = atoi(argv[4]);
	exp_0 = atoi(argv[5]);
	exp_1 = atoi(argv[6]);

	ps = 1UL << pgshift;
	exp_diff[0] = exp_0 * ps;
	exp_diff[1] = exp_1 * ps;

	if (mode != 1 && mode != 2) {
		printf("error: invalid mode\n");
		ret = -1;
		goto out;
	}

	printf("INTERLEAVE BIT_MASK: 0x%lx\n", mask);

	get_current_numa_stat(numa_stat_bfr, NUMA_NUM);
	switch (mode) {
	case 1: /* set_mempolicy */
		printf("set_mempolicy: INTERLEAVE  mask 0x%lx\n", mask);
		if (set_mempolicy(MPOL_INTERLEAVE, &mask, NUMA_NUM)) {
			perror("set_mempolicy");
			ret = -1;
			goto out;
		}

		p = mmap(NULL, ps * pgnum, PROT_READ|PROT_WRITE,
				MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (p == ((void *)-1)) {
			perror("mmap");
			ret = -1;
			goto out;
		}
		break;
	case 2: /* mbind */
		printf("set_mempolicy: BIND  mask 0x%lx\n", bind_mask);
		if (set_mempolicy(MPOL_BIND, &bind_mask, NUMA_NUM)) {
			perror("set_mempolicy");
			ret = -1;
			goto out;
		}

		p = mmap(NULL, ps * pgnum, PROT_READ|PROT_WRITE,
				MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (p == ((void *)-1)) {
			perror("mmap");
			ret = -1;
			goto out;
		}

		printf("mbind        : INTERLEAVE  mask 0x%lx\n", mask);
		if (mbind(p, ps * pgnum, MPOL_INTERLEAVE, &mask,
				NUMA_NUM, 0) == -1) {
			perror("mbind");
			ret = -1;
			goto out;
		}
		break;
	default:
		printf("error: invalid mode\n");
		ret = -1;
		goto out;
	}

	memset(p, '0', ps * pgnum);

	get_current_numa_stat(numa_stat_aft, NUMA_NUM);

	printf("** Difference of numa_stat **\n");
	for (i = 0; i < NUMA_NUM; i++) {
		long long diff = numa_stat_aft[i] - numa_stat_bfr[i];

		if (diff == exp_diff[i]) {
			printf("[OK] ");
		} else {
			printf("[NG] ");
			ret = -1;
		}
		printf(" NUMA[%d] 0x%llx\n", i, diff);
	}

	munmap(p, ps * pgnum);
out:
	return ret;
}
