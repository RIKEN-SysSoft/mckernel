#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include "util.h"
#include "ihklib.h"

#define DEBUG

int sz_anon[] = {
	4 * (1ULL<<10),
	2 * (1ULL<<20),
	1 * (1ULL<<30),
	134217728};

#define SZ_INDEX 0
#define NLOOP 2

int main(int argc, char **argv)
{
	int i, j, ret = 0;
	void *mem;
	struct ihk_os_rusage rusage;

	for (j = 0; j < NLOOP; j++) {
		mem = mmap(0, sz_anon[SZ_INDEX], PROT_READ | PROT_WRITE,
			   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		CHKANDJUMP(mem == MAP_FAILED, 255, "mmap failed\n");
		*((unsigned long *)mem) = 0x123456789abcdef0;

		ret = syscall(900);
		CHKANDJUMP(ret != 0, 255, "syscall failed\n");

		ret  = ihk_os_getrusage(0, &rusage);
		CHKANDJUMP(ret != 0, 255, "ihk_os_getrusage failed\n");

		for (i = 0; i < IHK_MAX_NUM_PGSIZES; i++) {
			printf("memory_stat_rss[%d]=%ld\n", i,
			       rusage.memory_stat_rss[i]);
			printf("memory_stat_mapped_file[%d]=%ld\n", i,
			       rusage.memory_stat_mapped_file[i]);
		}
		printf("memory_max_usage=%ld\n", rusage.memory_max_usage);
		printf("memory_kmem_usage=%ld\n", rusage.memory_kmem_usage);
		printf("memory_kmem_max_usage=%ld\n",
		       rusage.memory_kmem_max_usage);
#define NUM_NUMA_NODES 2
		for (i = 0; i < NUM_NUMA_NODES; i++) {
			printf("memory_numa_stat[%d]=%ld\n", i,
			       rusage.memory_numa_stat[i]);
		}
#define NUM_CPUS 2
		for (i = 0; i < NUM_CPUS; i++) {
			printf("cpuacct_usage_percpu[%d]=%ld\n", i,
			       rusage.cpuacct_usage_percpu[i]);
		}
		printf("cpuacct_stat_system=%ld\n",
		       rusage.cpuacct_stat_system);
		printf("cpuacct_stat_user=%ld\n", rusage.cpuacct_stat_user);
		printf("cpuacct_usage=%ld\n", rusage.cpuacct_usage);

		printf("num_threads=%d\n", rusage.num_threads);
		printf("max_num_threads=%d\n", rusage.max_num_threads);
	}
 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}
