#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sched.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

//#ifdef MCKERNEL
//#include <sys/types.h>
//#include <ihklib.h>
//#endif

//#define MMAP_SIZE 1024*1024*1024
//#define ITERATIONS 1

#define MMAP_SIZE 1024*1024
#define ITERATIONS 1024
#define PEBS_BUFFER 1024*1024
#define PEBS_COUNTDOWN 1003

#define MSR_IA32_PMC0	0x000004c1

#define PMC_NUM_BITS 40




#define PERFCTR_USER_MODE   0x01
#define PERFCTR_KERNEL_MODE 0x02
#define PERFCTR_PEBS        0x04

enum ihk_perfctr_type {
	APT_TYPE_DATA_PAGE_WALK,
	APT_TYPE_DATA_READ_MISS,
	APT_TYPE_DATA_WRITE_MISS,
	APT_TYPE_BANK_CONFLICTS,
	APT_TYPE_CODE_CACHE_MISS,
	APT_TYPE_INSTRUCTIONS_EXECUTED,
	APT_TYPE_INSTRUCTIONS_EXECUTED_V_PIPE,

	APT_TYPE_L2_READ_MISS,
	APT_TYPE_L2_CODE_READ_MISS_CACHE_FILL,
	APT_TYPE_L2_DATA_READ_MISS_CACHE_FILL,
	APT_TYPE_L2_CODE_READ_MISS_MEM_FILL,
	APT_TYPE_L2_DATA_READ_MISS_MEM_FILL,

	APT_TYPE_L1D_REQUEST,
	APT_TYPE_L1I_REQUEST,
	APT_TYPE_L1_MISS,
	APT_TYPE_LLC_MISS,
	APT_TYPE_DTLB_MISS,
	APT_TYPE_ITLB_MISS,
	APT_TYPE_STALL,
	APT_TYPE_CYCLE,

        APT_TYPE_INSTRUCTIONS,
        APT_TYPE_L1D_MISS,
        APT_TYPE_L1I_MISS,
        APT_TYPE_L2_MISS,
        APT_TYPE_L2_HIT_LOADS,
	APT_TYPE_L2_MISS_LOADS,

	PERFCTR_MAX_TYPE,
};


void sig_handler(int signo)
{
	//if (signo == SIGIO)
		//printf("received SIGIO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

}


static unsigned long rdmsr(unsigned int index)
{
	unsigned int high, low;

	asm volatile("rdmsr" : "=a" (low), "=d" (high) : "c" (index));

	return (unsigned long)high << 32 | low;
}


int read_pebs(unsigned long long *buf, size_t len, FILE *fd)
{
	size_t read_len;
	size_t nelem;
	unsigned long long i;
#ifdef MCKERNEL
	//pmc0 = pmc_pebs_read()
	if ((read_len=syscall(606, buf, len)) < 0) {
		fprintf(stderr,"Error reading pebs buffer:%s", strerror(read_len));
		return 1;
	}
	nelem = read_len/sizeof(unsigned long long);

	//printf(" - pebs bytes read:%llu (%llu elem)\n", read_len, nelem);

	for (i = 0; i < nelem; i++) {
		fprintf(fd, "%llx\n", buf[i]);
	}
#endif
	return 0;
}

int read_pmc(int counter, long long int *pmc) {
	long long int tmp;
	int err;
	//pmc0 = rdmsr(MSR_IA32_PMC0);
	if (err=syscall(605, counter, &tmp)) {
		fprintf(stderr,"Error pmc_read: %s", strerror(err));
		return 1;
	}


	struct {signed long long int x:PMC_NUM_BITS;} s;
	*pmc = s.x = tmp;

	return 0;
}


int main(int argc, char **argv)
{
	int cpu;
	int err;
	char *addr;
	int cpuid;
	FILE *fd = stdout;
	char out_file_name[300];
	long long int pmc0;
	unsigned long long i, it, sum;
	unsigned long long *pebs_buf;

	#ifdef MCKERNEL

	printf("setting up signal handler\n");
	if (signal(SIGIO, sig_handler) == SIG_ERR) {
		fprintf(stderr,"Error in signal setup\n");
		return 1;
	}

	printf("openning output file\n");
	if ((cpuid=sched_getcpu())==-1) {
		perror("Error getting CPU ID");
	}
	printf(" - running on cpu: %d\n", cpuid);
	snprintf(out_file_name, 300, "./pebs_%d.out", cpuid);
	if ((fd=fopen(out_file_name, "w")) == NULL) {
		perror("Cannot open pebs output file");
		return 1;
	}

	printf("allocating PEBS user buffer\n");
	if ((pebs_buf=malloc(PEBS_BUFFER))==NULL) {
		perror("Cannot allocate pebs buffer");
		return 1;
	}

	printf("stopping PMC\n");
	//pmc_stop(0);
	if (err=syscall(603, 0)) {
		fprintf(stderr,"Error pmc_stop: %s", strerror(err));
		return 1;
	}

	printf("init pmc\n");
	//pmc_init(0, APT_TYPE_L2_MISS);
	//if (err=syscall(601, 0, APT_TYPE_L2_HIT_LOADS,
	//		PERFCTR_USER_MODE, -(1ULL<<39)+1 )) {
	if (err=syscall(601, 0, APT_TYPE_L2_MISS_LOADS, PERFCTR_PEBS |
			PERFCTR_USER_MODE, 10)) {
		fprintf(stderr,"Error pmc_init: %s", strerror(-err));
		return 1;
	}

	////pmc_reset(0);
	//printf("reseting PMC\n");
	//if (err=syscall(604, 0)) {
	//	fprintf(stderr,"Error pmc_reset: %s", strerror(err));
	//	return 1;
	//}

	printf("Reading PMC0 MSR register\n");
	if (err = read_pmc(0, &pmc0)) {
		fprintf(stderr, "Error reading PMC0: %s", strerror(-err));
		return 1;
	}
	//printf("pmc0_before=%lld (0x%llx)\n", pmc0, pmc0);
	#endif

	//printf("mapping memory\n");
	//addr = mmap(NULL, MMAP_SIZE*ITERATIONS, PROT_READ | PROT_WRITE,
	//	    MAP_ANONYMOUS | MAP_PRIVATE,-1,0);
	//if (addr == MAP_FAILED) {
	//	perror("cannot allocate memory");
	//	return 1;
	//}

	printf("mapping memory\n");
	addr = mmap(NULL, MMAP_SIZE, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE,-1,0);
	if (addr == MAP_FAILED) {
		perror("cannot allocate memory");
		return 1;
	}
	printf("  - vaddress: %llx-%llx\n", addr, addr+MMAP_SIZE);

	printf("preloading L2 cache\n");
	/* bring everything to L2 */
	for (i = 0; i < MMAP_SIZE; i++) {
		sum += addr[i];
	}

	#ifdef MCKERNEL
	printf("starting PMC\n");
	//pmc_start(0);
	if (err=syscall(602, 0)) {
		fprintf(stderr,"Error pmc_start: %s", strerror(err));
		return 1;
	}
	#endif


	printf("computing\n");

	//for (it = 0; it < ITERATIONS; it++) {
	//	for (i = 0; i < MMAP_SIZE; i++) {
	//		//sum += addr[i*4111%ITERATIONS];
	//		sum += addr[i];

	//		#ifdef MCKERNEL
	//		if (i%1024 == 0) {
	//			if (err = read_pmc(0, &pmc0)) {
	//				fprintf(stderr, "Error reading PMC0: %s", strerror(-err));
	//				return 1;
	//			}
	//			printf("pmc0 = %lld (0x%llx)\n", pmc0, pmc0);

	//			if (read_pebs(pebs_buf, PEBS_BUFFER, fd)) {
	//				return 1;
	//			}
	//		}
	//		#endif
	//	}
	//}

	for (it = 0; it < ITERATIONS; it++) {
		for (i = 0; i < MMAP_SIZE; i++) {
			//sum += addr[i*4111%ITERATIONS];
			sum += addr[i];
		}

		#ifdef MCKERNEL
		if (err = read_pmc(0, &pmc0)) {
			fprintf(stderr, "Error reading PMC0: %s", strerror(-err));
			return 1;
		}
		//printf("pmc0 = %lld (0x%llx)\n", pmc0, pmc0);

		if (read_pebs(pebs_buf, PEBS_BUFFER, fd)) {
			return 1;
		}
		#endif
	}

	#ifdef MCKERNEL
	printf("finalizing PMC\n");
	//pmc_stop(0);
	if (err=syscall(603, 0)) {
		fprintf(stderr,"Error pmc_stop: %s", strerror(err));
		return 1;
	}

	printf("Reading MSR register\n");
	//pmc0 = rdmsr(MSR_IA32_PMC0);
	if (err=syscall(605, 0, &pmc0)) {
		fprintf(stderr,"Error pmc_read: %s", strerror(err));
		return 1;
	}

	//if (pread(fd, &pmc0, 8, MSR_IA32_PMC0) != 8) {
	//	perror("can't read msr");
	//}
	printf("pmc0=%llu (0x%llx)\n", pmc0, pmc0);
	#endif

	printf("sum=%llu\n", sum);

	return 0;
}
