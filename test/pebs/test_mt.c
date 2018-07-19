#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sched.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>

//#ifdef MCKERNEL
//#include <sys/types.h>
//#include <ihklib.h>
//#endif

//#define MMAP_SIZE 1024*1024*1024
//#define ITERATIONS 1

//#define MMAP_SIZE 1024*1024 //1MiB
#define MMAP_SIZE_BASE 1024*1024*40
#define MMAP_SIZE_FBLK (MMAP_SIZE_BASE)
#define MMAP_SIZE_HOLE (MMAP_SIZE_BASE*2)
#define MMAP_SIZE_LBLK (MMAP_SIZE_BASE/2)

#define ITERATIONS 1024
#define PEBS_BUFFER 1024*1024
#define PEBS_COUNTDOWN 1003
#define PMC_NUM_BITS 40
#define PAGE_SIZE 4096



int read_pebs(unsigned long long *buf, size_t len, FILE *fd)
{
	size_t read_len;
	size_t nelem;
	unsigned long long i;
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


int gettid()
{
	return syscall(__NR_gettid);
}


void *pthread_main(void * arg)
{
	int cpu;
	int err;
	char *addr1, *hole, *addr2;
	int cpuid;
	long long int pmc0;
	unsigned long long i, it, sum;
	unsigned long long *pebs_buf;
	int id = (*(int *)arg);

	int tid = gettid();

	printf("Hi! I'm thread %d, nice to meet you!\n", tid);

	printf("%d: mapping memory\n", tid);
	addr1 = mmap(NULL, MMAP_SIZE_FBLK, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE,-1,0);
	if (addr1 == MAP_FAILED) {
		perror("cannot allocate memory");
		return NULL;
	}
	printf("%d: first block vaddress: %llx-%llx\n", tid, addr1, addr1+MMAP_SIZE_FBLK);

	hole = mmap(NULL, MMAP_SIZE_HOLE, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE,-1,0);
	if (hole == MAP_FAILED) {
		perror("cannot allocate memory");
		return NULL;
	}
	printf("%d: hole vaddress: %llx-%llx\n", tid, hole, hole+MMAP_SIZE_HOLE);

	addr2 = mmap(NULL, MMAP_SIZE_LBLK, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE,-1,0);
	if (addr2 == MAP_FAILED) {
		perror("cannot allocate memory");
		return NULL;
	}
	printf("%d: last block vaddress: %llx-%llx\n", tid, addr2, addr2+MMAP_SIZE_LBLK);

	printf("%d: computing\n", tid);

	int k = 1;
	int bin;
	const int num_its = 8;
	const int bin_size = 1024*1024*4; //4MiB

	for (bin = 0; bin < MMAP_SIZE_FBLK; bin += bin_size) {
		printf("computing bin %d/%d\n", k,MMAP_SIZE_FBLK/bin_size);
		k++;
		for (it = 0; it < num_its; it++) {
			for (i = 0; i < bin_size; i++) {
				sum += addr1[bin + ((i*4111)%bin_size)];
			}
		}
	}

	k = 1;
	for (bin = 0; bin < MMAP_SIZE_LBLK; bin += bin_size) {
		printf("computing bin %d/%d\n", k,MMAP_SIZE_LBLK/bin_size);
		k++;
		for (it = 0; it < num_its; it++) {
			for (i = 0; i < bin_size; i++) {
				sum += addr2[bin + ((i*4111)%bin_size)];
			}
		}
	}


	if (munmap(addr1, MMAP_SIZE_FBLK) == -1) {
		perror("Cannot munmap first block\n");
	}
	if (munmap(hole, MMAP_SIZE_HOLE) == -1) {
		perror("Cannot munmap hole\n");
	}
	if (munmap(addr2, MMAP_SIZE_LBLK) == -1) {
		perror("Cannot munmap last block\n");
	}

	//for (it = 0; it < ITERATIONS; it++) {
	//	for (i = 0; i < MMAP_SIZE; i++) {
	//		//sum += addr[i*4111%ITERATIONS];
	//		sum += addr[i];
	//	}

	//	// 7 8
	//	//int iit;
	//	//for (iit = 0; iit < 100; iit++) {
	//	//	for (i = PAGE_SIZE*32; i < PAGE_SIZE*64; i++) {
	//	//		sum += addr[i];
	//	//	}
	//	//}

	//	//if (err = read_pmc(0, &pmc0)) {
	//	//	fprintf(stderr, "Error reading PMC0: %s", strerror(-err));
	//	//	return 1;
	//	//}
	//	////printf("pmc0 = %lld (0x%llx)\n", pmc0, pmc0);

	//	//if (read_pebs(pebs_buf, PEBS_BUFFER, fd)) {
	//	//	return 1;
	//	//}
	//}

	printf("%d: sum=%llu\n", tid, sum);

	if (id == 0) {
		//while (1){};
		pthread_exit(NULL);
	}

	return NULL;
}


int main(int argc, char **argv)
{
	int i;
	int nt = 0;
	pthread_t thr[nt];
	int thr_arg = 0;
	int main_arg = 1;
	int tid = gettid();

	if (argc == 2) {
		nt = atoi(argv[1]);
	}

	printf("%d: Creating %d threads! (+ main thread)\n", tid, nt);

	for (i = 0; i < nt; i++) {
		if (pthread_create(&thr[i], NULL, pthread_main, &thr_arg)) {
			perror("cannot create thread");
			return 1;
		}
	}

	pthread_main(&main_arg);

	//exit(0);

	printf("%d: Joining threads\n", tid, nt);
	for (i = 0; i < nt; i++) {
		pthread_join(thr[i], NULL);
	}

	return 0;
}
