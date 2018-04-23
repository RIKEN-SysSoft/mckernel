#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <uti.h>

int sem;
pthread_barrier_t bar;
int flag;
pthread_t thr;
long t_futex_wait, t_fwq;
long nloop;
long blocktime = 10L * 1000 * 1000;

#define DIFFNSEC(end, start) ((end.tv_sec - start.tv_sec) * 1000000000UL + (end.tv_nsec - start.tv_nsec))
#define TIMER_KIND CLOCK_MONOTONIC_RAW /* CLOCK_THREAD_CPUTIME_ID */

static inline uint64_t rdtsc_light(void )
{
    uint64_t x;
    __asm__ __volatile__("rdtscp;" /* rdtscp don't jump over earlier instructions */
                         "shl $32, %%rdx;"
                         "or %%rdx, %%rax" :
                         "=a"(x) :
                         :    
                         "%rcx", "%rdx", "memory");
    return x;
}

static int print_cpu_last_executed_on() {
	char fn[256];
	char* result;
	pid_t tid = syscall(SYS_gettid);
	int fd;
	int offset;
    int mpi_errno = 0;

	sprintf(fn, "/proc/%d/task/%d/stat", getpid(), (int)tid);
	//printf("fn=%s\n", fn);
	fd = open(fn, O_RDONLY);
	if(fd == -1) {
		printf("open() failed\n");
		goto fn_fail;
	}

	result = malloc(65536);
	if(result == NULL) {
		printf("malloc() failed");
		goto fn_fail;
	}

	int amount = 0;
	offset = 0;
	while(1) {
		amount = read(fd, result + offset, 65536);
		//		printf("amount=%d\n", amount);
		if(amount == -1) {
			printf("read() failed");
			goto fn_fail;
		}
		if(amount == 0) {
			goto eof;
		}
		offset += amount;
	}
 eof:;
    //printf("result:%s\n", result);

	char* next_delim = result;
	char* field;
	int i;
	for(i = 0; i < 39; i++) {
		field = strsep(&next_delim, " ");
	}

	int cpu = sched_getcpu();
	if(cpu == -1) {
		printf("getcpu() failed\n");
		goto fn_fail;
	}

	printf("stat-cpu=%02d,sched_getcpu=%02d,tid=%d\n", atoi(field), cpu, tid);
 fn_exit:
    free(result);
    return mpi_errno;
 fn_fail:
	mpi_errno = -1;
    goto fn_exit;
}

static inline void fixed_size_work() {
	asm volatile(
	    "movq $0, %%rcx\n\t"
		"1:\t"
		"addq $1, %%rcx\n\t"
		"cmpq $99, %%rcx\n\t"
		"jle 1b\n\t"
		:
		: 
		: "rcx", "cc");
}

static inline void bulk_fsw(unsigned long n) {
	int j;
	for (j = 0; j < (n); j++) {
		fixed_size_work(); 
	} 
}

double nspw; /* nsec per work */
unsigned long nsec;

void fwq_init() {
	struct timespec start, end;
	int i;
	clock_gettime(TIMER_KIND, &start);
#define N_INIT 10000000
	bulk_fsw(N_INIT);
	clock_gettime(TIMER_KIND, &end);
	nsec = DIFFNSEC(end, start);
	nspw = nsec / (double)N_INIT;
}

#if 1
void fwq(long delay_nsec) {
	if (delay_nsec < 0) { 
        return;
		//printf("%s: delay_nsec < 0\n", __FUNCTION__);
	}
	bulk_fsw(delay_nsec / nspw);
}
#else /* For machines with large core-to-core performance variation (e.g. OFP) */
void fwq(long delay_nsec) {
	struct timespec start, end;
	
	if (delay_nsec < 0) { return; }
	clock_gettime(TIMER_KIND, &start);

	while (1) {
		clock_gettime(TIMER_KIND, &end);
		if (DIFFNSEC(end, start) >= delay_nsec) {
			break;
		}
		bulk_fsw(2); /* ~150 ns per iteration on FOP */
	}
}
#endif

void *util_thread(void *arg)
{
	int i;
	int rc;
    long start, end;
	int testid = 32101;

	print_cpu_last_executed_on();

	rc = syscall(732);
	if (rc == -1)
		fprintf(stderr, "[INFO] Running on Linux\n");
	else {
		fprintf(stderr, "[INFO] Running on McKernel\n");
	}
	errno = 0;

	pthread_barrier_wait(&bar);
	for (i = 0; i < nloop; i++) {
		start = rdtsc_light();

		fwq(blocktime);

		end = rdtsc_light();
		t_fwq += end - start;

		rc = syscall(__NR_futex, &sem, FUTEX_WAKE, 1, NULL, NULL, 0);
		if (rc != 1) {
			printf("ERROR: futex wake failed (%d,%s)\n", rc, strerror(errno));
		}
		
		//pthread_barrier_wait(&bar);
	}

	pthread_exit(NULL);
}

static struct option options[] = {
	/* end */
	{ NULL, 0, NULL, 0, }
};

int main(int argc, char **argv)
{
	int i;
	int rc;
    long start, end;
	cpu_set_t cpuset;
	pthread_attr_t attr;
	pthread_barrierattr_t bar_attr;
	struct sched_param param = { .sched_priority = 99 };
	int opt;

	while ((opt = getopt_long(argc, argv, "+b:", options, NULL)) != -1) {
		switch (opt) {
			case 'b':
				blocktime = atoi(optarg);
				break;
			default: /* '?' */
				printf("unknown option %c\n", optopt);
				exit(1);
		}
	}
	nloop = (10 * 1000000000UL) / blocktime;
	printf("nloop=%ld,blocktime=%ld\n", nloop, blocktime);

	
 	CPU_ZERO(&cpuset);
	CPU_SET(61, &cpuset);
	sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
	print_cpu_last_executed_on();

	fwq_init();

	pthread_barrierattr_init(&bar_attr);
	pthread_barrier_init(&bar, &bar_attr, 2);

#if 1
	fprintf(stderr, "CT10001 futex START\n");
	rc = syscall(731, 1, NULL);
	if (rc) {
		fprintf(stderr, "util_indicate_clone rc=%d, errno=%d\n", rc, errno);
		fflush(stderr);
	}
#endif

	if ((rc = pthread_attr_init(&attr))) {
 		printf("%s: ERROR: pthread_attr_init failed (%d)\n", __FUNCTION__, rc);
		exit(1);
	}

#if 0
	uti_attr_t uti_attr;
	rc = uti_attr_init(&uti_attr);
	if (rc) {
		printf("%s: ERROR: uti_attr_init failed (%d)\n", __FUNCTION__, rc);
		exit(1);
	}

	/* Give a hint that it's beneficial to prioritize it in scheduling. */
	rc = UTI_ATTR_HIGH_PRIORITY(&uti_attr);
	if (rc) {
		printf("%s: ERROR: UTI_ATTR_HIGH_PRIORITY failed (%d)\n", __FUNCTION__, rc);
		exit(1);
	}
	
	if ((rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))) {
		printf("%s: ERROR: pthread_attr_setdetachstate failed (%d)\n", __FUNCTION__, rc);
		exit(1);
	}
	
	if ((rc = uti_pthread_create(&thr, &attr, progress_function, NULL, &uti_attr))) {
		printf("%s: ERROR: uti_pthread_create failed (%d)\n", __FUNCTION__, rc);
		exit(1);
	}
	
	if ((rc = uti_attr_destroy(&uti_attr))) {
		printf("%s: ERROR: uti_attr_destroy failed (%d)\n", __FUNCTION__, rc);
		exit(1);
	}
#else
 	CPU_ZERO(&cpuset);
	CPU_SET(63, &cpuset);

	if ((rc = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset))) {
 		printf("%s: ERROR: pthread_attr_setaffinity_np failed (%d)\n", __FUNCTION__, rc);
		exit(1);
	}

	rc = pthread_create(&thr, &attr, util_thread, NULL);
	if(rc){
		fprintf(stderr, "ERROR: pthread_create failed (%d)\n", rc);
		exit(1);
	}
	fprintf(stderr, "CT10002 pthread_create OK\n");
#endif

	if ((rc = sched_setscheduler(0, SCHED_FIFO, &param))) {
		fprintf(stderr, "ERROR: sched_setscheduler failed (%d)\n", rc);
		exit(1);
	}

	syscall(701, 1 | 2);
	pthread_barrier_wait(&bar);
	start = rdtsc_light();
	for (i = 0; i < nloop; i++) {
		
		rc = syscall(__NR_futex, &sem, FUTEX_WAIT, 0, NULL, NULL, 0);
		if (rc != 0) {
			printf("ERROR: futex wait failed (%s)\n", strerror(errno));
		}

		//pthread_barrier_wait(&bar); /* 2nd futex */
	}
	end = rdtsc_light();
	t_futex_wait += end - start;
	syscall(701, 4 | 8);

	pthread_join(thr, NULL);
	fprintf(stderr, "t_fwq: %ld, t_futex_wait: %ld, wait-fwq/nloop: %ld nsec\n", t_fwq, t_futex_wait, (t_futex_wait - t_fwq) / nloop);

	fprintf(stderr, "CT10004 END\n");
	exit(0);
}
