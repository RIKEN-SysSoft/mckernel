#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include "util.h"

/* Messaging */
enum test_loglevel test_loglevel = TEST_LOGLEVEL_DEBUG;

/* Time */
double spw; /* sec per work */
double omp_ovh;

/* Perform asm loop for <delay> seconds */
void sdelay(double _delay)
{
	double delay = MAX2(_delay - omp_ovh, 0);

	if (delay == 0) {
		return;
	}

	if (delay < 0) {
		printf("delay < 0\n");
		return;
	}

	#pragma omp parallel
	{
		asmloop(delay / spw);
	}
}

void sdelay_init(int verbose)
{
	int i;
	int rank;
	double start, end, sum;

	MPI_Comm_rank(MPI_COMM_WORLD, &rank);

	start = mytime();

	#pragma omp parallel
	{
		asmloop(N_INIT);
	}

	end = mytime();
	spw = (end - start) / (double)N_INIT;
	if (verbose) {
		pr_debug("%.0f nsec per work\n", spw * MYTIME_TONSEC);
	}


#define NSAMPLES_OMP_OVH_OUTER 100 /* 1 sec */
#define NSAMPLES_OMP_OVH_OUTER_DROP 10
#define NSAMPLES_OMP_OVH_INNER 10000 /* 5 msec */

	/* Measure OMP startup/shutdown cost (around 200 usec on KNL) */
	sum = 0;
	for (i = 0;
	     i < NSAMPLES_OMP_OVH_OUTER +
		     NSAMPLES_OMP_OVH_OUTER_DROP;
	     i++) {

		/* Simulating preceding communication phase */
		asmloop(NSAMPLES_OMP_OVH_INNER);

		start = mytime();
		#pragma omp parallel
		{
		asmloop(NSAMPLES_OMP_OVH_INNER);
		}
		end = mytime();

		/* Simulating following communication phase */
		asmloop(NSAMPLES_OMP_OVH_INNER);

		if (i < NSAMPLES_OMP_OVH_OUTER_DROP) {
			continue;
		}

		sum += MAX2((end - start) - (spw * NSAMPLES_OMP_OVH_INNER), 0);
#if 0
		if (rank == 0) {
			pr_debug("%.0f, %.0f\n",
				 (end - start) * MYTIME_TOUSEC,
				 (spw * NSAMPLES_OMP_OVH_INNER) *
				 MYTIME_TOUSEC);
#endif
	}

	omp_ovh = sum / NSAMPLES_OMP_OVH_OUTER;
	if (verbose) {
		pr_debug("OMP overhead: %.0f usec\n", omp_ovh * MYTIME_TOUSEC);
	}
}

double cycpw; /* cyc per work */

void cdlay_init(void)
{
	unsigned long start, end;

	start = rdtsc_light();
	asmloop(N_INIT);
	end = rdtsc_light();
	cycpw = (end - start) / (double)N_INIT;
}

void cdelay(long delay_cyc)
{
	if (delay_cyc < 0) { 
		return;
	}
	asmloop(delay_cyc / cycpw);
}

int print_cpu_last_executed_on(const char *name)
{
	char fn[256];
	char* result;
	pid_t tid = syscall(SYS_gettid);
	int fd;
	int offset;
    int mpi_errno = 0;
	int rc;

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
		printf("getpu() failed\n");
		goto fn_fail;
	}

	rc = syscall(732);
	
	printf("%s: pmi_rank=%02d,os=%s,stat-cpu=%02d,sched_getcpu=%02d,tid=%d\n", name, atoi(getenv("PMI_RANK")), rc == -1 ? "lin" : "mck", atoi(field), cpu, tid); fflush(stdout);
 fn_exit:
    free(result);
    return mpi_errno;
 fn_fail:
	mpi_errno = -1;
    goto fn_exit;
}
