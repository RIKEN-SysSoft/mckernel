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
#include <errno.h>
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
	int rank, nranks;
	double start, end, sum;
	double omp_ovh_max, omp_ovh_min, omp_ovh_sum_g;

	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &nranks);

	start = mytime();

	#pragma omp parallel
	{
		asmloop(N_INIT);
	}

	end = mytime();
	spw = (end - start) / (double)N_INIT;
	if (verbose) {
		double max, min, sum;
		MPI_Barrier(MPI_COMM_WORLD);
		MPI_Reduce(&spw, &max, 1, MPI_DOUBLE,
			   MPI_MAX, 0, MPI_COMM_WORLD);
		MPI_Reduce(&spw, &min, 1, MPI_DOUBLE,
			   MPI_MIN, 0, MPI_COMM_WORLD);
		MPI_Reduce(&spw, &sum, 1, MPI_DOUBLE,
			   MPI_SUM, 0, MPI_COMM_WORLD);

		if (rank == 0) {
			pr_debug("Time of asm loop (nsec): max: %.0f min: %.0f ave: %.0f\n",
				 max * MYTIME_TONSEC,
				 min * MYTIME_TONSEC,
				 sum / nranks * MYTIME_TONSEC);
		}
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

	MPI_Barrier(MPI_COMM_WORLD);
	MPI_Allreduce(&omp_ovh, &omp_ovh_max, 1, MPI_DOUBLE,
		   MPI_MAX, MPI_COMM_WORLD);
	MPI_Allreduce(&omp_ovh, &omp_ovh_min, 1, MPI_DOUBLE,
		   MPI_MIN, MPI_COMM_WORLD);
	MPI_Allreduce(&omp_ovh, &omp_ovh_sum_g, 1, MPI_DOUBLE,
		   MPI_SUM, MPI_COMM_WORLD);

	if (verbose) {
		if (rank == 0) {
			pr_debug("OMP overhead (usec): max: %.0f min: %.0f ave: %.0f\n",
				 omp_ovh_max * MYTIME_TOUSEC,
				 omp_ovh_min * MYTIME_TOUSEC,
				 omp_ovh_sum_g / nranks * MYTIME_TOUSEC);
		}
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

int show_maps() {
	int ret;
	FILE *fp;
	char *maps;
	size_t nread;
	
	maps = malloc(65536);
	if (!maps) {
		pr_err("%s: ERROR: fopen: %s",
		       __func__, strerror(errno));
		ret = -errno;
		goto out;
	}
	
	fp = fopen("/proc/self/maps", "r");
	if (!fp) {
		pr_err("%s: ERROR: fopen: %s",
		       __func__, strerror(errno));
		ret = -errno;
		goto out;
	}
	
	nread = fread(maps, sizeof(char), 65536, fp);
	if (!feof(fp)) {
		pr_err("%s: ERROR: EOF not reached\n",
		       __func__);
		ret = -1;
		goto out;
	}
	
	pr_debug("%s\n", maps);
 out:
	return ret;

}
