#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <mpi.h>
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <getopt.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "async_progress.h"
#include "util.h"

#define MYTIME_UNIT "cyc"

static inline double mytime() {
	return rdtsc_light()/*MPI_Wtime()*/;
}

static int ppn = -1;

void rma(int my_rank, int nproc, MPI_Win win, double *rbuf, double *result, int szbuf, long cyc_calc, int progress) {
	int i, j;

		for (i = 0; i < nproc; i++) {
			int target = j % nproc;

			/* Inter-node communication only */
			if (target /*/ ppn*/ == my_rank /*/ ppn*/) {
				continue;
			}
			
			MPI_Get_accumulate(rbuf, szbuf, MPI_DOUBLE,
					   result, szbuf, MPI_DOUBLE,
					   i,
					   0, szbuf, MPI_DOUBLE,
					   MPI_SUM, win);
		}
	
	if (progress) {
		progress_start();
	}
#pragma omp parallel
	{
		cdelay(cyc_calc);
	}
	if (progress) {
		progress_stop();
	}
	MPI_Win_flush_local_all(win);
}

double measure(int rank, int nproc, MPI_Win win, double *rbuf, double* result, int szbuf, long cyc_calc, int progress, int nsamples, int nsamples_drop) {
	int i;
	double t_l, t_g, t_sum = 0;
	double start, end;

	for (i = 0; i < nsamples + nsamples_drop; i++) {
		MPI_Barrier(MPI_COMM_WORLD);
		MPI_Win_lock_all(0, win);
		
		start = mytime();
		rma(rank, nproc, win, rbuf, result, szbuf, cyc_calc, progress);
		end = mytime();
		
		MPI_Win_unlock_all(win);
		MPI_Barrier(MPI_COMM_WORLD);

		t_l = end - start;
		MPI_Allreduce(&t_l, &t_g, 1, MPI_DOUBLE, MPI_MAX, MPI_COMM_WORLD);

		if (i < nsamples_drop) {
			continue;
		}

		t_sum += t_g;
	}
	return t_sum / nsamples;
}

#define NROW 11
#define NCOL 4

int main(int argc, char **argv)
{
	int ret;
	int actual;
	int nproc;
	int rank = -1, size = -1;
	int i, j, progress, l, m;
	double *wbuf, *rbuf, *result;
	MPI_Win win;
	double t_comm_l, t_comm_g, t_comm_sum, t_comm_ave;
	double t_total_l, t_total_g, t_total_sum, t_total_ave;
	double t_table[NROW][NCOL];
	int opt;
	int szbuf = 1; /* Number of doubles to send */
	struct rusage ru_start, ru_end;
	struct timeval tv_start, tv_end;
	int disable_syscall_intercept = 0;
 
	cpu_set_t cpuset;

	test_set_loglevel(TEST_LOGLEVEL_WARN);	
	fwq_init();

	while ((opt = getopt(argc, argv, "+p:I:")) != -1) {
		switch (opt) {
		case 'p':
			ppn = atoi(optarg);
			break;
		case 'I':
			disable_syscall_intercept = atoi(optarg);
			break;
		default: /* '?' */
			printf("unknown option %c\n", optopt);
			ret = -1;
			goto out;
		}
	}

	NG(ppn != -1, "Error: Specify processes-per-rank with -p");

	MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &actual);
	NG(actual == MPI_THREAD_MULTIPLE, "Error: MPI_THREAD_MULTIPLE is not available\n");

	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &nproc);

#if 0 /* Avoid phys with Linux threads is allocated to progress */
	CPU_ZERO(&cpuset);
	CPU_SET(sched_getcpu() + 1, &cpuset);
	if ((sched_setaffinity(0, sizeof(cpu_set_t), &cpuset))) {
		printf("[%d] setaffinity failed\n", rank);
	}
#endif	
	if (rank == 0) {
		printf("ndoubles=%d,nproc=%d\n", szbuf, nproc); 

#pragma omp parallel
		{
			printf("%d cpu\n", sched_getcpu());
			if (omp_get_thread_num() == 0) {
				printf("#threads=%d\n", omp_get_num_threads());
			}
		}
	}

	/* accumulate-to buffer */
	wbuf = malloc(sizeof(double) * szbuf);
	NG(wbuf, "Error: allocating wbuf");
	memset(wbuf, 0, sizeof(double) * szbuf);

	/* read-from buffer */
	rbuf = malloc(sizeof(double) * szbuf);
	NG(rbuf, "Error: alloacting rbuf");
	memset(rbuf, 0, sizeof(double) * szbuf);

	/* fetch-to buffer */
	result = malloc(sizeof(double) * szbuf);
	NG(result, "Error: allocating result");
	memset(result, 0, sizeof(double) * szbuf);

	/* Expose accumulate-to buffer*/
	ret = MPI_Win_create(wbuf, sizeof(double) * szbuf, sizeof(double), MPI_INFO_NULL, MPI_COMM_WORLD, &win);
	NG(ret == 0, "Error: MPI_Win_create returned %d\n", ret);

	for (j = 0; j < szbuf; j++) {
		wbuf[j] = j + 1;
		rbuf[j] = 10000 + j + 1;
		result[j] = 100000 + j + 1;
	}
	
#if 0
	for (j = 0; j < szbuf; j++) {
		printf("wbuf,j=%d,val=%f\n", j, wbuf[j]);
		printf("rbuf,j=%d,val=%f\n", j, rbuf[j]);
		printf("result,j=%d,val=%f\n", j, result[j]);
	}
	
#endif	

#define NSAMPLES_DROP 10
#define NSAMPLES_T_COMM 20
	/* Measure RMA-only time */
	t_comm_ave = measure(rank, nproc, win, rbuf, result, szbuf, 0, 0, NSAMPLES_T_COMM, NSAMPLES_DROP);

	if (rank == 0) {
		printf("t_comm_ave: %.2f %s\n", t_comm_ave, MYTIME_UNIT);
	}

	syscall(701, 1 | 2 | 0x80000000); /* syscall profile start */

	/* 0: no progress, 1: progress, no uti, 2: progress, uti */
	for (progress = 0; progress <= (disable_syscall_intercept ? 0 : 0); progress += 1) {

		if (progress == 1) {
			setenv("DISABLE_UTI", "1", 1); /* Don't use uti_attr and pin to Linux/McKernel CPUs */
			progress_init();
		} else if (progress == 2) {
			progress_finalize();
			unsetenv("DISABLE_UTI");
			progress_init();
		}

		/* RMA-start, compute for i / 10 * T(RMA), RMA-flush, ... */
		for (l = 0; l <= 0; l++) {
			long cyc_calc = t_comm_ave * l / 10; /* in nsec */
#define NSAMPLES_T_TOTAL 20

			t_total_ave = measure(rank, nproc, win, rbuf, result, szbuf, cyc_calc, progress, NSAMPLES_T_TOTAL, NSAMPLES_DROP);

			if (rank == 0) {
				if (l == 0) {
					pr_debug("progress=%d\n", progress);
				}
				if (progress == 0) { 
					if (l == 0) {
						pr_debug("calc\ttotal\n");
					}
					/* usec */
					pr_debug("%ld\t%.2f\n", cyc_calc, t_total_ave);
					t_table[l][0] = cyc_calc;
					t_table[l][progress + 1] = t_total_ave;
				} else {
					if (l == 0) {
						pr_debug("total\n");
					}
					/* usec */
					pr_debug("%.2f\n", t_total_ave);
					t_table[l][progress + 1] = t_total_ave;
				}
			}

#if 0
			for (i = 0; i < nproc; i++) {
				for (j = 0; j < sbuf; j++) {
					printf("wbuf,j=%d,val=%f\n", j, wbuf[j]);
					printf("rbuf,j=%d,val=%f\n", j, rbuf[j]);
					printf("result,j=%d,val=%f\n", j, result[j]);
				}
			}
#endif
		}

	}
	
	syscall(701, 4 | 8 | 0x80000000); /* syscall profile report */

	if (rank == 0) {
		printf("calc,no prog,prog and no uti, prog and uti\n");
		for (l = 0; l <= 10; l++) {
			for (i = 0; i < NCOL; i++) {
				if (i > 0) {
					printf(",");
				}
				printf("%.0f", t_table[l][i]);
			}
			printf("\n");
		}
	}

	if (progress >= 1) {
		progress_finalize();
	}

	MPI_Finalize();
	ret = 0;
out:
	return ret;
}
