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

static struct option options[] = {
	/* end */
	{ NULL, 0, NULL, 0, },
};

static int ppn = -1;

void rma(int my_rank, int nsamples, int nproc, MPI_Win win, double *rbuf, double *result, int szbuf, long t_calc, int progress) {
	int i, j;

	for (j = 0; j < nsamples; j++) {
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
	}
	
	if (progress) {
		progress_start();
	}
#pragma omp parallel
	{
		fwq(t_calc * nsamples);
	}
	if (progress) {
		progress_stop();
	}
	MPI_Win_flush_local_all(win);
}

#define NROW 11
#define NCOL 4

int main(int argc, char **argv)
{
	int ret;
	int actual;
	int nproc;
	int nsamples = -1;
	int rank = -1, size = -1;
	int i, j, progress, l, m;
	double *wbuf, *rbuf, *result;
	MPI_Win win;
	double start, end;
	double t_comm_l, t_comm_g, t_comm_sum, t_comm_ave;
	double t_total_l, t_total_g, t_total_sum, t_total_ave;
	double t_table[NROW][NCOL];
	int opt;
	int szbuf = 1; /* Number of doubles to send */
	struct rusage ru_start, ru_end;
	struct timeval tv_start, tv_end;
 
	test_set_loglevel(TEST_LOGLEVEL_WARN);	
	fwq_init();

	while ((opt = getopt_long(argc, argv, "+n:p:", options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			nsamples = atoi(optarg);
			break;
		case 'p':
			ppn = atoi(optarg);
			break;
		default: /* '?' */
			printf("unknown option %c\n", optopt);
			ret = -1;
			goto out;
		}
	}

	NG(nsamples != -1, "Error: Specify nsamples with -n");
	NG(ppn != -1, "Error: Specify processes-per-rank with -p");

	MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &actual);
	NG(actual == MPI_THREAD_MULTIPLE, "Error: MPI_THREAD_MULTIPLE is not available\n");

	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &nproc);
	
	if (rank == 0) {
		printf("ndoubles=%d,nproc=%d,nsamples=%d\n", szbuf, nproc, nsamples); 

#pragma omp parallel
		{
			//printf("cpu=%d\n", sched_getcpu());
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

#define NSAMPLES_T_COMM 10
	/* Measure RMA-only time */
	t_comm_sum = 0;
	for (i = 0; i < NSAMPLES_T_COMM; i++) {
		MPI_Barrier(MPI_COMM_WORLD);
		MPI_Win_lock_all(0, win);

		start = MPI_Wtime();
		rma(rank, nsamples, nproc, win, rbuf, result, szbuf, 0, 0);
		end = MPI_Wtime();

		MPI_Win_unlock_all(win);
		MPI_Barrier(MPI_COMM_WORLD);
		
		t_comm_l = (end - start) / nsamples;
		MPI_Allreduce(&t_comm_l, &t_comm_g, 1, MPI_DOUBLE, MPI_MAX, MPI_COMM_WORLD);

		t_comm_sum += t_comm_g;
	}
	t_comm_ave = t_comm_sum / NSAMPLES_T_COMM;
	if (rank == 0) {
		printf("t_comm_ave: %.2f usec\n", t_comm_ave * 1000000);
	}

	/* 0: w/o async, 1: w/ async */
	for (progress = 0; progress <= 2; progress++) {

		if (progress == 1) {
			setenv("DISABLE_UTI", "1", 1);
		} else if (progress == 2) {
			progress_finalize();
			unsetenv("DISABLE_UTI");
		}

		/* RMA-start, compute for i / 10 * T(RMA), RMA-flush, ... */
		for (l = 0; l <= 10; l++) {
			unsigned long t_calc = t_comm_ave * 1000000000 * l / 10; /* in nsec */
#define NSAMPLES_T_TOTAL 10
			t_total_sum = 0;
			for (i = 0; i < NSAMPLES_T_TOTAL; i++) {

				MPI_Barrier(MPI_COMM_WORLD);
				MPI_Win_lock_all(0, win);
					
				start = MPI_Wtime();
				rma(rank, nsamples, nproc, win, rbuf, result, szbuf, t_calc, progress);
				end = MPI_Wtime();
					
				MPI_Win_unlock_all(win);
				MPI_Barrier(MPI_COMM_WORLD);
				t_total_l = (end - start) / nsamples;

				MPI_Allreduce(&t_total_l, &t_total_g, 1, MPI_DOUBLE, MPI_MAX, MPI_COMM_WORLD);
				t_total_sum += t_total_g;
			}
			t_total_ave = t_total_sum / NSAMPLES_T_TOTAL;

			if (rank == 0) {
				if (l == 0) {
					pr_debug("progress=%d\n", progress);
				}
				if (progress == 0) { 
					if (l == 0) {
						pr_debug("calc\ttotal\n");
					}
					/* usec */
					pr_debug("%.2f\t%.2f\n", t_calc / (double)1000, t_total_ave * 1000000);
					t_table[l][0] = t_calc / (double)1000;
					t_table[l][progress + 1] = t_total_ave * 1000000;
				} else {
					if (l == 0) {
						pr_debug("total\n");
					}
					/* usec */
					pr_debug("%.2f\n", t_total_ave * 1000000);
					t_table[l][progress + 1] = t_total_ave * 1000000;
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
	
	if (rank == 0) {
		printf("calc,no prog,prog and no uti, prog and uti\n");
		for (l = 0; l <= 10; l++) {
			for (i = 0; i < NCOL; i++) {
				if (i > 0) {
					printf(",");
				}
				printf("%.2f", t_table[l][i]);
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
