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
#include "delay.h"

#define MYTIME_UNIT "usec"
#define MYTIME_TOUSEC 1000000
#define MYTIME_TONSEC 1000000000

#define NROW 16 /* 0%, 10%, ..., 140% */
#define NCOL 4

#define NSAMPLES_DROP 5/*10*/
#define NSAMPLES_COMM 10/*20*/
#define NSAMPLES_TOTAL 10/*20*/
#define NSAMPLES_INNER 5

#define PROGRESS_CALC_PHASE_ONLY

static inline double mytime(void)
{
	return /*rdtsc_light()*/MPI_Wtime();
}

static int ppn = -1;

void init_buf(double *origin_buf, double *result, double *target_buf,
	      int szbuf, int rank, int id)
{
	int j;

	for (j = 0; j < szbuf; j++) {
		origin_buf[j] = (rank + 1) * 100.0 + (j + 1);
		result[j] = (id + 1) * 100000000.0 + (rank + 1) * 10000.0 +
			(j + 1);
		target_buf[j] = (rank + 1) * 1000000.0 + (j + 1);
	}
}

void pr_buf(double *origin_buf, double *result, double *target_buf, int szbuf,
	    int rank, int nproc)
{
	int i, j;

	for (i = 0; i < nproc; i++) {
		MPI_Barrier(MPI_COMM_WORLD);

		if (i != rank) {
			usleep(100000);
			continue;
		}

		for (j = 0; j < szbuf; j++) {
			pr_debug("[%d] origin_buf,j=%d,val=%f\n",
				 rank, j, origin_buf[j]);
			pr_debug("[%d] result,j=%d,val=%f\n",
				 rank, j, result[j]);
			pr_debug("[%d] target_buf,j=%d,val=%f\n",
				 rank, j, target_buf[j]);
		}
	}
}

void rma(int rank, int nproc, MPI_Win win, double *origin_buf, double *result,
	 int szbuf, long nsec_calc, int async_progress, int sync_progress,
	 double pct_calc)
{
	int i, j, target_rank;
	int completed, ret;

	for (j = 0; j < NSAMPLES_INNER; j++) {
		for (i = 1; i < nproc; i++) {
			target_rank = (rank + i) % nproc;

			MPI_Get_accumulate(origin_buf, szbuf, MPI_DOUBLE,
					   result, szbuf, MPI_DOUBLE,
					   target_rank,
					   0, szbuf, MPI_DOUBLE,
					   MPI_NO_OP, win);
#if 0
			if (sync_progress) {
				if ((ret = MPI_Iprobe(MPI_ANY_SOURCE,
						      MPI_ANY_TAG,
						      MPI_COMM_WORLD,
						      &completed,
						      MPI_STATUS_IGNORE)) !=
				    MPI_SUCCESS) {
					pr_err("%s: error: MPI_Iprobe: %d\n",
					       __func__, ret);
				}
			}
#endif
		}
	}

	if (async_progress) {
#ifdef PROGRESS_CALC_PHASE_ONLY
		progress_start();
#endif
	}

	ndelay(nsec_calc);

	if (async_progress) {
#ifdef PROGRESS_CALC_PHASE_ONLY
		progress_stop();
#endif
	}

#define MAX2(x, y) ((x) > (y) ? (x) : (y))

#if 1
	/* iprobe is 10 times faster than win_flush_local_all,
	 * 20679 usec / (8*63*5) messages for 8-ppn 8-node case
	 */
	if (1/*!sync_progress*/)
		for (
#if 1
		     j = 0;
		     j < (async_progress ?
			  MAX2(NSAMPLES_INNER * (nproc - 1) *
			       (1.0 - pct_calc),  nproc - 1) :
			  NSAMPLES_INNER * (nproc - 1));
		     j++
#else
		     j = 0;
		     j < MAX2(NSAMPLES_INNER * (nproc - 1) *
			      (1.0 - pct_calc),  nproc - 1);
		     j++
#endif
		     ) {
			if ((ret = MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG,
					      MPI_COMM_WORLD, &completed,
					      MPI_STATUS_IGNORE)) !=
			    MPI_SUCCESS) {
				pr_err("%s: error: MPI_Iprobe: %d\n",
				       __func__, ret);
			}
		}
#endif

	MPI_Win_flush_local_all(win);
}

double measure(int rank, int nproc, MPI_Win win, double *origin_buf,
	       double *result, double *target_buf, int szbuf, long nsec_calc,
	       int async_progress, int sync_progress, int nsamples,
	       int nsamples_drop, double pct_calc)
{
	int i;
	double t_l, t_g, t_sum = 0;
	double start, end;

	for (i = 0; i < nsamples + nsamples_drop; i++) {
		MPI_Barrier(MPI_COMM_WORLD);
		MPI_Win_lock_all(0, win);

		/* Set parameter based on current IPC and frequency */
		ndelay_init(0);

		start = mytime();
		rma(rank, nproc, win, origin_buf, result, szbuf, nsec_calc,
		    async_progress, sync_progress, pct_calc);
		end = mytime();

		MPI_Win_unlock_all(win);
		MPI_Barrier(MPI_COMM_WORLD);

		t_l = end - start;
		MPI_Allreduce(&t_l, &t_g, 1, MPI_DOUBLE, MPI_MAX,
			      MPI_COMM_WORLD);

		if (i < nsamples_drop) {
			continue;
		}

		t_sum += t_g;
	}
	return t_sum / nsamples;
}

int main(int argc, char **argv)
{
	int ret;
	int actual;
	int rank = -1;
	int nproc;
	int i, j, progress, l, m;
	double *target_buf, *origin_buf, *result;
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

	//test_set_loglevel(TEST_LOGLEVEL_WARN);
	ndelay_init(1);

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

	if (ppn == -1) {
		pr_err("Error: Specify processes-per-rank with -p");
		ret = -1;
		goto out;
	}

	MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &actual);
	if (actual != MPI_THREAD_MULTIPLE) {
		pr_err("Error: MPI_THREAD_MULTIPLE is not available\n");
		ret = -1;
		goto out;
	}

	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &nproc);

	if (rank == 0) {
		printf("ndoubles=%d,nproc=%d\n", szbuf, nproc);

#pragma omp parallel
		{
			//printf("%d cpu\n", sched_getcpu());
			if (omp_get_thread_num() == 0) {
				printf("#threads=%d\n", omp_get_num_threads());
			}
		}
	}

	/* accumulate-to buffer */
	target_buf = malloc(sizeof(double) * szbuf);
	if (!target_buf) {
		pr_err("Error: allocating target_buf");
		ret = -1;
		goto out;
	}
	memset(target_buf, 0, sizeof(double) * szbuf);

	/* read-from buffer */
	origin_buf = malloc(sizeof(double) * szbuf);
	if (!origin_buf) {
		pr_err("Error: alloacting origin_buf");
		ret = -1;
		goto out;
	}
	memset(origin_buf, 0, sizeof(double) * szbuf);

	/* fetch-to buffer */
	result = malloc(sizeof(double) * szbuf);
	if (!result) {
		pr_err("Error: allocating result");
		ret = -1;
		goto out;
	}
	memset(result, 0, sizeof(double) * szbuf);

	/* Expose accumulate-to buffer*/
	ret = MPI_Win_create(target_buf, sizeof(double) * szbuf,
			     sizeof(double), MPI_INFO_NULL, MPI_COMM_WORLD,
			     &win);
	if (ret != 0) {
		pr_err("Error: MPI_Win_create returned %d\n", ret);
		ret = -1;
		goto out;
	}

	/* Measure RMA-only time */
	init_buf(origin_buf, result, target_buf, szbuf, rank, 99);
	t_comm_ave = measure(rank, nproc, win, origin_buf, result, target_buf,
			     szbuf, 0, 0, 1, NSAMPLES_COMM, NSAMPLES_DROP, 0);

	if (rank == 0) {
		printf("t_comm_ave: %.0f %s\n",
		       t_comm_ave * MYTIME_TOUSEC, MYTIME_UNIT);
	}

#ifdef PROFILE
	syscall(701, 1 | 2 | 0x80000000); /* syscall profile start */
#endif

	/* 0: no progress, 1: progress, no uti, 2: progress, uti */
	for (progress = 0; progress <= (disable_syscall_intercept ? 0 : 2);
	     progress += 1) {

		if (progress == 1) {
			/* Don't use uti_attr and pin to Linux/McKernel CPUs */
			setenv("DISABLE_UTI", "1", 1);
			progress_init();
		} else if (progress == 2) {
			progress_finalize();
			unsetenv("DISABLE_UTI");
			progress_init();
		}

		if (progress == 1 || progress == 2) {
#ifndef PROGRESS_CALC_PHASE_ONLY
			//progress_start();
#endif
		}

		/* RMA-start, compute for T_{RMA} * l / 10, RMA-flush */
		for (l = 0; l <= NROW - 1; l += 1) {
			long nsec_calc = (t_comm_ave * MYTIME_TONSEC * l) / 10;

			init_buf(origin_buf, result, target_buf, szbuf, rank,
				 l);
#if 0
			pr_buf(origin_buf, result, target_buf, szbuf, rank,
			       nproc);
#endif
			t_total_ave = measure(rank, nproc, win, origin_buf,
					      result, target_buf, szbuf,
					      nsec_calc, progress, 0,
					      NSAMPLES_TOTAL, NSAMPLES_DROP,
					      l / 10.0);
#if 0
			pr_buf(origin_buf, result, target_buf, szbuf, rank,
			       nproc);
#endif

			if (rank == 0) {

				if (l == 0) {
					pr_debug("progress=%d\n", progress);
					if (progress == 0) {
						pr_debug("calc\ttotal\n");
					} else {
						pr_debug("total\n");
					}
				}

				t_table[l][0] = nsec_calc *
					(MYTIME_TOUSEC / (double)MYTIME_TONSEC);
				if (progress == 0) {
					pr_debug("%.0f\t%.0f\n",
						 nsec_calc *
						 (MYTIME_TOUSEC /
						  (double)MYTIME_TONSEC),
						 t_total_ave * MYTIME_TOUSEC);
					t_table[l][progress + 1] =
						t_total_ave * MYTIME_TOUSEC;
				} else {
					pr_debug("%.0f\n",
						 t_total_ave * MYTIME_TOUSEC);
					t_table[l][progress + 1] =
						t_total_ave * MYTIME_TOUSEC;
				}
			}
		}

		if (progress == 1 || progress == 2) {
#ifndef PROGRESS_CALC_PHASE_ONLY
			//progress_stop();
#endif
		}

	}

#ifdef PROFILE
	syscall(701, 4 | 8 | 0x80000000); /* syscall profile report */
#endif

	if (rank == 0) {
		printf("calc,no prog,prog and no uti, prog and uti\n");
		for (l = 0; l <= NROW - 1; l++) {
			for (i = 0; i < NCOL; i++) {
				if (i > 0) {
					printf(",");
				}
				printf("%.0f", t_table[l][i]);
			}
			printf("\n");
		}
	}

	MPI_Barrier(MPI_COMM_WORLD);

	if (progress >= 1) {
		progress_finalize();
	}

	MPI_Finalize();
	ret = 0;
out:
	return ret;
}
