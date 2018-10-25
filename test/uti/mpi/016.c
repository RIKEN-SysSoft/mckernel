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

#define MYTIME_TOUSEC 1000000
#define MYTIME_TONSEC 1000000000

#define NSAMPLES_INIT 4/*20*/
#define NSAMPLES_DROP_INIT 1/*10*/

#define NSAMPLES_TRIAL 4/*20*/
#define NSAMPLES_DROP_TRIAL 1/*10*/

#define NSAMPLES_TOTAL 4/*20*/
#define NSAMPLES_DROP_TOTAL 1/*10*/

#define NSAMPLES_INNER 2 /* (#ranks - 1) * NSAMPLES_INNER doubles are sent from each rank */

#define MAX2(x,y) ((x) > (y) ? (x) : (y))

static inline double mytime() {
	return /*rdtsc_light()*/MPI_Wtime();
}

static int ppn = -1;

/* Time components to measure */
struct measure_desc {
	double rma;
	double calc;
	double pswitch; /* Overhead of turning on/off progress */
	double iprobe;
	double flush;
	double total;
};

/* Buffers used for RMA */
struct buf_desc {
	double *origin_buf, *result, *target_buf;
	int sz;
};

/* Time components for simulated computation and communication */
struct time_desc {
	long calc_nsec;
	double calc_ratio;
	double iprobe;
};

struct double_int {
	double val;
	int rank;

};

int alloc_buf(struct buf_desc *buf) {
	int ret;

	/* accumulate-to buffer */
	buf->target_buf = malloc(sizeof(double) * buf->sz);
	if (!buf->target_buf) {
		pr_err("ERROR: allocating target_buf");
		ret = -1;
		goto out;
	}
	memset(buf->target_buf, 0, sizeof(double) * buf->sz);

	/* read-from buffer */
	buf->origin_buf = malloc(sizeof(double) * buf->sz);
	if (!buf->origin_buf) {
		pr_err("ERROR: alloacting origin_buf");
		ret = -1;
		goto out;
	}
	memset(buf->origin_buf, 0, sizeof(double) * buf->sz);

	/* fetch-to buffer */
	buf->result = malloc(sizeof(double) * buf->sz);
	if (!buf->result) {
		pr_err("ERROR: allocating result");
		ret = -1;
		goto out;
	}
	memset(buf->result, 0, sizeof(double) * buf->sz);

	ret = 0;
 out:
	return ret;
}

void init_buf(struct buf_desc *buf, int rank, double id) {
	int j;
	for (j = 0; j < buf->sz; j++) {
		buf->origin_buf[j] = (rank + 1) * 100.0 + (j + 1);
		buf->result[j] = (id + 1) * 100000000.0 + (rank + 1) * 10000.0 + (j + 1);
		buf->target_buf[j] = (rank + 1) * 1000000.0 + (j + 1);
	}
}	

void pr_buf(struct buf_desc *buf, int rank, int nproc) {
	int i, j;
	for (i = 0; i < nproc; i++) {
		MPI_Barrier(MPI_COMM_WORLD);

		if (i != rank) {
			usleep(100000);
			continue;
		}

		for (j = 0; j < buf->sz; j++) {
			pr_debug("[%d] origin_buf,j=%d,val=%f\n", rank, j, buf->origin_buf[j]);
			pr_debug("[%d] result,j=%d,val=%f\n", rank, j, buf->result[j]);
			pr_debug("[%d] target_buf,j=%d,val=%f\n", rank, j, buf->target_buf[j]);
		}
	}
}

void pr_measure_first_row()
{
	printf("%8s\t%8s\t%8s\t", "rma", "calc", "pswitch");
	printf("%8s\t", "iprobe");
	printf("%8s\t%8s\n", "flush", "total");
}

void pr_measure(struct measure_desc *measure)
{
	printf("%8.1f\t%8.1f\t%8.1f\t",
	       measure->rma * MYTIME_TOUSEC,
	       measure->calc * MYTIME_TOUSEC,
	       measure->pswitch * MYTIME_TOUSEC);
	printf("%8.1f\t", measure->iprobe * MYTIME_TOUSEC);
	printf("%8.1f\t%8.1f\n",
	       measure->flush * MYTIME_TOUSEC,
	       measure->total * MYTIME_TOUSEC);
}

/* iprobe is 10 times faster than win_flush_local_all
   which takes 20679 usec for 8-ppn * 63-target * 5-sample messages from each node, for 8-ppn 8-node case */
int iprobe(double duration)
{
	int ret, completed;
	int i;
	double start, end;
	
	if (duration <= 0) {
		ret = 0;
		goto out;
	}

	start = mytime();
	while(1) {
		if ((ret = MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &completed, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
			pr_err("%s: error: MPI_Iprobe: %d\n", __func__, ret);
			goto out;
		}
		
		end = mytime();
		//printf("%s: %f\n", __func__, (end - start) * MYTIME_TOUSEC);
		if (end - start > duration) {
			break;
		}
		usleep(1);
	}
	ret = 0;
 out:
	return ret;
}


void rma(int rank, int nproc, MPI_Win win, struct buf_desc *buf, struct time_desc *time, struct measure_desc *measure, int async_progress, int sync_progress) {
	int i, j, target_rank;
	int completed, ret;
	double start, start2, end;

	start = mytime();
	for (j = 0; j < NSAMPLES_INNER; j++) {
		for (i = 1; i < nproc; i++) {
			target_rank = (rank + i) % nproc;
			
			MPI_Get_accumulate(buf->origin_buf, buf->sz, MPI_DOUBLE,
					   buf->result, buf->sz, MPI_DOUBLE,
					   target_rank,
					   0, buf->sz, MPI_DOUBLE,
					   MPI_NO_OP, win);
#if 0
			if (sync_progress) {
				if ((ret = MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &completed, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
					pr_err("%s: error: MPI_Iprobe: %d\n", __func__, ret);
				}
			}
#endif
		}
	}
	end = mytime();
	measure->rma = end - start;
	
	start2 = mytime();
	if (async_progress) {
		progress_start();
	}

	start = mytime();
	ndelay(time->calc_nsec);
	end = mytime();
	measure->calc = end - start;

	if (async_progress) {
		progress_stop();
	}
	end = mytime();
	measure->pswitch = (end - start2) - measure->calc;


#if 1
	start = mytime();
	if (iprobe(async_progress ?
		  MAX2(time->iprobe * (1.0 - time->calc_ratio),  0) :
		  time->iprobe)) {
		pr_err("%s: ERROR: iprobe: %d\n", __func__, ret);
	}

	end = mytime();
	measure->iprobe = end - start;
#endif

	start = mytime();
	MPI_Win_flush_local_all(win);
	end = mytime();
	measure->flush = end - start;
}

void measure(int rank, int nproc, MPI_Win win, struct buf_desc *buf, struct time_desc *time, struct measure_desc *measure, int async_progress, int sync_progress, int nsamples, int nsamples_drop) {
	int i;
	double t_l, t_g, t_sum = 0;
	double t_rma_l, t_rma_g, t_rma_sum = 0;
	double t_iprobe_l, t_iprobe_g, t_iprobe_sum = 0;
	double t_flush_l, t_flush_g, t_flush_sum = 0;
	double start, end;
	struct measure_desc measure_l, measure_g;
	struct measure_desc measure_s = { 0 };
	struct double_int double_int_l, double_int_g;

	for (i = 0; i < nsamples + nsamples_drop; i++) {
		MPI_Barrier(MPI_COMM_WORLD);
		MPI_Win_lock_all(0, win);
		
		/* Set parameter based on current IPC and frequency */
		ndelay_init(0);

		start = mytime();
		rma(rank, nproc, win, buf, time, &measure_l, async_progress, sync_progress);
		end = mytime();
		measure_l.total = end - start;
		
		MPI_Win_unlock_all(win);

		double_int_l.val = measure_l.total;
		double_int_l.rank = rank;
		MPI_Allreduce(&double_int_l, &double_int_g, 1, MPI_DOUBLE_INT, MPI_MAXLOC, MPI_COMM_WORLD);

		if (rank == 0) {
			//printf("double_int_g.rank=%d,val=%.0f usec\n", double_int_g.rank, double_int_g.val * MYTIME_TOUSEC);
		}

		measure_g.rma = measure_l.rma;
		measure_g.calc = measure_l.calc;
		measure_g.pswitch = measure_l.pswitch;
		measure_g.iprobe = measure_l.iprobe;
		measure_g.flush = measure_l.flush;
		measure_g.total = measure_l.total;

		MPI_Bcast(&measure_g.rma, 1, MPI_DOUBLE, double_int_g.rank, MPI_COMM_WORLD);
		MPI_Bcast(&measure_g.calc, 1, MPI_DOUBLE, double_int_g.rank, MPI_COMM_WORLD);
		MPI_Bcast(&measure_g.pswitch, 1, MPI_DOUBLE, double_int_g.rank, MPI_COMM_WORLD);
		MPI_Bcast(&measure_g.iprobe, 1, MPI_DOUBLE, double_int_g.rank, MPI_COMM_WORLD);
		MPI_Bcast(&measure_g.flush, 1, MPI_DOUBLE, double_int_g.rank, MPI_COMM_WORLD);
		MPI_Bcast(&measure_g.total, 1, MPI_DOUBLE, double_int_g.rank, MPI_COMM_WORLD);

		if (i < nsamples_drop) {
			continue;
		}

		measure_s.rma += measure_g.rma;
		measure_s.calc += measure_g.calc;
		measure_s.pswitch += measure_g.pswitch;
		measure_s.iprobe += measure_g.iprobe;
		measure_s.flush += measure_g.flush;
		measure_s.total += measure_g.total;
	}

	measure->rma = measure_s.rma / nsamples;
	measure->calc = measure_s.calc / nsamples;
	measure->pswitch = measure_s.pswitch / nsamples;
	measure->iprobe = measure_s.iprobe / nsamples;
	measure->flush = measure_s.flush / nsamples;
	measure->total = measure_s.total / nsamples;
}

int main(int argc, char **argv)
{
	int ret;
	int actual;
	int rank = -1;
	int nproc;
	int i, j, progress, m;
	double l;
	double ratio, ratio_min;
	MPI_Win win;
	struct buf_desc buf = { .sz = 1 }; /* Number of doubles to send */
	struct time_desc time_init, time_trial, time_min, time_target;
	struct measure_desc measure_init, measure_trial, measure_min, measure_target;
	int opt;
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
		pr_err("ERROR: Specify processes-per-rank with -p");
		ret = -1;
		goto out;
	}

	MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &actual);
	if (actual != MPI_THREAD_MULTIPLE) {
		pr_err("ERROR: MPI_THREAD_MULTIPLE is not available\n");
		ret = -1;
		goto out;
	}

	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &nproc);

	if (rank == 0) {
		printf("ndoubles=%d,nproc=%d\n", buf.sz, nproc); 

#pragma omp parallel
		{
			//printf("%d cpu\n", sched_getcpu());
			if (omp_get_thread_num() == 0) {
				printf("#threads=%d\n", omp_get_num_threads());
			}
		}
	}

	/* Allocate buffer */
	if (alloc_buf(&buf) != 0) {
		pr_err("ERROR: alloc_buf returned %d\n", ret);
		goto out;
	}

	/* Expose accumulate-to buffer*/
	ret = MPI_Win_create(buf.target_buf, sizeof(double) * buf.sz, sizeof(double), MPI_INFO_NULL, MPI_COMM_WORLD, &win);
	if (ret != 0) {
		pr_err("ERROR: MPI_Win_create returned %d\n", ret);
		ret = -1;
		goto out;
	}

	/* Measure RMA without iprobe optimization */
	init_buf(&buf, rank, 99);
	time_init.calc_nsec = 0;
	time_init.calc_ratio = 0;
	time_init.iprobe = 0;
	measure(rank, nproc, win, &buf, &time_init, &measure_init, 0, 1, NSAMPLES_INIT, NSAMPLES_DROP_INIT);
	if (rank == 0) {
		pr_debug("RMA, flush:\n");
		pr_measure_first_row();
		pr_measure(&measure_init);
	}

	/* Find optimal iprobe time. It's around one tenth of flush. */
	memcpy(&measure_min, &measure_init, sizeof(struct measure_desc));
	memcpy(&time_min, &time_init, sizeof(struct time_desc));

#if 1
	for (ratio = 0.025; ratio < 0.3; ratio += 0.025) {
		init_buf(&buf, rank, 99);
		time_trial.calc_nsec = 0;
		time_trial.calc_ratio = 0;
		time_trial.iprobe = measure_init.flush * ratio;
		measure(rank, nproc, win, &buf, &time_trial, &measure_trial, 0, 1, NSAMPLES_TRIAL, NSAMPLES_DROP_TRIAL);
		if (rank == 0) {
			pr_debug("RMA, iprobe(%.0f usec), flush:\n", time_trial.iprobe * MYTIME_TOUSEC);
			pr_measure(&measure_trial);
		}

		if (measure_trial.total < measure_min.total) {
			memcpy(&measure_min, &measure_trial, sizeof(struct measure_desc));
			memcpy(&time_min, &time_trial, sizeof(struct time_desc));
			ratio_min = ratio;
		}
	}

	if (ratio_min + 0.025 >= 0.3) {
		pr_err("ERROR: Search space didn't cover minimum\n");
		ret = -1;
		goto out;
	}
#endif

	if (rank == 0) {
		pr_debug("RMA, iprobe, flush:\n");
		pr_measure(&measure_min);
	}

#ifdef PROFILE	
	syscall(701, 1 | 2 | 0x80000000); /* syscall profile start */
#endif

	/* 0: no progress, 1: progress, no uti, 2: progress, uti */
	for (progress = 0; progress <= (disable_syscall_intercept ? 0 : 2); progress += 1/*1*/) {

		if (progress == 1) {
			setenv("DISABLE_UTI", "1", 1); /* Don't use uti_attr and pin to Linux/McKernel CPUs */
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

		/* RMA-start, calc for 0%, 10%, ..., 150% of (iprobe + flush), flush */
		for (ratio = 0; ratio <= 1.5; ratio += 0.3) {
			time_target.calc_nsec = (measure_min.iprobe + measure_min.flush) * MYTIME_TONSEC * ratio;
			time_target.calc_ratio = ratio;
			time_target.iprobe = time_min.iprobe;
			init_buf(&buf, rank, ratio);
			measure(rank, nproc, win, &buf, &time_target, &measure_target, progress, 0, NSAMPLES_TOTAL, NSAMPLES_DROP_TOTAL);

			if (rank == 0) {
				if (ratio == 0) {
					pr_debug("progress=%d\n", progress);
					pr_measure_first_row();
				}

#if 0
				pr_debug("%.0f\t",
					 time_target.calc_nsec * (MYTIME_TOUSEC / (double)MYTIME_TONSEC));
#endif
				pr_measure(&measure_target);
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

	MPI_Barrier(MPI_COMM_WORLD);

	if (progress >= 1) {
		progress_finalize();
	}

	MPI_Finalize();
	ret = 0;
out:
	return ret;
}
