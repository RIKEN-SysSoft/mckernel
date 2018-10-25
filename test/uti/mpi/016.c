#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <errno.h>
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

//#define PROFILE 1 /* McKernel internal system call profile */

#define NSAMPLES_INIT 10/*10*/
#define NSAMPLES_DROP_INIT 2/*2*/

#define SEARCH_MIN 0.01
#define SEARCH_MAX 0.15
#define SEARCH_STEP 0.0025/*0.0025*/

#define NSAMPLES_SEARCH 10/*10*/
#define NSAMPLES_DROP_SEARCH 2/*2*/

#define NSAMPLES_TOTAL 10/*10*/
#define NSAMPLES_DROP_TOTAL 2/*2*/

/* MPI loop is repeated NSAMPLES_INNER times in comm_start() */
#define NSAMPLES_INNER 8

/* Ratio fraction of progress time is spent in computation */
#define RATIO_MAX 1.5/*1.5*/
#define RATIO_STEP 0.5/*0.1*/

/* 0: Without progress, 1: With non-uti progress, 2: With uti progress */
#define PROGRESS_START 0/*0*/
#define PROGRESS_STEP 2/*1*/
#define PROGRESS_END 2/*2*/

static int rank = -1;
static int ppn = -1;

/* Report min, max, ave at each comm_start() call */
static int profile_minmaxave = 0;

/* Time components to measure */
struct measure_desc {
	double comm_start;
	double pswitch; /* Overhead of turning on/off progress */
	double calc;
	double iprobe;
	double flush;
	double lock;
	double total;
};

/* Buffers used for RMA */
struct buf_desc {
	double *origin_buf, *result, *target_buf;
	int sz;
};

/* Amouont of computation in time and optimal iprobe time */
struct time_desc {
	double calc;
	double iprobe;
};

/* Measurement target MPI function */
typedef void (*mpi_func_t)(int rank, int nproc, MPI_Win win,
			  struct buf_desc *buf, struct time_desc *time,
			  struct measure_desc *measure,
			  int async_progress, int sync_progress);

/* Pair of MPI function and buffer configuration */
struct bench_desc {
	mpi_func_t func;
	struct buf_desc *buf;
};

/* Array of benchmark configurations */
static void get_accumulate(int rank, int nproc, MPI_Win win,
			  struct buf_desc *buf, struct time_desc *time,
			  struct measure_desc *measure,
			  int async_progress, int sync_progress);

static void alltoall(int rank, int nproc, MPI_Win win,
	      struct buf_desc *buf, struct time_desc *time,
	      struct measure_desc *measure,
	      int async_progress, int sync_progress);

static struct buf_desc get_accumulate_buf = { .sz = 1 },
	alltoall_buf = { .sz = (1ULL << 16) };

static struct bench_desc benchmarks[] = {
	{.func = get_accumulate, .buf = &get_accumulate_buf},
	{.func = alltoall, .buf = &alltoall_buf}
};

struct double_int {
	double val;
	int rank;

};

int alloc_buf(struct buf_desc *buf)
{
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

void init_buf(struct buf_desc *buf, int rank, double id)
{
	int j;

	for (j = 0; j < buf->sz; j++) {
		buf->origin_buf[j] = (rank + 1) * 100.0 + (j + 1);
		buf->result[j] = (id + 1) * 100000000.0 +
			(rank + 1) * 10000.0 + (j + 1);
		buf->target_buf[j] = (rank + 1) * 1000000.0 + (j + 1);
	}
}

void pr_buf(struct buf_desc *buf, int rank, int nproc)
{
	int i, j;

	for (i = 0; i < nproc; i++) {
		MPI_Barrier(MPI_COMM_WORLD);

		if (i != rank) {
			usleep(100000);
			continue;
		}

		for (j = 0; j < buf->sz; j++) {
			pr_debug("[%d] origin_buf,j=%d,val=%f\n",
				 rank, j, buf->origin_buf[j]);
			pr_debug("[%d] result,j=%d,val=%f\n",
				 rank, j, buf->result[j]);
			pr_debug("[%d] target_buf,j=%d,val=%f\n",
				 rank, j, buf->target_buf[j]);
		}
	}
}

void pr_measure_first_row(void)
{
	printf("%8s\t%8s\t%8s\t%8s\t",
	       "calc(requested)", "comm_start", "pswitch", "calc");
	printf("%8s\t", "iprobe");
	printf("%8s\t%8s\t%8s\n", "flush", "lock", "total");
}

void pr_measure(struct time_desc *time, struct measure_desc *measure)
{
	printf("%8.1f\t%8.1f\t%8.1f\t%8.1f\t",
	       time->calc * MYTIME_TOUSEC,
	       measure->comm_start * MYTIME_TOUSEC,
	       measure->pswitch * MYTIME_TOUSEC,
	       measure->calc * MYTIME_TOUSEC);
	printf("%8.1f\t", measure->iprobe * MYTIME_TOUSEC);
	printf("%8.1f\t%8.1f\t%8.1f\n",
	       measure->flush * MYTIME_TOUSEC,
	       measure->lock * MYTIME_TOUSEC,
	       measure->total * MYTIME_TOUSEC);
}

/* 5,000 usec of iprobe reduces time for flush
 * from 340,000 usec to 20,000 for 8 nodes, 8 ranks per node, 8 get_acc
 */
int iprobe(double duration)
{
	int ret, completed;
	int i;
	double start, end;
	double time_progress;
	struct timeval tv_start, tv_end;
	struct rusage ru_start, ru_end;

	if (duration <= 0) {
		ret = 0;
		goto out;
	}

	start = mytime();
#if 0
	getrusage(RUSAGE_THREAD, &ru_start);
	gettimeofday(&tv_start, NULL);
#endif
	int count = 0;
	while (1) {
		if ((ret = MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG,
				      MPI_COMM_WORLD, &completed,
				      MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
			pr_err("%s: error: MPI_Iprobe: %d\n", __func__, ret);
			goto out;
		}

		end = mytime();

		if (end - start > duration) {
			break;
		}
		usleep(1);
		count++;
	}

#if 0
        end = mytime();
	time_progress = end - start;
	if (rank < 3) pr_debug("[%d] time_progress=%.0f usec,count=%d\n", rank, time_progress * MYTIME_TOUSEC, count);

	getrusage(RUSAGE_THREAD, &ru_end);
	gettimeofday(&tv_end, NULL);
	if (rank < 3) {
		pr_debug("[%d]: wall: %ld, user: %ld, sys: %ld\n",
			 rank,
			 DIFFUSEC(tv_end, tv_start),
			 DIFFUSEC(ru_end.ru_utime, ru_start.ru_utime),
			 DIFFUSEC(ru_end.ru_stime, ru_start.ru_stime));
	}
#endif
	ret = 0;
 out:
	return ret;
}


void get_accumulate(int rank, int nproc, MPI_Win win,
	 struct buf_desc *buf, struct time_desc *time,
	 struct measure_desc *measure,
	 int async_progress, int sync_progress)
{
	int i, j, target_rank;
	int completed, ret;
	double start, start2, end;
	double iprobe_time;
	double time_progress;

	MPI_Win_lock_all(0, win);

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
	end = mytime();
	measure->comm_start = end - start;

	time_progress = 0;
	if (time->calc > 0) {
		if (async_progress) {
			start2 = mytime();
			progress_start();
		}
		
		start = mytime();
		sdelay(time->calc);
		end = mytime();
		measure->calc = end - start;
		
		if (async_progress) {
			progress_stop(&time_progress);
			end = mytime();
			measure->pswitch = (end - start2) - measure->calc;
		}
	}
	
#ifdef IPROBE_PLUS_FLUSH
	switch (async_progress) {
	case 0:
		iprobe_time = time->iprobe;
		break;
	case 1:
		/* There's no way to know the exact time with oversubscription */
		iprobe_time = MAX2(time->iprobe - time->calc,  0);
		break;
	case 2:
		iprobe_time = MAX2(time->iprobe - time_progress,  0);
		break;
	}

	if (iprobe_time > 0) {
		start = mytime();
		if (iprobe(iprobe_time)) {
			pr_err("%s: ERROR: iprobe: %d\n", __func__, ret);
		}
		end = mytime();
		measure->iprobe = end - start;
	}
#endif

	start = mytime();
	MPI_Win_flush_local_all(win);
	end = mytime();
	measure->flush = end - start;

	MPI_Win_unlock_all(win);
}

void alltoall(int rank, int nproc, MPI_Win win,
	 struct buf_desc *buf, struct time_desc *time,
	 struct measure_desc *measure,
	 int async_progress, int sync_progress)
{
	int i, j, target_rank;
	int completed, ret;
	double start, start2, end;
	double iprobe_time;
	double time_progress;
	MPI_Request req;

	start = mytime();
	MPI_Ialltoall(buf->origin_buf, buf->sz, MPI_DOUBLE,
		      buf->result, buf->sz, MPI_DOUBLE,
		      MPI_COMM_WORLD, &req);
	end = mytime();
	measure->comm_start = end - start;

	time_progress = 0;
	if (time->calc > 0) {
		if (async_progress) {
			start2 = mytime();
			progress_start();
		}

		start = mytime();
		sdelay(time->calc);
		end = mytime();
		measure->calc = end - start;

		if (async_progress) {
			progress_stop(&time_progress);
			end = mytime();
			measure->pswitch = (end - start2) - measure->calc;
		}
	}

	start = mytime();
	MPI_Wait(&req, MPI_STATUS_IGNORE);
	end = mytime();
	measure->flush = end - start;
}

void measure(int rank, int nproc, MPI_Win win, struct buf_desc *buf,
	     struct time_desc *time, struct measure_desc *measure,
	     int async_progress, int sync_progress,
	     int nsamples, int nsamples_drop,
	     mpi_func_t mpi_func)
{
	int i;
	double t_l, t_g, t_sum = 0;
	double t_comm_start_l, t_comm_start_g, t_comm_start_sum = 0;
	double t_iprobe_l, t_iprobe_g, t_iprobe_sum = 0;
	double t_flush_l, t_flush_g, t_flush_sum = 0;
	double start, end;
	struct measure_desc measure_l, measure_g;
	struct measure_desc measure_s;
	struct double_int double_int_l, double_int_g;
	struct measure_desc min, max, ave;

	memset(&measure_s, 0, sizeof(struct measure_desc));

	for (i = 0; i < nsamples + nsamples_drop; i++) {
		/* Set pswitch to zero when async_progress is zero */
		memset(&measure_l, 0, sizeof(struct measure_desc));

		MPI_Barrier(MPI_COMM_WORLD);

		start = mytime();
		mpi_func(rank, nproc, win, buf, time, &measure_l,
		    async_progress, sync_progress);
		end = mytime();
		measure_l.total = end - start;
		measure_l.lock = measure_l.total -
			(measure_l.comm_start +
			 measure_l.pswitch +
			 measure_l.calc +
			 measure_l.iprobe +
			 measure_l.flush);

		/* MPI_Allreduce could take forever without this */
		MPI_Barrier(MPI_COMM_WORLD);

		double_int_l.val = measure_l.total;
		double_int_l.rank = rank;
		MPI_Allreduce(&double_int_l, &double_int_g, 1, MPI_DOUBLE_INT,
			      MPI_MAXLOC, MPI_COMM_WORLD);

		measure_g.comm_start = measure_l.comm_start;
		measure_g.pswitch = measure_l.pswitch;
		measure_g.calc = measure_l.calc;
		measure_g.iprobe = measure_l.iprobe;
		measure_g.flush = measure_l.flush;
		measure_g.lock = measure_l.lock;
		measure_g.total = measure_l.total;

		MPI_Bcast(&measure_g.comm_start, 1, MPI_DOUBLE,
			  double_int_g.rank, MPI_COMM_WORLD);
		MPI_Bcast(&measure_g.calc, 1, MPI_DOUBLE, double_int_g.rank,
			  MPI_COMM_WORLD);
		MPI_Bcast(&measure_g.pswitch, 1, MPI_DOUBLE, double_int_g.rank,
			  MPI_COMM_WORLD);
		MPI_Bcast(&measure_g.iprobe, 1, MPI_DOUBLE, double_int_g.rank,
			  MPI_COMM_WORLD);
		MPI_Bcast(&measure_g.flush, 1, MPI_DOUBLE, double_int_g.rank,
			  MPI_COMM_WORLD);
		MPI_Bcast(&measure_g.lock, 1, MPI_DOUBLE, double_int_g.rank,
			  MPI_COMM_WORLD);
		MPI_Bcast(&measure_g.total, 1, MPI_DOUBLE, double_int_g.rank,
			  MPI_COMM_WORLD);

#define allreduce(component, result, op) do {			\
		MPI_Allreduce(&measure_l.component, &result.component, 1, MPI_DOUBLE, \
			      op, MPI_COMM_WORLD); \
		} while (0)

#define min_max_ave(component) do { \
			allreduce(component, min, MPI_MIN);	\
			allreduce(component, max, MPI_MAX);	\
			allreduce(component, ave, MPI_SUM);	\
			ave.component /= nproc; \
		} while (0)
		
		if (profile_minmaxave) {
			min_max_ave(comm_start);
			min_max_ave(pswitch);
			min_max_ave(calc);
			min_max_ave(iprobe);
			min_max_ave(flush);
			min_max_ave(lock);
			min_max_ave(total);
			
			if (rank == 0) {
				pr_measure_first_row();
				pr_measure(time, &min);
				pr_measure(time, &max);
				pr_measure(time, &ave);
			}
		}

		if (i < nsamples_drop) {
			continue;
		}

		measure_s.comm_start += measure_g.comm_start;
		measure_s.calc += measure_g.calc;
		measure_s.pswitch += measure_g.pswitch;
		measure_s.iprobe += measure_g.iprobe;
		measure_s.flush += measure_g.flush;
		measure_s.lock += measure_g.lock;
		measure_s.total += measure_g.total;
	}

	measure->comm_start = measure_s.comm_start / nsamples;
	measure->calc = measure_s.calc / nsamples;
	measure->pswitch = measure_s.pswitch / nsamples;
	measure->iprobe = measure_s.iprobe / nsamples;
	measure->flush = measure_s.flush / nsamples;
	measure->lock = measure_s.lock / nsamples;
	measure->total = measure_s.total / nsamples;
}

int main(int argc, char **argv)
{
	int ret;
	int actual;
	int nproc;
	int i, j, progress, m;
	double l;
	double ratio, ratio_min;
	MPI_Win win;
	struct time_desc time_init, time_search, time_min, time_target;
	struct measure_desc measure_init, measure_search, measure_min,
		measure_target;
	int opt;
	struct rusage ru_start, ru_end;
	struct timeval tv_start, tv_end;
	int disable_syscall_intercept = 0;

	cpu_set_t cpuset;

	/* Index to measurement target MPI function array */
	int mpi_func_idx = 0;

	if (rank == 0) {
		printf("%s: enter\n", __func__);
	}

	//test_set_loglevel(TEST_LOGLEVEL_WARN);

	while ((opt = getopt(argc, argv, "+p:I:m:")) != -1) {
		switch (opt) {
		case 'p':
			ppn = atoi(optarg);
			break;
		case 'I':
			disable_syscall_intercept = atoi(optarg);
			break;
		case 'm':
			mpi_func_idx = atoi(optarg);
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

	if (rank == 1) {
		//show_maps();
	}

	if (rank == 0) {
		printf("nproc=%d\n", nproc);

#pragma omp parallel
		{
			if (omp_get_thread_num() == 0) {
				printf("#threads=%d\n", omp_get_num_threads());
			}
		}
	}

	/* Allocate buffer */
	if (alloc_buf(benchmarks[mpi_func_idx].buf) != 0) {
		pr_err("ERROR: alloc_buf returned %d\n", ret);
		goto out;
	}

	/* Expose accumulate-to buffer*/
	ret = MPI_Win_create(benchmarks[mpi_func_idx].buf->target_buf,
			     sizeof(double) * benchmarks[mpi_func_idx].buf->sz,
			     sizeof(double), MPI_INFO_NULL,
			     MPI_COMM_WORLD, &win);
	if (ret != 0) {
		pr_err("ERROR: MPI_Win_create returned %d\n", ret);
		ret = -1;
		goto out;
	}

	/* Measure RMA without iprobe optimization */
	if (rank == 0) {
		pr_debug("Measuring RMA and flush time\n");
	}
	init_buf(benchmarks[mpi_func_idx].buf, rank, 99);
	time_init.calc = 0;
	time_init.iprobe = 0;

	/* Re-calibrate to deal with DVFS */
	sdelay_init(1);

	measure(rank, nproc, win,
		benchmarks[mpi_func_idx].buf, &time_init, &measure_init,
		0, 1,
		NSAMPLES_INIT, NSAMPLES_DROP_INIT,
		benchmarks[mpi_func_idx].func);
	if (rank == 0) {
		pr_measure_first_row();
		pr_measure(&time_init, &measure_init);
	}

//#define IPROBE_PLUS_FLUSH
#ifdef IPROBE_PLUS_FLUSH
	/* Find optimal iprobe time. It's around one tenth of flush. */
	if (rank == 0) {
		pr_debug("Searching optimal iprobe time\n");
	}
	memcpy(&measure_min, &measure_init, sizeof(struct measure_desc));
	memcpy(&time_min, &time_init, sizeof(struct time_desc));

	/* Re-calibrate to deal with DVFS */
	sdelay_init(1);

	for (ratio = SEARCH_MIN; ratio < SEARCH_MAX; ratio += SEARCH_STEP) {
		init_buf(benchmarks[mpi_func_idx].buf, rank, 99);

		/* Flush time flactuate more with computation */
		time_search.calc = measure_init.comm_start/*0*/;

		time_search.iprobe = measure_init.flush * ratio;
		measure(rank, nproc, win,
			benchmarks[mpi_func_idx].buf, &time_search,
			&measure_search,
			0, 1, NSAMPLES_SEARCH, NSAMPLES_DROP_SEARCH,
			benchmarks[mpi_func_idx].func);
		if (rank == 0) {
			pr_measure(&time_search, &measure_search);
		}

		if (measure_search.total < measure_min.total) {
			memcpy(&measure_min, &measure_search,
			       sizeof(struct measure_desc));
			memcpy(&time_min, &time_search,
			       sizeof(struct time_desc));
			ratio_min = ratio;
		}
	}

	if (ratio_min + SEARCH_STEP >= SEARCH_MAX) {
		pr_warn("WARNING: SEARCH_MAX is too small\n");
	}

	if (rank == 0) {
		pr_debug("Time with optimal iprobe time\n");
		pr_measure(&time_min, &measure_min);
	}
#else
	memcpy(&measure_min, &measure_init, sizeof(struct measure_desc));
	memcpy(&time_min, &time_init, sizeof(struct time_desc));
	measure_min.iprobe = measure_init.flush;
#endif

#ifdef PROFILE
	syscall(701, 1 | 2 | 0x80000000); /* syscall profile start */
#endif

	/* 0: no progress, 1: progress, no uti, 2: progress, uti */
	for (progress = PROGRESS_START;
	     progress <= (disable_syscall_intercept ? 0 : PROGRESS_END);
	     progress += PROGRESS_STEP) {

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

		/* Re-calibrate to deal with DVFS */
		sdelay_init(1);

		//printf("[%d] cpu=%d\n", rank, sched_getcpu());

		/* RMA-start, calc for 0%, ..., 150% of iprobe, flush */
		for (ratio = 0; ratio <= RATIO_MAX; ratio += RATIO_STEP) {
			if (rank == 0) {
				if (ratio == 0) {
					pr_debug("progress=%d\n", progress);
					pr_measure_first_row();
				}
			}

			time_target.calc = measure_min.iprobe * ratio;
			time_target.iprobe = time_min.iprobe;
			init_buf(benchmarks[mpi_func_idx].buf, rank, ratio);
			measure(rank, nproc, win,
				benchmarks[mpi_func_idx].buf, &time_target,
				&measure_target,
				progress, 0,
				NSAMPLES_TOTAL, NSAMPLES_DROP_TOTAL,
				benchmarks[mpi_func_idx].func);

				
			if (rank == 0) {
				pr_measure(&time_target, &measure_target);
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
