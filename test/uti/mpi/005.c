#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <mpi.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sched.h>
#include "util.h"
#include "fwq.h"

//#define DEBUG
#ifdef DEBUG
#define dprintf printf
#else
#define dprintf {}
#endif

#if 1
#define BEGIN_EPOCH(win) do { MPI_Win_fence(0, win); } while (0)
#define END_EPOCH(win) do { MPI_Win_fence(0, win); } while (0)
#define BAR_EPOCH do { } while (0)
#else
#define BEGIN_EPOCH(win) do { MPI_Win_lock_all(0, win); } while (0)
#define END_EPOCH(win) do { MPI_Win_unlock_all(win); } while (0)
#define BAR_EPOCH do { MPI_Barrier(MPI_COMM_WORLD); } while (0)
#endif

static inline int on_same_node(int ppn, int me, int you)
{
	return (me / ppn == you / ppn);
}

/* fence-accumulate-calc-fence */
void accumulate(int nproc, int ppn, int rank, double *wbuf, double *rbuf,
		int ndoubles, MPI_Win win, long calc_nsec)
{
	int i, j;
	int r = 0, s = 0;
	int req = 0;

	BEGIN_EPOCH(win);
	for (i = 0; i < nproc; i++) {
		if (!on_same_node(ppn, rank, i)) {
			for (j = 0; j < ndoubles; j++) {
#if 0
				printf("i=%d,j=%d,rbuf=%f,wbuf=%f\n",
				       i, j, rbuf[i * ndoubles + j],
				       wbuf[i * ndoubles + j]);
#endif
				MPI_Accumulate(rbuf + i * ndoubles + j, 1,
					       MPI_DOUBLE, i, i * ndoubles + j,
					       1, MPI_DOUBLE, MPI_SUM, win);
			}
		}
	}
	fwq(calc_nsec);
	END_EPOCH(win);
}

static struct option options[] = {
	{
		.name =		"ppn",
		.has_arg =	required_argument,
		.flag =		NULL,
		.val =		'P',
	},
	/* end */
	{ NULL, 0, NULL, 0, },
};

int main(int argc, char **argv)
{
	int rc;
	int actual;
	int ppn = -1;
	int nproc;
	int ndoubles = -1;
	int my_rank = -1, size = -1;
	int i, j;
	double *wbuf, *rbuf;
	MPI_Win win;
	struct timespec start, end;
	long t_fence_l, t_pure_l, t_overall_l;
	long t_fence, t_pure, t_overall;
	int opt;

	fwq_init();

	while ((opt = getopt_long(argc, argv, "+d:P:", options, NULL)) != -1) {
		switch (opt) {
		case 'd':
			ndoubles = (1ULL << atoi(optarg));
			break;
		case 'P':
			ppn = atoi(optarg);
			break;
		default: /* '?' */
			printf("unknown option %c\n", optopt);
			exit(1);
		}
	}

	if (ndoubles == -1 || ppn == -1) {
		printf("specify ndoubles with -d and ppn with --ppn");
		exit(1);
	}

	MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &actual);
	if (actual != 3) {
		printf("ERROR: MPI_THREAD_MULTIPLE not available "
		       "(level was set to %d)\n",
		       actual);
		exit(1);
	}

	MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
	MPI_Comm_size(MPI_COMM_WORLD, &nproc);

	if (my_rank == 0) {
		printf("ndoubles=%d,nproc=%d\n", ndoubles, nproc);
		printf("nsec=%ld, nspw=%f\n", nsec, nspw);
	}

	/* write-to buffer */
	wbuf = malloc(sizeof(double) * ndoubles * nproc);
	if (!wbuf) {
		printf("malloc failed");
		goto fn_fail;
	}
	memset(wbuf, 0, sizeof(double) * ndoubles * nproc);

	/* read-from buffer */
	rbuf = malloc(sizeof(double) * ndoubles * nproc);
	if (!rbuf) {
		printf("malloc failed");
		goto fn_fail;
	}
	memset(rbuf, 0, sizeof(double) * ndoubles * nproc);

	if (rc = MPI_Win_create(wbuf, sizeof(double) * ndoubles * nproc,
				sizeof(double), MPI_INFO_NULL, MPI_COMM_WORLD,
				&win)) {
		printf("MPI_Win_create failed,rc=%d\n", rc);
	}

	print_cpu_last_executed_on("main");

	for (i = 0; i < nproc; i++) {
		for (j = 0; j < ndoubles; j++) {
			wbuf[i * ndoubles + j] = i + 1 + j;
			rbuf[i * ndoubles + j] = (i + 1) * 2 + j;
		}
	}

#if 0
	for (i = 0; i < nproc; i++) {
		for (j = 0; j < ndoubles; j++) {
			printf("wbuf,proc=%d,j=%d,val=%f\n",
			       i, j, wbuf[i * ndoubles + j]);
			printf("rbuf,proc=%d,j=%d,val=%f\n",
			       i, j, rbuf[i * ndoubles + j]);
		}
	}
#endif
	/* Measure fence-fence time */
	MPI_Barrier(MPI_COMM_WORLD);
#define NSKIP 5
#define NFENCE 30
	for (i = 0; i < NFENCE + NSKIP; i++) {
		if (i == NSKIP) {
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
		}
		BEGIN_EPOCH(win);
		END_EPOCH(win);
	}
	BAR_EPOCH;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	t_fence_l = DIFFNSEC(end, start) / NFENCE;
	//printf("t_fence (local): %ld usec\n", t_fence_l / 1000UL);
	MPI_Allreduce(&t_fence_l, &t_fence, 1, MPI_LONG, MPI_MAX,
		      MPI_COMM_WORLD);
	if (my_rank == 0)
		printf("t_fence (max): %ld usec\n", t_fence / 1000UL);

	/* Measure fence-acc-fence time */
	MPI_Barrier(MPI_COMM_WORLD);
#define NPURE 30
	for (i = 0; i < NPURE + NSKIP; i++) {
		if (i == NSKIP) {
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
		}
		accumulate(nproc, ppn, my_rank, wbuf, rbuf, ndoubles, win, 0);
	}
	BAR_EPOCH;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	t_pure_l = DIFFNSEC(end, start) / NPURE;
	//printf("t_pure (local): %ld usec\n", t_pure_l / 1000UL);
	MPI_Allreduce(&t_pure_l, &t_pure, 1, MPI_LONG, MPI_MAX,
		      MPI_COMM_WORLD);
	if (my_rank == 0)
		printf("t_pure (max): %ld usec\n", t_pure / 1000UL);

#if 0
	for (i = 0; i < nproc; i++) {
		for (j = 0; j < ndoubles; j++) {
			printf("wbuf,proc=%d,j=%d,val=%f\n",
			       i, j, wbuf[i * ndoubles + j]);
			printf("rbuf,proc=%d,j=%d,val=%f\n",
			       i, j, rbuf[i * ndoubles + j]);
		}
	}
#endif

	/* Measure fenc-acc-calc-fence time */
	MPI_Barrier(MPI_COMM_WORLD);
#define NOVERALL 30
	for (i = 0; i < NOVERALL + NSKIP; i++) {
		if (i == NSKIP) {
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
		}
		accumulate(nproc, ppn, my_rank, wbuf, rbuf, ndoubles, win,
			   t_pure - t_fence);
	}
	BAR_EPOCH;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	t_overall_l = DIFFNSEC(end, start) / NOVERALL;
	//printf("t_overall (local): %ld usec\n", t_overall_l / 1000UL);
	MPI_Allreduce(&t_overall_l, &t_overall, 1, MPI_LONG, MPI_MAX,
		      MPI_COMM_WORLD);
	if (my_rank == 0)
		printf("t_overall (max): %ld usec\n", t_overall / 1000UL);
	if (my_rank == 0) {
		long t_abs = (t_pure * 2) - t_overall;

		printf("overlap: %.2f %%\n", (t_abs * 100) / (double)t_pure);
	}

 fn_exit:
	MPI_Finalize();
	return 0;
 fn_fail:
	goto fn_exit;
}
