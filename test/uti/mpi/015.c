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
#include "async_progress.h"
#include "util.h"
#include "delay.h"

//#define DEBUG
#ifdef DEBUG
#define dprintf printf
#else
#define dprintf {}
#endif

#define BEGIN_EPOCH(win) do { MPI_Win_lock_all(0, win); } while (0)
#define END_EPOCH(win) do { MPI_Win_unlock_all(win); } while (0)

/* ga_acc per rank:ga_sync=40:1 */
void rma(int nproc, int my_rank, double *wbuf, double *rbuf, int ndoubles,
	 MPI_Win win, long calc_nsec)
{
	int i, j;
	int r = 0, s = 0;
	int req = 0;

	for (i = 0; i < nproc; i++) {
		if (i != my_rank) {
			for (j = 0; j < ndoubles; j++) {
				MPI_Accumulate(rbuf + i * ndoubles + j, 1,
					       MPI_DOUBLE, i, i * ndoubles + j,
					       1, MPI_DOUBLE, MPI_SUM, win);
				/* ga_acc() calls flush_local() immediately */
				MPI_Win_flush_local(i, win);
			}
		}
	}
	cdelay(calc_nsec);
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
	double add_rate = 1.0;
	int my_rank = -1, size = -1;
	int i, j, k, l;
	double *wbuf, *rbuf, *result;
	MPI_Win win;
	long start, end;
	//struct timespec start, end;
	long t_pure_l, t_overall_l;
	long t_pure, t_overall;
	int opt;

	cdelay_init();

	while ((opt = getopt_long(argc, argv, "+d:P:R:", options, NULL))
	       != -1) {
		switch (opt) {
		case 'd':
			ndoubles = atoi(optarg);
			break;
		case 'P':
			ppn = atoi(optarg);
			break;
		case 'R':
			add_rate = atof(optarg);
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
		printf("ndoubles=%d,nproc=%d,add_rate=%f\n",
		       ndoubles, nproc, add_rate);
		printf("cyc=%ld, cycpw=%ld\n", cyc, cycpw);
	}

	/* accumulate-to buffer */
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

	/* Expose accumulate-to buffer*/
	if (rc = MPI_Win_create(wbuf, sizeof(double) * ndoubles * nproc,
				sizeof(double), MPI_INFO_NULL, MPI_COMM_WORLD,
				&win)) {
		printf("MPI_Win_create failed,rc=%d\n", rc);
	}

	for (i = 0; i < nproc; i++) {
		for (j = 0; j < ndoubles; j++) {
			wbuf[i * ndoubles + j] = (i + 1) * 1000 + (j + 1);
			rbuf[i * ndoubles + j] = (i + 1) * 10000 + (j + 1);
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

	for (k = 0; k < 2; k++) {
		if (k == 1) {
			INIT_ASYNC_THREAD_();
		}

		/* Measure get_acc-flush time */
		MPI_Barrier(MPI_COMM_WORLD);
#define NPURE 10
		//clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
		start = rdtsc_light();
		MPI_Pcontrol(1, "rma");
		syscall(701, 1);
		syscall(701, 2);
		for (i = 0; i < NPURE; i++) {
			BEGIN_EPOCH(win);
			rma(nproc, my_rank, wbuf, rbuf, ndoubles, win, 0);
			END_EPOCH(win);
		}
		MPI_Pcontrol(-1, "rma");
		syscall(701, 4);
		syscall(701, 8);
		end = rdtsc_light();
		//clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
		MPI_Barrier(MPI_COMM_WORLD);
		t_pure_l = (end - start) / NPURE;
		//t_pure_l = DIFFNSEC(end, start) / NPURE;
		//printf("t_pure (local): %ld usec\n", t_pure_l / 1000UL);
		MPI_Allreduce(&t_pure_l, &t_pure, 1, MPI_LONG, MPI_MAX,
			      MPI_COMM_WORLD);
		if (my_rank == 0)
			printf("t_pure (max): %ld cycles\n", t_pure);


#if 1
		for (l = 1; l <= 10; l++) {
			MPI_Barrier(MPI_COMM_WORLD);
#define NOVERALL 10
			start = rdtsc_light();
			for (i = 0; i < NOVERALL; i++) {
				BEGIN_EPOCH(win);
				rma(nproc, my_rank, wbuf, rbuf, ndoubles, win,
				    100UL * 1000000 * l);
				END_EPOCH(win);
			}
			end = rdtsc_light();
			MPI_Barrier(MPI_COMM_WORLD);
			t_overall_l = (end - start) / NOVERALL;
			MPI_Allreduce(&t_overall_l, &t_overall, 1, MPI_LONG,
				      MPI_MAX, MPI_COMM_WORLD);
			if (my_rank == 0)
				printf("t_overall (max): %ld cycle\n",
				       t_overall);
		}
#endif

		if (k == 1) {
			FINALIZE_ASYNC_THREAD_();
		}

#if 0
		for (i = 0; i < nproc; i++) {
			for (j = 0; j < ndoubles; j++) {
				printf("wbuf,proc=%d,j=%d,val=%f\n",
				       i, j, wbuf[i * ndoubles + j]);
				printf("rbuf,proc=%d,j=%d,val=%f\n",
				       i, j, rbuf[i * ndoubles + j]);
				printf("result,proc=%d,j=%d,val=%f\n",
				       i, j, result[i * ndoubles + j]);
			}
		}
#endif
	}

fn_exit:
	MPI_Finalize();
	return 0;
fn_fail:
	goto fn_exit;
}
