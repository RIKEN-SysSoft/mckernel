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

static inline int on_same_node(int ppn, int me, int you)
{
	return (me / ppn == you / ppn);
}

/* isend-calc-wait */
void my_send(int nproc, int ppn, int rank, double *sbuf, double *rbuf,
	     int ndoubles, MPI_Request *reqs, long calc_nsec)
{
	int i;
	int r = 0, s = 0;
	int req = 0;

	for (i = 0; i < nproc; i++) {
		if (!on_same_node(ppn, rank, i)) {
			MPI_Irecv(rbuf + r * ndoubles, ndoubles, MPI_DOUBLE,
				  i, 0, MPI_COMM_WORLD, &reqs[req]);
			r++;
			req++;
			MPI_Isend(sbuf + s * ndoubles, ndoubles, MPI_DOUBLE,
				  i, 0, MPI_COMM_WORLD, &reqs[req]);
			s++;
			req++;
		}
	}
	fwq(calc_nsec);
	MPI_Waitall(req, reqs, MPI_STATUSES_IGNORE);
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
	int actual;
	int ppn = -1;
	int nproc;
	int ndoubles = -1;
	int my_rank = -1, size = -1;
	int i, j;
	double *sbuf, *rbuf;
	MPI_Request *reqs;
	struct timespec start, end;
	long t_pure_l, t_overall_l;
	long t_pure, t_overall;
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
		printf("ERROR: Thread support level is %d (it should be 3)\n",
		       actual);
		exit(1);
	}

	MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
	MPI_Comm_size(MPI_COMM_WORLD, &nproc);

	if (my_rank == 0) {
		printf("tid=%d,pid=%d,ndoubles=%d,nproc=%d\n",
		       syscall(__NR_gettid), getpid(), ndoubles, nproc);
		printf("nsec=%ld, nspw=%f\n", nsec, nspw);
	}

	reqs = (MPI_Request *)malloc(sizeof(MPI_Request) * nproc * 2);
	if (!reqs) {
		printf("malloc failed");
		goto fn_fail;
	}

	sbuf = malloc(sizeof(double) * ndoubles * nproc);
	if (!sbuf) {
		printf("malloc failed");
		goto fn_fail;
	}
	memset(sbuf, 0, sizeof(double) * ndoubles);
	printf("tid=%d,pid=%d,sbuf=%p\n", syscall(__NR_gettid), getpid(), sbuf);

	rbuf = malloc(sizeof(double) * ndoubles * nproc);
	if (!rbuf) {
		printf("malloc failed");
		goto fn_fail;
	}
	memset(rbuf, 0, sizeof(double) * ndoubles);
	printf("tid=%d,pid=%d,rbuf=%p\n", syscall(__NR_gettid), getpid(), rbuf);

	print_cpu_last_executed_on("main");

	/* Measure isend-wait time */
	MPI_Barrier(MPI_COMM_WORLD);
#define NSKIP 5
#define NPURE 30
	for (i = 0; i < NPURE + NSKIP; i++) {
		if (i == NSKIP) {
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
		}
		my_send(nproc, ppn, my_rank, sbuf, rbuf, ndoubles, reqs, 0);
	}
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	t_pure_l = DIFFNSEC(end, start) / NPURE;
	//printf("t_pure (local): %ld usec\n", t_pure_l / 1000UL);
	MPI_Allreduce(&t_pure_l, &t_pure, 1, MPI_LONG, MPI_MAX, MPI_COMM_WORLD);
	if (my_rank == 0)
		printf("t_pure (max): %ld usec\n", t_pure / 1000UL);

	/* Measure isend-calc-wait time */
	MPI_Barrier(MPI_COMM_WORLD);
#define NOVERALL 30
	for (i = 0; i < NOVERALL + NSKIP; i++) {
		if (i == NSKIP) {
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
		}
		my_send(nproc, ppn, my_rank, sbuf, rbuf, ndoubles, reqs,
			t_pure);
	}
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
