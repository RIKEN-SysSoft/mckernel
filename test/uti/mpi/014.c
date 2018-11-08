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

//#define DEBUG
#ifdef DEBUG
#define dprintf printf
#else
#define dprintf {}
#endif

static struct option options[] = {
	/* end */
	{ NULL, 0, NULL, 0, },
};

int main(int argc, char **argv) {
	int rc;
    int actual;
	int nproc;
    int nsamples = -1;
	int my_rank = -1, size = -1;
	int i, j, k, l, m;
	double *wbuf, *rbuf, *result;
	MPI_Win win;
    long start, end;
	long t_pure_l, t_pure, t_pure0 = 0;
	int opt;
	int szbuf = 8;
	struct rusage ru_start, ru_end;
	struct timeval tv_start, tv_end;
 
	fwq_init();

	while ((opt = getopt_long(argc, argv, "+n:", options, NULL)) != -1) {
		switch (opt) {
			case 'n':
				nsamples = atoi(optarg);
				break;
			default: /* '?' */
				printf("unknown option %c\n", optopt);
				exit(1);
		}
	}

	if (nsamples == -1) {
		printf("specify nsamples with -n");
		exit(1);
	}

    MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &actual);
	if (actual != 3) {
		printf("ERROR: MPI_THREAD_MULTIPLE not available (level was set to %d)\n", actual);
		exit(1);
	}

    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nproc);

	if (my_rank == 0) {
		printf("nsamples=%d,nproc=%d\n", nsamples, nproc); 
	}

	/* accumulate-to buffer */
	wbuf = malloc(sizeof(double) * szbuf);
	if(!wbuf) { printf("malloc failed"); goto fn_fail; }
	memset(wbuf, 0, sizeof(double) * szbuf);

	/* read-from buffer */
	rbuf = malloc(sizeof(double) * szbuf);
	if(!rbuf) { printf("malloc failed"); goto fn_fail; }
	memset(rbuf, 0, sizeof(double) * szbuf);

	/* fetch-to buffer */
	result = malloc(sizeof(double) * szbuf);
	if(!result) { printf("malloc failed"); goto fn_fail; }
	memset(result, 0, sizeof(double) * szbuf);

	/* Expose accumulate-to buffer*/
	if (rc = MPI_Win_create(wbuf, sizeof(double) * szbuf, sizeof(double), MPI_INFO_NULL, MPI_COMM_WORLD, &win)) {
		printf("MPI_Win_create failed,rc=%d\n", rc);
	}

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
    }
#endif	

	for (k = 0; k < 2; k++) {

		if (k == 1) {
			
			print_cpu_last_executed_on("main");

			INIT_ASYNC_THREAD_();

			if ((rc = getrusage(RUSAGE_THREAD, &ru_start))) {
				printf("%s: ERROR: getrusage failed (%d)\n", __FUNCTION__, rc);
			}
			
			if ((rc = gettimeofday(&tv_start, NULL))) {
				printf("%s: ERROR: gettimeofday failed (%d)\n", __FUNCTION__, rc);
			}

			syscall(701, 1 | 2 | 0x80000000);
		}

		for (m = 0; m < 3; m++) {

			for (l = 0; l <= 10; l++) {
				long calc_cyc = /*(k == 1 && l == 0) ? (double)t_pure0 * 0.1 :*/ t_pure0 / 10 * l; 

			MPI_Barrier(MPI_COMM_WORLD);
			MPI_Win_lock_all(0, win);
			//clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);

			start = rdtsc_light();
			for (j = 0; j < nsamples; j++) {
				for (i = 0; i < nproc; i++) {
					int target = j % nproc;
					if (target == my_rank) {
						continue;
					}
#if 0
					MPI_Get_accumulate(rbuf + j % szbuf, 1, MPI_DOUBLE,
									   result + j % szbuf, 1, MPI_DOUBLE,
									   i,
									   j % szbuf, 1, MPI_DOUBLE,
									   MPI_SUM, win);
#endif
#if 1
					MPI_Get_accumulate(rbuf, szbuf, MPI_DOUBLE,
									   result, szbuf, MPI_DOUBLE,
									   i,
									   0, szbuf, MPI_DOUBLE,
									   MPI_SUM, win);
#endif
#if 0
					MPI_Accumulate(rbuf, szbuf, MPI_DOUBLE,
							i,
							0, szbuf, MPI_DOUBLE,
							MPI_SUM, win);
#endif
#if 0
					MPI_Get(rbuf + j % szbuf, 1, MPI_DOUBLE,
							i,
							j % szbuf, 1, MPI_DOUBLE,
							win);
#endif
				}
			}
			fwq(calc_cyc * nsamples);
			MPI_Win_flush_local_all(win);
			end = rdtsc_light();

			//clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
			MPI_Win_unlock_all(win);
			MPI_Barrier(MPI_COMM_WORLD);
			t_pure_l = (end - start) / nsamples;
			//t_pure_l = DIFFNSEC(end, start) / nsamples;

			if (1||m == 2) {
				MPI_Allreduce(&t_pure_l, &t_pure, 1, MPI_LONG, MPI_MAX, MPI_COMM_WORLD);
				if (my_rank == 0) {
					if (l == 0) {
						printf("async: %d, trial: %d\n", k, m);
					}
					if (k == 0) { 
						printf("%ld\t%ld\n", calc_cyc, t_pure);
					} else {
						printf("%ld\n", t_pure);
					}
				}
			}

			if (k == 0 && l == 0) {
				t_pure0 = t_pure;
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

		if (k == 1) {
			FINALIZE_ASYNC_THREAD_();
			
#if 0
			if ((rc = getrusage(RUSAGE_THREAD, &ru_end))) {
				printf("%s: ERROR: getrusage failed (%d)\n", __FUNCTION__, rc);
			}
			
			if ((rc = gettimeofday(&tv_end, NULL))) {
				printf("%s: ERROR: gettimeofday failed (%d)\n", __FUNCTION__, rc);
			}
			
			printf("%s: wall: %ld, user: %ld, sys: %ld\n", __FUNCTION__,
				   DIFFUSEC(tv_end, tv_start),
				   DIFFUSEC(ru_end.ru_utime, ru_start.ru_utime),
				   DIFFUSEC(ru_end.ru_stime, ru_start.ru_stime));
			syscall(701, 4 | 8 | 0x80000000);
#endif
		}
	}
	
 fn_exit:
    MPI_Finalize();
	return 0;
 fn_fail:
    goto fn_exit;
}
