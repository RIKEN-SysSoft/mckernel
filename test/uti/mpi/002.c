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
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sched.h>
#include "util.h"

//#define DEBUG
#ifdef DEBUG
#define dprintf printf
#else
#define dprintf {}
#endif

#define SZENTRY_DEFAULT (65536) /* Size of one slot */
#define NENTRY_DEFAULT 10000 /* Number of slots */

int main(int argc, char **argv)
{
	int my_rank = -1, size = -1;
	int i, j;

	struct timespec start, end;

	int actual;

	printf("nloop=%d\n", atoi(argv[1]));

	MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &actual);
	printf("Thread support level is %d\n", actual);

	MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
	MPI_Comm_size(MPI_COMM_WORLD, &size);

	print_cpu_last_executed_on("main");

	printf("Before 1st barrier\n"); fflush(stdout);
	MPI_Barrier(MPI_COMM_WORLD);

	printf("Before 2nd barrier\n"); fflush(stdout);
	if (my_rank == 0) {
		clock_gettime(CLOCK_REALTIME, &start);
	}
	for (i = 0; i < atoi(argv[1]); i++) {
		MPI_Barrier(MPI_COMM_WORLD);
	}
	if (my_rank == 0) {
		clock_gettime(CLOCK_REALTIME, &end);
		printf("%4.4f sec\n",
		       DIFFNSEC(end, start) / (double)1000000000);
		fflush(stdout);
	}

 fn_exit:
	//MPI_Finalize();
	usleep(100000);
	return 0;
 fn_fail:
	goto fn_exit;
}
