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

//#define DEBUG
#ifdef DEBUG
#define dprintf printf
#else
#define dprintf {}
#endif

#define SZENTRY_DEFAULT (65536) /* Size of one slot */
#define NENTRY_DEFAULT 10000 /* Number of slots */

#define DIFFNSEC(end, start) ((end.tv_sec - start.tv_sec) * 1000000000UL + (end.tv_nsec - start.tv_nsec))

static int print_cpu_last_executed_on() {
	char fn[256];
	char* result;
	pid_t tid = syscall(SYS_gettid);
	int fd;
	int offset;
    int mpi_errno = 0;

	sprintf(fn, "/proc/%d/task/%d/stat", getpid(), (int)tid);
	//printf("fn=%s\n", fn);
	fd = open(fn, O_RDONLY);
	if(fd == -1) {
		printf("open() failed\n");
		goto fn_fail;
	}

	result = malloc(65536);
	if(result == NULL) {
		printf("malloc() failed");
		goto fn_fail;
	}

	int amount = 0;
	offset = 0;
	while(1) {
		amount = read(fd, result + offset, 65536);
		//		printf("amount=%d\n", amount);
		if(amount == -1) {
			printf("read() failed");
			goto fn_fail;
		}
		if(amount == 0) {
			goto eof;
		}
		offset += amount;
	}
 eof:;
    //printf("result:%s\n", result);

	char* next_delim = result;
	char* field;
	int i;
	for(i = 0; i < 39; i++) {
		field = strsep(&next_delim, " ");
	}

	int cpu = sched_getcpu();
	if(cpu == -1) {
		printf("getpu() failed\n");
		goto fn_fail;
	}

	printf("compute thread,pmi_rank=%02d,stat-cpu=%02d,sched_getcpu=%02d,tid=%d\n", atoi(getenv("PMI_RANK")), atoi(field), cpu, tid); fflush(stdout);
 fn_exit:
    free(result);
    return mpi_errno;
 fn_fail:
	mpi_errno = -1;
    goto fn_exit;
}

int main(int argc, char **argv) {
	int my_rank = -1, size = -1;
	int i, j;
    struct timespec start, end;

    int actual;

    printf("nloop=%d\n", atoi(argv[1]));

    MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &actual);
	printf("Thread support level is %d\n", actual);

    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    print_cpu_last_executed_on();

	printf("Before 1st barrier\n"); fflush(stdout);
    MPI_Barrier(MPI_COMM_WORLD);

	printf("Before 2nd barrier\n"); fflush(stdout);
    if(my_rank == 0) {
      clock_gettime(CLOCK_REALTIME, &start);
    }
    for (i = 0; i < atoi(argv[1]); i++) {
		MPI_Barrier(MPI_COMM_WORLD);
	}
    if(my_rank == 0) {
		clock_gettime(CLOCK_REALTIME, &end);
        printf("%4.4f sec\n", DIFFNSEC(end, start) / (double)1000000000); fflush(stdout);
	}


 fn_exit:
    //MPI_Finalize();
	usleep(100000);
	return 0;
 fn_fail:
    goto fn_exit;
}
