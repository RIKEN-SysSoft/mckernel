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

void sendrecv(int rank, int nentry, char **sendv, char **recvv, int szentry, int src, int dest, MPI_Request* reqs, MPI_Status* status, double usec) {
	int i;
	if(rank == 1) {
		for(i = 0; i < nentry; i++) {
			MPI_Isend(sendv[i], szentry, MPI_CHAR, dest, 0, MPI_COMM_WORLD, &reqs[i]);
			if (nentry > 10 && i % (nentry / 10) == 0) {
				printf("s"); fflush(stdout);
			}
		}
		MPI_Waitall(nentry, reqs, status);
		printf("w\n"); fflush(stdout);
	} else {
		for(i = 0; i < nentry; i++) {
			MPI_Irecv(recvv[i], szentry, MPI_CHAR, src, 0, MPI_COMM_WORLD, &reqs[i]);
			if (nentry > 10 && i % (nentry / 10) == 0) {
				printf("r"); fflush(stdout);
			}
		}
		usleep(usec);
		MPI_Waitall(nentry, reqs, status);
		printf("W\n"); fflush(stdout);
	}
}

int main(int argc, char **argv) {
	int my_rank = -1, size = -1;
	int i, j;
	char **sendv, **recvv;
	MPI_Status* status;
	MPI_Request* reqs;
    long szentry;
    long nentry;
	int src, dest;
    struct timespec start, end;
	double diffusec;

    if(argc == 3) {
        szentry = atoi(argv[1]);
        nentry = atoi(argv[2]);
    } else {
        szentry = SZENTRY_DEFAULT;
		nentry = NENTRY_DEFAULT;
    }
	printf("szentry=%ld,nentry=%ld\n", szentry, nentry);

    status = (MPI_Status*)malloc(sizeof(MPI_Status) * nentry);
    reqs = (MPI_Request*)malloc(sizeof(MPI_Request) * nentry);

    int actual;

    MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &actual);
	printf("Thread support level is %d\n", actual);

    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    src = (size + my_rank - 1) % size;
    dest = (my_rank + 1) % size;

    printf("rank=%d, size=%d, src=%d, dest=%d\n", my_rank, size, src, dest);

	sendv = malloc(sizeof(char *) * nentry);
	if(!sendv) { printf("malloc failed"); goto fn_fail; }
	for (i = 0; i < nentry; i++) {
#if 0
		int fd;
		fd = open("./file", O_RDWR);
		if(fd == -1) { printf("open failed\n"); goto fn_fail; }
		sendv[i] = (char*)mmap(0, szentry, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
#else
		sendv[i] = (char*)mmap(0, szentry, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#endif
		if(sendv[i] == MAP_FAILED) { printf("mmap failed"); goto fn_fail; }
		dprintf("[%d] sendv[%d]=%p\n", my_rank, i, sendv[i]);
		memset(sendv[i], 0xaa, szentry);
	}

	recvv = malloc(sizeof(char *) * nentry);
	if(!recvv) { printf("malloc failed"); goto fn_fail; }
	for (i = 0; i < nentry; i++) {
#if 0
		int fd;
		fd = open("./file", O_RDWR);
		if(fd == -1) { printf("open failed\n"); goto fn_fail; }
		recvv[i] = (char*)mmap(0, szentry, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
#else
		recvv[i] = (char*)mmap(0, szentry, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
#endif
		if(recvv[i] == MAP_FAILED) { printf("mmap failed"); goto fn_fail; }
		dprintf("[%d] recvv[%d]=%p\n", my_rank, i, recvv[i]);
		memset(recvv[i], 0, szentry);
	}

	printf("after memset\n");

	print_cpu_last_executed_on();

#pragma omp parallel for
	for (i = 0; i < omp_get_num_threads(); i++) {
		printf("thread_num=%d,tid=%d\n", i, syscall(SYS_gettid));
	}

	for (i = 0; i < 1; i++) {
		MPI_Barrier(MPI_COMM_WORLD);
		if(my_rank == 0) {
			clock_gettime(CLOCK_REALTIME, &start);
		}
		sendrecv(my_rank, nentry, sendv, recvv, szentry, src, dest, reqs, status, 0);
		MPI_Barrier(MPI_COMM_WORLD);
		if(my_rank == 0) {
			clock_gettime(CLOCK_REALTIME, &end);
			diffusec = DIFFNSEC(end, start) / (double)1000;
			printf("%4.4f sec\n", DIFFNSEC(end, start) / (double)1000000000); fflush(stdout);
		}

		MPI_Barrier(MPI_COMM_WORLD);
		if(my_rank == 0) {
			clock_gettime(CLOCK_REALTIME, &start);
		}
		sendrecv(my_rank, nentry, sendv, recvv, szentry, src, dest, reqs, status, diffusec);
		MPI_Barrier(MPI_COMM_WORLD);
		if(my_rank == 0) {
			clock_gettime(CLOCK_REALTIME, &end);
			printf("%4.4f sec\n", DIFFNSEC(end, start) / (double)1000000000); fflush(stdout);
		}
	}

 fn_exit:
    MPI_Finalize();
	return 0;
 fn_fail:
    goto fn_exit;
}
