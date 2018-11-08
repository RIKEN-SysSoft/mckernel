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

//#define DEBUG
#ifdef DEBUG
#define dprintf printf
#else
#define dprintf {}
#endif

#define DIFFNSEC(end, start) ((end.tv_sec - start.tv_sec) * 1000000000UL + (end.tv_nsec - start.tv_nsec))

#define BEGIN_EPOCH(win) do { MPI_Win_lock_all(0, win); } while(0)
#define END_EPOCH(win) do { MPI_Win_unlock_all(win); } while(0)


static inline void fixed_size_work() {
	asm volatile(
	    "movq $0, %%rcx\n\t"
		"1:\t"
		"addq $1, %%rcx\n\t"
		"cmpq $99, %%rcx\n\t"
		"jle 1b\n\t"
		:
		: 
		: "rcx", "cc");
}

static inline void bulk_fsw(unsigned long n) {
	int j;
	for (j = 0; j < (n); j++) {
		fixed_size_work(); 
	} 
}

double nspw; /* nsec per work */
unsigned long nsec;

void fwq_init() {
	struct timespec start, end;
	int i;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
#define N_INIT 10000000
	bulk_fsw(N_INIT);
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	nsec = DIFFNSEC(end, start);
	nspw = nsec / (double)N_INIT;
}

#if 0
void fwq(long delay_nsec) {
	if (delay_nsec < 0) { 
        return;
		//printf("%s: delay_nsec < 0\n", __FUNCTION__);
	}
	bulk_fsw(delay_nsec / nspw);
}
#else /* For machines with large core-to-core performance variation (e.g. OFP) */
void fwq(long delay_nsec) {
	struct timespec start, end;
	
	if (delay_nsec < 0) { return; }
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);

	while (1) {
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
		if (DIFFNSEC(end, start) >= delay_nsec) {
			break;
		}
		bulk_fsw(2); /* ~150 ns per iteration on OFP */
	}
}
#endif


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

static inline int on_same_node(int ppn, int me, int you) {
	return (me / ppn == you / ppn);
}

/* get_acc-calc-flush_local */
void rma(int nproc, int ppn, int rank, double *wbuf, double *rbuf, int ndoubles, MPI_Win win, long calc_nsec, int flush_only) {
	int i, j;
	int r = 0, s = 0;
	int req = 0;
	for (i = 0; i < nproc; i++) {
		if (!on_same_node(ppn, rank, i)) {
			for (j = 0; j < ndoubles; j++) {
				//printf("i=%d,j=%d,rbuf=%f,wbuf=%f\n", i, j, rbuf[i * ndoubles + j], wbuf[i * ndoubles + j]);
				if (!flush_only) {
					MPI_Accumulate(rbuf + i * ndoubles + j, 1, MPI_DOUBLE,
								   i, i * ndoubles + j, 1, MPI_DOUBLE,
								   MPI_SUM, win);
				}
				MPI_Win_flush_local(i, win);
			}
		}
	}
	fwq(calc_nsec);
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

int main(int argc, char **argv) {
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
	long t_flush_l, t_pure_l, t_overall_l;
	long t_flush, t_pure, t_overall;
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
		printf("ERROR: MPI_THREAD_MULTIPLE not available (level was set to %d)\n", actual);
		exit(1);
	}

    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nproc);

	if (my_rank == 0) {
		printf("ndoubles=%d,nproc=%d\n", ndoubles, nproc); 
		printf("nsec=%ld, nspw=%f\n", nsec, nspw);
	}

	/* accumulate-to buffer */
	wbuf = malloc(sizeof(double) * ndoubles * nproc);
	if(!wbuf) { printf("malloc failed"); goto fn_fail; }
	memset(wbuf, 0, sizeof(double) * ndoubles * nproc);

	/* read-from buffer */
	rbuf = malloc(sizeof(double) * ndoubles * nproc);
	if(!rbuf) { printf("malloc failed"); goto fn_fail; }
	memset(rbuf, 0, sizeof(double) * ndoubles * nproc);

	/* Expose accumulate-to buffer*/
	if (rc = MPI_Win_create(wbuf, sizeof(double) * ndoubles * nproc, sizeof(double), MPI_INFO_NULL, MPI_COMM_WORLD, &win)) {
		printf("MPI_Win_create failed,rc=%d\n", rc);
	}

	//print_cpu_last_executed_on();

	for (i = 0; i < nproc; i++) {
		for (j = 0; j < ndoubles; j++) {
			wbuf[i * ndoubles + j] = (i + 1) * 1000 + (j + 1);
			rbuf[i * ndoubles + j] = (i + 1) * 10000 + (j + 1);
		}
	}
	
#if 0
	for (i = 0; i < nproc; i++) {
		for (j = 0; j < ndoubles; j++) {
			printf("wbuf,proc=%d,j=%d,val=%f\n", i, j, wbuf[i * ndoubles + j]);
			printf("rbuf,proc=%d,j=%d,val=%f\n", i, j, rbuf[i * ndoubles + j]);
		}
    }
#endif	

	/* Measure flush time */
	MPI_Barrier(MPI_COMM_WORLD);
#define NFENCE 10
	BEGIN_EPOCH(win);
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	for (i = 0; i < NFENCE; i++) {
		rma(nproc, ppn, my_rank, wbuf, rbuf, ndoubles, win, 0, 1);
	}
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	END_EPOCH(win);
	t_flush_l = DIFFNSEC(end, start) / NFENCE;
	//printf("t_flush (local): %ld usec\n", t_flush_l / 1000UL);
	MPI_Allreduce(&t_flush_l, &t_flush, 1, MPI_LONG, MPI_MAX, MPI_COMM_WORLD);
	if (my_rank == 0) printf("t_flush (max): %ld usec\n", t_flush / 1000UL);

	/* Measure get_acc-flush time */
	MPI_Barrier(MPI_COMM_WORLD);
#define NPURE 10
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	//MPI_Pcontrol(1, "rma");
	for (i = 0; i < NPURE; i++) {
		BEGIN_EPOCH(win);
		rma(nproc, ppn, my_rank, wbuf, rbuf, ndoubles, win, 0, 0);
		END_EPOCH(win);
	}
	//MPI_Pcontrol(-1, "rma");
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	t_pure_l = DIFFNSEC(end, start) / NPURE;
	//printf("t_pure (local): %ld usec\n", t_pure_l / 1000UL);
	MPI_Allreduce(&t_pure_l, &t_pure, 1, MPI_LONG, MPI_MAX, MPI_COMM_WORLD);
	if (my_rank == 0) printf("t_pure (max): %ld usec\n", t_pure / 1000UL);

#if 0
	for (i = 0; i < nproc; i++) {
		for (j = 0; j < ndoubles; j++) {
			printf("wbuf,proc=%d,j=%d,val=%f\n", i, j, wbuf[i * ndoubles + j]);
			printf("rbuf,proc=%d,j=%d,val=%f\n", i, j, rbuf[i * ndoubles + j]);
		}
	}
#endif

	/* Measure get_acc-calc-flush time */
	MPI_Barrier(MPI_COMM_WORLD);
#define NOVERALL 10
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	//MPI_Pcontrol(1, "rma-calc");
	for (i = 0; i < NOVERALL; i++) {
		BEGIN_EPOCH(win);
		rma(nproc, ppn, my_rank, wbuf, rbuf, ndoubles, win, t_pure - t_flush, 0);
		END_EPOCH(win);
	}
	//MPI_Pcontrol(-1, "rma-calc");
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	t_overall_l = DIFFNSEC(end, start) / NOVERALL;
	//printf("t_overall (local): %ld usec\n", t_overall_l / 1000UL);
	MPI_Allreduce(&t_overall_l, &t_overall, 1, MPI_LONG, MPI_MAX, MPI_COMM_WORLD);
	if (my_rank == 0) printf("t_overall (max): %ld usec\n", t_overall / 1000UL);
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
