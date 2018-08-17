#define _GNU_SOURCE
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <aio.h>
#include <signal.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <mpi.h>
#include <linux/limits.h>
#include <semaphore.h>
#include "util.h"

#define SZBUF (1ULL << 23)/*23*/

#define MYTIME_TOUSEC 1000000
#define MYTIME_TONSEC 1000000000

#define NROW 16
#define NCOL 4

#define NSAMPLES_PROFILE 3
#define NSAMPLES_DROP 1/*10*/
#define NSAMPLES_IO 5/*20*/
#define NSAMPLES_TOTAL 5/*20*/
#define NSAMPLES_INNER 1

#define WAIT_TYPE_BUSY_LOOP 0
#define WAIT_TYPE_SEM 1
#define WAIT_TYPE WAIT_TYPE_SEM

static sem_t aio_sem;
volatile int completion_count;

static inline double mytime() {
	return /*rdtsc_light()*/MPI_Wtime();
}

struct aioreq {
	int rank, aio_num_threads;
	int status;
	struct aiocb *aiocbp;
};

static void aio_handler(sigval_t sigval)
{
	struct aioreq *aioreq = sigval.sival_ptr;
	int ret;

	//pr_debug("%s: debug: rank=%d\n", __func__, aioreq->rank);
	ret = __sync_add_and_fetch(&completion_count, 1);
	if (ret == aioreq->aio_num_threads) {
		if (sem_post(&aio_sem)) {
			pr_err("%s: error: sem_post: %s\n",
			       __func__, strerror(errno));
		}
	}

	//pr_debug("%s: debug: completion_count: %d\n", __func__, ret);
}

static void aio_sighandler(int sig, siginfo_t *si, void *ucontext)
{
	pr_debug("%s: debug: enter\n", __func__);
#if WAIT_TYPE == WAIT_TYPE_SEM
	struct aioreq *aioreq = si->si_value.sival_ptr;

	if (si->si_code != SI_ASYNCIO) {
		pr_err("%s: error: unexpected si_code: %d\n",
	       __func__, si->si_code);
	}
	
	aioreq->status = aio_error(aioreq->aiocbp);
	if (aioreq->status != 0) {
		pr_err("%s: error: unexpected status: %d\n",
	       __func__, aioreq->status);
	}

	if (__sync_add_and_fetch(&completion_count, 1) == aioreq->aio_num_threads) {
		if (sem_post(&aio_sem)) {
			pr_err("%s: error: sem_post: %s\n",
			       __func__, strerror(errno));
		}
	}

	//pr_debug("%s: debug: completion_count: %d\n", __func__, completion_count);
#endif /* WAIT_TYPE */
}

int my_aio_init(int nreqs, struct aioreq *iolist, struct aiocb *aiocblist, char **aiobufs) {
	int ret;
	int i;
	
	for (i = 0; i < nreqs; i++) {
		iolist[i].rank = i;
		iolist[i].aio_num_threads = nreqs;
		iolist[i].aiocbp = &aiocblist[i];
		iolist[i].aiocbp->aio_fildes = -1;
		iolist[i].aiocbp->aio_buf = aiobufs[i];
		iolist[i].aiocbp->aio_nbytes = SZBUF;
		iolist[i].aiocbp->aio_reqprio = 0;
		iolist[i].aiocbp->aio_offset = 0;
#if 0
		iolist[i].aiocbp->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
		iolist[i].aiocbp->aio_sigevent.sigev_signo = SIGUSR1;
		iolist[i].aiocbp->aio_sigevent.sigev_value.sival_ptr = &iolist[i];
#else
		iolist[i].aiocbp->aio_sigevent.sigev_notify = SIGEV_THREAD;
		iolist[i].aiocbp->aio_sigevent.sigev_notify_function = aio_handler;
		iolist[i].aiocbp->aio_sigevent.sigev_notify_attributes = NULL;
		iolist[i].aiocbp->aio_sigevent.sigev_value.sival_ptr = &iolist[i];
#endif
	}

	ret = 0;
	return ret;
}

int my_aio_open(int aio_num_threads, struct aioreq *iolist, char **fn) {
	int ret;
	int i;
	
	for (i = 0; i < aio_num_threads; i++) {
		iolist[i].aiocbp->aio_fildes = open(fn[i], O_RDWR | O_CREAT | O_TRUNC | O_DIRECT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
		if (iolist[i].aiocbp->aio_fildes == -1) {
			pr_err("%s: error: open %s: %s\n",
			       __func__, fn[i], strerror(errno));
			ret = 1;
			goto out;
		}
	}
	ret = 0;
 out:
	return ret;
}

int my_aio_check(struct aioreq *iolist, int aio_num_threads, char **fn) {
	int ret;
	int i;
	FILE **fp = { 0 };
	char *data;

	if (!(fp = malloc(sizeof(FILE *) * aio_num_threads))) {
		pr_err("error: allocating fp\n");
		ret = -ENOMEM;
		goto out;
	}

	/* Check contents */
	for (i = 0; i < aio_num_threads; i++) {
		if (!(data = malloc(SZBUF))) {
			pr_err("error: allocating data\n");
			ret = -ENOMEM;
			goto out;
		}

		if (!(fp[i] = fopen(fn[i], "r+"))) {
			pr_err("%s: error: fopen %s: %s\n",
			       __func__, fn[i], strerror(errno));
			ret = -errno;
			goto out;
		}

		if (fread(data, sizeof(char), SZBUF, fp[i]) != SZBUF) {
			pr_err("%s: error: fread\n",
			       __func__);
			ret = -1;
			goto out;
		}

		if (memcmp((const void*)iolist[i].aiocbp->aio_buf, data, SZBUF)) {
			pr_err("%s: Data written to file %s differs from data in memory\n",
			       __func__, fn[i]);
			ret = -1;
			goto out;
		}
	}
	ret = 0;
 out:
	for (i = 0; i < aio_num_threads; i++) {
		fclose(fp[i]);
	}

	return ret;
}

void my_aio_close(int aio_num_threads, struct aioreq *iolist) {
	int ret;
	int i;
	
	for (i = 0; i < aio_num_threads; i++) {
		if (iolist[i].aiocbp->aio_fildes != -1) {
			close(iolist[i].aiocbp->aio_fildes);
			iolist[i].aiocbp->aio_fildes = -1;
		}
	}
}

int my_aio(int aio_num_threads, struct aioreq *iolist, char **fn, long nsec_calc, int no_aio) {
	int ret;
	int i, j;

	//pr_debug("%s: debug: enter\n", __func__);


	/* Start async IO */
	for (i = 0; i < NSAMPLES_INNER; i++) {
		if (no_aio) goto skip1;

		if ((ret = my_aio_open(aio_num_threads, iolist, fn)) == -1) {
			pr_err("%s: error: my_aio_open: %s\n",
			       __func__, strerror(errno));
			ret = -errno;
			goto out;
		}
		//pr_debug("%s: debug: after my_aio_open\n", __func__);
	
		
		/* Reset completion */
		completion_count = 0;
		__sync_synchronize();

		for (j = 0; j < aio_num_threads; j++) {
			iolist[j].status = EINPROGRESS;

			if ((ret = aio_write(iolist[j].aiocbp)) == -1) {
				pr_err("%s: error: aio_write: %s\n",
				       __func__, strerror(errno));
				ret = -errno;
				goto out;
			}

			//pr_debug("%s: debug: after %d-th aio_write\n", __func__, j);
		}
	skip1:
		/* Emulate calcuation phase */
		ndelay(nsec_calc);
		if (no_aio) goto skip2;

#if 0
		int k;
		for (k = 0; k < 20; k++) {
			char cmd[256];
			sprintf(cmd, "ls /proc/%d/task | wc -l", getpid());
			system(cmd);
			usleep(200000);
		}
#endif
		
		/* Wait for completion of async IO */
#if WAIT_TYPE == WAIT_TYPE_SEM

	retry:
		ret = sem_wait(&aio_sem);
		if (ret == -1) {
			if (errno == EINTR) {
				pr_warn("%s: warning: sem_wait interrupted\n",
				       __func__);
				goto retry;
			} else {
				pr_err("%s: error: sem_wait: %s\n",
				       __func__, strerror(errno));
			}
		}
		//pr_debug("%s: debug: completion_count: %d\n", __func__, completion_count);
		
#elif WAIT_TYPE == WAIT_TYPE_BUSY_LOOP

		while (completion_count != aio_num_threads) {
			for (j = 0; j < aio_num_threads; j++) {
				if (iolist[j].status != EINPROGRESS) {
					continue;
				}
				
				iolist[j].status = aio_error(iolist[j].aiocbp);
				
				switch (iolist[j].status) {
				case 0: /* Completed */
					goto completed;
				case EINPROGRESS:
					break;
				case ECANCELED:
					pr_err("%s: error: aio is cancelled\n",
					       __func__);
					goto completed;
				default:
					pr_err("%s: error: aio_error: %s\n",
					       __func__, strerror(iolist[j].status));
					goto completed;
				completed:
					completion_count++;
					break;
				}
			}
		}
#endif /* WAIT_TYPE */
		/* Check amount read */
		for (j = 0; j < aio_num_threads; j++) {
			ssize_t size;
			
			if ((size = aio_return(iolist[j].aiocbp)) != SZBUF) {
				pr_err("%s: Expected to read %ld B but #%d has read %ld B\n",
				       __func__, SZBUF, j, size);
				continue;
			}
		}

		my_aio_close(aio_num_threads, iolist);
	skip2:;
	}
	ret = 0;
 out:
	my_aio_close(aio_num_threads, iolist);
	return ret;
}

int measure(double *result, int nsamples, int nsamples_drop, int aio_num_threads, struct aioreq *iolist, char **fn, long nsec_calc, int rank, int profile, int no_aio) {
	int ret;
	int i;
	double t_l, t_g, t_sum = 0;
	double start, end;
	
	for (i = 0; i < nsamples + nsamples_drop; i++) {
		
		MPI_Barrier(MPI_COMM_WORLD);

		/* Set parameter based on current IPC and frequency */
		ndelay_init(0);
		
		start = mytime();
		
		struct rusage ru_start, ru_end;
		struct timeval tv_start, tv_end;
		
		if (profile) {
			if ((ret = getrusage(RUSAGE_SELF, &ru_start))) {
				pr_err("%s: error: getrusage failed (%d)\n", __func__, ret);
			}
			
			if ((ret = gettimeofday(&tv_start, NULL))) {
				pr_err("%s: error: gettimeofday failed (%d)\n", __func__, ret);
			}
		}

		if ((ret = my_aio(aio_num_threads, iolist, fn, nsec_calc, no_aio))) {
			pr_err("%s: error: my_aio returned %d\n",
			       __func__, ret);
		}

		if (profile) {
			if ((ret = getrusage(RUSAGE_SELF, &ru_end))) {
				pr_err("%s: error: getrusage failed (%d)\n", __func__, ret);
			}
			
			if ((ret = gettimeofday(&tv_end, NULL))) {
				pr_err("%s: error: gettimeofday failed (%d)\n", __func__, ret);
			}
			
			if (rank == 0) pr_debug("%s: wall: %ld, user: %ld, sys: %ld\n", __func__,
						DIFFUSEC(tv_end, tv_start),
						DIFFUSEC(ru_end.ru_utime, ru_start.ru_utime),
						DIFFUSEC(ru_end.ru_stime, ru_start.ru_stime));
		}		
		
		end = mytime();
		
		MPI_Barrier(MPI_COMM_WORLD);

		/* Check contents */
		if ((ret = my_aio_check(iolist, aio_num_threads, fn))) {
			pr_err("%s: error: my_aio_check returned %d\n",
			       __func__, ret);
		}

		if (i < nsamples_drop) {
			continue;
		}

		/* Take max */
		t_l = end - start;
		MPI_Allreduce(&t_l, &t_g, 1, MPI_DOUBLE, MPI_MAX, MPI_COMM_WORLD);
		t_sum += t_g;
	}

	*result = t_sum / nsamples;
	ret = 0;

	return ret;
}

int main(int argc, char **argv)
{
	int ret;
	int i, j, progress, l;
	int rank, nproc;
	int ppn = -1;
	int aio_num_threads = -1;
	int disable_syscall_intercept = 0;
	struct aioreq *iolist;
	struct aiocb *aiocblist;
	struct sigaction sa;
	double t_io_ave, t_total_ave;
	double t_table[NROW][NCOL] = { 0 };
	int opt;
	char **aiobufs;
	char **fn;
	char src_dir[PATH_MAX];
	char *argv0;

	opterr = 0; /* Don't print out error when not recognizing option character */
	
	while ((opt = getopt(argc, argv, ":I:p:t:")) != -1) {
		switch (opt) {
		case 'I':
			disable_syscall_intercept = atoi(optarg);
			break;
		case 'p':
			ppn = atoi(optarg);
			break;
		case 't':
			aio_num_threads = atoi(optarg);
			break;
		case '?':
			pr_err("error: invalid option: -%c\n",
			       optopt);
			ret = 1;
			goto out;
		case ':':
			pr_err("error: option -%c requires an argument\n",
			       optopt);
			ret = 1;
			goto out;
		}
	}

	if (ppn == -1) {
		pr_err("error: specify ppn with -p <ppn>\n");
		ret = 1;
		goto out;
	}

	if (aio_num_threads == -1) {
		pr_err("error: specify aio_num_threads with -p <aio_num_threads>\n");
		ret = 1;
		goto out;
	}

	/* Initialize MPI */
	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &nproc);

#if 0
	int k;
	for (k = 0; k < 20; k++) {
		char cmd[256];
		sprintf(cmd, "ls /proc/%d/task | wc -l", getpid());
		system(cmd);
		usleep(200000);
	}
#endif

	/* Show parameters */
	if (rank == 0) {
#pragma omp parallel
		{
			if (omp_get_thread_num() == 0) {
				printf("nproc=%d,#threads=%d\n", nproc, omp_get_num_threads());
			}
		}
	}

	/* Set verbosity */
	//test_set_loglevel(TEST_LOGLEVEL_WARN);	
	
	/* Set parameter based on current IPC and frequency */
	ndelay_init(1);

	/* Initialize files */
	if (!(fn = malloc(sizeof(char *) * aio_num_threads))) {
		pr_err("error: allocating fn\n");
		ret = -ENOMEM;
		goto out;
	}
	
	argv0 = strdup(argv[0]);
	sprintf(src_dir, "%s", dirname(argv0));
	for (i = 0; i < aio_num_threads; i++) {
                if (!(fn[i] = malloc(SZBUF))) {
			pr_err("error: allocating data\n");
			ret = -ENOMEM;
			goto out;
                }

		sprintf(fn[i], "%s/rank%d-number%d", src_dir, rank, i);
		if (rank < 2 && i < 2) {
			pr_debug("debug: rank: %d, fn[%d]: %s\n",
				 rank, i, fn[i]);
		}
	}

	/* Allocate aio arrays */
	if (!(iolist = calloc(aio_num_threads, sizeof(struct aioreq)))) {
		pr_err("%s: error: allocating iolist\n",
		       __func__);
		ret = 1;
		goto out;
	}

	if (!(aiocblist = calloc(aio_num_threads, sizeof(struct aiocb)))) {
		pr_err("%s: error: allocating aiocblist\n",
		       __func__);
		ret = 1;
		goto out;
	}

	/* Prepare data to be written */
	if (!(aiobufs = malloc(sizeof(char *) * aio_num_threads))) {
		pr_err("error: allocating aiobufs\n");
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < aio_num_threads; i++) {
		aiobufs[i] = malloc(SZBUF);
		if (!aiobufs[i]) {
			pr_err("%s: error: allocating aiobufs\n",
			       __func__);
			ret = 1;
			goto out;
		}

		for (j = 0; j < SZBUF; j++) {
			*(aiobufs[i] + j) = i + j + rank;
		}
	}

	/* Initialize aio parameters except fd and status */
	if ((ret = my_aio_init(aio_num_threads, iolist, aiocblist, aiobufs))) {
		pr_err("%s: error: my_aio_init returned %d\n",
		       __func__, ret);
		goto out;
	}

#if 0
	/* Set signal handlers */
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	sa.sa_sigaction = aio_sighandler;
	if (sigaction(SIGUSR1, &sa, NULL) == -1) {
		pr_err("%s: error: sigaction: %s\n",
		       __func__, strerror(errno));
		ret = 1;
		goto out;
	}
#endif

	/* Initialize semaphore */
	if ((ret = sem_init(&aio_sem, 0, 0))) {
		pr_err("%s: error: sem_init: %s\n", __func__, strerror(errno));
		ret = -errno;
		goto out;		
	}

	/* Take profile */
	if ((ret = measure(&t_io_ave, NSAMPLES_PROFILE, 0, aio_num_threads, iolist, fn, 0, rank, 1, 0))) {
		pr_err("error: measure returned %d\n", ret);
		goto out;
	}

	/* Measure IO only time */
	if ((ret = measure(&t_io_ave, NSAMPLES_IO, NSAMPLES_DROP, aio_num_threads, iolist, fn, 0, rank, 0, 0))) {
		pr_err("error: measure returned %d\n", ret);
		goto out;
	}

	if (rank == 0) {
		printf("t_io_ave: %.0f usec, %.0f MB/s per node\n",
		       t_io_ave * MYTIME_TOUSEC,
		       SZBUF * ppn * aio_num_threads / t_io_ave / 1000000);
	}

	/* Measure time with no progress, progress and no uti, progress and uti */
	for (progress = 0; progress <= (disable_syscall_intercept ? 0 : -1); progress += 1) {

		if (progress == 1) {
			/* Ignore uti_attr, spawn a thread onto compute CPUs */
			setenv("DISABLE_UTI", "1", 1); 
		} else if (progress == 2) {
			unsetenv("DISABLE_UTI");
		}

		/* Increasing calculation time up to 100% of IO time */
		for (l = 0; l <= NROW - 1; l += 1) {
			long nsec_calc = (t_io_ave * MYTIME_TONSEC * l) / 10;
			
			if ((ret = measure(&t_total_ave, NSAMPLES_TOTAL, NSAMPLES_DROP, aio_num_threads, iolist, fn, nsec_calc, rank, 0, 0))) {
				pr_err("error: measure returned %d\n", ret);
				goto out;
			}

			if (rank == 0) {
				if (l == 0) {
					pr_debug("progress=%d\n", progress);
					if (progress == 0) { 
						pr_debug("calc\ttotal\n");
					} else {
						pr_debug("total\n");
					}
				}

				t_table[l][0] = nsec_calc * (MYTIME_TOUSEC / (double)MYTIME_TONSEC);
				if (progress == 0) { 
					pr_debug("%.0f\t%.0f\n", nsec_calc * (MYTIME_TOUSEC / (double)MYTIME_TONSEC), t_total_ave * MYTIME_TOUSEC);
					t_table[l][progress + 1] = t_total_ave * MYTIME_TOUSEC;
				} else {
					pr_debug("%.0f\n", t_total_ave * MYTIME_TOUSEC);
					t_table[l][progress + 1] = t_total_ave * MYTIME_TOUSEC;
				}
			}
		}
	}

	if (rank == 0) {
		printf("calc,no prog,prog and no uti, prog and uti\n");
		for (l = 0; l <= NROW - 1; l++) {
			for (i = 0; i < NCOL; i++) {
				if (i > 0) {
					printf(",");
				}
				printf("%.0f", t_table[l][i]);
			}
			printf("\n");
		}
	}

	MPI_Barrier(MPI_COMM_WORLD);
	//pr_debug("after barrier\n");

	MPI_Finalize();
	//pr_debug("after finalize\n");

	ret = 0;
out:
	if ((ret = sem_destroy(&aio_sem))) {
 		pr_err("%s: error: sem_destroy: %s\n", __func__, strerror(errno));
		goto out;		
	}

	free(argv0);
	return ret;
}
