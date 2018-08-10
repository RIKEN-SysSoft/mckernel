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
#include "util.h"

#define NREQS 32 /*1*/ /* Total number of parallel I/O requests */
#define SZBUF (1ULL << 23)/*23*/

#define MYTIME_TOUSEC 1000000
#define MYTIME_TONSEC 1000000000

#define NROW 16
#define NCOL 4

#define NSAMPLES_DROP 0/*10*/
#define NSAMPLES_IO 1/*20*/
#define NSAMPLES_TOTAL 1/*20*/
#define NSAMPLES_INNER 1

#define WAIT_TYPE_BUSY_LOOP 0
#define WAIT_TYPE_FUTEX 1
#define WAIT_TYPE WAIT_TYPE_FUTEX

static pthread_mutex_t progress_mutex;
static pthread_cond_t progress_cond_down;
static volatile int progress_flag_down;
int completion_count;

static inline double mytime() {
	return /*rdtsc_light()*/MPI_Wtime();
}

struct aioreq {
	int rank;
	int status;
	struct aiocb *aiocbp;
};

static void aio_sighandler(int sig, siginfo_t *si, void *ucontext)
{
	if (si->si_code == SI_ASYNCIO) {
#if WAIT_TYPE == WAIT_TYPE_FUTEX
		struct aioreq *aioreq = si->si_value.sival_ptr;

		aioreq->status = aio_error(aioreq->aiocbp);
		switch (aioreq->status) {
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
			       __func__, strerror(aioreq->status));
			goto completed;
		completed:
			__sync_fetch_and_add(&completion_count, 1);
			break;
		}

		if (completion_count == NREQS) {
			pthread_mutex_lock(&progress_mutex);
			progress_flag_down = 1;
			pthread_cond_signal(&progress_cond_down);
			pthread_mutex_unlock(&progress_mutex);
		}		
#endif /* WAIT_TYPE */
	}
}

int my_aio_init(int nreqs, struct aioreq *iolist, struct aiocb *aiocblist, char *aiobufs[NREQS]) {
	int ret;
	int i;
	
	for (i = 0; i < nreqs; i++) {
		iolist[i].rank = i;
		iolist[i].aiocbp = &aiocblist[i];
		iolist[i].aiocbp->aio_fildes = -1;
		iolist[i].aiocbp->aio_buf = aiobufs[i];
		iolist[i].aiocbp->aio_nbytes = SZBUF;
		iolist[i].aiocbp->aio_reqprio = 0;
		iolist[i].aiocbp->aio_offset = 0;
		iolist[i].aiocbp->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
		iolist[i].aiocbp->aio_sigevent.sigev_signo = SIGUSR1;
		iolist[i].aiocbp->aio_sigevent.sigev_value.sival_ptr = &iolist[i];
	}

	ret = 0;
	return ret;
}

int my_aio_open(int nreqs, struct aioreq *iolist, char **fn) {
	int ret;
	int i;
	
	for (i = 0; i < NREQS; i++) {
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

int my_aio_check(struct aioreq *iolist, int nreqs, char **fn) {
	int ret;
	int i;
	FILE *fp[NREQS] = { 0 };
	char *data;

	/* Check contents */
	for (i = 0; i < nreqs; i++) {
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
	for (i = 0; i < nreqs; i++) {
		fclose(fp[i]);
	}

	return ret;
}

void my_aio_close(int nreqs, struct aioreq *iolist) {
	int ret;
	int i;
	
	for (i = 0; i < nreqs; i++) {
		if (iolist[i].aiocbp->aio_fildes != -1) {
			close(iolist[i].aiocbp->aio_fildes);
			iolist[i].aiocbp->aio_fildes = -1;
		}
	}
}

int my_aio(int nreqs, struct aioreq *iolist, char **fn, long nsec_calc) {
	int ret;
	int i, j;

	/* Start async IO */
	for (i = 0; i < NSAMPLES_INNER; i++) {

		if ((ret = my_aio_open(nreqs, iolist, fn)) == -1) {
			pr_err("%s: error: aio_read: %s\n",
			       __func__, strerror(errno));
			ret = -errno;
			goto out;
		}
		
		/* Reset completion */
		completion_count = 0;

		for (j = 0; j < nreqs; j++) {

			iolist[j].status = EINPROGRESS;

			if ((ret = aio_write(iolist[j].aiocbp)) == -1) {
				pr_err("%s: error: aio_write: %s\n",
				       __func__, strerror(errno));
				ret = -errno;
				goto out;
			}
		}

		/* Emulate calcuation phase */
		ndelay(nsec_calc);
		
		/* Wait for completion of async IO */
#if WAIT_TYPE == WAIT_TYPE_FUTEX

		pthread_mutex_lock(&progress_mutex);
		while (!progress_flag_down) {
			pthread_cond_wait(&progress_cond_down, &progress_mutex);
		}
		progress_flag_down = 0;

#elif WAIT_TYPE == WAIT_TYPE_BUSY_LOOP

		while (completion_count != nreqs) {
			for (j = 0; j < nreqs; j++) {
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
		for (j = 0; j < nreqs; j++) {
			ssize_t size;
			
			if ((size = aio_return(iolist[j].aiocbp)) != SZBUF) {
				pr_err("%s: Expected to read %ld B but I've read %ld B\n",
				       __func__, SZBUF, size);
				ret = -1;
				goto out;
			}
		}

		my_aio_close(nreqs, iolist);
	}
	ret = 0;
 out:
	my_aio_close(nreqs, iolist);
	return ret;
}

int measure(double *result, int nsamples, int nsamples_drop, int nreqs, struct aioreq *iolist, char **fn, long nsec_calc, int rank, int profile) {
	int ret;
	int i;
	double t_l, t_g, t_sum = 0;
	double start, end;
	
	for (i = 0; i < nsamples + nsamples_drop; i++) {
		
		MPI_Barrier(MPI_COMM_WORLD);
		
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
		
		if ((ret = my_aio(nreqs, iolist, fn, nsec_calc))) {
			pr_err("%s: error: my_aio_read returned %d\n",
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
		if ((ret = my_aio_check(iolist, nreqs, fn))) {
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
	int disable_syscall_intercept = 0;
	struct aioreq *iolist;
	struct aiocb *aiocblist;
	struct sigaction sa;
	double t_io_ave, t_total_ave;
	double t_table[NROW][NCOL] = { 0 };
	int opt;
	char *aiobufs[NREQS];
	FILE *fp[NREQS] = { 0 };
	char *data[NREQS] = { 0 };
	char **fn;
	char src_dir[PATH_MAX];
	char *argv0;

	opterr = 0; /* Don't print out error when not recognizing option character */
	
	while ((opt = getopt(argc, argv, ":I:p:")) != -1) {
		switch (opt) {
		case 'I':
			disable_syscall_intercept = atoi(optarg);
			break;
		case 'p':
			ppn = atoi(optarg);
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

	/* Initialize MPI */
	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &nproc);

	/* Initialize mutex and cond */
	if ((ret = pthread_mutex_init(&progress_mutex, NULL))) {
 		pr_err("%s: error: pthread_mutex_init failed (%d)\n", __func__, ret);
		goto out;		
	}

	if ((ret = pthread_cond_init(&progress_cond_down, NULL))) {
 		pr_err("%s: error: pthread_cond_init failed (%d)\n", __func__, ret);
		goto out;
	}

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

	/* Initialize delay function */
	ndelay_init();

	/* Initialize files */
	if (!(fn = malloc(sizeof(char *) * NREQS))) {
		pr_err("error: allocating fn\n");
		ret = -ENOMEM;
		goto out;
	}
	
	argv0 = strdup(argv[0]);
	sprintf(src_dir, "%s", dirname(argv0));
	for (i = 0; i < NREQS; i++) {
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
	if (!(iolist = calloc(NREQS, sizeof(struct aioreq)))) {
		pr_err("%s: error: allocating iolist\n",
		       __func__);
		ret = 1;
		goto out;
	}

	if (!(aiocblist = calloc(NREQS, sizeof(struct aiocb)))) {
		pr_err("%s: error: allocating aiocblist\n",
		       __func__);
		ret = 1;
		goto out;
	}

	/* Prepare data to be written */
	for (i = 0; i < NREQS; i++) {
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
	if ((ret = my_aio_init(NREQS, iolist, aiocblist, aiobufs))) {
		pr_err("%s: error: my_aio_init returned %d\n",
		       __func__, ret);
		goto out;
	}

	/* Set signal handlers */
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	sa.sa_sigaction = aio_sighandler;
	if (sigaction(SIGUSR1, &sa, NULL) == -1) {
		pr_err("%s: error: sigaction: %s\n",
		       __func__, strerror(errno));
		ret = 1;
		goto out;
	}

	/* Measure IO only time */
	if ((ret = measure(&t_io_ave, NSAMPLES_IO, NSAMPLES_DROP, NREQS, iolist, fn, 0, rank, 1))) {
		pr_err("error: measure returned %d\n", ret);
		goto out;
	}

	if (rank == 0) {
		printf("t_io_ave: %.0f usec, %.0f MB/s per node\n",
		       t_io_ave * MYTIME_TOUSEC,
		       SZBUF * ppn * NREQS / t_io_ave / 1000000);
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
			
			if ((ret = measure(&t_total_ave, NSAMPLES_TOTAL, NSAMPLES_DROP, NREQS, iolist, fn, nsec_calc, rank, 0))) {
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

	MPI_Finalize();

	ret = 0;
out:
	free(argv0);
	return ret;
}
