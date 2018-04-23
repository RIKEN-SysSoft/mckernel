#include <fcntl.h>
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
#include <mpi.h>
#include <linux/limits.h>
#include "util.h"

#define NREQS 1 /* # of parallel I/O requests per process */
#define SZBUF (1ULL<<23)

#define MYTIME_TOUSEC 1000000
#define MYTIME_TONSEC 1000000000

#define NROW 11
#define NCOL 4

#define NSAMPLES_DROP 0/*10*/
#define NSAMPLES_IO 2/*20*/
#define NSAMPLES_TOTAL 2/*20*/
#define NSAMPLES_INNER 1

#define Q(x) #x
#define QUOTE(x) Q(x)

char test_srcdir[PATH_MAX];

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
		//struct aioreq *aioreq = si->si_value.sival_ptr;
		//pr_debug("I/O completion signal received\n");
	}
}

int my_aio_init(int nreqs, struct aioreq *iolist, struct aiocb *aiocblist, char *aiobufs[NREQS]) {
	int j;
	
	for (j = 0; j < nreqs; j++) {
		iolist[j].rank = j;
		iolist[j].aiocbp = &aiocblist[j];
		iolist[j].aiocbp->aio_buf = aiobufs[j];
		iolist[j].aiocbp->aio_nbytes = SZBUF;
		iolist[j].aiocbp->aio_reqprio = 0;
		iolist[j].aiocbp->aio_offset = 0;
		iolist[j].aiocbp->aio_sigevent.sigev_notify = SIGEV_SIGNAL;
		iolist[j].aiocbp->aio_sigevent.sigev_signo = SIGUSR1;
		iolist[j].aiocbp->aio_sigevent.sigev_value.sival_ptr = &iolist[j];
	}

	return 0;
}


int my_aio_evict(int nreqs, char **fn) {
	int ret;
	int i;
	char cmd[PATH_MAX];
	
	for (i = 0; i < NREQS; i++) {

		sprintf(cmd, "%s -e %s > /dev/null", QUOTE(VMTOUCH), fn[i]);
		ret = system(cmd);

		if (ret == -1) {
			pr_err("%s: error: system\n",
                               __func__);
                        goto out;
		}

		if (WEXITSTATUS(ret)) {
			pr_err("%s: error: system returned %d\n",
                               __func__, WEXITSTATUS(ret));
			ret = WEXITSTATUS(ret);
                        goto out;
		}
	}
	ret = 0;
 out:
	return ret;
}
int my_aio_open(int nreqs, struct aioreq *iolist, char **fn) {
	int ret;
	int j;
	
	for (j = 0; j < NREQS; j++) {
		iolist[j].aiocbp->aio_fildes = open(fn[j], O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
		if (iolist[j].aiocbp->aio_fildes == -1) {
			pr_err("%s: error: open %s: %s\n",
			       __func__, fn[j], strerror(errno));
			ret = 1;
			goto out;
		}
	}

	ret = 0;
 out:
	return ret;
}

int my_aio_check(int nreqs, char **fn, char **mem_data) {
	int ret;
	int i;
	FILE *fp[NREQS] = { 0 };
	char *file_data[NREQS];

	/* Check contents */
	for (i = 0; i < nreqs; i++) {

		if (!(file_data[i] = malloc(SZBUF))) {
			pr_err("error: allocating data\n");
			ret = -ENOMEM;
			goto out;
		}

		if (!(fp[i] = fopen(fn[i], "r+"))) {
			pr_err("error: fopen %s: %s\n",
			       fn[i], strerror(errno));
			ret = -errno;
			goto out;
		}
		
		if (fread(file_data[i], sizeof(char), SZBUF, fp[i]) != SZBUF) {
			pr_err("error: fread: %s\n",
			       strerror(errno));
			ret = -1;
			goto out;
		}

		fclose(fp[i]);

		if (memcmp((const char *)file_data[i], mem_data[i], SZBUF)) {
			pr_err("%s: file_data[%d] and mem_data[%d] doesn't match\n",
			       __func__, i, i);
			ret = -1;
			goto out;
		}

		free(file_data[i]);
	}
	ret = 0;
 out:
	return ret;
}

void my_aio_close(int nreqs, struct aioreq *iolist) {
	int j;
	
	for (j = 0; j < NREQS; j++) {
		close(iolist[j].aiocbp->aio_fildes);
		iolist[j].aiocbp->aio_fildes = -1;
	}
}

int my_aio(int nreqs, struct aioreq *iolist, char **fn, long nsec_calc) {
	int ret;
	int i, j;

	/* Start async IO */
	for (j = 0; j < NSAMPLES_INNER; j++) {
		int completion_count = 0;

		//pr_debug("debug: opening file\n");
		if ((ret = my_aio_open(nreqs, iolist, fn)) == -1) {
			pr_err("%s: error: aio_read: %s\n",
			       __func__, strerror(errno));
			ret = -errno;
			goto out;
		}

		//pr_debug("debug: issuing write command\n");
		for (j = 0; j < nreqs; j++) {

			/* Reset completion notice */
			iolist[j].status = EINPROGRESS;

			if ((ret = aio_write(iolist[j].aiocbp)) == -1) {
				pr_err("%s: error: aio_read: %s\n",
				       __func__, strerror(errno));
				ret = -errno;
				goto out;
			}
		}

		/* Emulate calcuation phase */
		ndelay(nsec_calc);
		
		/* Wait for completion of async IO */
		//pr_debug("debug: waiting for completion\n");
		while (completion_count != nreqs) {
			for (j = 0; j < nreqs; j++) {
				if (iolist[j].status != EINPROGRESS) {
					continue;
				}
				
				iolist[j].status = aio_error(iolist[j].aiocbp);
				
				switch (iolist[j].status) {
				case 0: /* Succeeded */
					goto completed;
				case EINPROGRESS:
					break;
				case ECANCELED:
					pr_err("%s: error: aio is cancelled\n",
					       __func__);
					goto completed;
				default:
					pr_err("%s: error: unexpected status: %d\n",
					       __func__, iolist[j].status);
					goto completed;
				completed:
					completion_count++;
					break;
				}
			}
		}
		
		/* Check write amount */
		for (j = 0; j < nreqs; j++) {
			ssize_t size;
			
			if ((size = aio_return(iolist[j].aiocbp)) != SZBUF) {
				pr_err("%s: Expected to have written %ld B but reported to have written %ld B\n",
				       __func__, SZBUF, size);
				ret = -1;
				goto out;
			}
		}

		my_aio_close(nreqs, iolist);
	}
	ret = 0;
 out:
	return ret;
}

int measure(double *result, int nsamples, int nsamples_drop, int nreqs, struct aioreq *iolist, char **fn, char **aiobufs, long nsec_calc) {
	int ret;
	int i;
	double t_l, t_g, t_sum = 0;
	double start, end;

	for (i = 0; i < nsamples + nsamples_drop; i++) {

#if 0
		pr_debug("debug: evicting file cache\n");
		if ((ret = my_aio_evict(nreqs, fn))) {
			pr_err("%s: error: my_aio_evict returned %d\n",
			       __func__, ret);
		}
#endif
		MPI_Barrier(MPI_COMM_WORLD);
		
		start = mytime();
		if ((ret = my_aio(nreqs, iolist, fn, nsec_calc))) {
			pr_err("%s: error: my_aio_read returned %d\n",
			       __func__, ret);
		}
		end = mytime();
		
		MPI_Barrier(MPI_COMM_WORLD);

		/* Check contents */
		if ((ret = my_aio_check(nreqs, fn, aiobufs))) {
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
 out:
	return ret;
}

int main(int argc, char **argv)
{
	int ret;
	int i, j, progress, l;
	int rank, nproc;
	int disable_syscall_intercept = 0, ppn = -1;
	struct aioreq *iolist;
	struct aiocb *aiocblist;
	struct sigaction sa;
	double t_io_ave, t_total_ave;
	double t_table[NROW][NCOL] = { 0 };
	int opt;
	char *aiobufs[NREQS] = { 0 };
	char **fn;

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
		pr_err("error: specify -p <PPN>\n");
		ret = -EINVAL;
		goto out;
	}

	/* Initialize MPI */
	MPI_Init(&argc, &argv);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	MPI_Comm_size(MPI_COMM_WORLD, &nproc);

	/* Show parameters */
	if (rank == 0) {
#pragma omp parallel
		{
			if (omp_get_thread_num() == 0) {
				printf("nproc: %d, ppn: %d, #threads: %d\n", nproc, ppn, omp_get_num_threads());
			}
		}
	}

	/* Set verbosity */
	//test_set_loglevel(TEST_LOGLEVEL_WARN);	

	/* Initialize delay function */
	ndelay_init();

	/* Prepare file names */

#define TEST_SRCDIR "/work/gg10/e29005"
	sprintf(test_srcdir, "%s", /*TEST_SRCDIR*/dirname(argv[0]));

	if (!(fn = malloc(sizeof(char *) * NREQS))) {
		pr_err("error: allocating fn\n");
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < NREQS; i++) {
		if (!(fn[i] = malloc(PATH_MAX))) {
			pr_err("error: allocating fn\n");
			ret = -ENOMEM;
			goto out;
		}

		sprintf(fn[i], "%s/rank%d-number%d", test_srcdir, rank, i);
		if (rank == 0) pr_debug("debug: rank: %d, fn[%d]: %s\n",
			 rank, i, fn[i]);
	}

	/* Allocate aio commands */
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

	/* Prepare contents to be written */
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

	/* Set signal handlers */
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	sa.sa_sigaction = aio_sighandler;
	if (sigaction(SIGUSR1, &sa, NULL) == -1) {
		pr_err("%s: error: sigaction: %s\n",
		       __func__, strerror(errno));
		ret = 1;
		goto out;
	}

	/* Set aio parameters except fd and status */
	if ((ret = my_aio_init(NREQS, iolist, aiocblist, aiobufs))) {
		pr_err("%s: error: my_aio_init returned %d\n",
		       __func__, ret);
		goto out;
	}

	/* Measure IO only time */
	//pr_debug("debug: measuring IO only time\n");
	if ((ret = measure(&t_io_ave, NSAMPLES_IO, NSAMPLES_DROP, NREQS, iolist, fn, aiobufs, 0))) {
		pr_err("error: measure returned %d\n", ret);
		goto out;
	}

	if (rank == 0) {
		printf("t_io_ave: %.0f usec, %.0f MB/s per node\n",
		       t_io_ave * MYTIME_TOUSEC,
		       SZBUF * ppn / t_io_ave / 1000000);
	}

	/* Measure time with no progress, progress and no uti, progress and uti */
	for (progress = 0; progress <= (disable_syscall_intercept ? 0 : 0); progress += 1) {

		/* Spawn helper thread onto compute CPUs with ignoring uti_attr */
		if (progress == 1) {
			setenv("DISABLE_UTI", "1", 1); 
		}
		/* Spawn helper thread onto dedicated CPUs with respecting uti_attr */
		else if (progress == 2) {
			unsetenv("DISABLE_UTI");
		}

		/* Measure with various calculation time */
		for (l = 0; l <= 10; l += 2) {
			long nsec_calc = (t_io_ave * MYTIME_TONSEC * l) / 10;
			
			if ((ret = measure(&t_total_ave, NSAMPLES_TOTAL, NSAMPLES_DROP, NREQS, iolist, fn, aiobufs, nsec_calc))) {
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
		for (l = 0; l <= 10; l++) {
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
	for (i = 0; i < NREQS; i++) {
		free(aiobufs[i]);
	}
	return ret;
}
