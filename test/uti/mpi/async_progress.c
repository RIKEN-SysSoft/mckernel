#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <unistd.h>
#include <sys/syscall.h>   /* For SYS_xxx definitions */
#include <sched.h>
#include <pthread.h>
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <uti.h>
#include "util.h"
#include "async_progress.h"

//#define PROFILE

#define STOP_BY_MPI 0
#define STOP_BY_MEM 1
#define STOP_TYPE STOP_BY_MEM/*STOP_BY_MPI*/

#define POLL_BY_PROBE 0
#define POLL_BY_WAIT 1
#define POLL_BY_TEST 2
#define POLL_TYPE POLL_BY_PROBE/*POLL_BY_WAIT*/

static int progress_rank, progress_world_rank, progress_world_nproc;
static pthread_t progress_thr;
static pthread_mutex_t progress_mutex;
static pthread_cond_t progress_cond_down;
static volatile int progress_flag_up, progress_flag_down;

static enum progress_state progress_state;
static volatile int progress_stop_flag;
static double time_progress;
static MPI_Comm progress_comm;
static int progress_refc;
#define WAKE_TAG 100

#define NROW_STAT 10
#define NRANK_STAT 1
#define RECORD_STAT(count, array, end, start) do { \
	if (count < NROW_STAT) { \
		array[count++] += (end - start);	\
	} \
} while(0)

static int cyc_prog1_count, cyc_prog2_count, cyc_init1_count, cyc_init2_count, cyc_start_count, cyc_stop1_count, cyc_stop2_count, cyc_stop3_count, cyc_finalize_count;
static unsigned long cyc_prog1[NROW_STAT];
static unsigned long cyc_prog2[NROW_STAT];
static unsigned long cyc_init1[NROW_STAT];
static unsigned long cyc_init2[NROW_STAT];
static unsigned long cyc_start[NROW_STAT];
static unsigned long cyc_stop1[NROW_STAT];
static unsigned long cyc_stop2[NROW_STAT];
static unsigned long cyc_stop3[NROW_STAT];
static unsigned long cyc_finalize[NROW_STAT];

#define MIN2(x,y) ((x) < (y) ? (x) : (y))

void pr_stat(char *name, int count, unsigned long *array) {
	int i;

	pr_debug("[%d] %s: ", progress_world_rank, name);
	for (i = 0; i < MIN2(count, NROW_STAT); i++) {
		if (i > 0) pr_debug(",");
		pr_debug("%ld", array[i]);
	}
	pr_debug("\n");
}

static void *progress_fn(void* data)
{
	int ret;
	MPI_Request req;
	struct rusage ru_start, ru_end;
	struct timeval tv_start, tv_end;
	unsigned long start, end;
	double start2, end2;

#if 0
	ret = syscall(732);
	if (ret == -1) {
		pr_debug("Progress is running on Linux\n");
	} else {
		pr_debug("Progress is running on McKernel\n");
	}

	if ((ret = getrusage(RUSAGE_THREAD, &ru_start))) {
		pr_err("%s: error: getrusage failed (%d)\n", __func__, ret);
	}

	if ((ret = gettimeofday(&tv_start, NULL))) {
		pr_err("%s: error: gettimeofday failed (%d)\n", __func__, ret);
	}
#endif

#if STOP_TYPE == STOP_BY_MEM && POLL_TYPE == POLL_BY_TEST

	if ((ret = MPI_Irecv(NULL, 0, MPI_CHAR, progress_rank, WAKE_TAG, progress_comm, &req)) != MPI_SUCCESS) {
		pr_err("%s: error: MPI_Irecv: %d\n", __func__, ret);
	}

#endif

init:
#ifdef PROFILE
	start = rdtsc_light();
#endif

	/* Wait for state transition */
	pthread_mutex_lock(&progress_mutex);
	while (!progress_flag_down) {
		pthread_cond_wait(&progress_cond_down, &progress_mutex);
	}
	progress_flag_down = 0;

	if (progress_state == PROGRESS_FINALIZE) {
		pthread_mutex_unlock(&progress_mutex);
		goto finalize;
	}

	if (progress_state != PROGRESS_START) {
		pr_err("%s: error: unexpected state: %d\n", __func__, progress_state);	
		pthread_mutex_unlock(&progress_mutex);
		goto finalize;
	}

	pthread_mutex_unlock(&progress_mutex);

#ifdef PROFILE
	end = rdtsc_light();
	RECORD_STAT(cyc_prog1_count, cyc_prog1, end, start);
#endif

#ifdef PROFILE
	start = rdtsc_light();
#endif

#if STOP_TYPE == STOP_BY_MEM

#if POLL_TYPE == POLL_BY_PROBE

	//if (progress_world_rank < 2) pr_debug("[%d] poll,cpu=%d\n", progress_world_rank, sched_getcpu());


	//#define REPORT_PROGRESS_TIME
#ifdef REPORT_PROGRESS_TIME
	start2 = mytime();
	getrusage(RUSAGE_THREAD, &ru_start);
	gettimeofday(&tv_start, NULL);
	double start3, end3, time3;
#endif
	int completed = 0, count = 0;
	while (!progress_stop_flag) {

#ifdef REPORT_PROGRESS_TIME
		start3 = mytime();
#endif
		//pr_debug("[%d] poll,cpu=%d\n", progress_world_rank, sched_getcpu());
		if ((ret = MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &completed, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
			pr_err("%s: error: MPI_Iprobe: %d\n", __func__, ret);
			break;
		}
#ifdef REPORT_PROGRESS_TIME
		end3 = mytime();

		if (count < 3) {
			if (1 && progress_world_rank < 5) {
				pr_debug("[%d] cpu=%d,count=%d,iprobe=%.0f nsec\n", progress_world_rank, sched_getcpu(), count, (end3 - start3) * MYTIME_TONSEC);
			}
		}

		/* Exclude lead time including first time futex */
		if (count == 0) {
			double lead_time;

			end2 = mytime();
			lead_time = end2 - start2;
			if (1 && progress_world_rank == 0) {
				pr_debug("[%d] 1st iprobe takes %.0f nsec\n", progress_world_rank, lead_time * MYTIME_TONSEC);
			}
			start2 = mytime();
		}
#endif
		count++;
		//usleep(1);
	}
#ifdef REPORT_PROGRESS_TIME
        end2 = mytime();
	time_progress = end2 - start2;

	if (1 && progress_world_rank < 3) pr_debug("[%d] time_progress=%.0f usec,count=%d\n", progress_world_rank, time_progress * MYTIME_TOUSEC, count);

	getrusage(RUSAGE_THREAD, &ru_end);
	gettimeofday(&tv_end, NULL);

	if (1 && progress_world_rank < 3) {
		pr_debug("[%d]: wall: %ld, user: %ld, sys: %ld\n",
			 progress_world_rank,
			 DIFFUSEC(tv_end, tv_start),
			 DIFFUSEC(ru_end.ru_utime, ru_start.ru_utime),
			 DIFFUSEC(ru_end.ru_stime, ru_start.ru_stime));
	}
#endif

#elif POLL_TYPE == POLL_BY_TEST

	int completed = 0;
	while (!completed && !progress_stop_flag) {
		if ((ret = MPI_Test(&req, &completed, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
			pr_err("%s: error: MPI_Iprobe: %d\n", __func__, ret);
			break;
		}
		//usleep(1);
	}

#endif /* POLL_TYPE */

#elif STOP_TYPE == STOP_BY_MPI


#if POLL_TYPE == POLL_BY_WAIT

	if ((ret = MPI_Irecv(NULL, 0, MPI_CHAR, progress_rank, WAKE_TAG, progress_comm, &req)) != MPI_SUCCESS) {
		pr_err("%s: error: MPI_Irecv: %d\n", __func__, ret);
	}

	if ((ret = MPI_Wait(&req, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
		pr_err("%s: error: MPI_Wait failed (%d)\n", __func__, ret);
	}

#elif POLL_TYPE == POLL_BY_PROBE

	int completed = 0;
	while (!completed) {
		if ((ret = MPI_Iprobe(progress_rank, WAKE_TAG, progress_comm, &completed, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
			pr_err("%s: error: MPI_Iprobe: %d\n", __func__, ret);
			break;
		}
		usleep(1);
	}

	if ((ret = MPI_Recv(NULL, 0, MPI_CHAR, progress_rank, WAKE_TAG, progress_comm, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
		pr_err("%s: error: MPI_Irecv: %d\n", __func__, ret);
	}

#endif /* POLL_TYPE */
#endif /* STOP_TYPE */

	progress_state = PROGRESS_INIT;
	__sync_synchronize(); /* st-st barrier */
	progress_flag_up = 1;

#ifdef PROFILE
	end = rdtsc_light();
	RECORD_STAT(cyc_prog2_count, cyc_prog2, end, start);
#endif
	goto init;

 finalize:

#if 0
	if ((ret = getrusage(RUSAGE_THREAD, &ru_end))) {
		pr_err("%s: error: getrusage failed (%d)\n", __func__, ret);
	}

	if ((ret = gettimeofday(&tv_end, NULL))) {
		pr_err("%s: error: gettimeofday failed (%d)\n", __func__, ret);
	}

	pr_debug("%s: wall: %ld, user: %ld, sys: %ld\n", __func__,
		   DIFFUSEC(tv_end, tv_start),
		   DIFFUSEC(ru_end.ru_utime, ru_start.ru_utime),
		   DIFFUSEC(ru_end.ru_stime, ru_start.ru_stime));
#endif

	progress_state = PROGRESS_INIT;
	__sync_synchronize(); /* st-st barrier */
	progress_flag_up = 1;

	return NULL;
}

void progress_init()
{
	int ret = 0;
	pthread_attr_t pthread_attr;
	uti_attr_t uti_attr;
	unsigned long start, end;

#ifdef PROFILE
	start = rdtsc_light();
#endif
	MPI_Comm_rank(MPI_COMM_WORLD, &progress_world_rank);
	MPI_Comm_size(MPI_COMM_WORLD, &progress_world_nproc);

	if (__sync_val_compare_and_swap(&progress_refc, 0, 1) == 1) {
		return;
	}

	/* printf costs much in MPI */
	uti_set_loglevel(UTI_LOGLEVEL_ERR);

	if ((ret = MPI_Comm_dup(MPI_COMM_SELF, &progress_comm))) {
		pr_err("%s: error: MPI_Comm_dup failed (%d)\n", __func__, ret);
		goto out;
	}

	MPI_Comm_rank(progress_comm, &progress_rank);

	if ((ret = pthread_mutex_init(&progress_mutex, NULL))) {
 		pr_err("%s: error: pthread_mutex_init failed (%d)\n", __func__, ret);
		goto out;		
	}

	if ((ret = pthread_cond_init(&progress_cond_down, NULL))) {
 		pr_err("%s: error: pthread_cond_init failed (%d)\n", __func__, ret);
		goto out;		
	}
	
	if ((ret = pthread_attr_init(&pthread_attr))) {
 		pr_err("%s: error: pthread_attr_init failed (%d)\n", __func__, ret);
		goto out;
	}
	
	if ((ret = uti_attr_init(&uti_attr))) {
 		pr_err("%s: error: uti_attr_init failed (%d)\n", __func__, ret);
		goto out;
	}
	
	/* Linux CPU might be congested */
	if ((ret = UTI_ATTR_HIGH_PRIORITY(&uti_attr))) {
		pr_err("%s: error: UTI_ATTR_HIGH_PRIORITY failed\n", __func__);
	}

	/* Expecting round-robin CPU binding */
	if ((ret = UTI_ATTR_CPU_INTENSIVE(&uti_attr))) {
		pr_err("%s: error: UTI_ATTR_CPU_INTENSIVE failed\n", __func__);
	}

#ifdef PROFILE
	end = rdtsc_light();
	RECORD_STAT(cyc_init1_count, cyc_init1, end, start);
#endif
	
#ifdef PROFILE
	start = rdtsc_light();
#endif

	if ((ret = uti_pthread_create(&progress_thr, &pthread_attr, progress_fn, NULL, &uti_attr))) {
		pr_err("%s: error: uti_pthread_create failed (%d)\n", __func__, ret);
		goto out;
	}

	ret = 0;
 out:
	if (ret) {
		__sync_fetch_and_sub(&progress_refc, 1);
	}

#ifdef PROFILE
	end = rdtsc_light();
	RECORD_STAT(cyc_init2_count, cyc_init2, end, start);
#endif
}

void progress_start()
{
	unsigned long start, end;

	if (progress_refc == 0) {
		progress_init();
	}

#ifdef PROFILE
	start = rdtsc_light();
#endif
	pthread_mutex_lock(&progress_mutex);

	if (progress_state == PROGRESS_FINALIZE) {
		pr_warn("%s: warning: FINALIZE\n", __func__);
		pthread_mutex_unlock(&progress_mutex);
		return;
	}

	if (progress_state == PROGRESS_START) {
		//pr_warn("%s: warning: START\n", __func__);
		pthread_mutex_unlock(&progress_mutex);
		return;
	}

	if (progress_state != PROGRESS_INIT) {
		pr_err("%s: error: unexpected state: %d\n", __func__, progress_state);
		pthread_mutex_unlock(&progress_mutex);
		return;
	}
		
	progress_state = PROGRESS_START;
#if STOP_TYPE == STOP_BY_MEM
	progress_stop_flag = 0;
#endif
	__sync_synchronize(); /* memory barrier instruction */
	progress_flag_down = 1;
	pthread_cond_signal(&progress_cond_down);
	pthread_mutex_unlock(&progress_mutex);
	
#ifdef PROFILE
	end = rdtsc_light();
	RECORD_STAT(cyc_start_count, cyc_start, end, start);
#endif
}

double do_progress_stop()
{
	int ret;
	unsigned long start, end;

	//if (progress_world_rank < 2) pr_debug("[%d] stop,cpu=%d\n", progress_world_rank, sched_getcpu());

#ifdef PROFILE
	start = rdtsc_light();
#endif

#if STOP_TYPE == STOP_BY_MEM

	progress_stop_flag = 1;
        __sync_synchronize(); /* st-st barrier */

#elif STOP_TYPE == STOP_BY_MPI

	if ((ret = MPI_Send(NULL, 0, MPI_CHAR, progress_rank, WAKE_TAG, progress_comm)) != MPI_SUCCESS) {
		pr_err("%s: error: MPI_Send failed (%d)\n", __func__, ret);
		return;
	}


#endif /* STOP_TYPE */

#ifdef PROFILE
	end = rdtsc_light();
	RECORD_STAT(cyc_stop2_count, cyc_stop2, end, start);
	start = rdtsc_light();
#endif

	/* Make sure the following command will observe INIT */
	while (!progress_flag_up) {
	}
	progress_flag_up = 0;

#ifdef PROFILE
	end = rdtsc_light();
	RECORD_STAT(cyc_stop3_count, cyc_stop3, end, start);
#endif
	return time_progress;
}

void progress_stop(double *time_progress)
{
	unsigned long start, end;

#ifdef PROFILE
	start = rdtsc_light();
#endif

	if (progress_refc == 0) {
		return;
	}

	pthread_mutex_lock(&progress_mutex);

	if (progress_state == PROGRESS_INIT) {
		pthread_mutex_unlock(&progress_mutex);
		return;
	}

	if (progress_state == PROGRESS_FINALIZE) {
		pthread_mutex_unlock(&progress_mutex);
		return;
	}

	if (progress_state != PROGRESS_START) {
		pr_err("%s: error: unexpected state: %d\n", __func__, progress_state);
		pthread_mutex_unlock(&progress_mutex);
		return;
	}

	pthread_mutex_unlock(&progress_mutex);

#ifdef PROFILE
	end = rdtsc_light();
	RECORD_STAT(cyc_stop1_count, cyc_stop1, end, start);
#endif	

	*time_progress = do_progress_stop();
}

void progress_finalize()
{
	int ret;
	int i, j;
	MPI_Request req;
	unsigned long start, end;
	int nproc;

	MPI_Comm_size(MPI_COMM_WORLD, &nproc);

#ifdef PROFILE
	start = rdtsc_light();
#endif

	if (progress_refc == 0) {
		return;
	}

 retry:
	pthread_mutex_lock(&progress_mutex);

	if (progress_state == PROGRESS_START) {
		pthread_mutex_unlock(&progress_mutex);
		do_progress_stop();
		goto retry;
	}

	if (progress_state == PROGRESS_FINALIZE) {
		pthread_mutex_unlock(&progress_mutex);
		return;
	}

	if (progress_state != PROGRESS_INIT) {
		pr_err("%s: error: unexpected state: %d\n", __func__, progress_state);
		pthread_mutex_unlock(&progress_mutex);
		return;
	}

	progress_state = PROGRESS_FINALIZE;
	__sync_synchronize(); /* st-st barrier */
	progress_flag_down = 1;
	pthread_cond_signal(&progress_cond_down);
	pthread_mutex_unlock(&progress_mutex);

	/* Make sure the following command will observe INIT */
	while (!progress_flag_up) {
	}
	progress_flag_up = 0;

	pthread_join(progress_thr, NULL);

	if ((ret = MPI_Comm_free(&progress_comm)) != MPI_SUCCESS) {
		pr_err("%s: error: MPI_Comm_free failed (%d)\n", __func__, ret);
		return;
	}

	progress_refc = 0;

#ifdef PROFILE
	end = rdtsc_light();
	RECORD_STAT(cyc_finalize_count, cyc_finalize, end, start);

	for (j = 0; j < NRANK_STAT; j++) {

		MPI_Barrier(MPI_COMM_WORLD);

		if (j != progress_world_rank) {
			usleep(1000000);
			continue;
		}

		pr_stat("cyc_prog1", cyc_prog1_count, cyc_prog1);
		pr_stat("cyc_prog2", cyc_prog2_count, cyc_prog2);
		pr_stat("cyc_init1", cyc_init1_count, cyc_init1);
		pr_stat("cyc_init2", cyc_init2_count, cyc_init2);
		pr_stat("cyc_start", cyc_start_count, cyc_start);
		pr_stat("cyc_stop1", cyc_stop1_count, cyc_stop1);
		pr_stat("cyc_stop2", cyc_stop2_count, cyc_stop2);
		pr_stat("cyc_stop3", cyc_stop3_count, cyc_stop3);
		pr_stat("cyc_finalize", cyc_finalize_count, cyc_finalize);
	}
#endif
}
