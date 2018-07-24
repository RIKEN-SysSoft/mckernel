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

static int progress_rank;
static pthread_t progress_thr;
static pthread_mutex_t progress_mutex;
static pthread_cond_t progress_cond_up, progress_cond_down;
static volatile int progress_flag_up, progress_flag_down;

static enum progress_state progress_state;
static MPI_Comm progress_comm;
static int progress_refc;
#define WAKE_TAG 100

#define NROW_STAT 100
static int cyc_init1_count, cyc_init2_count, cyc_start_count, cyc_stop1_count, cyc_stop2_count, cyc_stop3_count, cyc_finalize_count;
static unsigned long cyc_init1[NROW_STAT];
static unsigned long cyc_init2[NROW_STAT];
static unsigned long cyc_start[NROW_STAT];
static unsigned long cyc_stop1[NROW_STAT];
static unsigned long cyc_stop2[NROW_STAT];
static unsigned long cyc_stop3[NROW_STAT];
static unsigned long cyc_finalize[NROW_STAT];

static void *progress_fn(void* data)
{
	int ret;
	MPI_Request req;
	struct rusage ru_start, ru_end;
	struct timeval tv_start, tv_end;

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

	pr_debug("progress: cpu=%d\n", sched_getcpu());
#endif

init:
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

#if 0
	int completed = 0;
	while (!completed) {
		if ((ret = MPI_Iprobe(progress_rank, WAKE_TAG, progress_comm, &completed, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
			pr_err("%s: error: MPI_Iprobe: %d\n", __func__, ret);
			break;
		}
		usleep(1);
		//sched_yield();
	}

	if ((ret = MPI_Recv(NULL, 0, MPI_CHAR, progress_rank, WAKE_TAG, progress_comm, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
		pr_err("%s: error: MPI_Irecv: %d\n", __func__, ret);
	}

#else
	if ((ret = MPI_Irecv(NULL, 0, MPI_CHAR, progress_rank, WAKE_TAG, progress_comm, &req)) != MPI_SUCCESS) {
		pr_err("%s: error: MPI_Irecv: %d\n", __func__, ret);
	}

	if ((ret = MPI_Wait(&req, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
		pr_err("%s: error: MPI_Wait failed (%d)\n", __func__, ret);
	}
#endif

 	pthread_mutex_lock(&progress_mutex);
	progress_state = PROGRESS_INIT;
	__sync_synchronize(); /* st-st barrier */
	progress_flag_up = 1;
	pthread_cond_signal(&progress_cond_up);
        pthread_mutex_unlock(&progress_mutex);

	goto init;

 finalize:

	if ((ret = getrusage(RUSAGE_THREAD, &ru_end))) {
		pr_err("%s: error: getrusage failed (%d)\n", __func__, ret);
	}

	if ((ret = gettimeofday(&tv_end, NULL))) {
		pr_err("%s: error: gettimeofday failed (%d)\n", __func__, ret);
	}

#if 0
	pr_debug("%s: wall: %ld, user: %ld, sys: %ld\n", __func__,
		   DIFFUSEC(tv_end, tv_start),
		   DIFFUSEC(ru_end.ru_utime, ru_start.ru_utime),
		   DIFFUSEC(ru_end.ru_stime, ru_start.ru_stime));
#endif

 	pthread_mutex_lock(&progress_mutex);
	progress_state = PROGRESS_INIT;
	__sync_synchronize(); /* st-st barrier */
	progress_flag_up = 1;
	pthread_cond_signal(&progress_cond_up);
	pthread_mutex_unlock(&progress_mutex);

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

	if ((ret = pthread_cond_init(&progress_cond_up, NULL))) {
 		pr_err("%s: error: pthread_cond_init failed (%d)\n", __func__, ret);
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
	
	if ((ret = UTI_ATTR_SAME_L1(&uti_attr))) {
		pr_err("%s: error: UTI_ATTR_SAME_L1 failed\n", __func__);
	}
	
	//pr_debug("master: cpu=%d\n", sched_getcpu());

#ifdef PROFILE
	end = rdtsc_light();
	cyc_init1[cyc_init1_count++] += (end - start);
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
	cyc_init2[cyc_init2_count++] += (end - start);
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
		pr_warn("%s: warning: START\n", __func__);
		pthread_mutex_unlock(&progress_mutex);
		return;
	}

	if (progress_state != PROGRESS_INIT) {
		pr_err("%s: error: unexpected state: %d\n", __func__, progress_state);
		pthread_mutex_unlock(&progress_mutex);
		return;
	}
		
	progress_state = PROGRESS_START;
	__sync_synchronize(); /* memory barrier instruction */
	progress_flag_down = 1;
	pthread_cond_signal(&progress_cond_down);
	pthread_mutex_unlock(&progress_mutex);
	
#ifdef PROFILE
	end = rdtsc_light();
	cyc_start[cyc_start_count++] += (end - start);
#endif
}

void do_progress_stop()
{
	int ret;
	unsigned long start, end;
	
#ifdef PROFILE
	start = rdtsc_light();
#endif

	/* No stray MPI_Send is generated because the first MPI_Send waits for completion of state transision from START to INIT */
	if ((ret = MPI_Send(NULL, 0, MPI_CHAR, progress_rank, WAKE_TAG, progress_comm)) != MPI_SUCCESS) {
		pr_err("%s: error: MPI_Send failed (%d)\n", __func__, ret);
		return;
	}

#ifdef PROFILE
	end = rdtsc_light();
	cyc_stop2[cyc_stop2_count++] += (end - start);
#endif

#ifdef PROFILE
	start = rdtsc_light();
#endif

	/* Make sure the following command will observe INIT */
	pthread_mutex_lock(&progress_mutex);
	while (!progress_flag_up) {
		pthread_cond_wait(&progress_cond_up, &progress_mutex);
	}
	progress_flag_up = 0;
	pthread_mutex_unlock(&progress_mutex);

#ifdef PROFILE
	end = rdtsc_light();
	cyc_stop3[cyc_stop3_count++] += (end - start);
#endif
}

void progress_stop()
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
	cyc_stop1[cyc_stop1_count++] += (end - start);
#endif	
	do_progress_stop();
}

void progress_finalize()
{
	int ret;
	int i;
	MPI_Request req;
	unsigned long start, end;

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
	pthread_mutex_lock(&progress_mutex);
	while (!progress_flag_up) {
		pthread_cond_wait(&progress_cond_up, &progress_mutex);
	}
	progress_flag_up = 0;
	pthread_mutex_unlock(&progress_mutex);

	pthread_join(progress_thr, NULL);

	if ((ret = MPI_Comm_free(&progress_comm)) != MPI_SUCCESS) {
		pr_err("%s: error: MPI_Comm_free failed (%d)\n", __func__, ret);
		return;
	}

	progress_refc = 0;

#ifdef PROFILE
	end = rdtsc_light();
	cyc_finalize[cyc_finalize_count++] += (end - start);

	pr_debug("cyc_init1\n");
	for (i = 0; i < cyc_init1_count; i++) {
		pr_debug("%ld\n", cyc_init1[i]);
	}

	pr_debug("cyc_init2\n");
	for (i = 0; i < cyc_init2_count; i++) {
		pr_debug("%ld\n", cyc_init2[i]);
	}

	pr_debug("cyc_start\n");
	for (i = 0; i < cyc_start_count; i++) {
		pr_debug("%ld\n", cyc_start[i]);
	}

	pr_debug("cyc_stop1\n");
	for (i = 0; i < cyc_stop1_count; i++) {
		pr_debug("%ld\n", cyc_stop1[i]);
	}

	pr_debug("cyc_stop2\n");
	for (i = 0; i < cyc_stop2_count; i++) {
		pr_debug("%ld\n", cyc_stop2[i]);
	}

	pr_debug("cyc_stop3\n");
	for (i = 0; i < cyc_stop3_count; i++) {
		pr_debug("%ld\n", cyc_stop3[i]);
	}

	pr_debug("cyc_finalize\n");
	for (i = 0; i < cyc_finalize_count; i++) {
		pr_debug("%ld\n", cyc_finalize[i]);
	}
#endif
}
