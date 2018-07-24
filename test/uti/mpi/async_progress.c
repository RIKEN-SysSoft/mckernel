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

static int progress_rank;
static pthread_t progress_thr;
static pthread_mutex_t progress_mutex;
static pthread_cond_t progress_cond_up, progress_cond_down;
static volatile int progress_flag_up, progress_flag_down;

static enum progress_state progress_state;
static MPI_Comm progress_comm;
static int progress_refc;
#define WAKE_TAG 100

static void *progress_fn(void* data)
{
	int ret;
	MPI_Request req;
	struct rusage ru_start, ru_end;
	struct timeval tv_start, tv_end;

	ret = syscall(732);
	if (ret == -1) {
		pr_debug("Progress is running on Linux\n");
	}

	if ((ret = getrusage(RUSAGE_THREAD, &ru_start))) {
		printf("%s: error: getrusage failed (%d)\n", __func__, ret);
	}

	if ((ret = gettimeofday(&tv_start, NULL))) {
		printf("%s: error: gettimeofday failed (%d)\n", __func__, ret);
	}

	printf("progress: cpu=%d\n", sched_getcpu());

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
		printf("%s: error: unexpected state: %d\n", __func__, progress_state);	
		pthread_mutex_unlock(&progress_mutex);
		goto finalize;
	}

	pthread_mutex_unlock(&progress_mutex);

#if 0
	int completed = 0;
	while (!completed) {
		if ((ret = MPI_Iprobe(progress_rank, WAKE_TAG, progress_comm, &completed, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
			printf("%s: error: MPI_Iprobe: %d\n", __func__, ret);
			break;
		}
		usleep(1);
		//sched_yield();
	}

	if ((ret = MPI_Recv(NULL, 0, MPI_CHAR, progress_rank, WAKE_TAG, progress_comm, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
		printf("%s: error: MPI_Irecv: %d\n", __func__, ret);
	}

#else
	if ((ret = MPI_Irecv(NULL, 0, MPI_CHAR, progress_rank, WAKE_TAG, progress_comm, &req)) != MPI_SUCCESS) {
		printf("%s: error: MPI_Irecv: %d\n", __func__, ret);
	}

	if ((ret = MPI_Wait(&req, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
		printf("%s: error: MPI_Wait failed (%d)\n", __func__, ret);
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
		printf("%s: error: getrusage failed (%d)\n", __func__, ret);
	}

	if ((ret = gettimeofday(&tv_end, NULL))) {
		printf("%s: error: gettimeofday failed (%d)\n", __func__, ret);
	}

#if 0
	printf("%s: wall: %ld, user: %ld, sys: %ld\n", __func__,
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

static void progress_init()
{
	int ret = 0;
	pthread_attr_t pthread_attr;
	uti_attr_t uti_attr;

	uti_set_loglevel(UTI_LOGLEVEL_WARN);

	if ((ret = MPI_Comm_dup(MPI_COMM_SELF, &progress_comm))) {
		printf("%s: error: MPI_Comm_dup failed (%d)\n", __func__, ret);
		goto out;
	}

	MPI_Comm_rank(progress_comm, &progress_rank);

	if ((ret = pthread_mutex_init(&progress_mutex, NULL))) {
 		printf("%s: error: pthread_mutex_init failed (%d)\n", __func__, ret);
		goto out;		
	}

	if ((ret = pthread_cond_init(&progress_cond_up, NULL))) {
 		printf("%s: error: pthread_cond_init failed (%d)\n", __func__, ret);
		goto out;		
	}

	if ((ret = pthread_cond_init(&progress_cond_down, NULL))) {
 		printf("%s: error: pthread_cond_init failed (%d)\n", __func__, ret);
		goto out;		
	}
	
	if ((ret = pthread_attr_init(&pthread_attr))) {
 		printf("%s: error: pthread_attr_init failed (%d)\n", __func__, ret);
		goto out;
	}
	
	if ((ret = uti_attr_init(&uti_attr))) {
 		printf("%s: error: uti_attr_init failed (%d)\n", __func__, ret);
		goto out;
	}
	
	if ((ret = UTI_ATTR_SAME_L1(&uti_attr))) {
		printf("%s: error: UTI_ATTR_SAME_L1 failed\n", __func__);
	}
	
	printf("master: cpu=%d\n", sched_getcpu());

	if ((ret = uti_pthread_create(&progress_thr, &pthread_attr, progress_fn, NULL, &uti_attr))) {
		printf("%s: error: uti_pthread_create failed (%d)\n", __func__, ret);
		goto out;
	}

	ret = 0;
out:
	if (ret) {
		__sync_fetch_and_sub(&progress_refc, 1);
	}
}

void progress_start()
{
	//printf("%s: enter\n", __func__);
	if (__sync_val_compare_and_swap(&progress_refc, 0, 1) == 0) {
		progress_init();
	}
	
	pthread_mutex_lock(&progress_mutex);

	if (progress_state == PROGRESS_FINALIZE) {
		printf("%s: info: FINALIZE\n", __func__);
		pthread_mutex_unlock(&progress_mutex);
		return;
	}

	if (progress_state == PROGRESS_START) {
		printf("%s: info: START\n", __func__);
		pthread_mutex_unlock(&progress_mutex);
		return;
	}

	if (progress_state != PROGRESS_INIT) {
		printf("%s: error: unexpected state: %d\n", __func__, progress_state);
		pthread_mutex_unlock(&progress_mutex);
		return;
	}
		
	progress_state = PROGRESS_START;
	__sync_synchronize(); /* memory barrier instruction */
	progress_flag_down = 1;
	pthread_cond_signal(&progress_cond_down);
	pthread_mutex_unlock(&progress_mutex);
}

void do_progress_stop()
{
	int ret;

	/* No stray MPI_Send is generated because the first MPI_Send waits for completion of state transision from START to INIT */
	if ((ret = MPI_Send(NULL, 0, MPI_CHAR, progress_rank, WAKE_TAG, progress_comm)) != MPI_SUCCESS) {
		printf("%s: error: MPI_Send failed (%d)\n", __func__, ret);
		return;
	}

	/* Make sure the following command will observe INIT */
	pthread_mutex_lock(&progress_mutex);
	while (!progress_flag_up) {
		pthread_cond_wait(&progress_cond_up, &progress_mutex);
	}
	progress_flag_up = 0;
	pthread_mutex_unlock(&progress_mutex);
}

void progress_stop()
{
	//printf("%s: enter\n", __func__);

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
		printf("%s: error: unexpected state: %d\n", __func__, progress_state);
		pthread_mutex_unlock(&progress_mutex);
		return;
	}

	pthread_mutex_unlock(&progress_mutex);
	
	do_progress_stop();
}

void progress_finalize()
{
	int ret;
	MPI_Request req;

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
		printf("%s: error: unexpected state: %d\n", __func__, progress_state);
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
		printf("%s: error: MPI_Comm_free failed (%d)\n", __func__, ret);
		return;
	}

	progress_refc = 0;
}
