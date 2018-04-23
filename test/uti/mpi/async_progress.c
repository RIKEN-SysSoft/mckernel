#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "util.h"

static pthread_t thr;
static pthread_mutex_t mutex;
static pthread_cond_t cond;
static volatile int flag;

static MPI_Comm progress_comm;
static int progress_refc;
#define WAKE_TAG 100

static void *progress_fn(void* data)
{
	int rc;
	MPI_Request req;
	int completed;
	struct rusage ru_start, ru_end;
	struct timeval tv_start, tv_end;

	if ((rc = getrusage(RUSAGE_THREAD, &ru_start))) {
		printf("%s: ERROR: getrusage failed (%d)\n", __FUNCTION__, rc);
	}

	if ((rc = gettimeofday(&tv_start, NULL))) {
		printf("%s: ERROR: gettimeofday failed (%d)\n", __FUNCTION__, rc);
	}

	print_cpu_last_executed_on("async");

	if ((rc = MPI_Irecv(NULL, 0, MPI_CHAR, 0, WAKE_TAG, progress_comm, &req)) != MPI_SUCCESS) {
		printf("%s: ERROR: MPI_Irecv failed (%d)\n", __FUNCTION__, rc);
	}

#if 0
	completed = 0;
	while (!completed) {
		if ((rc = MPI_Test(&req, &completed, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
			printf("%s: ERROR: MPI_Test failed (%d)\n", __FUNCTION__, rc);
			break;
		}
		usleep(1);
		//sched_yield();
	}
#else
	if ((rc = MPI_Wait(&req, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
		printf("%s: ERROR: MPI_Wait failed (%d)\n", __FUNCTION__, rc);
	}
#endif
 out:
	if ((rc = getrusage(RUSAGE_THREAD, &ru_end))) {
		printf("%s: ERROR: getrusage failed (%d)\n", __FUNCTION__, rc);
	}

	if ((rc = gettimeofday(&tv_end, NULL))) {
		printf("%s: ERROR: gettimeofday failed (%d)\n", __FUNCTION__, rc);
	}

	printf("%s: wall: %ld, user: %ld, sys: %ld\n", __FUNCTION__,
		   DIFFUSEC(tv_end, tv_start),
		   DIFFUSEC(ru_end.ru_utime, ru_start.ru_utime),
		   DIFFUSEC(ru_end.ru_stime, ru_start.ru_stime));

	pthread_mutex_lock(&mutex);
	flag = 1;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);
	//printf("%s: after cond_signal,flag=%d\n", __FUNCTION__, flag);
}

void INIT_ASYNC_THREAD_()
{
	int rc;
	char *my_async_progress_str;
	pthread_attr_t attr;
	cpu_set_t cpuset;
	char *async_progress_pin_str;
	int progress_cpus[1024];
	int n_progress_cpus = 0;
	char *list, *token;
	char *rank_str;
	int rank;

	my_async_progress_str = getenv("MY_ASYNC_PROGRESS");
	if (!my_async_progress_str) {
		return;
	}
	if (atoi(my_async_progress_str) == 0) {
		return;
	}

	if (__sync_fetch_and_add(&progress_refc, 1) > 0) {
		return;
	}

	if ((rc = MPI_Comm_dup(MPI_COMM_SELF, &progress_comm))) {
		printf("%s: ERROR: MPI_Comm_dup failed (%d)\n", __FUNCTION__, rc);
		goto sub_out;
	}

	if ((rc = pthread_attr_init(&attr))) {
 		printf("%s: ERROR: pthread_attr_init failed (%d)\n", __FUNCTION__, rc);
		goto sub_out;
	}

	char *disable_uti_str = getenv("DISABLE_UTI");
	if (!disable_uti_str) {

		rc = syscall(731, 1, NULL);
		if (rc) {
			fprintf(stderr, "util_indicate_clone rc=%d, errno=%d\n", rc, errno);
			fflush(stderr);
		}
		
	} else {
		async_progress_pin_str = getenv("I_MPI_ASYNC_PROGRESS_PIN");
		if (!async_progress_pin_str) {
			printf("%s: ERROR: I_MPI_ASYNC_PROGRESS_PIN not found\n", __FUNCTION__);
			goto sub_out;
		}
		
		list = async_progress_pin_str;
		while (1) {
			token = strsep(&list, ",");
			if (!token) {
				break;
			}
			progress_cpus[n_progress_cpus++] = atoi(token);
		}
		
		rank_str = getenv("PMI_RANK");
		if (!rank_str) {
			printf("%s: ERROR: PMI_RANK not found\n", __FUNCTION__);
			goto sub_out;
		}
		rank = atoi(rank_str);

		CPU_ZERO(&cpuset);
		CPU_SET(progress_cpus[rank % n_progress_cpus], &cpuset);
		
		//printf("%s: rank=%d,n_progress_cpus=%d,progress_cpu=%d\n", __FUNCTION__, rank, n_progress_cpus, progress_cpus[rank % n_progress_cpus]);
		
		if ((rc = pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpuset))) {
			printf("%s: ERROR: pthread_attr_setaffinity_np failed (%d)\n", __FUNCTION__, rc);
			goto sub_out;
		}
	}

	pthread_mutex_init(&mutex, NULL);
	pthread_cond_init(&cond, NULL);

	if ((rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))) {
 		printf("%s: ERROR: pthread_attr_setdetachstate failed (%d)\n", __FUNCTION__, rc);
		goto sub_out;
	}

    if ((rc = pthread_create(&thr, &attr, progress_fn, NULL))) {
		printf("%s: ERROR: pthread_create failed (%d)\n", __FUNCTION__, rc);
		goto sub_out;
	}

 fn_exit:
	return;

 sub_out:
	__sync_fetch_and_sub(&progress_refc, 1);
	goto fn_exit;
}

void FINALIZE_ASYNC_THREAD_()
{
	int rc;
	char *my_async_progress_str;
	MPI_Request req;

	my_async_progress_str = getenv("MY_ASYNC_PROGRESS");
	if (!my_async_progress_str) {
		return;
	}
	if (atoi(my_async_progress_str) == 0) {
		return;
	}

	if (progress_refc == 0) {
		return;
	}

	if (__sync_sub_and_fetch(&progress_refc, 1) != 0) {
		return;
	}

	if ((rc = MPI_Isend(NULL, 0, MPI_CHAR, 0, WAKE_TAG, progress_comm, &req)) != MPI_SUCCESS) {
		printf("%s: ERROR: MPI_Send failed (%d)\n", __FUNCTION__, rc);
		return;
	}

	if ((rc = MPI_Wait(&req, MPI_STATUS_IGNORE)) != MPI_SUCCESS) {
		printf("%s: ERROR: MPI_Wait failed (%d)\n", __FUNCTION__, rc);
		return;
	}

#if 1
	//printf("%s: before cond_wait\n", __FUNCTION__);

	pthread_mutex_lock(&mutex);
	while(!flag) {
		pthread_cond_wait(&cond, &mutex);
	}
	flag = 0;
	pthread_mutex_unlock(&mutex);
	//printf("%s: after cond_wait\n", __FUNCTION__);
#else
	pthread_join(thr, NULL);
#endif

	if ((rc = MPI_Comm_free(&progress_comm)) != MPI_SUCCESS) {
		printf("%s: ERROR: MPI_Comm_free failed (%d)\n", __FUNCTION__, rc);
		return;
	}
}
