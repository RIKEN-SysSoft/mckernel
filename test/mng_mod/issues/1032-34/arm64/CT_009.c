#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "./test_chk.h"
#include "./test_rusage.h"

#define TEST_NAME "CT_009"

void *child_func(void *arg)
{
	int rc;
	struct rusage cur_rusage;
	long cur_utime, cur_stime;
	long delta_utime, delta_stime;
	long prev_utime = 0, prev_stime = 0;

	/* check rusage in sub thread */
	rc = getrusage(RUSAGE_THREAD, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage");

	cur_utime = get_rusage_utime(&cur_rusage);
	cur_stime = get_rusage_stime(&cur_rusage);
	delta_utime = cur_utime - prev_utime;
	delta_stime = cur_stime - prev_stime; 

	printf("    [ RUSAGE_THREAD ]\n");
	OKNG(cur_utime < 0 || cur_utime > (0.1 * ONE_SEC),
			"      utime: %d.%06d s (+ %d.%06d s)",
			(cur_utime / ONE_SEC), (cur_utime % ONE_SEC),
			(delta_utime / ONE_SEC), (delta_utime % ONE_SEC));
	OKNG(cur_stime < 0 || cur_stime > (0.1 * ONE_SEC),
			"      stime: %d.%06d s (+ %d.%06d s)",
			(cur_stime / ONE_SEC), (cur_stime % ONE_SEC),
			(delta_stime / ONE_SEC), (delta_stime % ONE_SEC));

	/* add utime 2sec */
	printf("    ----  add utime 2sec in sub thread  ----\n");
	add_utime(2);

	/* add stime 1sec */
	printf("    ----  add stime 1sec in sub thread  ----\n");
	add_stime(1);

	/* check rusage in sub thread */
	rc = getrusage(RUSAGE_THREAD, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage");

	cur_utime = get_rusage_utime(&cur_rusage);
	cur_stime = get_rusage_stime(&cur_rusage);
	delta_utime = cur_utime - prev_utime;
	delta_stime = cur_stime - prev_stime; 

	printf("    [ RUSAGE_THREAD ]\n");
	OKNG(delta_utime < (1.9 * ONE_SEC) || delta_utime > (2.1 * ONE_SEC),
			"      utime: %d.%06d s (+ %d.%06d s)",
			(cur_utime / ONE_SEC), (cur_utime % ONE_SEC),
			(delta_utime / ONE_SEC), (delta_utime % ONE_SEC));
	OKNG(delta_stime < (0.9 * ONE_SEC) || delta_stime > (1.1 * ONE_SEC),
			"      stime: %d.%06d s (+ %d.%06d s)",
			(cur_stime / ONE_SEC), (cur_stime % ONE_SEC),
			(delta_stime / ONE_SEC), (delta_stime % ONE_SEC));

fn_fail:
	printf("    ----  sub thread exit  ----\n");
	return;
}

int main(int argc, char* argv[])
{
	int rc;
	struct rusage cur_rusage;
	long cur_utime, cur_stime;
	long delta_utime, delta_stime;
	long prev_utime = 0, prev_stime = 0;
	int status;
	pthread_t sub_th;

	printf("----  just started ----\n");
	/* check rusage 1st */
	rc = getrusage(RUSAGE_THREAD, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 1st");

	cur_utime = get_rusage_utime(&cur_rusage);
	cur_stime = get_rusage_stime(&cur_rusage);
	delta_utime = cur_utime - prev_utime;
	delta_stime = cur_stime - prev_stime; 

	OKNG(cur_utime < 0 || cur_utime > (0.1 * ONE_SEC),
			"  utime: %d.%06d s (+ %d.%06d s)",
			(cur_utime / ONE_SEC), (cur_utime % ONE_SEC),
			(delta_utime / ONE_SEC), (delta_utime % ONE_SEC));
	OKNG(cur_stime < 0 || cur_stime > (0.1 * ONE_SEC),
			"  stime: %d.%06d s (+ %d.%06d s)",
			(cur_stime / ONE_SEC), (cur_stime % ONE_SEC),
			(delta_stime / ONE_SEC), (delta_stime % ONE_SEC));

	prev_utime = cur_utime;
	prev_stime = cur_stime;

	/* add utime 1sec */
	printf("----  add utime 1sec in main thread  ----\n");
	add_utime(1);

	printf("----  create thread and join  ----\n");
	status = pthread_create(&sub_th, NULL, child_func, NULL);
	CHKANDJUMP(status != 0, "pthread_create()");

	pthread_join(sub_th, NULL);

	/* check rusage 2nd  */
	rc = getrusage(RUSAGE_THREAD, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 2nd");

	cur_utime = get_rusage_utime(&cur_rusage);
	cur_stime = get_rusage_stime(&cur_rusage);
	delta_utime = cur_utime - prev_utime;
	delta_stime = cur_stime - prev_stime; 

	printf("[ RUSAGE_THREAD ]\n");
	OKNG(delta_utime < (0.9 * ONE_SEC) || delta_utime > (1.1 * ONE_SEC),
			"  utime: %d.%06d s (+ %d.%06d s)",
			(cur_utime / ONE_SEC), (cur_utime % ONE_SEC),
			(delta_utime / ONE_SEC), (delta_utime % ONE_SEC));
	OKNG(delta_stime < (2.9 * ONE_SEC) || delta_stime > (3.1 * ONE_SEC),
			"  stime: %d.%06d s (+ %d.%06d s)  <- join待ち3秒",
			(cur_stime / ONE_SEC), (cur_stime % ONE_SEC),
			(delta_stime / ONE_SEC), (delta_stime % ONE_SEC));

	prev_utime = cur_utime;
	prev_stime = cur_stime;

	printf("*** %s PASS\n\n", TEST_NAME);
	return 0;
fn_fail:

	printf("*** %s FAILED\n\n", TEST_NAME);
	return -1;
}
