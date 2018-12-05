#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "./test_chk.h"
#include "./test_rusage.h"

#define TEST_NAME "CT_001"

int main(int argc, char* argv[])
{
	int rc;
	struct rusage cur_rusage;
	long cur_utime, cur_stime;
	long delta_utime, delta_stime;
	long prev_utime = 0, prev_stime = 0;

	printf("----  just started ----\n");
	/* check rusage 1st */
	rc = getrusage(RUSAGE_SELF, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 1st");

	cur_utime = get_rusage_utime(&cur_rusage);
	cur_stime = get_rusage_stime(&cur_rusage);
	delta_utime = cur_utime - prev_utime;
	delta_stime = cur_stime - prev_stime; 

	printf("[ RUSAGE_SELF ]\n");
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

	/* add utime 2sec */
	printf("----  add utime 2sec ----\n");
	add_utime(2);

	/* check rusage 2nd */
	rc = getrusage(RUSAGE_SELF, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 2nd");

	cur_utime = get_rusage_utime(&cur_rusage);
	cur_stime = get_rusage_stime(&cur_rusage);
	delta_utime = cur_utime - prev_utime;
	delta_stime = cur_stime - prev_stime; 

	printf("[ RUSAGE_SELF ]\n");
	OKNG(delta_utime < (1.9 * ONE_SEC) || delta_utime > (2.1 * ONE_SEC),
			"  utime: %d.%06d s (+ %d.%06d s)",
			(cur_utime / ONE_SEC), (cur_utime % ONE_SEC),
			(delta_utime / ONE_SEC), (delta_utime % ONE_SEC));
	OKNG(delta_stime < 0 || delta_stime > (0.1 * ONE_SEC),
			"  stime: %d.%06d s (+ %d.%06d s)",
			(cur_stime / ONE_SEC), (cur_stime % ONE_SEC),
			(delta_stime / ONE_SEC), (delta_stime % ONE_SEC));

	prev_utime = cur_utime;
	prev_stime = cur_stime;

	/* add stime 1sec */
	printf("----  add stime 1sec ----\n");
	add_stime(1);

	/* check rusage 3rd */
	rc = getrusage(RUSAGE_SELF, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 3rd");

	cur_utime = get_rusage_utime(&cur_rusage);
	cur_stime = get_rusage_stime(&cur_rusage);
	delta_utime = cur_utime - prev_utime;
	delta_stime = cur_stime - prev_stime; 

	printf("[ RUSAGE_SELF ]\n");
	OKNG(delta_utime < 0 || delta_utime > (0.1 * ONE_SEC),
			"  utime: %d.%06d s (+ %d.%06d s)",
			(cur_utime / ONE_SEC), (cur_utime % ONE_SEC),
			(delta_utime / ONE_SEC), (delta_utime % ONE_SEC));
	OKNG(delta_stime < (0.9 * ONE_SEC) || delta_stime > (1.1 * ONE_SEC),
			"  stime: %d.%06d s (+ %d.%06d s)",
			(cur_stime / ONE_SEC), (cur_stime % ONE_SEC),
			(delta_stime / ONE_SEC), (delta_stime % ONE_SEC));

	printf("*** %s PASS\n\n", TEST_NAME);
	return 0;
fn_fail:

	printf("*** %s FAILED\n\n", TEST_NAME);
	return -1;
}
