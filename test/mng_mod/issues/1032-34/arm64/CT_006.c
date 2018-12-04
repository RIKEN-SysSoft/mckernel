#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "./test_chk.h"
#include "./test_rusage.h"

#define TEST_NAME "CT_006"

int main(int argc, char* argv[])
{
	int rc;
	char *buf = NULL;
	struct rusage cur_rusage;
	long cur_utime, cur_stime, cur_maxrss;
	long delta_utime, delta_stime, delta_maxrss;
	long prev_utime = 0, prev_stime = 0, prev_maxrss = 0;
	int pid, status;

	printf("----  just started ----\n");
	/* check rusage 1st */
	rc = getrusage(RUSAGE_CHILDREN, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 1st");

	cur_utime = get_rusage_utime(&cur_rusage);
	cur_stime = get_rusage_stime(&cur_rusage);
	delta_utime = cur_utime - prev_utime;
	delta_stime = cur_stime - prev_stime; 

	printf("[ RUSAGE_CHILDREN ]\n");
	OKNG(cur_utime != 0,
			"  utime: %d.%06d s (+ %d.%06d s)",
			(cur_utime / ONE_SEC), (cur_utime % ONE_SEC),
			(delta_utime / ONE_SEC), (delta_utime % ONE_SEC));
	OKNG(cur_stime != 0,
			"  stime: %d.%06d s (+ %d.%06d s)",
			(cur_stime / ONE_SEC), (cur_stime % ONE_SEC),
			(delta_stime / ONE_SEC), (delta_stime % ONE_SEC));

	prev_utime = cur_utime;
	prev_stime = cur_stime;

	printf("----  fork child process  ----\n");
	pid = fork();
	CHKANDJUMP(pid == -1, "fork");

	if (pid == 0) { /* child */
		/* add utime 2sec */
		printf("    ----  add utime 2sec in child  ----\n");
		add_utime(2);
	
		/* add stime 1sec */
		printf("    ----  add stime 1sec in child  ----\n");
		add_stime(1);

		printf("    ----  child process exit  ----\n");
		_exit(123);
	} else { /* parent */
		/* add utime 1sec */
		printf("----  add utime 1sec in parent  ----\n");
		add_utime(1);
		
		/* check rusage 2nd */
		rc = getrusage(RUSAGE_CHILDREN, &cur_rusage);
		CHKANDJUMP(rc == -1, "getrusage 1st");

		cur_utime = get_rusage_utime(&cur_rusage);
		cur_stime = get_rusage_stime(&cur_rusage);
		delta_utime = cur_utime - prev_utime;
		delta_stime = cur_stime - prev_stime; 

		printf("[ RUSAGE_CHILDREN ]\n");
		OKNG(cur_utime != 0,
				"  utime: %d.%06d s (+ %d.%06d s)  <- 子プロセスが未終了のため、0",
				(cur_utime / ONE_SEC), (cur_utime % ONE_SEC),
				(delta_utime / ONE_SEC), (delta_utime % ONE_SEC));
		OKNG(cur_stime != 0,
				"  stime: %d.%06d s (+ %d.%06d s)  <- 子プロセスが未終了のため、0",
				(cur_stime / ONE_SEC), (cur_stime % ONE_SEC),
				(delta_stime / ONE_SEC), (delta_stime % ONE_SEC));

		printf("----  wait child's exit  ----\n");
		rc = waitpid(pid, &status, 0);
		CHKANDJUMP(rc == -1, "waitpid");

	}

	/* check rusage 3rd */
	rc = getrusage(RUSAGE_CHILDREN, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 2nd");

	cur_utime = get_rusage_utime(&cur_rusage);
	cur_stime = get_rusage_stime(&cur_rusage);
	delta_utime = cur_utime - prev_utime;
	delta_stime = cur_stime - prev_stime; 

	printf("[ RUSAGE_CHILDREN ]\n");
	OKNG(delta_utime < (1.9 * ONE_SEC) || delta_utime > (2.1 * ONE_SEC),
			"  utime: %d.%06d s (+ %d.%06d s)",
			(cur_utime / ONE_SEC), (cur_utime % ONE_SEC),
			(delta_utime / ONE_SEC), (delta_utime % ONE_SEC));
	OKNG(delta_stime < (0.9 * ONE_SEC) || delta_stime > (1.1 * ONE_SEC),
			"  stime: %d.%06d s (+ %d.%06d s)",
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
