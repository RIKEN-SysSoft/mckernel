#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "./test_chk.h"
#include "./test_rusage.h"

#define TEST_NAME "CT_008"

int main(int argc, char* argv[])
{
	int rc;
	char *buf_child = NULL, *buf_grand_child = NULL;
	struct rusage cur_rusage;
	long cur_utime, cur_stime, cur_maxrss;
	long delta_utime, delta_stime, delta_maxrss;
	long prev_utime = 0, prev_stime = 0, prev_maxrss = 0;
	int pid, pid_grand_child, status, status_grand_child;

	printf("----  just started ----\n");
	/* check rusage 1st */
	rc = getrusage(RUSAGE_CHILDREN, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 1st");

	cur_utime = get_rusage_utime(&cur_rusage);
	cur_stime = get_rusage_stime(&cur_rusage);
	cur_maxrss = get_rusage_maxrss(&cur_rusage);
	delta_utime = cur_utime - prev_utime;
	delta_stime = cur_stime - prev_stime; 
	delta_maxrss = cur_maxrss - prev_maxrss; 

	printf("[ RUSAGE_CHILDREN ]\n");
	OKNG(cur_utime != 0,
			"  utime: %d.%06d s (+ %d.%06d s)",
			(cur_utime / ONE_SEC), (cur_utime % ONE_SEC),
			(delta_utime / ONE_SEC), (delta_utime % ONE_SEC));
	OKNG(cur_stime != 0,
			"  stime: %d.%06d s (+ %d.%06d s)",
			(cur_stime / ONE_SEC), (cur_stime % ONE_SEC),
			(delta_stime / ONE_SEC), (delta_stime % ONE_SEC));
	OKNG(cur_maxrss != 0 ,
			"  maxrss: %d KB (+ %d KB)", cur_maxrss, delta_maxrss);

	prev_utime = cur_utime;
	prev_stime = cur_stime;
	prev_maxrss = cur_maxrss;

	printf("----  fork child process  ----\n");
	pid = fork();
	CHKANDJUMP(pid == -1, "fork");

	if (pid == 0) { /* child */
		printf("    ----  fork grand_child process  ----\n");
		pid_grand_child = fork();
		CHKANDJUMP(pid_grand_child == -1, "fork grand_child");

		if (pid_grand_child == 0) /* grand_child */
		{
			/* add utime 1sec */
			printf("        ----  add utime 1sec in grand_child  ----\n");
			add_utime(1);

			/* add stime 1sec */
			printf("        ----  add stime 1sec in grand_child  ----\n");
			add_stime(1);
			
			/* mmap 32MB */
			printf("        ----  mmap and access 32MB (%d KB) in grand_child  ----\n", 32 * 1024);
			buf_grand_child = mmap(0, 32 * M_BYTE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
			CHKANDJUMP(!buf_grand_child, "mmap");
			memset(buf_grand_child, 0xff, 32 * M_BYTE);

			/* munmap 32MB */
			printf("        ----  munmap 32MB (%d KB) in grand_child  ----\n", 32 * 1024);
			munmap(buf_grand_child, 16 * M_BYTE);

			printf("        ----  grand_child process exit  ----\n");
			_exit(234);
		}

		/* add utime 2sec */
		printf("    ----  add utime 2sec in child  ----\n");
		add_utime(2);
	
		/* add stime 1sec */
		printf("    ----  add stime 1sec in child  ----\n");
		add_stime(1);

		/* mmap 8MB */
		printf("    ----  mmap and access 8MB (%d KB) in child  ----\n", 8 * 1024);
		buf_child = mmap(0, 8 * M_BYTE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		CHKANDJUMP(!buf_child, "mmap");
		memset(buf_child, 0xff, 8 * M_BYTE);

		/* munmap 8MB */
		printf("    ----  munmap 8MB (%d KB) in child  ----\n", 8 * 1024);
		munmap(buf_child, 8 * M_BYTE);

		printf("    ----  wait grand_child's exit  ----\n");
		rc = waitpid(pid_grand_child, &status_grand_child, 0);
		CHKANDJUMP(rc == -1, "waitpid");

		printf("    ----  child process exit  ----\n");
		_exit(123);
	} else { /* parent */
		printf("----  wait child's exit  ----\n");
		rc = waitpid(pid, &status, 0);
		CHKANDJUMP(rc == -1, "waitpid");
	}

	/* check rusage 2nd */
	rc = getrusage(RUSAGE_CHILDREN, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 2nd");

	cur_utime = get_rusage_utime(&cur_rusage);
	cur_stime = get_rusage_stime(&cur_rusage);
	cur_maxrss = get_rusage_maxrss(&cur_rusage);
	delta_utime = cur_utime - prev_utime;
	delta_stime = cur_stime - prev_stime; 
	delta_maxrss = cur_maxrss - prev_maxrss; 

	printf("[ RUSAGE_CHILDREN ]\n");
	OKNG(cur_utime < (2.9 * ONE_SEC) || delta_utime > (3.1 * ONE_SEC),
			"  utime: %d.%06d s (+ %d.%06d s)  <- 子プロセス2秒、孫プロセス1秒の和",
			(cur_utime / ONE_SEC), (cur_utime % ONE_SEC),
			(delta_utime / ONE_SEC), (delta_utime % ONE_SEC));
	OKNG(cur_stime < (1.9 * ONE_SEC) || delta_stime > (2.1 * ONE_SEC),
			"  stime: %d.%06d s (+ %d.%06d s)  <- 子プロセス1秒、孫プロセス1秒の和",
			(cur_stime / ONE_SEC), (cur_stime % ONE_SEC),
			(delta_stime / ONE_SEC), (delta_stime % ONE_SEC));
	OKNG(cur_maxrss < 32 * 1024 || cur_maxrss > 40 * 1024,
			"  maxrss: %d KB (+ %d KB)  <- 子、孫のmaxrssの最大値",
	        cur_maxrss, delta_maxrss);

	prev_utime = cur_utime;
	prev_stime = cur_stime;
	prev_maxrss = cur_maxrss;

	printf("*** %s PASS\n\n", TEST_NAME);
	return 0;
fn_fail:

	printf("*** %s FAILED\n\n", TEST_NAME);
	return -1;
}
