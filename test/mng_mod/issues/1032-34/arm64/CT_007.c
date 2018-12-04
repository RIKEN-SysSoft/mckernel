#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "./test_chk.h"
#include "./test_rusage.h"

#define TEST_NAME "CT_007"

int main(int argc, char* argv[])
{
	int rc;
	char *buf = NULL, *buf_child = NULL;
	struct rusage cur_rusage;
	long cur_utime, cur_stime, cur_maxrss;
	long delta_utime, delta_stime, delta_maxrss;
	long prev_utime = 0, prev_stime = 0, prev_maxrss = 0;
	int pid, status;

	printf("----  just started ----\n");
	/* check rusage 1st */
	rc = getrusage(RUSAGE_CHILDREN, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 1st");

	cur_maxrss = get_rusage_maxrss(&cur_rusage);
	delta_maxrss = cur_maxrss - prev_maxrss; 

	printf("[ RUSAGE_CHILDREN ]\n");
	OKNG(cur_maxrss != 0,
			"  maxrss: %d KB (+ %d KB)", cur_maxrss, delta_maxrss);

	prev_maxrss = cur_maxrss;

	printf("----  fork child process  ----\n");
	pid = fork();
	CHKANDJUMP(pid == -1, "fork");

	if (pid == 0) { /* child */
		/* add utime 1sec */
		printf("    ----  add utime 1sec in child  ----\n");
		add_utime(1);

		/* mmap 16MB */
		printf("    ----  mmap and access 16MB (%d KB) in child  ----\n", 16 * 1024);
		buf = mmap(0, 16 * M_BYTE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		CHKANDJUMP(!buf, "mmap");
		memset(buf, 0xff, 16 * M_BYTE);

		/* munmap 16MB */
		printf("    ----  munmap 16MB (%d KB) in child  ----\n", 16 * 1024);
		munmap(buf, 16 * M_BYTE);

		printf("    ----  child process exit ----\n");
		_exit(123);
	} else { /* parent */
		/* mmap 32MB */
		printf("----  mmap and access 32MB (%d KB) in parent  ----\n", 32 * 1024);
		buf = mmap(0, 32 * M_BYTE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		CHKANDJUMP(!buf, "mmap");
		memset(buf, 0xff, 32 * M_BYTE);

		/* munmap 32MB */
		printf("----  munmap 32MB (%d KB) in parent  ----\n", 32 * 1024);
		munmap(buf, 32 * M_BYTE);
		
		printf("----  wait child's exit  ----\n");
		rc = waitpid(pid, &status, 0);
		CHKANDJUMP(rc == -1, "waitpid");

	}

	/* check rusage 2nd */
	rc = getrusage(RUSAGE_CHILDREN, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 2nd");

	cur_maxrss = get_rusage_maxrss(&cur_rusage);
	delta_maxrss = cur_maxrss - prev_maxrss; 

	printf("[ RUSAGE_CHILDREN ]\n");
	OKNG(cur_maxrss < 16 * 1024 || cur_maxrss > 32 * 1024,
			"  maxrss: %d KB (+ %d KB)  <- 子プロセス終了後に更新 (プロセス生成時の5～6M + mmapでの16M)", 
	        cur_maxrss, delta_maxrss);

	prev_maxrss = cur_maxrss;

	printf("*** %s PASS\n\n", TEST_NAME);
	return 0;
fn_fail:

	printf("*** %s FAILED\n\n", TEST_NAME);
	return -1;
}
