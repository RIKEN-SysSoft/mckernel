#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "./test_chk.h"
#include "./test_rusage.h"

#define TEST_NAME "CT_002"

int main(int argc, char* argv[])
{
	int rc;
	char *buf1 = NULL, *buf2 = NULL;
	struct rusage cur_rusage;
	long cur_maxrss, prev_maxrss = 0, delta_maxrss;

	printf("----  just started ----\n");
	/* check rusage 1st */
	rc = getrusage(RUSAGE_SELF, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 1st");

	cur_maxrss = get_rusage_maxrss(&cur_rusage);
	delta_maxrss = cur_maxrss - prev_maxrss;
	printf("[ RUSAGE_SELF ]\n");
	OKNG(cur_maxrss < 0,
			"  maxrss: %d KB (+ %d KB)", cur_maxrss, delta_maxrss);

	prev_maxrss = cur_maxrss;

	/* mmap 12MB */
	printf("----  mmap and access 12MB (%d KB)  ----\n", 12 * 1024);
	buf1 = mmap(0, 12 * M_BYTE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	CHKANDJUMP(!buf1, "mmap 1st");
	memset(buf1, 0xff, 12 * M_BYTE);

	/* check rusage 2nd */
	rc = getrusage(RUSAGE_SELF, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 2nd");

	cur_maxrss = get_rusage_maxrss(&cur_rusage);
	delta_maxrss = cur_maxrss - prev_maxrss;
	printf("[ RUSAGE_SELF ]\n");
	OKNG(cur_maxrss < (12 * 1024),
			"  maxrss: %d KB (+ %d KB)", cur_maxrss, delta_maxrss);

	prev_maxrss = cur_maxrss;

	/* munmap 12MB */
	printf("----  munmap 12MB (%d KB)  ----\n", 12 * 1024);
	munmap(buf1, 12 * M_BYTE);

	/* check rusage 3rd */
	rc = getrusage(RUSAGE_SELF, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 3rd");

	cur_maxrss = get_rusage_maxrss(&cur_rusage);
	delta_maxrss = cur_maxrss - prev_maxrss;
	printf("[ RUSAGE_SELF ]\n");
	OKNG(cur_maxrss != prev_maxrss,
			"  maxrss: %d KB (+ %d KB)", cur_maxrss, delta_maxrss);

	prev_maxrss = cur_maxrss;

	/* mmap 16MB */
	printf("----  mmap and access 16MB (%d KB)  ----\n", 16 * 1024);
	buf2 = mmap(0, 16 * M_BYTE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	CHKANDJUMP(!buf2, "mmap 2nd");
	memset(buf2, 0xff, 16 * M_BYTE);

	/* check rusage 4th */
	rc = getrusage(RUSAGE_SELF, &cur_rusage);
	CHKANDJUMP(rc == -1, "getrusage 4th");

	cur_maxrss = get_rusage_maxrss(&cur_rusage);
	delta_maxrss = cur_maxrss - prev_maxrss;
	printf("[ RUSAGE_SELF ]\n");
	OKNG(delta_maxrss < (3.8 * 1024) || delta_maxrss > (4.2 * 1024),
			"  maxrss: %d KB (+ %d KB)", cur_maxrss, delta_maxrss);

	prev_maxrss = cur_maxrss;

	munmap(buf2, 16 * M_BYTE);

	printf("*** %s PASS\n\n", TEST_NAME);
	return 0;
fn_fail:

	printf("*** %s FAILED\n\n", TEST_NAME);
	return -1;
}
