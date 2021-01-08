#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <xpmem.h>
#include <libgen.h>
#include "util.h"

int main(int argc, char **argv)
{
	void *mem, *attach;
	int rc = 0;
	int status;
	pid_t pid;
	xpmem_segid_t segid;
	xpmem_apid_t apid;
	struct xpmem_addr addr;

	printf("*** %s start ***\n", basename(argv[0]));

	mem = mmap(0, SZ_MEM, PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE |
		MAP_HUGETLB | (LARGE_PAGE_SHIFT << MAP_HUGE_SHIFT), -1, 0);
	CHKANDJUMP(mem == NULL, "mmap");
	memset(mem, 0, SZ_MEM);

	rc = xpmem_init();
	CHKANDJUMP(rc != 0, "xpmem_init");

	segid = xpmem_make(mem, SZ_MEM, XPMEM_PERMIT_MODE, (void *)0666);
	OKNG(segid == -1, "xpmem_make");

	fflush(0);
	pid = fork();
	CHKANDJUMP(pid == -1, "fork failed\n");

	if (pid == 0) {
		/* Child process */
		sleep(1); /* wait for parent process exit */
		apid = xpmem_get(segid, XPMEM_RDWR, XPMEM_PERMIT_MODE, NULL);
		OKNG(apid != -1,
			"xpmem_get in child failed (parent process exited already");
		fflush(0);

	} else {
		/* Parent process */
		_exit(0);
	}

	printf("*** %s PASSED\n\n", basename(argv[0]));
	return 0;

fn_fail:
	printf("*** %s FAILED\n\n", basename(argv[0]));

	return -1;
}
