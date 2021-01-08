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
#include "okng.h"

int main(int argc, char **argv)
{
	void *mem, *attach;
	int ret = 0;
	int status;
	pid_t pid;
	xpmem_segid_t segid;
	xpmem_apid_t apid;
	struct xpmem_addr addr;

	printf("*** %s start ***\n", basename(argv[0]));

	mem = mmap(0, SZ_MEM, PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE |
		MAP_HUGETLB | (LARGE_PAGE_SHIFT << MAP_HUGE_SHIFT), -1, 0);
	INTERR(mem == NULL, "mmap failed\n");
	memset(mem, 0, SZ_MEM);

	INTERR(ret != 0, "xpmem_init failed\n");

	segid = xpmem_make(mem, SZ_MEM, XPMEM_PERMIT_MODE, (void *)0666);
	OKNG(segid != -1, "xpmem_make\n");

	fflush(0);
	pid = fork();
	INTERR(pid == -1, "fork failed\n");

	if (pid == 0) {
		/* Child process */
		apid = xpmem_get(segid, XPMEM_RDWR, XPMEM_PERMIT_MODE, NULL);
		OKNG(apid != -1, "xpmem_get in child\n");

		addr.apid = apid;
		addr.offset = 0;
		attach = xpmem_attach(addr, SZ_MEM, NULL);
		OKNG(attach != (void *)-1, "xpmem_attach in child\n");

		*((unsigned long *)attach) = TEST_VAL;

		fflush(0);
		_exit(0);
	} else {
		/* Parent process */
		ret = waitpid(pid, &status, 0);
		INTERR(ret == -1, "waitpid failed\n");

		OKNG(*((unsigned long *)mem) == TEST_VAL,
		     "TEST_VAL found\n");

		ret = xpmem_remove(segid);
		OKNG(ret != -1, "xpmem_remove in parent\n");
	}

	printf("*** %s PASSED\n\n", basename(argv[0]));
	return 0;

out:
	printf("*** %s FAILED\n\n", basename(argv[0]));

	return -1;
}
