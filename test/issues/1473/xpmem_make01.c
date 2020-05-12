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
	int ret;
	int status;
	pid_t pid;
	xpmem_segid_t segid;
	xpmem_apid_t apid;
	struct xpmem_addr addr;

	START("xpmem_make size: -1\n");

	mem = mmap(0, SZ_MEM, PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE |
		MAP_HUGETLB | (LARGE_PAGE_SHIFT << MAP_HUGE_SHIFT), -1, 0);
	INTERR(mem == MAP_FAILED, "mmap failed\n");
	memset(mem, 0, SZ_MEM);

	segid = xpmem_make(0, -1, XPMEM_PERMIT_MODE, (void *)0666);
	OKNG(segid != -1, "xpmem_make returned %lx\n", (unsigned long)segid);

	fflush(0);
	pid = fork();
	INTERR(pid == -1, "fork failed\n");

	if (pid == 0) {
		/* Child process */
		apid = xpmem_get(segid, XPMEM_RDWR, XPMEM_PERMIT_MODE, NULL);
		OKNG(apid != -1, "child: xpmem_get returned %lx\n",
		     (unsigned long)apid);

		addr.apid = apid;
		addr.offset = (unsigned long)mem;
		attach = xpmem_attach(addr, SZ_MEM, NULL);
		OKNG(attach != (void *)-1, "child: xpmem_attach returned %lx\n",
		     (unsigned long)attach);

		*((unsigned long *)attach) = TEST_VAL;

		ret = xpmem_detach(attach);
		OKNG(ret != -1, "child: xpmem_detach returned %d\n",
		     ret);

		fflush(0);
		_exit(0);
	} else {
		/* Parent process */
		ret = waitpid(pid, &status, 0);
		INTERR(ret == -1, "waitpid failed\n");

		OKNG(*((unsigned long *)mem) == TEST_VAL,
		     "parent: TEST_VAL found\n");

		ret = xpmem_remove(segid);
		OKNG(ret != -1, "parent: xpmem_remove returned %d\n",
		     errno);
	}

	return 0;

out:
	return 1;
}
