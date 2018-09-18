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
#include "util.h"

#define DEBUG

int sz_mem[] = {
	4 * (1ULL<<10),
	2 * (1ULL<<20),
	1 * (1ULL<<30),
	134217728};

#define SZ_INDEX 0

int main(int argc, char **argv)
{
	void *mem;
	int ret = 0;
	pid_t pid;
	int status;
	xpmem_segid_t segid;

	mem = mmap(0, sz_mem[SZ_INDEX], PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	CHKANDJUMP(mem == MAP_FAILED, 255, "mmap failed\n");
	memset(mem, 0, sz_mem[SZ_INDEX]);

	segid = xpmem_make(mem, sz_mem[SZ_INDEX], XPMEM_PERMIT_MODE,
			   (void *)0666);
	CHKANDJUMP(segid == -1, 255, "xpmem_ioctl failed: %s\n",
		   strerror(errno));

	pid = fork();
	CHKANDJUMP(pid == -1, 255, "fork failed\n");
	if (pid == 0) {
		xpmem_apid_t apid = xpmem_get(segid, XPMEM_RDWR,
					      XPMEM_PERMIT_MODE, NULL);

		CHKANDJUMP(apid == -1, 255, "xpmem_get failed: %s\n",
			   strerror(errno));

		struct xpmem_addr addr = { .apid = apid, .offset = 0 };
		void *attach = xpmem_attach(addr, sz_mem[SZ_INDEX], NULL);

		CHKANDJUMP(attach == (void *)-1, 255,
			   "xpmem_attach failed: %s\n", strerror(errno));

		*((unsigned long *)attach) = 0x1234;

		ret = xpmem_detach(attach);
		CHKANDJUMP(ret == -1, 255, "xpmem_detach failed\n");

		_exit(123);
	} else {
		ret = waitpid(pid, &status, 0);
		CHKANDJUMP(ret == -1, 255, "waitpid failed\n");

		printf("%lx\n", *((unsigned long *)mem));

		ret = xpmem_remove(segid);
		CHKANDJUMP(ret == -1, 255, "xpmem_remove failed\n");
	}

 fn_exit:
	return ret;
 fn_fail:
	goto fn_exit;
}
