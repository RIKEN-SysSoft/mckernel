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
	xpmem_segid_t segid;
	xpmem_apid_t apid;
	struct xpmem_addr addr;

	printf("*** %s start ***\n", basename(argv[0]));

	mem = mmap(0, SZ_MEM, PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE |
		MAP_HUGETLB | (LARGE_PAGE_SHIFT << MAP_HUGE_SHIFT), -1, 0);
	INTERR(mem == NULL, "mmap failed\n");
	memset(mem, 0, SZ_MEM);

	segid = xpmem_make(mem, SZ_MEM, XPMEM_PERMIT_MODE, (void *)0666);
	OKNG(segid != -1, "segid: %lx\n", (unsigned long)segid);

	apid = xpmem_get(segid, XPMEM_RDWR, XPMEM_PERMIT_MODE, NULL);
	OKNG(apid != -1, "apid: %lx\n", (unsigned long)apid);

	addr.apid = apid;
	addr.offset = 0;
	attach = xpmem_attach(addr, SZ_MEM, NULL);
	OKNG(attach != (void *)-1, "attach: %lx\n", (unsigned long)attach);

	ret = xpmem_detach(attach);
	OKNG(ret != -1, "xpmem_detach\n");

	ret = xpmem_remove(segid);
	OKNG(ret != -1, "xpmem_remove\n");

	printf("*** %s PASSED\n\n", basename(argv[0]));
	return 0;

out:
	printf("*** %s FAILED\n\n", basename(argv[0]));

	return -1;
}
