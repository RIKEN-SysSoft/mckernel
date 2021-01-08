#include <unistd.h>
#include <stdlib.h>
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
#include <libgen.h>
#include <xpmem.h>
#include "okng.h"
#include "util.h"

#define DEBUG

#define MAP_HUGE_SHIFT 26
#define MAGIC_HEAD 0x12345678UL
#define MAGIC_TAIL 0x9abcdef0UL

int main(int argc, char **argv)
{
	int i;
	void *mem;
	int ret;
	pid_t pid;
	int status;
	xpmem_segid_t segid;
	int att_pgshift, seg_pgshift;
	size_t att_pgsize, seg_pgsize;

	if (argc < 3) {
		printf("Err: Too few arguments\n");
		printf("Usage: %s <seg_pgshift> <att_pgshift>\n",
		       basename(argv[0]));
		printf("\tpgshift : page-shift of attachment\n");
		printf("\tpgshift : page-shift of segment\n");
		return 1;
	}

	seg_pgshift = atoi(argv[1]);
	seg_pgsize = (1UL << seg_pgshift);
	att_pgshift = atoi(argv[2]);
	att_pgsize = (1UL << att_pgshift);

	INTERR(seg_pgsize > att_pgsize,
	       "seg_pgsize (%lx) > att_pgsize (%lx)\n",
	       seg_pgsize, att_pgsize);

	printf("parent: seg_pgsize: 0x%lx\n", seg_pgsize);
	printf("parent: att_pgsize: 0x%lx\n", att_pgsize);

	mem = mmap(0, att_pgsize,
		   PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE |
		   MAP_HUGETLB | (att_pgshift << MAP_HUGE_SHIFT),
		   -1, 0);

	INTERR(mem == MAP_FAILED, "mapping att_pgsize memory failed\n");
	printf("parent: anonymous_map_addr: %lx - %lx\n",
	       (unsigned long)mem,
	       (unsigned long)mem + att_pgsize);

	/* Create physically-contiguous maps with smaller page-size */
	for (i = 0; i < att_pgsize / seg_pgsize; i++) {
		void *smaller;
		void *addr = mem + i * seg_pgsize;

		smaller = mmap(addr, seg_pgsize,
			   PROT_READ | PROT_WRITE,
			   MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
			   -1, 0);
		INTERR(smaller == MAP_FAILED,
		       "mapping seg_pgsize memory failed\n");

		/* to distinguish from the large page at mem */
		if (i == 1) {
			printf("parent: seg_addr: %lx\n",
			       (unsigned long)addr);
		}
	}

	segid = xpmem_make((void *)mem,
			   att_pgsize, XPMEM_PERMIT_MODE, (void *)0666);
	INTERR(segid == -1, "xpmem_make: addr: %lx, size: %lx, error: %s\n",
	       (unsigned long)mem, att_pgsize, strerror(errno));

	fflush(stdout); /* to prevent buffer from getting duplicated */

	pid = fork();
	INTERR(pid == -1, "fork failed\n");

	if (pid == 0) {
		xpmem_apid_t apid;
		struct xpmem_addr addr;
		void *attach;

		apid = xpmem_get(segid, XPMEM_RDWR,
				 XPMEM_PERMIT_MODE, NULL);
		OKNG(apid != -1, "apid: %lx\n", (unsigned long)apid);

		addr.apid = apid;
		addr.offset = 0;

		INFO("child: attaching...\n");
		attach = xpmem_attach(addr, att_pgsize, NULL);
		INTERR(attach == (void *)-1,
		       "xpmem_attach: size: %lx, error: %s\n",
		     att_pgsize, strerror(errno));

		printf("child: att_addr: %lx\n", (unsigned long)attach);

		*((unsigned long *)attach) = MAGIC_HEAD;
		*((unsigned long *)(attach + att_pgsize
				    - sizeof(unsigned long *))) = MAGIC_TAIL;

		ret = xpmem_detach(attach);
		INTERR(ret == -1, "xpmem_detach failed\n");

		exit(0);
	} else {
		INFO("parent: waiting...\n");
		ret = waitpid(pid, &status, 0);
		INFO("parent: children found\n");
		INTERR(ret == -1, "waitpid failed\n");

		OKNG(*(unsigned long *)mem == MAGIC_HEAD,
		     "HEAD of xpmem area is shared\n");
		OKNG(*((unsigned long *)(mem + att_pgsize
					 - sizeof(unsigned long *))) ==
		     MAGIC_TAIL, "TAIL of xpmem area is shared\n");

		ret = xpmem_remove(segid);
		INTERR(ret == -1, "xpmem_remove failed\n");
	}

	ret = 0;
 out:
	return ret;
}
