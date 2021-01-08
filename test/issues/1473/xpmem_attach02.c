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
#define MAGIC_MIDDLE 0x9abcdef0UL
#define MAGIC_TAIL 0x87654321UL

int main(int argc, char **argv)
{
	int i;
	int ret;
	void *mem;
	void *seg_addr;
	size_t seg_size;
	xpmem_segid_t segid;
	pid_t pid;
	int status;
	int large_pgshift, small_pgshift;
	size_t large_pgsize, small_pgsize;

	if (argc < 3) {
		printf("Err: Too few arguments\n");
		printf("Usage: %s <small_pgshift> <large_pgshift>\n",
		       basename(argv[0]));
		printf("\tpgshift : page-shift of head and tail part\n");
		printf("\tpgshift : page-shift of middle part\n");
		return 1;
	}

	small_pgshift = atoi(argv[1]);
	small_pgsize = (1UL << small_pgshift);
	large_pgshift = atoi(argv[2]);
	large_pgsize = (1UL << large_pgshift);

	INTERR(small_pgsize > large_pgsize,
	       "small_pgsize (%lx) > large_pgsize (%lx)\n",
	       small_pgsize, large_pgsize);

	printf("parent: small_pgsize: 0x%lx\n", small_pgsize);
	printf("parent: large_pgsize: 0x%lx\n", large_pgsize);

	mem = mmap(0, 3 * large_pgsize,
		   PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE |
		   MAP_HUGETLB | (large_pgshift << MAP_HUGE_SHIFT),
		   -1, 0);

	INTERR(mem == MAP_FAILED, "anonymous mmap failed\n");
	printf("parent: anonymous: addr: %lx, size: %lx\n",
	       (unsigned long)mem, 3 * large_pgsize);

	seg_addr = mem + large_pgsize - 3 * small_pgsize;
	seg_size = 3 * small_pgsize + large_pgsize + 3 * small_pgsize;
	segid = xpmem_make(seg_addr, seg_size,
			   XPMEM_PERMIT_MODE, (void *)0666);
	INTERR(segid == -1, "xpmem_make: addr: %lx, size: %lx, error: %s\n",
	       (unsigned long)seg_addr, seg_size, strerror(errno));

	fflush(stdout); /* to prevent buffer from getting duplicated */

	pid = fork();
	INTERR(pid == -1, "fork failed\n");

	if (pid == 0) {
		xpmem_apid_t apid;
		struct xpmem_addr xpmem_addr;
		void *head_addr, *middle_addr, *tail_addr;
		void *addr;

		apid = xpmem_get(segid, XPMEM_RDWR,
				 XPMEM_PERMIT_MODE, NULL);
		OKNG(apid != -1, "apid: %lx\n", (unsigned long)apid);

		xpmem_addr.apid = apid;
		xpmem_addr.offset = 0;

		INFO("child: attaching...\n");
		head_addr = xpmem_attach(xpmem_addr, seg_size, NULL);
		INTERR(head_addr == (void *)-1,
		       "xpmem_attach: size: %lx, error: %s\n",
		       seg_size, strerror(errno));

		printf("child: head_addr: %lx\n", (unsigned long)head_addr);

		middle_addr = head_addr + 3 * small_pgsize;
		printf("child: middle_addr: %lx\n", (unsigned long)middle_addr);

		tail_addr = head_addr + 3 * small_pgsize + large_pgsize;
		printf("child: tail_addr: %lx\n", (unsigned long)tail_addr);

		fflush(stdout);

		for (i = 0; i < 3; i++) {
			addr = head_addr + i * small_pgsize;
			*((unsigned long *)addr) = MAGIC_HEAD + i;
		}
		*((unsigned long *)middle_addr) = MAGIC_MIDDLE;
		for (i = 0; i < 3; i++) {
			addr = tail_addr + i * small_pgsize;
			*((unsigned long *)addr) = MAGIC_TAIL + i;
		}

		ret = xpmem_detach(head_addr);
		INTERR(ret == -1, "xpmem_detach failed\n");

		exit(0);
	} else {
		void *head_addr = seg_addr;
		void *middle_addr = seg_addr + 3 * small_pgsize;
		void *tail_addr = seg_addr + 3 * small_pgsize + large_pgsize;
		void *addr;

		INFO("parent: waiting...\n");
		ret = waitpid(pid, &status, 0);
		INFO("parent: children reaped\n");
		INTERR(ret == -1, "waitpid failed\n");

		for (i = 0; i < 3; i++) {
			addr = head_addr + i * small_pgsize;
			OKNG(*((unsigned long *)addr) == MAGIC_HEAD + i,
			     "%lx: %lx, expected: %lx\n",
			     (unsigned long)addr, *((unsigned long *)addr),
			     MAGIC_HEAD + i);
		}
		OKNG(*((unsigned long *)middle_addr) == MAGIC_MIDDLE,
		     "%lx: %lx, expected: %lx\n",
		     (unsigned long)middle_addr,
		     *((unsigned long *)middle_addr),
		     MAGIC_MIDDLE);
		for (i = 0; i < 3; i++) {
			addr = tail_addr + i * small_pgsize;
			OKNG(*((unsigned long *)addr) == MAGIC_TAIL + i,
			     "%lx: %lx, expected: %lx\n",
			     (unsigned long)addr, *((unsigned long *)addr),
			     MAGIC_TAIL + i);
		}

		ret = xpmem_remove(segid);
		INTERR(ret == -1, "xpmem_remove failed\n");
	}

	ret = 0;
 out:
	return ret;
}
