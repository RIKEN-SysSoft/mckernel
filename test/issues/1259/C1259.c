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
#include <xpmem.h>
#include "util.h"

#define DEBUG


#define LARGE_PAGE_SHIFT 21
#define LARGE_PAGE_SIZE (1UL << LARGE_PAGE_SHIFT)

#define XPMEM_SIZE (LARGE_PAGE_SIZE * 1)
#define SHM_SIZE (1UL << 12)

#define KEYWORD 0x12345678UL

int main(int argc, char **argv)
{
	void *mem;
	int ret = 0;
	pid_t pid;
	int status;
	key_t key = ftok(argv[0], 0);
	void *shm;
	int shmid;
	xpmem_segid_t segid;
	struct shmid_ds shmctl_buf;

	shmid = shmget(key, SHM_SIZE, IPC_CREAT | 0660);
	CHKANDJUMP(shmid == -1, EXIT_FAILURE, "shmget failed: %s\n",
		   strerror(errno));

	pid = fork();
	CHKANDJUMP(pid == -1, EXIT_FAILURE, "fork failed\n");
	if (pid == 0) {
		xpmem_apid_t apid;
		struct xpmem_addr addr;
		void *attach;

		shm = shmat(shmid, NULL, 0);
		CHKANDJUMP(shm == (void *)-1, EXIT_FAILURE,
			   "shmat failed: %s\n", strerror(errno));

		while ((segid = *(xpmem_segid_t *)shm) == 0) {
		};

		ret = shmdt(shm);
		CHKANDJUMP(ret == -1, EXIT_FAILURE, "shmdt failed\n");

		apid = xpmem_get(segid, XPMEM_RDWR,
				 XPMEM_PERMIT_MODE, NULL);
		CHKANDJUMP(apid == -1, EXIT_FAILURE, "xpmem_get failed: %s\n",
			   strerror(errno));

		addr.apid = apid;
		addr.offset = 0;
		attach = xpmem_attach(addr, XPMEM_SIZE, NULL);

		CHKANDJUMP(attach == (void *)-1, EXIT_FAILURE,
			   "xpmem_attach failed: %s\n", strerror(errno));

		printf("child: xpmem_attachment_addr: %lx\n",
		       attach);

		*((unsigned long *)attach) = KEYWORD;

		ret = xpmem_detach(attach);
		CHKANDJUMP(ret == -1, EXIT_FAILURE, "xpmem_detach failed\n");

		exit(0);
	} else {
		mem = mmap(0, XPMEM_SIZE,
			   PROT_READ | PROT_WRITE,
			   MAP_ANONYMOUS | MAP_PRIVATE |
			   MAP_HUGETLB | (LARGE_PAGE_SHIFT << MAP_HUGE_SHIFT),
			   -1, 0);
		CHKANDJUMP(mem == MAP_FAILED, EXIT_FAILURE, "mmap failed\n");
		printf("parent: anonymous_map_addr: %lx\n",
		       mem);
		memset(mem, 0, XPMEM_SIZE);

		shm = shmat(shmid, NULL, 0);

		CHKANDJUMP(mem == (void *)-1, EXIT_FAILURE,
			   "shmat failed: %s\n", strerror(errno));

		segid = xpmem_make(mem, XPMEM_SIZE, XPMEM_PERMIT_MODE,
				   (void *)0666);
		CHKANDJUMP(segid == -1, EXIT_FAILURE,
			   "xpmem_ioctl failed: %s\n", strerror(errno));

		*(xpmem_segid_t *)shm = segid;

		ret = waitpid(pid, &status, 0);
		CHKANDJUMP(ret == -1, EXIT_FAILURE, "waitpid failed\n");

		NG(*(unsigned long *)mem == KEYWORD,
		   "xpmem area isn't shared?\n");

		ret = shmctl(shmid, IPC_RMID, &shmctl_buf);
		CHKANDJUMP(ret == -1, EXIT_FAILURE, "shmctl failed\n");

		ret = shmdt(shm);
		CHKANDJUMP(ret == -1, EXIT_FAILURE, "shmdt failed\n");

		ret = xpmem_remove(segid);
		CHKANDJUMP(ret == -1, EXIT_FAILURE, "xpmem_remove failed\n");
	}

	ret = 0;
 out:
	return ret;
}
