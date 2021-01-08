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
#include <sched.h>
#include <xpmem.h>
#include "util.h"
#include "okng.h"

#define DEBUG

#define SHM_SIZE (1UL << 12)

#define MAP_HUGE_SHIFT 26
#define KEYWORD 0x12345678UL

void usage(void)
{
	printf("Usage: huge_page_map: <pgshift> <pgnum> <pgoffset>\n");
	printf("\tpgshift : pageshift of map area (Using MAP_HUGETLB)\n");
	printf("\t            -1 means using small pagesize\n");
	printf("\tpgnum   : number of page of map area\n");
	printf("\tpgoffset: offset of last page\n");
}


void *mmap_flag(size_t mapsize, int page_shift)
{
	char *addr_mmap;
	int flags = MAP_ANONYMOUS | MAP_PRIVATE;

	if (page_shift >= 0) {
		/* mean use MAP_HUGETLB */
		flags |= MAP_HUGETLB | (page_shift << MAP_HUGE_SHIFT);
	}

	addr_mmap = mmap(0, mapsize,
			PROT_READ | PROT_WRITE,
			flags, -1, 0);

	return addr_mmap;
}

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
	int pgshift, pgnum;
	size_t pgsize, map_size, pgoffset;

	if (argc < 4) {
		printf("Err: Too few arguments\n");
		usage();
		return -1;
	}

	pgshift = atoi(argv[1]);
	pgnum = atoi(argv[2]);
	pgoffset = atol(argv[3]);
	if (pgshift > 0) {
		pgsize = (1UL << pgshift);
	} else {
		pgsize = getpagesize();
	}

	if (pgoffset > 0) {
		map_size = (pgsize * (pgnum - 1)) + pgoffset;
	} else {
		map_size = pgsize * pgnum;
	}
	INFO("map_size: %lx\n", map_size);

	shmid = shmget(key, SHM_SIZE, IPC_CREAT | 0660);
	INTERR(shmid == -1, "shmget failed: %s\n",
		   strerror(errno));

	printf("EXPECT_PAGE_SIZE: 0x%lx\n", pgsize);
	fflush(stdout);

	pid = fork();
	INTERR(pid == -1, "fork failed\n");
	if (pid == 0) {
		xpmem_apid_t apid;
		struct xpmem_addr addr;
		void *attach;

		shm = shmat(shmid, NULL, 0);
		INTERR(shm == (void *)-1,
			   "shmat failed: %s\n", strerror(errno));

		INFO("child: wait until segid is posted\n");
		while ((segid = *(xpmem_segid_t *)shm) == 0) {
			sched_yield();
		};

		INFO("child: segid: %lx\n", (unsigned long)segid);

		ret = shmdt(shm);
		INTERR(ret == -1, "shmdt failed\n");

		apid = xpmem_get(segid, XPMEM_RDWR,
				 XPMEM_PERMIT_MODE, NULL);
		INTERR(apid == -1, "xpmem_get failed: %s\n",
			   strerror(errno));

		addr.apid = apid;
		addr.offset = 0;
		attach = xpmem_attach(addr, map_size, NULL);

		INTERR(attach == (void *)-1,
			   "xpmem_attach failed: %s\n", strerror(errno));

		printf("child: xpmem_attachment_addr: %lx\n",
		       (unsigned long)attach);

		*((unsigned long *)attach) = KEYWORD;
		if (pgnum > 1 && pgshift > 0) {
			*((unsigned long *)(attach +
				(1UL << pgshift))) = KEYWORD;
		}
		*((unsigned long *)(attach + map_size
			- sizeof(unsigned long *))) = KEYWORD;

		ret = xpmem_detach(attach);
		INTERR(ret == -1, "xpmem_detach failed\n");

		exit(0);
	} else {
		mem = mmap_flag(map_size, pgshift);
		INTERR(mem == MAP_FAILED, "mmap failed\n");
		INFO("parent: anonymous_map_addr: %lx - %lx\n",
		     (unsigned long)mem, (unsigned long)(mem + map_size));

		shm = shmat(shmid, NULL, 0);

		INTERR(shm == (void *)-1,
			   "shmat failed: %s\n", strerror(errno));

		segid = xpmem_make(mem, map_size, XPMEM_PERMIT_MODE,
				   (void *)0666);
		INTERR(segid == -1,
			   "xpmem_ioctl failed: %s\n", strerror(errno));

		INFO("parent: posting segid of %lx\n", (unsigned long)segid);
		*(xpmem_segid_t *)shm = segid;

		ret = waitpid(pid, &status, 0);
		INTERR(ret == -1, "waitpid failed\n");

		ret = shmctl(shmid, IPC_RMID, &shmctl_buf);
		INTERR(ret == -1, "shmctl failed\n");

		ret = shmdt(shm);
		INTERR(ret == -1, "shmdt failed\n");

		OKNG(*(unsigned long *)mem == KEYWORD,
			"HEAD of xpmem area is shared\n");
		if (pgnum > 1 && pgshift > 0) {
			OKNG(*((unsigned long *)(mem +
				(1UL << pgshift))) == KEYWORD,
			"MIDDLE of xpmem area is shared\n");
		}
		OKNG(*((unsigned long *)(mem + map_size
				- sizeof(unsigned long *))) == KEYWORD,
			"TAIL of xpmem area is shared\n");
		printf("xpmem area is shared: OK\n");

		ret = xpmem_remove(segid);
		INTERR(ret == -1, "xpmem_remove failed\n");
	}

	ret = 0;
 out:
	return ret;
}
