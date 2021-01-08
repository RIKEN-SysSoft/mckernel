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

#define BUFF_SIZE 1024

int main(int argc, char **argv)
{
	void *mem, *attach;
	int rc = 0;
	int status;
	pid_t pid;
	xpmem_segid_t segid;
	xpmem_apid_t apid;
	struct xpmem_addr addr;
	key_t key = ftok(argv[0], 0);
	int shmid;

	printf("*** %s start ***\n", basename(argv[0]));

	shmid = shmget(key, SZ_MEM, IPC_CREAT | 0660);
	CHKANDJUMP(shmid == -1, "shmget");

	mem = mmap(0, SZ_MEM, PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE |
		MAP_HUGETLB | (LARGE_PAGE_SHIFT << MAP_HUGE_SHIFT), -1, 0);
	CHKANDJUMP(mem == NULL, "mmap");
	memset(mem, 0, SZ_MEM);

	fflush(0);
	pid = fork();
	CHKANDJUMP(pid == -1, "fork failed\n");

	if (pid == 0) {
		/* Child process */
		void *shm = shmat(shmid, NULL, 0);

		CHKANDJUMP(shm == (void *)-1, "shmat in child");

		while ((segid = *(xpmem_segid_t *)shm) == 0) {
		};

		rc = shmdt(shm);
		CHKANDJUMP(rc == -1, "shmdt");

		rc = xpmem_init();
		CHKANDJUMP(rc != 0, "xpmem_init in child");

		apid = xpmem_get(segid, XPMEM_RDWR, XPMEM_PERMIT_MODE, NULL);
		OKNG(apid == -1, "xpmem_get in child");

		addr.apid = apid;
		addr.offset = 0;
		attach = xpmem_attach(addr, SZ_MEM, NULL);
		OKNG(attach == (void *)-1, "xpmem_attach in child");

		*((unsigned long *)attach) = TEST_VAL;

		rc = xpmem_detach(attach);
		OKNG(rc == -1, "xpmem_detach in child");

		fflush(0);
		_exit(0);
	} else {
		/* Parent process */
		void *shm = shmat(shmid, NULL, 0);
		struct shmid_ds buf;

		CHKANDJUMP(shm == (void *)-1, "shmat in parent");
		rc = xpmem_init();
		CHKANDJUMP(rc != 0, "xpmem_init");

		segid = xpmem_make(mem, SZ_MEM, XPMEM_PERMIT_MODE,
			(void *)0666);
		OKNG(segid == -1, "xpmem_make");

		*(xpmem_segid_t *)shm = segid;

		rc = waitpid(pid, &status, 0);
		CHKANDJUMP(rc == -1, "waitpid failed\n");

		OKNG(*((unsigned long *)mem) != TEST_VAL, "validate TEST_VAL");

		rc = shmctl(shmid, IPC_RMID, &buf);
		CHKANDJUMP(rc == -1, "shmctl");

		rc = shmdt(shm);
		CHKANDJUMP(rc == -1, "shmdt");

		rc = xpmem_remove(segid);
		OKNG(rc == -1, "xpmem_remove");
	}

	printf("*** %s PASSED\n\n", basename(argv[0]));
	return 0;

fn_fail:
	printf("*** %s FAILED\n\n", basename(argv[0]));

	return -1;
}
