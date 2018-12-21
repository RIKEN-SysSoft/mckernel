/* main.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/shm.h>
#include <sys/mman.h>

int main(int argc, char **argv)
{
	int ret;
	int shmid = -1;
	char *shm_addr = (void *)-1;
	size_t shm_length;
	const size_t pgsize = sysconf(_SC_PAGESIZE);

	printf("call shmget.\n");
	shm_length = pgsize;
	shmid = shmget(IPC_PRIVATE, shm_length, IPC_CREAT | SHM_R | SHM_W);
	if (shmid == -1) {
		perror("shmget error.");
		ret = EXIT_FAILURE;
		goto out;
	}

	printf("call shmat.\n");
	shm_addr = shmat(shmid, NULL, 0);
	if (shm_addr == (void *)-1) {
		perror("shmat error.");
		ret = EXIT_FAILURE;
		goto out;
	}
	memset(shm_addr, '0', shm_length);

	printf("call madvise.\n");
	ret = madvise(shm_addr, shm_length, MADV_REMOVE);
	if (ret == -1) {
		perror("madvise error.");
		ret = EXIT_FAILURE;
		goto out;
	}

	ret = EXIT_SUCCESS;
	printf("success.\n");
out:
	if (shm_addr != (void *)-1) {
		shmdt(shm_addr);
	}

	if (shmid != -1) {
		shmctl(shmid, IPC_RMID, 0);
	}
	return ret;
}
