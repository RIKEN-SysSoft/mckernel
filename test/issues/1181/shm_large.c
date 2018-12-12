#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define SHM_SIZE (16 << 20)

int main(int argc, char **argv)
{
	void *shm = NULL;
	key_t key = ftok(argv[0], 0);
	int shmid;
	struct shmid_ds buf;

	shmid = shmget(key, SHM_SIZE, IPC_CREAT | 0660);
	if (shmid < 0) {
		perror("shmget: ");
		return -1;
	}

	shm = shmat(shmid, NULL, 0);
	if (!shm) {
		perror("shmat: ");
		return -1;
	}

	printf("shmat to %p, size: %ldM\n", shm, SHM_SIZE / 1024 / 1024);
	memset(shm, 0, SHM_SIZE);

	shmdt(shm);

	shmctl(shmid, IPC_RMID, &buf);

	return 0;
}
