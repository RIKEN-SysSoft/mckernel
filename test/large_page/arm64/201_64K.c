#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "../util.h"

#define PAGE_SHIFT_2M 21
#define PAGE_SIZE_2M (1UL << PAGE_SHIFT_2M)

#define PAGE_SHIFT_512M 29
#define PAGE_SIZE_512M (1UL << PAGE_SHIFT_512M)

int trial_num;

int shmat_thp(char **argv, size_t page_size)
{
	int ret;
	key_t key;
	int shmid;
	struct shmid_ds shmid_ds;
	char *addr_shmget;

	key = ftok(argv[0], 0);

	shmid = shmget(key, page_size, IPC_CREAT | 0660);
	NG(shmid != -1, "shmget failed\n");

	addr_shmget = shmat(shmid, NULL, 0);
	NG(addr_shmget != (void *)-1, "shmat failed\n");

	addr_shmget[0] = 'z';
	NG(__atomic_load_n(addr_shmget, __ATOMIC_SEQ_CST) == 'z',
	   "memory access failed\n");
	printf("large page request, trial#: %03d, addr: %016lx, size: %ld\n",
	       trial_num++, (unsigned long)addr_shmget, page_size);

	ret = shmctl(shmid, IPC_RMID, &shmid_ds);
	NG(ret != -1, "shmctl failed\n");

	ret = shmdt(addr_shmget);
	NG(ret != -1, "shmdt failed\n");

	return 0;
 fn_fail:
	return 1;
}

int main(int argc, char **argv)
{
	int ret;

	ret = shmat_thp(argv, PAGE_SIZE_2M);
	NG(ret == 0, "shmat_thp failed, size: %ld\n",
	   PAGE_SIZE_2M);

	ret = shmat_thp(argv, PAGE_SIZE_512M);
	NG(ret == 0, "shmat_thp failed, size: %ld\n",
	   PAGE_SIZE_512M);

	return 0;
 fn_fail:
	return 1;
}
