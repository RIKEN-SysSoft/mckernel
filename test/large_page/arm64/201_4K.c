#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "../util.h"

#define PAGE_SHIFT_64K 16
#define PAGE_SIZE_64K (1UL << PAGE_SHIFT_64K)

#define PAGE_SHIFT_2M 21
#define PAGE_SIZE_2M (1UL << PAGE_SHIFT_2M)

#define PAGE_SHIFT_32M 25
#define PAGE_SIZE_32M (1UL << PAGE_SHIFT_32M)

#define PAGE_SHIFT_1G 30
#define PAGE_SIZE_1G (1UL << PAGE_SHIFT_1G)

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

	ret = shmdt(addr_shmget);
	NG(ret != -1, "shmdt failed\n");

	ret = shmctl(shmid, IPC_RMID, &shmid_ds);
	NG(ret != -1, "shmctl failed\n");

	return 0;
 fn_fail:
	return 1;
}

int main(int argc, char **argv)
{
	int ret;

	ret = shmat_thp(argv, PAGE_SIZE_64K);
	NG(ret == 0, "shmat_thp failed, size: %ld\n",
	   PAGE_SIZE_64K);

	ret = shmat_thp(argv, PAGE_SIZE_2M);
	NG(ret == 0, "shmat_thp failed, size: %ld\n",
	   PAGE_SIZE_2M);

	ret = shmat_thp(argv, PAGE_SIZE_32M);
	NG(ret == 0, "shmat_thp failed, size: %ld\n",
	   PAGE_SIZE_32M);

	ret = shmat_thp(argv, PAGE_SIZE_1G);
	NG(ret == 0, "shmat_thp failed, size: %ld\n",
	   PAGE_SIZE_1G);

	return 0;
 fn_fail:
	return 1;
}
