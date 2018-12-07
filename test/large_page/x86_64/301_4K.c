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

#define PAGE_SHIFT_1G 30
#define PAGE_SIZE_1G (1UL << PAGE_SHIFT_1G)

#define SHM_HUGE_SHIFT 26

int trial_num;

int shmat_thp(char **argv, size_t page_size, unsigned long page_shift)
{
	int ret;
	key_t key;
	int shmid;
	struct shmid_ds shmid_ds;
	char *addr_shmat;

	key = ftok(argv[0], 0);

	shmid = shmget(key, page_size, IPC_CREAT | 0660 |
		       SHM_HUGETLB | (page_shift << SHM_HUGE_SHIFT));
	NG(shmid != -1, "shmget failed\n");

	addr_shmat = shmat(shmid, NULL, 0);
	NG(addr_shmat != (void *)-1, "shmat failed\n");

	addr_shmat[0] = 'z';
	printf("large page request, trial#: %03d, addr: %016lx, size: %ld\n",
	       trial_num++, (unsigned long)addr_shmat, page_size);

	ret = shmctl(shmid, IPC_RMID, &shmid_ds);
	NG(ret != -1, "shmctl failed\n");

	ret = shmdt(addr_shmat);
	NG(ret != -1, "shmdt failed\n");

	return 0;
 fn_fail:
	return 1;
}

int main(int argc, char **argv)
{
	int ret;

	ret = shmat_thp(argv, PAGE_SIZE_2M, PAGE_SHIFT_2M);
	NG(ret == 0, "shmat_thp failed, size: %ld\n",
	   PAGE_SIZE_2M);

	ret = shmat_thp(argv, PAGE_SIZE_1G, PAGE_SHIFT_1G);
	NG(ret == 0, "shmat_thp failed, size: %ld\n",
	   PAGE_SIZE_1G);

	return 0;
 fn_fail:
	return 1;
}
