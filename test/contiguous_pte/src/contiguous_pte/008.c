/* 008.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include "test_mck.h"
#include "testsuite.h"

static int shmid = -1;
static char *shm_addr = (void *)-1;

SETUP_EMPTY(TEST_SUITE, TEST_NUMBER)

RUN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	unsigned long shift = CONT_PAGE_SHIFT;
	unsigned long length = (1UL << shift) * 2;
	char *aligned_addr;

	shmid = shmget(IPC_PRIVATE, length,
		       IPC_CREAT | SHM_R | SHM_W);
	tp_assert(shmid >= 0, "shmget error.");

	shm_addr = shmat(shmid, NULL, 0);
	tp_assert(shm_addr != (void *)-1,
		  "shmat error.\n");

	aligned_addr = (void *)align_up((unsigned long)shm_addr,
				(1UL << shift));
	aligned_addr[0] = 'z';

	// check
	{
		struct memory_info info = {0};

		get_memory_info_self((unsigned long)aligned_addr,
				     &info);
		tp_assert(info.present == 1,
			  "alloc error.");
		tp_assert(info.pgsize == (1UL << shift),
			  "size error.");
	}
	return NULL;
}

TEARDOWN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	if (shm_addr != (void *)-1) {
		shmdt(shm_addr);
	}

	if (shmid >= 0) {
		shmctl(shmid, IPC_RMID, NULL);
	}
}
