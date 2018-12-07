/* 000.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include "test_mck.h"
#include "testsuite.h"

static int shmid = -1;

SETUP_EMPTY(TEST_SUITE, TEST_NUMBER)

RUN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	unsigned long shift = CONT_LARGEST_PAGE_SHIFT;
	unsigned long length = 1UL << shift;
	unsigned long pgsize_log = shift << MAP_HUGE_SHIFT;

	shmid = shmget(IPC_PRIVATE, length, pgsize_log | SHM_HUGETLB | IPC_CREAT | SHM_R | SHM_W);
	tp_assert(0 <= shmid, "shmget error.");
	return NULL;
}

TEARDOWN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	if (0 <= shmid) {
		shmctl(shmid, IPC_RMID, NULL);
	}
}
