/* 409.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include "test_mck.h"
#include "testsuite.h"

static const size_t shift = PAGE_SHIFT;
static const size_t contshift = CONT_PAGE_SHIFT;

static int shmid = -1;
static char *shm_addr = (void *)-1;

SETUP_EMPTY(TEST_SUITE, TEST_NUMBER)

RUN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	size_t pgsize = 1UL << shift;
	size_t contpgsize = 1UL << contshift;

	int nr_contpage = 2;

	char *cmpaddr;
	char *loaddr;
	char *hiaddr;

	char *madvise_addr;
	char *madvise_end;
	size_t madvise_length;

	int res;

	// alloc
	shmid = shm_contiguous_pte(&shm_addr, &cmpaddr, &loaddr, &hiaddr,
				   contpgsize, nr_contpage);
	tp_assert(shmid != -1, "alloc contiguous error.");

	// test
	madvise_addr = (cmpaddr) - pgsize;
	madvise_end = (cmpaddr + contpgsize * nr_contpage);
	madvise_length = (unsigned long)(madvise_end - madvise_addr);
	res = madvise(madvise_addr, madvise_length, MADV_REMOVE);
	tp_assert(res == -1, "madvise error.");
	return NULL;
}

TEARDOWN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	if (shm_addr != (void *)-1) {
		shmdt(shm_addr);
	}

	if (shmid != -1) {
		shmctl(shmid, IPC_RMID, 0);
	}
}

