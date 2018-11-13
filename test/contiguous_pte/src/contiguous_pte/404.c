/* 400.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include "test_mck.h"
#include "testsuite.h"

static const size_t shift = PAGE_SHIFT;
static const size_t cmpshift = PAGE_SHIFT + CONT_PAGE_SHIFT;

static int shmid = -1;
static char* shm_addr = (void*)-1;

SETUP_EMPTY(TEST_SUITE, TEST_NUMBER)

RUN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	size_t pgsize = 1UL << shift;
	size_t cmppgsize = 1UL << cmpshift;

	int nr_cmppage = 1;

	char* cmpaddr;
	char* loaddr;
	char* hiaddr;

	char* madvise_addr;
	char* madvise_end;
	size_t madvise_length;

	int res;

	UNUSED_VARIABLE(pgsize);

	// alloc
	shmid = shm_contiguous_pte(&shm_addr, &cmpaddr, &loaddr, &hiaddr,
				   cmppgsize, nr_cmppage);
	tp_assert(shmid != -1, "alloc contiguous error.");

	// test
	madvise_addr = (cmpaddr);
	madvise_end = (cmpaddr + cmppgsize * nr_cmppage);
	madvise_length = (unsigned long)(madvise_end - madvise_addr);
	res = madvise(madvise_addr, madvise_length, MADV_REMOVE);
	tp_assert(res != -1, "madvise error.");

	// check
	{
		struct memory_info info;

		info.present = 0;
		get_memory_info_self((unsigned long)madvise_addr - 1, &info);
		tp_assert(info.present == 1 && info.pgsize == cmppgsize, "madvise_addr - 1 error.");

		info.present = 1;
		get_memory_info_self((unsigned long)madvise_addr, &info);
		tp_assert(info.present == 0, "madvise_addr error.");

		info.present = 1;
		get_memory_info_self((unsigned long)madvise_end - 1, &info);
		tp_assert(info.present == 0, "madvise_end - 1 error.");

		info.present = 0;
		get_memory_info_self((unsigned long)madvise_end, &info);
		tp_assert(info.present == 1 && info.pgsize ==  cmppgsize, "madvise_end error.");
	}

	return NULL;
}

TEARDOWN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	if (shm_addr != (void*)-1) {
		shmdt(shm_addr);
	}

	if (shmid != -1) {
		shmctl(shmid, IPC_RMID, 0);
	}
}

