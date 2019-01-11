/* contiguous_pte.c COPYRIGHT FUJITSU LIMITED 2018 */
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include "test_mck.h"
#include "testsuite.h"



/*
 *           lo_addr        cmp_addr           hi_addr
 *             V             V                  V
 *      +------+-------------+------------------+-------------+------+
 *      | NONE | !contig * 1 | contig * nr_comp | !contig * 1 | NONE |
 *      +------+-------------+------------------+-------------+------+
 *      A      A
 *      |  or  |
 *     return addr
 *
 */
void *map_contiguous_pte(size_t *length,
			 char **cmp_addr, char **lo_addr, char **hi_addr,
			 size_t contpgsize, int nr_contiguous)
{
	char *ptr = MAP_FAILED;

	char *none_addr;
	size_t none_length;

	char *aligned_addr;
	char *lo_normal_page;
	char *hi_normal_page;

	size_t pgsize;
	int contshift;
	int res;

	int i;

	int flags;

	if (length == NULL) {
		goto out;
	}

	switch (contpgsize) {
	case CONT_PAGE_SIZE:
		pgsize = PAGE_SIZE;
		contshift = CONT_PAGE_SHIFT;
		break;
	case CONT_LARGE_PAGE_SIZE:
		pgsize = LARGE_PAGE_SIZE;
		contshift = CONT_LARGE_PAGE_SHIFT;
		break;
	case CONT_LARGEST_PAGE_SIZE:
		pgsize = LARGEST_PAGE_SIZE;
		contshift = CONT_LARGEST_PAGE_SHIFT;
		break;
	default:
		goto out;
	}

	// reserve
	none_length = contpgsize + (contpgsize * nr_contiguous) + contpgsize;
	flags = MAP_PRIVATE
		| MAP_ANONYMOUS
		| MAP_HUGETLB
		| (contshift << MAP_HUGE_SHIFT);

	none_addr = mmap(NULL, none_length,
			 PROT_NONE,
			 flags,
			 -1, 0);
	if (none_addr == MAP_FAILED) {
		fprintf(stderr, "mmap(none) error.\n");
		goto out;
	}

	// map contiguous
	aligned_addr = (void *)align_up((unsigned long)none_addr, contpgsize);
	aligned_addr += contpgsize;
	res = mprotect(aligned_addr,
		       contpgsize * nr_contiguous,
		       PROT_READ | PROT_WRITE);
	if (res == -1) {
		fprintf(stderr, "mprotect(aligned) error.\n");
		goto out;
	}
	for (i = 0; i < nr_contiguous; i++) {
		*(aligned_addr + contpgsize * i) = 'z';
	}

	// map neighbor
	lo_normal_page = aligned_addr - pgsize;
	hi_normal_page = aligned_addr + contpgsize * nr_contiguous;

	res = mprotect(lo_normal_page, pgsize, PROT_READ|PROT_WRITE);
	if (res == -1) {
		fprintf(stderr, "mprotect(lo) error.\n");
		goto out;
	}
	*(lo_normal_page) = 'z';

	res = mprotect(hi_normal_page, pgsize, PROT_READ|PROT_WRITE);
	if (res == -1) {
		fprintf(stderr, "mprotect(hi) error.\n");
		goto out;
	}
	*(hi_normal_page) = 'z';

	// join
	res = mprotect(lo_normal_page,
		       pgsize + (contpgsize * nr_contiguous) + pgsize,
		       PROT_READ | PROT_WRITE);
	if (res == -1) {
		fprintf(stderr, "mprotect(join) error.\n");
		goto out;
	}

	//check
	check_page_size((unsigned long)lo_normal_page, pgsize);
	for (i = 0; i < nr_contiguous; i++) {
		check_page_size((unsigned long)aligned_addr + contpgsize * i,
				contpgsize);
	}
	check_page_size((unsigned long)hi_normal_page, pgsize);

	if (cmp_addr) {
		*cmp_addr = aligned_addr;
	}
	if (lo_addr) {
		*lo_addr = lo_normal_page;
	}
	if (hi_addr) {
		*hi_addr = hi_normal_page;
	}
	ptr = none_addr;
	*length = none_length;
	none_addr = MAP_FAILED;
out:
	if (none_addr != MAP_FAILED) {
		munmap(none_addr, none_length);
	}
	return ptr;
}

/*
 *           lo_addr       cmp_addr           hi_addr
 *             V            V                   V
 *      +------+------------+------------------+------------+------+
 *      |      | contig * 1 | contig * nr_comp | contig * 1 |      |
 *      +------+------------+------------------+------------+------+
 *      A      A
 *      |  or  |
 *      __shm_addr
 *
 */
int shm_contiguous_pte(char **__shm_addr,
		       char **cmp_addr, char **lo_addr, char **hi_addr,
		       size_t contpgsize, int nr_contiguous)
{
	int ret = -1;
	int shmid = -1;
	char *shm_addr = (void *)-1;
	size_t shm_length;

	char *aligned_addr;
	char *lo_page;
	char *hi_page;

	size_t pgsize;
	int contshift;
	int res;

	int i;
	int huge = 1;

	int shmflg;

	UNUSED_VARIABLE(pgsize);

	if (__shm_addr == NULL) {
		goto out;
	}

	switch (contpgsize) {
	case CONT_PAGE_SIZE:
		pgsize = PAGE_SIZE;
		contshift = CONT_PAGE_SHIFT;
		break;
	case CONT_LARGE_PAGE_SIZE:
		pgsize = LARGE_PAGE_SIZE;
		contshift = CONT_LARGE_PAGE_SHIFT;
		break;
	case CONT_LARGEST_PAGE_SIZE:
		pgsize = LARGEST_PAGE_SIZE;
		contshift = CONT_LARGEST_PAGE_SHIFT;
		break;
	default:
		goto out;
	}

	// reserve
	shm_length = contpgsize + (contpgsize * nr_contiguous) + contpgsize;
	shm_length += contpgsize;
	if (huge) {
		shmflg = IPC_CREAT
			| SHM_R
			| SHM_HUGETLB
			| (contshift << MAP_HUGE_SHIFT);
	} else {
		shmflg = IPC_CREAT
			| SHM_R;
	}

	shmid = shmget(IPC_PRIVATE, shm_length, shmflg);
	if (shmid == -1) {
		fprintf(stderr, "shmget error.\n");
		goto out;
	}

	shm_addr = shmat(shmid, NULL, 0);
	if (shm_addr == (void *)-1) {
		fprintf(stderr, "shmat error.\n");
		goto out;
	}

	// calc contiguous
	aligned_addr = (void *)align_up((unsigned long)shm_addr, contpgsize);
	aligned_addr += contpgsize;

	// calc neighbor
	lo_page = aligned_addr - contpgsize;
	hi_page = aligned_addr + contpgsize * nr_contiguous;

	// map
	res = mprotect(lo_page,
		       contpgsize + (contpgsize * nr_contiguous) + contpgsize,
		       PROT_READ | PROT_WRITE);
	if (res == -1) {
		fprintf(stderr, "mprotect error.\n");
		goto out;
	}
	for (i = 0; i < nr_contiguous; i++) {
		*(aligned_addr + contpgsize * i) = 'z';
	}
	*(lo_page) = 'z';
	*(hi_page) = 'z';

	//check
	check_page_size((unsigned long)lo_page, contpgsize);
	for (i = 0; i < nr_contiguous; i++) {
		check_page_size((unsigned long)aligned_addr + contpgsize * i,
				contpgsize);
	}
	check_page_size((unsigned long)hi_page, contpgsize);

	if (__shm_addr) {
		*__shm_addr = shm_addr;
	}
	if (cmp_addr) {
		*cmp_addr = aligned_addr;
	}
	if (lo_addr) {
		*lo_addr = lo_page;
	}
	if (hi_addr) {
		*hi_addr = hi_page;
	}
	ret = shmid;
	shmid = -1;
	shm_addr = (void *)-1;
out:
	if (shm_addr != (void *)-1) {
		shmdt(shm_addr);
	}
	if (shmid != -1) {
		shmctl(shmid, IPC_RMID, 0);
	}
	return ret;
}
