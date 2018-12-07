/* testsuite.h COPYRIGHT FUJITSU LIMITED 2015-2016 */
#ifndef __TEST_SUITE_H__
#define __TEST_SUITE_H__

#ifndef MAP_HUGE_SHIFT
# define MAP_HUGE_SHIFT 26
#endif

#ifndef SHM_HUGETLB
# define SHM_HUGETLB 04000
#endif

/* Only ia64 requires this */
#ifdef __ia64__
# define ADDR (void *)(0x8000000000000000UL)
# define SHMAT_FLAGS (SHM_RND)
#else
# define ADDR (void *)(0x0UL)
# define SHMAT_FLAGS (0)
#endif

void *map_contiguous_pte(size_t *length,
			 char **cmp_addr, char **lo_addr, char **hi_addr,
			 size_t contpgsize, int nr_contiguous);

int shm_contiguous_pte(char **__shm_addr,
		       char **cmp_addr, char **lo_addr, char **hi_addr,
		       size_t contpgsize, int nr_contiguous);

char *do_2xx(int shift, int contshift, int nr_contpage,
	     ssize_t adjust_lower, ssize_t adjust_upper);
void teardown_2xx(void);


char *do_3xx(size_t shift, size_t contshift, int nr_contpage,
	     ssize_t adjust_lower, ssize_t adjust_upper, int keep_align);
void teardown_3xx(void);

#endif /*__TEST_SUITE_H__*/
